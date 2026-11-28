package motorupdate

import (
    "context"
    "errors"
    "strings"
    "testing"
    "time"
)

const activationTestGUID = "{12345678-1234-1234-1234-123456789abc}"

type activationTestBackend struct {
    current map[string]DNSServerState
    writes int
    failOn int
    cancel context.CancelFunc
}

func activationKey(guid string, family DNSAddressFamily) string {
    return strings.ToLower(guid) + "|" + string(family)
}
func copyActivationState(s DNSServerState) DNSServerState {
    s.Servers=append([]string(nil),s.Servers...)
    return s
}
func (b *activationTestBackend) Read(ctx context.Context, guid string, family DNSAddressFamily)(DNSServerState,error){
    if err:=ctx.Err();err!=nil{return DNSServerState{},err}
    s,ok:=b.current[activationKey(guid,family)]
    if !ok{return DNSServerState{},errors.New("adapter not found")}
    return copyActivationState(s),nil
}
func (b *activationTestBackend) Apply(ctx context.Context, next DNSServerState)error{
    if err:=ctx.Err();err!=nil{return err}
    b.writes++
    b.current[activationKey(next.InterfaceGUID,next.Family)]=copyActivationState(next)
    if b.cancel!=nil && b.writes==1 { b.cancel() }
    if b.failOn==b.writes{return errors.New("synthetic DNS driver failed after mutation")}
    return nil
}

type activationTestGuard struct {
    backend *activationTestBackend
    originals []DNSServerState
    armCalls,healthCalls,recoverCalls,commitCalls int
    armedErr,healthErr,commitErr,recoverErr error
    pretendRecovered bool
}
func(g *activationTestGuard) VerifyArmed(ctx context.Context,pin string)error{
    if err:=ctx.Err();err!=nil{return err}
    g.armCalls++
    if len(pin)!=64{return errors.New("missing independent journal digest")}
    return g.armedErr
}
func(g *activationTestGuard) VerifyLiveProtection(ctx context.Context,pin string)error{
    if err:=ctx.Err();err!=nil{return err}
    g.healthCalls++
    return g.healthErr
}
func(g *activationTestGuard) RecoverIndependently(ctx context.Context,pin string)error{
    g.recoverCalls++
    if err:=ctx.Err();err!=nil{return err}
    if g.recoverErr!=nil{return g.recoverErr}
    if g.pretendRecovered{return nil} // dishonest recoverer: must be detected by readback
    for _,original:=range g.originals {
        g.backend.current[activationKey(original.InterfaceGUID,original.Family)]=copyActivationState(original)
    }
    return nil
}
func(g *activationTestGuard) CommitActive(ctx context.Context,pin string)error{
    if err:=ctx.Err();err!=nil{return err}
    g.commitCalls++
    return g.commitErr
}
func prepareActivationTest(t *testing.T)([]byte,string,*activationTestBackend,*activationTestGuard){
    t.Helper()
    originals:=[]DNSServerState{
        {InterfaceGUID:activationTestGUID,Family:DNSIPv4,Mode:DNSStatic,Servers:[]string{"9.9.9.9","1.1.1.1"}},
        {InterfaceGUID:activationTestGUID,Family:DNSIPv6,Mode:DNSAutomatic},
    }
    raw,pin,err:=BuildDNSOriginalJournal(context.Background(),originals)
    if err!=nil{t.Fatalf("build test original DNS journal: %v",err)}
    b:=&activationTestBackend{current:map[string]DNSServerState{}}
    for _,s:=range originals{b.current[activationKey(s.InterfaceGUID,s.Family)]=copyActivationState(s)}
    g:=&activationTestGuard{backend:b,originals:originals}
    return raw,pin,b,g
}
func assertActivationTestState(t *testing.T,b *activationTestBackend,original bool){
    t.Helper()
    for _,fam:=range []DNSAddressFamily{DNSIPv4,DNSIPv6}{
        current,err:=b.Read(context.Background(),activationTestGUID,fam)
        if err!=nil{t.Fatal(err)}
        if original{
            mode:=DNSAutomatic
            addresses:=[]string(nil)
            if fam==DNSIPv4{mode=DNSStatic;addresses=[]string{"9.9.9.9","1.1.1.1"}}
            if !sameDNSState(current,DNSServerState{InterfaceGUID:activationTestGUID,Family:fam,Mode:mode,Servers:addresses}){
                t.Fatalf("original DNS state not restored for %s: %#v",fam,current)
            }
        }else{
            local:="127.0.0.1"
            if fam==DNSIPv6{local="::1"}
            if !sameDNSState(current,DNSServerState{InterfaceGUID:activationTestGUID,Family:fam,Mode:DNSStatic,Servers:[]string{local}}){
                t.Fatalf("local DNS target not verified for %s: %#v",fam,current)
            }
        }
    }
}

func TestProtectedDNSActivationAllFamilyHealthyCommit(t *testing.T){
    raw,pin,b,g:=prepareActivationTest(t)
    if err:=activateVOLVEDNSWithRecovery(context.Background(),raw,pin,b,g);err!=nil{t.Fatal(err)}
    if b.writes!=2||g.recoverCalls!=0||g.healthCalls!=1||g.commitCalls!=1||g.armCalls<3{
        t.Fatalf("incomplete protected transaction: writes=%d guard=%+v",b.writes,g)
    }
    assertActivationTestState(t,b,false)
}
func TestProtectedDNSActivationRejectsUnpinnedOrModifiedJournalWithoutWrites(t *testing.T){
    for _,variant:=range []string{"wrong-pin","altered-payload","no-guard"}{
        t.Run(variant,func(t *testing.T){
            raw,pin,b,g:=prepareActivationTest(t)
            var guard DNSActivationSafetyGuard=g
            switch variant{
            case "wrong-pin":pin=strings.Repeat("0",64)
            case "altered-payload":raw=append([]byte(nil),raw...);raw[len(raw)-2]^=1
            case "no-guard":guard=nil
            }
            if err:=activateVOLVEDNSWithRecovery(context.Background(),raw,pin,b,guard);err==nil{
                t.Fatal("unsigned journal or missing recovery guard accepted")
            }
            if b.writes!=0||g.recoverCalls!=0||g.commitCalls!=0{t.Fatal("mutation or recovery on untrusted input")}
            assertActivationTestState(t,b,true)
        })
    }
}
func TestProtectedDNSActivationPreflightRejectsOtherFamilyBeforeAnyMutation(t *testing.T){
    raw,pin,b,g:=prepareActivationTest(t)
    b.current[activationKey(activationTestGUID,DNSIPv6)]=DNSServerState{
        InterfaceGUID:activationTestGUID,Family:DNSIPv6,Mode:DNSStatic,Servers:[]string{"2001:4860:4860::8888"},
    }
    err:=activateVOLVEDNSWithRecovery(context.Background(),raw,pin,b,g)
    if err==nil||!strings.Contains(err.Error(),"preflight"){t.Fatalf("preflight did not reject external IPv6: %v",err)}
    if b.writes!=0||g.recoverCalls!=0{t.Fatal("preflight wrote DNS or launched recovery")}
}
func TestProtectedDNSActivationRefusesUnarmedWatchdogWithoutWrites(t *testing.T){
    raw,pin,b,g:=prepareActivationTest(t)
    g.armedErr=errors.New("watchdog not armed")
    err:=activateVOLVEDNSWithRecovery(context.Background(),raw,pin,b,g)
    if err==nil||b.writes!=0||g.recoverCalls!=0||g.commitCalls!=0{
        t.Fatalf("missing watchdog was not fail-closed: %v",err)
    }
    assertActivationTestState(t,b,true)
}
func TestProtectedDNSActivationPartialMutationAlwaysRequestsIndependentRecovery(t *testing.T){
    raw,pin,b,g:=prepareActivationTest(t)
    b.failOn=2 // driver changes IPv6 THEN returns an error
    err:=activateVOLVEDNSWithRecovery(context.Background(),raw,pin,b,g)
    if err==nil||b.writes!=2||g.recoverCalls!=1||g.commitCalls!=0{
        t.Fatalf("partial failure was incorrectly committed: %v",err)
    }
    assertActivationTestState(t,b,true)
}
func TestProtectedDNSActivationUnhealthyDNSRestoresOriginal(t *testing.T){
    raw,pin,b,g:=prepareActivationTest(t)
    g.healthErr=errors.New("independent allowed-domain and blocked-domain checks failed")
    err:=activateVOLVEDNSWithRecovery(context.Background(),raw,pin,b,g)
    if err==nil||g.healthCalls!=1||g.recoverCalls!=1||g.commitCalls!=0{
        t.Fatalf("unhealthy DNS protection was not rolled back: %v",err)
    }
    assertActivationTestState(t,b,true)
}
func TestProtectedDNSActivationCommitFailureRestoresOriginal(t *testing.T){
    raw,pin,b,g:=prepareActivationTest(t)
    g.commitErr=errors.New("durable protected receipt failed")
    err:=activateVOLVEDNSWithRecovery(context.Background(),raw,pin,b,g)
    if err==nil||g.commitCalls!=1||g.recoverCalls!=1{
        t.Fatalf("commit failure did not request independent rescue: %v",err)
    }
    assertActivationTestState(t,b,true)
}
func TestProtectedDNSActivationCancelledInstallerStillRequestsRescue(t *testing.T){
    raw,pin,b,g:=prepareActivationTest(t)
    ctx,cancel:=context.WithCancel(context.Background())
    defer cancel()
    b.cancel=cancel
    err:=activateVOLVEDNSWithRecovery(ctx,raw,pin,b,g)
    if err==nil||g.recoverCalls!=1||g.commitCalls!=0{
        t.Fatalf("cancelled installer skipped independent rescue: %v",err)
    }
    assertActivationTestState(t,b,true)
}
func TestProtectedDNSActivationNeverClaimsSuccessWhenRecoveryFails(t *testing.T){
    raw,pin,b,g:=prepareActivationTest(t)
    b.failOn=1
    g.recoverErr=errors.New("SYSTEM recovery process unreachable")
    err:=activateVOLVEDNSWithRecovery(context.Background(),raw,pin,b,g)
    if err==nil||!strings.Contains(err.Error(),"CRITICAL")||g.recoverCalls!=1||g.commitCalls!=0{
        t.Fatalf("failed emergency recovery was not reported: %v",err)
    }
}

func TestProtectedDNSActivationIndependentRecoveryMustProveOriginalReadback(t *testing.T){
    raw,pin,b,g:=prepareActivationTest(t)
    b.failOn=1 // driver writes IPv4 then raises an error
    g.pretendRecovered=true // watchdog claims success without restoring
    err:=activateVOLVEDNSWithRecovery(context.Background(),raw,pin,b,g)
    if err==nil||!strings.Contains(err.Error(),"CRITICAL")||
        !strings.Contains(err.Error(),"readback")||
        g.recoverCalls!=1||g.commitCalls!=0{
        t.Fatalf("unverified recovery incorrectly considered safe: %v",err)
    }
    if b.writes!=1{t.Fatalf("unexpected DNS writes after failure: %d",b.writes)}
}


// Exercise failure at the final commit boundary rather than at the first
// admission or native write. The recovery agent may disappear while an
// otherwise successful health check is in progress.
type activationLateDriftGuard struct {
    *activationTestGuard
    variant string
}
func(g *activationLateDriftGuard) VerifyArmed(ctx context.Context,pin string)error{
    if err:=g.activationTestGuard.VerifyArmed(ctx,pin);err!=nil{return err}
    if g.healthCalls>0 {
        switch g.variant {
        case "watchdog-lost":
            return errors.New("independent recovery task lost after healthy probe")
        case "dns-changed":
            g.backend.current[activationKey(activationTestGUID,DNSIPv6)]=copyActivationState(g.originals[1])
        }
    }
    return nil
}
func TestProtectedDNSActivationReattestsAfterHealthBeforeCommit(t *testing.T){
    for _,variant:=range []string{"watchdog-lost","dns-changed"} {
        t.Run(variant,func(t *testing.T){
            raw,pin,b,g:=prepareActivationTest(t)
            guard:=&activationLateDriftGuard{activationTestGuard:g,variant:variant}
            err:=activateVOLVEDNSWithRecovery(context.Background(),raw,pin,b,guard)
            if err==nil||b.writes!=2||g.healthCalls!=1||g.commitCalls!=0||g.recoverCalls!=1{
                t.Fatalf("unsafe final activation verdict: %v; writes=%d health=%d commit=%d recovery=%d",err,b.writes,g.healthCalls,g.commitCalls,g.recoverCalls)
            }
            assertActivationTestState(t,b,true)
        })
    }
}


type activationRecoveryDeadlineGuard struct{
    *activationTestGuard
    deadline time.Time
    remaining time.Duration
}
func(g *activationRecoveryDeadlineGuard) RecoverIndependently(ctx context.Context,pin string)error{
    deadline,ok:=ctx.Deadline()
    if !ok{return errors.New("independent recovery has no finite deadline")}
    g.deadline=deadline
    g.remaining=time.Until(deadline)
    return g.activationTestGuard.RecoverIndependently(ctx,pin)
}
func TestProtectedDNSActivationRescueBudgetSurvivesCancelledInstaller(t *testing.T){
    raw,pin,b,g:=prepareActivationTest(t)
    ctx,cancel:=context.WithCancel(context.Background())
    defer cancel()
    b.cancel=cancel
    guard:=&activationRecoveryDeadlineGuard{activationTestGuard:g}
    if err:=activateVOLVEDNSWithRecovery(ctx,raw,pin,b,guard);err==nil{
        t.Fatal("cancelled activation unexpectedly committed")
    }
    // No wall-clock sleep. Confirm the actual child context passed to
    // the independent agent covers the measured real Windows restoration
    // interval and still has a finite maximum.
    if guard.deadline.IsZero()||guard.remaining<14*time.Minute||guard.remaining>15*time.Minute{
        t.Fatalf("unsafe emergency recovery deadline: %s",guard.remaining)
    }
    if g.recoverCalls!=1||g.commitCalls!=0{t.Fatal("rescue not independently requested")}
    assertActivationTestState(t,b,true)
}


// These fixtures deliberately panic in a dependency, not in the transaction.
// Every post-write panic must request independent restoration, and neither
// panic messages nor an unverified recovery may escape as success.
type activationPanicBackend struct {
    *activationTestBackend
    panicOnWrite int
    panicOnRead bool
}
func(b *activationPanicBackend) Apply(ctx context.Context,next DNSServerState)error{
    err:=b.activationTestBackend.Apply(ctx,next)
    if b.panicOnWrite==b.writes{panic("PRIVATE PANIC FIXTURE")}
    return err
}
func(b *activationPanicBackend) Read(ctx context.Context,guid string,family DNSAddressFamily)(DNSServerState,error){
    if b.panicOnRead{panic("PRIVATE READBACK FIXTURE")}
    return b.activationTestBackend.Read(ctx,guid,family)
}
type activationPanicGuard struct{
    *activationTestGuard
    panicAt string
    wrapped *activationPanicBackend
}
func(g *activationPanicGuard) VerifyArmed(ctx context.Context,pin string)error{
    if g.panicAt=="preflight"{panic("PRIVATE PREFLIGHT FIXTURE")}
    return g.activationTestGuard.VerifyArmed(ctx,pin)
}
func(g *activationPanicGuard) VerifyLiveProtection(ctx context.Context,pin string)error{
    if g.panicAt=="health"{panic("PRIVATE HEALTH FIXTURE")}
    return g.activationTestGuard.VerifyLiveProtection(ctx,pin)
}
func(g *activationPanicGuard) CommitActive(ctx context.Context,pin string)error{
    if g.panicAt=="commit"{panic("PRIVATE COMMIT FIXTURE")}
    return g.activationTestGuard.CommitActive(ctx,pin)
}
func(g *activationPanicGuard) RecoverIndependently(ctx context.Context,pin string)error{
    if g.panicAt=="rescue"{g.recoverCalls++;panic("PRIVATE RESCUE FIXTURE")}
    err:=g.activationTestGuard.RecoverIndependently(ctx,pin)
    if g.panicAt=="readback"{g.wrapped.panicOnRead=true}
    return err
}
func TestProtectedDNSActivationPanicRequestsIndependentRecovery(t *testing.T){
    for _,stage:=range []string{"preflight","first-write","second-write","health","commit","rescue","readback"}{
        t.Run(stage,func(t *testing.T){
            raw,pin,b,g:=prepareActivationTest(t)
            backend:=&activationPanicBackend{activationTestBackend:b}
            guard:=&activationPanicGuard{activationTestGuard:g,panicAt:stage,wrapped:backend}
            switch stage{
            case "first-write":backend.panicOnWrite=1
            case "second-write":backend.panicOnWrite=2
            case "rescue","readback":b.failOn=1
            }
            err:=activateVOLVEDNSWithRecovery(context.Background(),raw,pin,backend,guard)
            if err==nil||strings.Contains(err.Error(),"PRIVATE"){t.Fatalf("unsafe panic result: %v",err)}
            if stage=="preflight"{
                if b.writes!=0||g.recoverCalls!=0{t.Fatal("preflight panic mutated state")}
            }else if g.recoverCalls!=1{t.Fatalf("panic did not request independent recovery: %v",err)}
            if g.commitCalls!=0{t.Fatal("panic transaction reported commit")}
            if stage=="rescue"||stage=="readback"{
                if !strings.Contains(err.Error(),"CRITICAL")||!strings.Contains(err.Error(),"pending"){t.Fatalf("unverified recovery: %v",err)}
            }else{assertActivationTestState(t,b,true)}
        })
    }
}
