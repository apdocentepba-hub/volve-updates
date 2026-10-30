package motorupdate

import (
    "context"
    "errors"
    "os"
    "reflect"
    "strings"
    "testing"
)

// All tests use temporary fake binaries, ephemeral Ed25519 publisher keys and
// fake drivers. None launches a DNS service, alters Windows tasks or network.
type signedLegacyDriverLab struct {
    *managedDriverTest
    watchdogCount int
    failWatchdogAt int
    replaceCandidate bool
    replaceOldMotor string
}
func newSignedLegacyDriverLab()*signedLegacyDriverLab {
    return &signedLegacyDriverLab{managedDriverTest:&managedDriverTest{}}
}
func (d *signedLegacyDriverLab) IndependentRecoveryReady(_ context.Context, _ VerifiedLegacyMigrationProof)error{
    d.watchdogCount++
    if err:=d.tick("watchdog");err!=nil{return err}
    if d.failWatchdogAt==d.watchdogCount{return errors.New("independent recovery agent unavailable")}
    return nil
}
func (d *signedLegacyDriverLab) InstallVersionedCandidate(ctx context.Context,candidate string) error {
    if err:=d.managedDriverTest.InstallVersionedCandidate(ctx,candidate);err!=nil{return err}
    if d.replaceCandidate{
        return os.WriteFile(candidate,[]byte("MZ_CANDIDATE_MODIFIED_AFTER_FIRST_SIGNATURE"),0600)
    }
    if d.replaceOldMotor!=""{
        return os.WriteFile(d.replaceOldMotor,[]byte("MZ_LEGACY_CHANGED_BEFORE_SWITCH"),0600)
    }
    return nil
}
func runSignedLegacyLab(ctx context.Context,f *signedBridgeFixture,driver SignedLegacySwitchDriver,acl func(string)error,preflight func()error)error{
    return ApplySignedLegacyWithRollback(ctx,f.live,f.backup,f.candidate,"0.28.7",
        f.raw,f.sig,f.pub,acl,preflight,driver)
}
func TestSignedLegacyTransactionRequiresRevalidationAndIndependentWatchdog(t *testing.T){
    f:=newSignedBridge(t)
    d:=newSignedLegacyDriverLab()
    checks:=0
    err:=runSignedLegacyLab(context.Background(),f,d,testSecureLabFolderBridge,
        func()error{checks++;return nil})
    if err!=nil {t.Fatal(err)}
    want:=[]string{"preflight","watchdog","snapshot","install","watchdog","switch","probe","connectivity","commit"}
    if !reflect.DeepEqual(d.calls,want){t.Fatalf("unexpected signed migration order: %v",d.calls)}
    if checks!=2 || d.watchdogCount!=2{t.Fatalf("expected proof+watchdog rechecks before switch, got %d/%d",checks,d.watchdogCount)}
}
func TestSignedLegacyTransactionBlocksBeforeSnapshotWithoutPermissionOrWatchdog(t *testing.T){
    for _,kind:=range []string{"wrong-publisher","unsafe-parent","no-live-dns","missing-watchdog","no-driver"}{
        t.Run(kind,func(t *testing.T){
            f:=newSignedBridge(t)
            d:=newSignedLegacyDriverLab()
            var driver SignedLegacySwitchDriver=d
            acl:=testSecureLabFolderBridge
            preflight:=func()error{return nil}
            switch kind {
            case "wrong-publisher":
                f.sig=[]byte("not a real signature")
            case "unsafe-parent":
                acl=func(string)error{return errors.New("untrusted ACL")}
            case "no-live-dns":
                preflight=func()error{return errors.New("DNS stopped")}
            case "missing-watchdog":
                d.failWatchdogAt=1
            case "no-driver":
                driver=nil
            }
            err:=runSignedLegacyLab(context.Background(),f,driver,acl,preflight)
            if err==nil{t.Fatal("unsigned or unsafe migration accepted")}
            for _,call:=range d.calls {
                if call=="snapshot"||call=="install"||call=="switch"||call=="commit"{
                    t.Fatalf("unsafe operation %s before readiness: %v",call,d.calls)
                }
            }
        })
    }
}
func TestSignedLegacyTransactionFailsClosedOnRecheckAndRestores(t *testing.T){
    for _,kind:=range []string{"candidate-tamper","legacy-tamper","watchdog-down"}{
        t.Run(kind,func(t *testing.T){
            f:=newSignedBridge(t)
            d:=newSignedLegacyDriverLab()
            switch kind{
            case "candidate-tamper":d.replaceCandidate=true
            case "legacy-tamper":d.replaceOldMotor=f.live
            case "watchdog-down":d.failWatchdogAt=2
            }
            err:=runSignedLegacyLab(context.Background(),f,d,testSecureLabFolderBridge,func()error{return nil})
            if err==nil || !strings.Contains(err.Error(),"revertida"){
                t.Fatalf("post-snapshot recheck failure not recovered: %v",err)
            }
            for _,call:=range d.calls {
                if call=="switch"||call=="commit" {t.Fatalf("switch/commit after invalid recheck: %v",d.calls)}
            }
            tail:=d.calls[len(d.calls)-3:]
            if !reflect.DeepEqual(tail,[]string{"restore","probe","connectivity"}){
                t.Fatalf("not independently restored and probed: %v",d.calls)
            }
        })
    }
}
func TestSignedLegacyTransactionNeverCommitsAfterSwitchFailure(t *testing.T){
    f:=newSignedBridge(t)
    for _,step:=range []string{"install","switch","probe","connectivity","commit"}{
        t.Run(step,func(t *testing.T){
            d:=newSignedLegacyDriverLab()
            d.fail=step
            err:=runSignedLegacyLab(context.Background(),f,d,testSecureLabFolderBridge,func()error{return nil})
            if err==nil{t.Fatalf("failure in %s silently accepted",step)}
            seenRestore:=false
            for _,call:=range d.calls{if call=="restore"{seenRestore=true}}
            if !seenRestore{t.Fatalf("rollback not attempted after %s: %v",step,d.calls)}
        })
    }
}
func TestSignedLegacyTransactionRecoverAfterCancellationWithNewContext(t *testing.T){
    f:=newSignedBridge(t)
    ctx,cancel:=context.WithCancel(context.Background())
    defer cancel()
    d:=newSignedLegacyDriverLab()
    d.cancel=cancel
    err:=runSignedLegacyLab(ctx,f,d,testSecureLabFolderBridge,func()error{return nil})
    if err==nil || d.rollbackCancelled {t.Fatalf("independent recovery context missing: %v",err)}
    seen:=false
    for _,call:=range d.calls{if call=="restore"{seen=true}}
    if !seen {t.Fatalf("cancellation bypassed rollback: %v",d.calls)}
}
func TestSignedLegacyTransactionCannotClaimRecoveryIfInternetStillDown(t *testing.T){
    f:=newSignedBridge(t)
    d:=newSignedLegacyDriverLab()
    d.fail="connectivity"
    err:=runSignedLegacyLab(context.Background(),f,d,testSecureLabFolderBridge,func()error{return nil})
    if err==nil || !strings.Contains(err.Error(),"CRÍTICO"){
        t.Fatalf("false recovery with failed Internet probe: %v",err)
    }
}
