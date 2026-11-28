package motorupdate

import (
 "context"
 "errors"
 "strings"
 "testing"
 "time"
)

func publisherDNSGuardFixture(t *testing.T)(
 []byte,string,*activationTestBackend,*activationTestGuard,
 DNSActivationPublisherAuthorization,*time.Time,
){
 t.Helper()
 raw,pin,backend,inner:=prepareActivationTest(t)
 f:=makeDNSGrantFixture(t)
 f.pins.OriginalDNSJournalSHA256=pin
 f.grant.OriginalDNSJournalSHA256=pin
 grant,sig:=signDNSActivationFixture(t,f)
 auth:=DNSActivationPublisherAuthorization{
  GrantJSON:grant,Signature:sig,PinnedPublisherKey:f.pub,
  PinnedEvidence:f.pins,
 }
 now:=f.now
 return raw,pin,backend,inner,auth,&now
}

func TestPublisherScopedDNSActivationGuardRequiresSignedApprovalOnEveryWrite(t *testing.T){
 raw,pin,backend,inner,auth,clock:=publisherDNSGuardFixture(t)
 signed,err:=newPublisherScopedDNSActivationGuard(
  context.Background(),raw,pin,auth,inner,func()time.Time{return *clock},
 )
 if err!=nil{t.Fatal(err)}
 if err:=activateVOLVEDNSWithRecovery(context.Background(),raw,pin,backend,signed);err!=nil{
  t.Fatal(err)
 }
 if backend.writes!=2||inner.commitCalls!=1||inner.recoverCalls!=0{
  t.Fatalf("valid scoped permit did not complete exact activation: %d, %+v",backend.writes,inner)
 }
 assertActivationTestState(t,backend,false)
}

func TestPublisherScopedDNSActivationGuardRefusesForgedOrUnrelatedPermitBeforeWrites(t *testing.T){
 for _,tc:=range []string{"nil-recovery","missing-signed-permit","wrong-signer","wrong-journal-pin","altered-journal","invalid-time"}{
  t.Run(tc,func(t *testing.T){
   raw,pin,backend,inner,auth,clock:=publisherDNSGuardFixture(t)
   var trusted DNSActivationSafetyGuard=inner
   switch tc{
   case "nil-recovery":trusted=nil
   case "missing-signed-permit":auth.Signature=nil
   case "wrong-signer":auth.PinnedPublisherKey[0]^=1
   case "wrong-journal-pin":auth.PinnedEvidence.OriginalDNSJournalSHA256=strings.Repeat("f",64)
   case "altered-journal":raw=append([]byte(nil),raw...);raw[len(raw)-2]^=1
   case "invalid-time":*clock=clock.Add(30*time.Minute)
   }
   signed,err:=newPublisherScopedDNSActivationGuard(
    context.Background(),raw,pin,auth,trusted,func()time.Time{return *clock},
   )
   if err==nil||signed!=nil||backend.writes!=0||inner.commitCalls!=0{
    t.Fatalf("forged scoped activation guard was accepted: %v",err)
   }
   assertActivationTestState(t,backend,true)
  })
 }
}

type expiringActivationBackend struct{
 *activationTestBackend
 clock *time.Time
}
func(b *expiringActivationBackend)Apply(ctx context.Context,state DNSServerState)error{
 err:=b.activationTestBackend.Apply(ctx,state)
 if b.writes==1{*b.clock=b.clock.Add(30*time.Minute)}
 return err
}
func TestPublisherScopedDNSActivationPermitExpiryAfterFirstWriteMustRestoreOriginal(t *testing.T){
 raw,pin,backend,inner,auth,clock:=publisherDNSGuardFixture(t)
 signed,err:=newPublisherScopedDNSActivationGuard(
  context.Background(),raw,pin,auth,inner,func()time.Time{return *clock},
 )
 if err!=nil{t.Fatal(err)}
 expiring:=&expiringActivationBackend{activationTestBackend:backend,clock:clock}
 err=activateVOLVEDNSWithRecovery(context.Background(),raw,pin,expiring,signed)
 if err==nil||!strings.Contains(err.Error(),"publisher authorization")||
  backend.writes!=1||inner.recoverCalls!=1||inner.commitCalls!=0{
  t.Fatalf("expired activation permit incorrectly completed or blocked emergency recovery: %v",err)
 }
 assertActivationTestState(t,backend,true)
}

func TestPublisherScopedDNSActivationRecoveryDoesNotRequireStillValidActivationGrant(t *testing.T){
 raw,pin,backend,inner,auth,clock:=publisherDNSGuardFixture(t)
 signed,err:=newPublisherScopedDNSActivationGuard(
  context.Background(),raw,pin,auth,inner,func()time.Time{return *clock},
 )
 if err!=nil{t.Fatal(err)}
 *clock=clock.Add(30*time.Minute)
 backend.current[activationKey(activationTestGUID,DNSIPv4)]=DNSServerState{
  InterfaceGUID:activationTestGUID,Family:DNSIPv4,Mode:DNSStatic,Servers:[]string{"127.0.0.1"},
 }
 if err:=signed.VerifyArmed(context.Background(),pin);err==nil{
  t.Fatal("expired activation permit still armed for DNS writes")
 }
 if err:=signed.RecoverIndependently(context.Background(),pin);err!=nil{
  t.Fatalf("expired activation permit prevented original recovery: %v",err)
 }
 if inner.recoverCalls!=1{t.Fatal("emergency recovery was not invoked")}
 assertActivationTestState(t,backend,true)
}

func TestPublisherScopedDNSActivationInputBuffersCannotMutateSignedEvidence(t *testing.T){
 raw,pin,backend,inner,auth,clock:=publisherDNSGuardFixture(t)
 signed,err:=newPublisherScopedDNSActivationGuard(
  context.Background(),raw,pin,auth,inner,func()time.Time{return *clock},
 )
 if err!=nil{t.Fatal(err)}
 auth.GrantJSON[0]^=1
 auth.Signature[0]^=1
 auth.PinnedPublisherKey[0]^=1
 raw[0]^=1
 if err:=signed.VerifyArmed(context.Background(),pin);err!=nil{
  t.Fatalf("caller mutating input byte slices altered the approved immutable permit: %v",err)
 }
 if backend.writes!=0||inner.commitCalls!=0{t.Fatal("review-only permit guard modified DNS")}
}

func TestPublisherScopedDNSActivationCancelledContextDoesNotAuthorizeNewWrites(t *testing.T){
 raw,pin,backend,inner,auth,clock:=publisherDNSGuardFixture(t)
 signed,err:=newPublisherScopedDNSActivationGuard(
  context.Background(),raw,pin,auth,inner,func()time.Time{return *clock},
 )
 if err!=nil{t.Fatal(err)}
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 if err:=signed.VerifyArmed(ctx,pin);!errors.Is(err,context.Canceled){
  t.Fatalf("cancelled activation approval unexpectedly valid: %v",err)
 }
 if backend.writes!=0{t.Fatal("cancelled activation wrote DNS")}
}

type activationSlowAttestation struct{
 DNSActivationSafetyGuard
 afterArmed func()
 afterHealth func()
}
func(g *activationSlowAttestation)VerifyArmed(ctx context.Context,pin string)error{
 if err:=g.DNSActivationSafetyGuard.VerifyArmed(ctx,pin);err!=nil{return err}
 if g.afterArmed!=nil{g.afterArmed()}
 return nil
}
func(g *activationSlowAttestation)VerifyLiveProtection(ctx context.Context,pin string)error{
 if err:=g.DNSActivationSafetyGuard.VerifyLiveProtection(ctx,pin);err!=nil{return err}
 if g.afterHealth!=nil{g.afterHealth()}
 return nil
}

func TestPublisherScopedDNSActivationExpiryDuringAttestation(t *testing.T){
 for _,phase:=range []string{"armed","health"}{
  t.Run(phase,func(t *testing.T){
   raw,pin,backend,inner,auth,clock:=publisherDNSGuardFixture(t)
   slow:=&activationSlowAttestation{DNSActivationSafetyGuard:inner}
   expire:=func(){*clock=clock.Add(30*time.Minute)}
   if phase=="armed"{slow.afterArmed=expire}else{slow.afterHealth=expire}
   signed,err:=newPublisherScopedDNSActivationGuard(context.Background(),raw,pin,auth,slow,func()time.Time{return *clock})
   if err!=nil{t.Fatal(err)}
   if phase=="armed"{
    if err:=signed.VerifyArmed(context.Background(),pin);err==nil{t.Fatal("permit expiry during armed attestation accepted")}
    if backend.writes!=0||inner.commitCalls!=0{t.Fatal("armed review mutated state")}
   }else{
    if err:=activateVOLVEDNSWithRecovery(context.Background(),raw,pin,backend,signed);err==nil{t.Fatal("expired health attestation committed")}
    if backend.writes!=2||inner.recoverCalls!=1||inner.commitCalls!=0{t.Fatal("expired health proof did not force independent recovery")}
    assertActivationTestState(t,backend,true)
   }
  })
 }
}

func TestPublisherScopedDNSActivationSnapshotIsIndependent(t *testing.T){
 _,_,_,_,auth,_:=publisherDNSGuardFixture(t)
 snap:=snapshotDNSActivationAuthorization(auth)
 auth.GrantJSON[0]^=1;auth.Signature[0]^=1;auth.PinnedPublisherKey[0]^=1
 if snap.GrantJSON[0]==auth.GrantJSON[0]||snap.Signature[0]==auth.Signature[0]||snap.PinnedPublisherKey[0]==auth.PinnedPublisherKey[0]{t.Fatal("controller snapshot aliases caller-owned evidence")}
}
