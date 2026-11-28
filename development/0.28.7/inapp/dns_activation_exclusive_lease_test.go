package motorupdate

import (
 "context"
 "errors"
 "strings"
 "testing"
)

type activationLeaseHarness struct{
 held bool
 acquired int
 released int
 refuseReacquire bool
}
func(h *activationLeaseHarness)acquire(ctx context.Context)(func(),error){
 if err:=ctx.Err();err!=nil{return nil,err}
 h.acquired++
 if h.refuseReacquire&&h.acquired>1{return nil,errors.New("independent SYSTEM lock not reacquired")}
 if h.held{return nil,errors.New("exclusive lease acquired twice without release")}
 h.held=true
 released:=false
 return func(){
  if released{panic("lease released more than once")}
  if !h.held{panic("released nonexistent protected lease")}
  released=true;h.held=false;h.released++
 },nil
}
type activationLeaseGuardSpy struct{
 lease *activationLeaseHarness
 inner *activationTestGuard
 recoveryObservedWithoutLease bool
}
func(g *activationLeaseGuardSpy)VerifyArmed(ctx context.Context,pin string)error{
 if !g.lease.held{return errors.New("watchdog verified outside protected mutex")}
 return g.inner.VerifyArmed(ctx,pin)
}
func(g *activationLeaseGuardSpy)VerifyLiveProtection(ctx context.Context,pin string)error{
 if !g.lease.held{return errors.New("network health probe outside protected mutex")}
 return g.inner.VerifyLiveProtection(ctx,pin)
}
func(g *activationLeaseGuardSpy)CommitActive(ctx context.Context,pin string)error{
 if !g.lease.held{return errors.New("committing DNS outside protected mutex")}
 return g.inner.CommitActive(ctx,pin)
}
func(g *activationLeaseGuardSpy)RecoverIndependently(ctx context.Context,pin string)error{
 if g.lease.held{return errors.New("SYSTEM watchdog blocked by installer mutex")}
 g.recoveryObservedWithoutLease=true
 return g.inner.RecoverIndependently(ctx,pin)
}
func runLeaseFixture(t *testing.T,failAt int,cancelOnWrite bool,refuseReacquire bool)(error,*activationLeaseHarness,*activationLeaseGuardSpy,*activationTestBackend){
 t.Helper()
 journal,pin,b,rawGuard:=prepareActivationTest(t)
 lease:=&activationLeaseHarness{refuseReacquire:refuseReacquire}
 spy:=&activationLeaseGuardSpy{lease:lease,inner:rawGuard}
 b.failOn=failAt
 ctx:=context.Background()
 if cancelOnWrite{
  c,cancel:=context.WithCancel(context.Background())
  defer cancel()
  b.cancel=cancel
  ctx=c
 }
 factory:=func(ctx context.Context,guarded DNSActivationSafetyGuard)(DNSAdapterBackend,error){
  if !lease.held{return nil,errors.New("backend created outside protected mutex")}
  if err:=guarded.VerifyArmed(ctx,pin);err!=nil{return nil,err}
  return b,nil
 }
 err:=activateVOLVEDNSUnderProtectedLease(ctx,journal,pin,spy,lease.acquire,factory)
 return err,lease,spy,b
}

func TestWindowsProtectedDNSActivationLeaseHealthyCommit(t *testing.T){
 err,lease,guard,b:=runLeaseFixture(t,0,false,false)
 if err!=nil{t.Fatal(err)}
 if lease.held||lease.acquired!=1||lease.released!=1||
  guard.inner.commitCalls!=1||guard.inner.recoverCalls!=0||b.writes!=2{
  t.Fatalf("protected mutex not held/released for healthy activation: %+v",lease)
 }
 assertActivationTestState(t,b,false)
}

func TestWindowsProtectedDNSActivationLeaseHandoffToIndependentSYSTEM(t *testing.T){
 err,lease,guard,b:=runLeaseFixture(t,2,false,false)
 if err==nil||lease.held||lease.acquired!=2||lease.released!=2||
  !guard.recoveryObservedWithoutLease||guard.inner.recoverCalls!=1||
  guard.inner.commitCalls!=0||b.writes!=2{
  t.Fatalf("independent watchdog did not receive the released mutex: %v, %+v",err,lease)
 }
 assertActivationTestState(t,b,true)
}

func TestWindowsProtectedDNSActivationLeaseNeverReportsSuccessWithoutReacquire(t *testing.T){
 err,lease,guard,b:=runLeaseFixture(t,1,false,true)
 if err==nil||!strings.Contains(err.Error(),"CRITICAL")||
  !strings.Contains(err.Error(),"reacquire")||
  lease.held||lease.acquired!=2||lease.released!=1||
  guard.inner.recoverCalls!=1||guard.inner.commitCalls!=0{
  t.Fatalf("lost SYSTEM lease incorrectly committed: %v, %+v",err,lease)
 }
 // The fixture watchdog restored DNS, but the coordinator cannot prove
 // that state with protected exclusion; the outcome MUST remain critical.
 assertActivationTestState(t,b,true)
}

func TestWindowsProtectedDNSActivationLeaseCancelledInstallerStillHandsOff(t *testing.T){
 err,lease,guard,b:=runLeaseFixture(t,0,true,false)
 if err==nil||lease.held||lease.acquired!=2||lease.released!=2||
  !guard.recoveryObservedWithoutLease||guard.inner.recoverCalls!=1||
  guard.inner.commitCalls!=0{
  t.Fatalf("cancellation suppressed SYSTEM recovery handoff: %v, %+v",err,lease)
 }
 assertActivationTestState(t,b,true)
}

func TestWindowsProtectedDNSActivationLeaseRefusesUnsafeSetup(t *testing.T){
 journal,pin,b,guard:=prepareActivationTest(t)
 lease:=&activationLeaseHarness{}
 for _,name:=range []string{"nil-acquirer","nil-guard","nil-factory","rejected-backend"}{
  t.Run(name,func(t *testing.T){
   var trusted DNSActivationSafetyGuard=guard
   var acquire dnsActivationLeaseAcquirer=lease.acquire
   factory:=dnsActivationBackendFactory(func(context.Context,DNSActivationSafetyGuard)(DNSAdapterBackend,error){return b,nil})
   switch name{
   case "nil-acquirer":acquire=nil
   case "nil-guard":trusted=nil
   case "nil-factory":factory=nil
   case "rejected-backend":factory=func(context.Context,DNSActivationSafetyGuard)(DNSAdapterBackend,error){return nil,errors.New("native host conflict")}
   }
   if err:=activateVOLVEDNSUnderProtectedLease(context.Background(),journal,pin,trusted,acquire,factory);err==nil{
    t.Fatal("unsafe protected installer setup accepted")
   }
   if lease.held||b.writes!=0{t.Fatal("unsafe protected installer setup changed DNS or retained mutex")}
  })
 }
 if lease.acquired!=1||lease.released!=1{t.Fatalf("backend failure did not release protected mutex: %+v",lease)}
}

func TestWindowsProtectedDNSActivationLeaseCanceledAcquisitionDoesNotReachFactory(t *testing.T){
 journal,pin,_,guard:=prepareActivationTest(t)
 ctx,cancel:=context.WithCancel(context.Background())
 defer cancel()
 lease:=&activationLeaseHarness{}
 acquire:=func(c context.Context)(func(),error){
  release,err:=lease.acquire(c)
  cancel()
  return release,err
 }
 err:=activateVOLVEDNSUnderProtectedLease(ctx,journal,pin,guard,acquire,
  func(context.Context,DNSActivationSafetyGuard)(DNSAdapterBackend,error){
   t.Fatal("canceled acquisition reached authorization-consuming backend factory")
   return nil,errors.New("unreachable")
  })
 if !errors.Is(err,context.Canceled)||lease.held||lease.acquired!=1||lease.released!=1{
  t.Fatalf("canceled lease not safely released: %v %+v",err,lease)
 }
}
func TestWindowsProtectedDNSActivationLeaseCanceledReacquisitionRefusesReadback(t *testing.T){
 _,pin,_,rawGuard:=prepareActivationTest(t)
 ctx,cancel:=context.WithCancel(context.Background())
 defer cancel()
 lease:=&activationLeaseHarness{}
 first,err:=lease.acquire(ctx)
 if err!=nil{t.Fatal(err)}
 spy:=&activationLeaseGuardSpy{lease:lease,inner:rawGuard}
 g:=&exclusiveDNSActivationGuard{inner:spy,release:first,acquire:func(c context.Context)(func(),error){
  release,err:=lease.acquire(c)
  cancel()
  return release,err
 }}
 defer g.close()
 err=g.RecoverIndependently(ctx,pin)
 if !errors.Is(err,context.Canceled)||!strings.Contains(err.Error(),"CRITICAL")||
  lease.held||g.release!=nil||lease.acquired!=2||lease.released!=2||
  !spy.recoveryObservedWithoutLease{
  t.Fatalf("canceled recovery lease accepted: %v %+v",err,lease)
 }
}
