//go:build windows

package motorupdate

// CI-only contract test: real protected kernel object, no task, DNS or
// installed motor changes. The updater's delegated lab lock MUST NOT run.
import (
 "context"
 "errors"
 "os"
 "testing"
 "time"
)

type unsafeLeaseStub struct{
 SignedLegacySwitchDriver
 calls int
 handoffs int
}
func(s *unsafeLeaseStub)AcquireExclusiveMigration(context.Context)(func(),error){
 s.calls++
 return nil,errors.New("weaker delegate lock must never run")
}
func(s *unsafeLeaseStub)RestoreAfterProtectedHandoff(ctx context.Context)error{
 s.handoffs++
 // Independent SYSTEM watchdog must be able to own protected mutex now.
 // If updater forgot to release it, this bounded wait fails instead of
 // reporting a successful recovery. No product task is touched.
 received:=make(chan error,1)
 go func(){
  release,err:=AcquireProtectedResidentTransitionLease(ctx)
  if release!=nil{release()}
  received<-err
 }()
 select{
 case err:=<-received:return err
 case <-ctx.Done():return ctx.Err()
 }
}

type bootOriginalStub struct{}
func(bootOriginalStub)VerifySealedOriginal(context.Context,ResidentRecoveryIntent)error{return nil}
func(bootOriginalStub)RestoreOriginal(context.Context,ResidentRecoveryIntent)error{return errors.New("no productive restoration authorized")}

func TestProtectedSignedSwitchAndBootRecoveryShareProductionMutex(t *testing.T){
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{
  t.Skip("requires hosted disposable Windows CI")
 }
 delegate:=&unsafeLeaseStub{}
 updater,err:=NewProtectedSignedLegacySwitchDriver(delegate)
 if err!=nil{t.Fatal(err)}
 boot,err:=NewProtectedResidentBootDriver(bootOriginalStub{})
 if err!=nil{t.Fatal(err)}
 updateRelease,err:=updater.AcquireExclusiveMigration(context.Background())
 if err!=nil||updateRelease==nil{t.Fatalf("privileged updater cannot hold protected lease: %v",err)}
 held:=true
 defer func(){if held{updateRelease()}}()
 ctx,cancel:=context.WithTimeout(context.Background(),350*time.Millisecond)
 defer cancel()
 done:=make(chan error,1)
 go func(){
  release,err:=boot.AcquireExclusive(ctx)
  if release!=nil{release()}
  done<-err
 }()
 select{
 case err:=<-done:
  if !errors.Is(err,context.DeadlineExceeded){
   t.Fatalf("boot restorer bypassed active signed updater lock: %v",err)
  }
 case <-time.After(4*time.Second):
  t.Fatal("boot restorer ignored protected update lease cancellation")
 }
 if delegate.calls!=0{t.Fatal("unprotected migration driver bypassed guarded system mutex")}
 updateRelease()
 held=false
 bootRelease,err:=boot.AcquireExclusive(context.Background())
 if err!=nil||bootRelease==nil{t.Fatalf("SYSTEM boot recovery could not acquire protected mutex after updater exit: %v",err)}
 bootRelease()
 if delegate.calls!=0{t.Fatal("weaker original updater lease was used")}
}

func TestProtectedAdaptersFailClosedWithoutTrustedOperations(t *testing.T){
 if driver,err:=NewProtectedSignedLegacySwitchDriver(nil);err==nil||driver!=nil{
  t.Fatal("missing publisher switch driver was accepted")
 }
 if driver,err:=NewProtectedResidentBootDriver(nil);err==nil||driver!=nil{
  t.Fatal("missing boot restorer was accepted")
 }
}


func TestProtectedSignedRollbackHandsOffThenReacquiresBeforeHealth(t *testing.T){
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{
  t.Skip("protected Windows mutex handoff only in hosted VM")
 }
 stub:=&unsafeLeaseStub{}
 wrapped,err:=NewProtectedSignedLegacySwitchDriver(stub)
 if err!=nil{t.Fatal(err)}
 finish,err:=wrapped.AcquireExclusiveMigration(context.Background())
 if err!=nil{t.Fatal(err)}
 defer finish()
 // A real (separate-thread) SYSTEM watchdog simulation must acquire the
 // SAME protected kernel object during RestoreAfterProtectedHandoff.
 ctx,cancel:=context.WithTimeout(context.Background(),2*time.Second)
 defer cancel()
 if err:=wrapped.Restore(ctx);err!=nil{
  t.Fatalf("watchdog cannot acquire mutex released by updater: %v",err)
 }
 if stub.handoffs!=1||stub.calls!=0{
  t.Fatalf("unsafe delegated lock or missing watchdog handoff: calls=%d handoffs=%d",stub.calls,stub.handoffs)
 }
 // The updater now owns a fresh protected lease, so another boot agent
 // must fail closed while post-recovery health checks are still pending.
 secondCtx,stop:=context.WithTimeout(context.Background(),260*time.Millisecond)
 defer stop()
 observed:=make(chan error,1)
 go func(){
  release,err:=AcquireProtectedResidentTransitionLease(secondCtx)
  if release!=nil{release()}
  observed<-err
 }()
 select{
 case err:=<-observed:
  if !errors.Is(err,context.DeadlineExceeded){
   t.Fatalf("updater failed to reacquire protected mutex after recovery: %v",err)
  }
 case <-time.After(3*time.Second):
  t.Fatal("second boot recovery stuck behind protected health gate")
 }
 finish()
 // Final release must be the second acquired lease, not the original.
 last,err:=AcquireProtectedResidentTransitionLease(context.Background())
 if err!=nil{t.Fatalf("protected handoff leaked final mutex ownership: %v",err)}
 last()
}

func TestProtectedSignedDriverRejectsHandoffMissing(t *testing.T){
 type noHandoffDriver struct{SignedLegacySwitchDriver}
 if d,err:=NewProtectedSignedLegacySwitchDriver(&noHandoffDriver{});err==nil||d!=nil{
  t.Fatal("signed transition accepted driver that cannot release mutex for watchdog")
 }
}
