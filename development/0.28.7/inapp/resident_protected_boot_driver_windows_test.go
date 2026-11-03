//go:build windows

package motorupdate

// Native mutex regressions on disposable Windows CI; no productive task,
// DNS adapter, service, or installed VOLVÉ engine is touched.
import (
 "context"
 "errors"
 "sync"
 "testing"
 "time"
)

type protectedBootOpsSpy struct{
 mu sync.Mutex
 verified int
 restored int
 restoreStarted chan struct{}
 allowRestore chan struct{}
}
func(s *protectedBootOpsSpy)VerifySealedOriginal(context.Context,ResidentRecoveryIntent)error{
 s.mu.Lock();defer s.mu.Unlock()
 s.verified++
 return nil
}
func(s *protectedBootOpsSpy)RestoreOriginal(ctx context.Context,_ ResidentRecoveryIntent)error{
 if s.restoreStarted!=nil{
  close(s.restoreStarted)
  select{
  case <-s.allowRestore:
  case <-ctx.Done():return ctx.Err()
  }
 }
 s.mu.Lock();defer s.mu.Unlock()
 s.restored++
 return nil
}
func(s *protectedBootOpsSpy)counts()(int,int){
 s.mu.Lock();defer s.mu.Unlock()
 return s.verified,s.restored
}

func TestProtectedBootRefusesUnleasedOriginalOperations(t *testing.T){
 spy:=&protectedBootOpsSpy{}
 driver,err:=NewProtectedResidentBootDriver(spy)
 if err!=nil{t.Fatal(err)}
 ctx:=context.Background()
 if err:=driver.VerifySealedOriginal(ctx,ResidentRecoveryIntent{});err==nil{
  t.Fatal("unlocked boot verifier reached trusted SYSTEM driver")
 }
 if err:=driver.RestoreOriginal(ctx,ResidentRecoveryIntent{});err==nil{
  t.Fatal("unlocked boot restorer reached trusted SYSTEM driver")
 }
 if verify,restore:=spy.counts();verify!=0||restore!=0{
  t.Fatalf("native-mutex bypass reached underlying operations: verify=%d restore=%d",verify,restore)
 }
}

func TestProtectedBootLeaseGatesVerifyRestoreAndRejectsStaleFinalizer(t *testing.T){
 residentProtectedCITest(t)
 spy:=&protectedBootOpsSpy{}
 driver,err:=NewProtectedResidentBootDriver(spy)
 if err!=nil{t.Fatal(err)}
 ctx:=context.Background()
 previous,err:=driver.AcquireExclusive(ctx)
 if err!=nil{t.Fatal(err)}
 if err:=driver.VerifySealedOriginal(ctx,ResidentRecoveryIntent{});err!=nil{previous();t.Fatal(err)}
 if err:=driver.RestoreOriginal(ctx,ResidentRecoveryIntent{});err!=nil{previous();t.Fatal(err)}
 // Nested lease must be rejected, not reentrant on the current OS thread.
 if nested,err:=driver.AcquireExclusive(ctx);err==nil||nested!=nil{
  if nested!=nil{nested()}
  previous()
  t.Fatal("same boot adapter allowed overlapping protected leases")
 }
 previous()
 current,err:=driver.AcquireExclusive(ctx)
 if err!=nil{t.Fatal(err)}
 defer current()
 previous() // stale callback cannot unlock a later independent recovery
 contenderCtx,cancel:=context.WithTimeout(ctx,250*time.Millisecond)
 defer cancel()
 contender:=make(chan error,1)
 go func(){
  unlock,err:=AcquireProtectedResidentTransitionLease(contenderCtx)
  if unlock!=nil{unlock()}
  contender<-err
 }()
 select{
 case err:=<-contender:
  if !errors.Is(err,context.DeadlineExceeded){t.Fatalf("stale boot finalizer released newer mutex: %v",err)}
 case <-time.After(3*time.Second):t.Fatal("competing SYSTEM updater ignored mutex timeout")
 }
 current()
 if err:=driver.RestoreOriginal(ctx,ResidentRecoveryIntent{});err==nil{
  t.Fatal("boot original restorer remained callable after release")
 }
 if v,r:=spy.counts();v!=1||r!=1{t.Fatalf("unexpected delegated operations v=%d r=%d",v,r)}
 unlocked,err:=AcquireProtectedResidentTransitionLease(ctx)
 if err!=nil{t.Fatalf("boot lease failed to unlock native mutex: %v",err)}
 unlocked()
}

func TestProtectedBootFinalizerWaitsForOriginalRestore(t *testing.T){
 residentProtectedCITest(t)
 spy:=&protectedBootOpsSpy{restoreStarted:make(chan struct{}),allowRestore:make(chan struct{})}
 driver,err:=NewProtectedResidentBootDriver(spy)
 if err!=nil{t.Fatal(err)}
 ctx,cancel:=context.WithTimeout(context.Background(),6*time.Second)
 defer cancel()
 unlock,err:=driver.AcquireExclusive(ctx)
 if err!=nil{t.Fatal(err)}
 defer unlock()
 finishRestore:=make(chan error,1)
 go func(){finishRestore<-driver.RestoreOriginal(ctx,ResidentRecoveryIntent{})}()
 select{
 case <-spy.restoreStarted:
 case <-ctx.Done():t.Fatal("underlying SYSTEM restorer did not start")
 }
 releaseDone:=make(chan struct{})
 go func(){unlock();close(releaseDone)}()
 select{
 case <-releaseDone:t.Fatal("boot mutex finalizer ran before original restore finished")
 case <-time.After(150*time.Millisecond):
 }
 close(spy.allowRestore)
 select{
 case err:=<-finishRestore:if err!=nil{t.Fatal(err)}
 case <-ctx.Done():t.Fatal("original restore hung")
 }
 select{
 case <-releaseDone:
 case <-ctx.Done():t.Fatal("boot finalizer did not release after restore")
 }
 next,err:=AcquireProtectedResidentTransitionLease(ctx)
 if err!=nil{t.Fatalf("boot restorer leaked native kernel lease: %v",err)}
 next()
}
