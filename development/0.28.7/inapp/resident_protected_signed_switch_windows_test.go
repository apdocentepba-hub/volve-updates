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
}
func(s *unsafeLeaseStub)AcquireExclusiveMigration(context.Context)(func(),error){
 s.calls++
 return nil,errors.New("weaker delegate lock must never run")
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
