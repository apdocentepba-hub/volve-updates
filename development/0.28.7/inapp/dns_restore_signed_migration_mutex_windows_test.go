//go:build windows

package motorupdate

// Lab-only verification of the Windows kernel mutex used for signed-legacy
// migration. It does NOT install, start or alter any VOLVE task or adapter.
import (
 "context"
 "errors"
 "fmt"
 "os"
 "testing"
 "time"
)

func TestSignedLegacyLabKernelMutexExcludesConcurrentMigration(t *testing.T){
 if os.Getenv("GITHUB_ACTIONS")!="true"||
  os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{
  t.Skip("isolated GitHub Windows runner required")
 }
 name:=fmt.Sprintf("VOLVE-CI-ManagedMotor-%d",time.Now().UnixNano())
 release,err:=AcquireWindowsSignedLegacyLabLease(context.Background(),name)
 if err!=nil||release==nil{t.Fatalf("cannot acquire first real Windows mutex: %v",err)}
 deferred:=true
 defer func(){if deferred{release()}}()
 ctx,cancel:=context.WithTimeout(context.Background(),260*time.Millisecond)
 defer cancel()
 blocked:=make(chan error,1)
 go func(){
  acquired,e:=AcquireWindowsSignedLegacyLabLease(ctx,name)
  if acquired!=nil{acquired();blocked<-errors.New("second owner entered critical section")}
  else{blocked<-e}
 }()
 result:=<-blocked
 if !errors.Is(result,context.DeadlineExceeded) {
  t.Fatalf("concurrent motor transition did not wait for named OS mutex: %v",result)
 }
 release();deferred=false
 releaseAgain,err:=AcquireWindowsSignedLegacyLabLease(context.Background(),name)
 if err!=nil||releaseAgain==nil{t.Fatalf("named Windows mutex not usable after owner released: %v",err)}
 releaseAgain()
}
func TestSignedLegacyLabKernelMutexRejectsProductiveNameAndNonHostedCI(t *testing.T){
 if os.Getenv("GITHUB_ACTIONS")!="true"{
  t.Skip("isolated GitHub Windows runner required")
 }
 for _,name:=range []string{
  "VOLVE-DNS-SERVER-0270","VOLVE-CI-ManagedMotor-999","VOLVE-CI-ManagedMotor-1234567890123-extra",
 }{
  release,err:=AcquireWindowsSignedLegacyLabLease(context.Background(),name)
  if release!=nil{release()}
  if err==nil||release!=nil{t.Fatalf("untrusted task obtained migration lock: %s",name)}
 }
 original:=os.Getenv("RUNNER_ENVIRONMENT")
 t.Setenv("RUNNER_ENVIRONMENT","self-hosted")
 release,err:=AcquireWindowsSignedLegacyLabLease(context.Background(),"VOLVE-CI-ManagedMotor-1234567890123")
 if release!=nil{release()}
 if err==nil||release!=nil{t.Fatal("nonhosted Windows runner obtained lab migration lock")}
 t.Setenv("RUNNER_ENVIRONMENT",original)
}
