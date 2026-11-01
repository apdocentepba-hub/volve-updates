//go:build windows

package motorupdate

// Lab-only verification of the Windows kernel mutex used for signed-legacy
// migration. It does NOT install, start or alter any VOLVE task or adapter.
import (
 "context"
 "errors"
 "fmt"
 "os"
 "os/exec"
 "strings"
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
  if acquired!=nil{acquired();blocked<-errors.New("second owner entered critical section")}else{blocked<-e}
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

func TestSignedLegacyLabKernelMutexChildProbe(t *testing.T){
 name:=os.Getenv("VOLVE_CI_MUTEX_CHILD_NAME")
 if name==""{t.Skip("cross-process child probe only")}
 shouldAcquire:=os.Getenv("VOLVE_CI_MUTEX_CHILD_EXPECT_ACQUIRE")=="1"
 ctx,cancel:=context.WithTimeout(context.Background(),400*time.Millisecond)
 defer cancel()
 release,err:=AcquireWindowsSignedLegacyLabLease(ctx,name)
 if shouldAcquire{
  if err!=nil||release==nil{t.Fatalf("unlocked kernel mutex refused independent process: %v",err)}
  release()
  t.Log("CI_CROSS_PROCESS_MUTEX_ACQUIRED")
  return
 }
 if release!=nil{release()}
 if release!=nil||!errors.Is(err,context.DeadlineExceeded){
  t.Fatalf("a second Windows process entered another process's kernel mutex: release=%t err=%v",release!=nil,err)
 }
 t.Log("CI_CROSS_PROCESS_MUTEX_EXCLUDED")
}

func TestSignedLegacyLabKernelMutexCrossProcessExclusion(t *testing.T){
 if os.Getenv("GITHUB_ACTIONS")!="true"||
  os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{
  t.Skip("hosted disposable Windows VM only")
 }
 name:=fmt.Sprintf("VOLVE-CI-ManagedMotor-%d",time.Now().UnixNano())
 release,err:=AcquireWindowsSignedLegacyLabLease(context.Background(),name)
 if err!=nil||release==nil{t.Fatalf("parent cannot own named Windows mutex: %v",err)}
 held:=true
 defer func(){if held{release()}}()
 runChild:=func(accept bool){
  t.Helper()
  ctx,cancel:=context.WithTimeout(context.Background(),25*time.Second)
  defer cancel()
  cmd:=exec.CommandContext(ctx,os.Args[0],"-test.run=^TestSignedLegacyLabKernelMutexChildProbe$","-test.v")
  env:=append(os.Environ(),"VOLVE_CI_MUTEX_CHILD_NAME="+name)
  marker:="CI_CROSS_PROCESS_MUTEX_EXCLUDED"
  if accept{
   env=append(env,"VOLVE_CI_MUTEX_CHILD_EXPECT_ACQUIRE=1")
   marker="CI_CROSS_PROCESS_MUTEX_ACQUIRED"
  }
  cmd.Env=env
  output,err:=cmd.CombinedOutput()
  if err!=nil||!strings.Contains(string(output),marker){
   t.Fatalf("independent Windows process did not prove kernel mutex state: %v, output=%s",err,output)
  }
 }
 runChild(false)
 release();held=false
 runChild(true)
}
