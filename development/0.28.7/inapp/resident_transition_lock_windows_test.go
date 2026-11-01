//go:build windows

package motorupdate

// These tests are restricted to disposable hosted Windows CI. They create
// only a named Windows mutex; no DNS, Scheduler task, service, file policy or
// installed VOLVE component is modified.
import (
 "context"
 "errors"
 "os"
 "os/exec"
 "strings"
 "testing"
 "time"
 "unsafe"
 "runtime"
 "syscall"
)

func residentProtectedCITest(t *testing.T){
 t.Helper()
 if os.Getenv("GITHUB_ACTIONS")!="true"||
   os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{
  t.Skip("test requires isolated hosted Windows CI")
 }
 if err:=residentCurrentIsPrivileged();err!=nil{t.Skipf("CI runner has no elevated token: %v",err)}
}

func TestProtectedResidentMutexChild(t *testing.T){
 kind:=os.Getenv("VOLVE_CI_PROTECTED_RESIDENT_CHILD")
 if kind==""{t.Skip("helper process only")}
 residentProtectedCITest(t)
 ctx,cancel:=context.WithTimeout(context.Background(),450*time.Millisecond)
 defer cancel()
 release,err:=AcquireProtectedResidentTransitionLease(ctx)
 if kind=="blocked"{
  if release!=nil{release()}
  if !errors.Is(err,context.DeadlineExceeded){
   t.Fatalf("other Windows process bypassed protected mutex: %v",err)
  }
  t.Log("VOLVE_PROD_MUTEX_EXCLUDED")
  return
 }
 if err!=nil||release==nil{t.Fatalf("protected mutex not reacquirable by fresh process: %v",err)}
 release()
 t.Log("VOLVE_PROD_MUTEX_ACQUIRED")
}

func TestProtectedResidentTransitionMutexCrossProcessAndExactACL(t *testing.T){
 residentProtectedCITest(t)
 release,err:=AcquireProtectedResidentTransitionLease(context.Background())
 if err!=nil||release==nil{t.Fatalf("protected owner/DACL mutex cannot be acquired: %v",err)}
 held:=true
 defer func(){if held{release()}}()
 child:=func(mode string){
  t.Helper()
  ctx,cancel:=context.WithTimeout(context.Background(),12*time.Second)
  defer cancel()
  cmd:=exec.CommandContext(ctx,os.Args[0],"-test.run=^TestProtectedResidentMutexChild$","-test.v")
  cmd.Env=append(os.Environ(),"VOLVE_CI_PROTECTED_RESIDENT_CHILD="+mode)
  output,err:=cmd.CombinedOutput()
  marker:="VOLVE_PROD_MUTEX_EXCLUDED"
  if mode=="acquired"{marker="VOLVE_PROD_MUTEX_ACQUIRED"}
  if err!=nil||!strings.Contains(string(output),marker){
   t.Fatalf("protected kernel mutex failed for separate Windows process %s: %v %s",mode,err,output)
  }
 }
 child("blocked")
 release()
 held=false
 child("acquired")
}

func TestProtectedResidentMutexRejectsUnsafePreexistingObject(t *testing.T){
 residentProtectedCITest(t)
 // A predictable name lets an ordinary process squat on it. Verify a
 // default-DACL owner or extra-ACE object NEVER becomes an authorized lock.
 name,err:=syscall.UTF16PtrFromString(residentTransitionMutexName)
 if err!=nil{t.Fatal(err)}
 h,_,last:=residentCreateMutex.Call(0,0,uintptr(unsafe.Pointer(name)))
 runtime.KeepAlive(name)
 if h==0{t.Fatalf("fixture CreateMutexW failed: %v",last)}
 defer residentCloseHandle.Call(h)
 current,err:=residentObservedSecurity(h)
 if err!=nil{t.Fatal(err)}
 if err:=residentRequireExactSD(h);err==nil{
  t.Skipf("host default ACL unexpectedly exactly equals strict policy: %s",current)
 }
 ctx,cancel:=context.WithTimeout(context.Background(),time.Second)
 defer cancel()
 unlock,err:=AcquireProtectedResidentTransitionLease(ctx)
 if unlock!=nil{unlock()}
 if err==nil||unlock!=nil{
  t.Fatalf("existing untrusted Windows mutex was adopted: existing=%s",current)
 }
 t.Log("untrusted pre-existing mutex rejected without mutating Windows DNS/tasks")
}

func TestProtectedResidentMutexCancelledBeforeObjectAcquisition(t *testing.T){
 residentProtectedCITest(t)
 ctx,cancel:=context.WithCancel(context.Background())
 cancel()
 release,err:=AcquireProtectedResidentTransitionLease(ctx)
 if release!=nil{release()}
 if !errors.Is(err,context.Canceled){t.Fatalf("cancelled transition not refused: %v",err)}
}
