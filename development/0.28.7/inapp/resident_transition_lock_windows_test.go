//go:build windows

package motorupdate

// These tests are restricted to disposable hosted Windows CI. They create
// only a named Windows mutex; no DNS, Scheduler task, service, file policy or
// installed VOLVE component is modified.
import (
 "context"
 "errors"
 "fmt"
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
 if kind=="crash"{
  if err!=nil||release==nil{t.Fatalf("child cannot acquire protected transition lock before crash: %v",err)}
  fmt.Println("VOLVE_PROD_MUTEX_ABANDONED_OWNER")
  // Terminate the independent updater without release or defers. Kernel
  // WAIT_ABANDONED must permit the privileged watchdog to reclaim mutex.
  os.Exit(71)
 }
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

func TestProtectedResidentMutexRecoversAfterOwnerProcessDies(t *testing.T){
 residentProtectedCITest(t)
 // The parent keeps a SECOND open handle to the protected object without
 // taking ownership. Thus the object persists when the updater process
 // exits abruptly; otherwise Windows could destroy it and this test would
 // falsely pass through simple recreation.
 descriptor,err:=residentMutexSecurityDescriptor()
 if err!=nil{t.Fatal(err)}
 defer residentLocalFree.Call(descriptor)
 attributes:=residentSecurityAttributes{
  Length:uint32(unsafe.Sizeof(residentSecurityAttributes{})),Descriptor:descriptor,
 }
 name,err:=syscall.UTF16PtrFromString(residentTransitionMutexName)
 if err!=nil{t.Fatal(err)}
 keeper,_,last:=residentCreateMutex.Call(uintptr(unsafe.Pointer(&attributes)),0,uintptr(unsafe.Pointer(name)))
 runtime.KeepAlive(name)
 runtime.KeepAlive(attributes)
 if keeper==0{t.Fatalf("cannot retain protected Windows mutex object: %v",last)}
 defer residentCloseHandle.Call(keeper)
 if err:=residentRequireExactSD(keeper);err!=nil{t.Fatalf("keeper DACL mismatch: %v",err)}
 ctx,cancel:=context.WithTimeout(context.Background(),12*time.Second)
 defer cancel()
 command:=exec.CommandContext(ctx,os.Args[0],"-test.run=^TestProtectedResidentMutexChild$","-test.v")
 command.Env=append(os.Environ(),"VOLVE_CI_PROTECTED_RESIDENT_CHILD=crash")
 output,err:=command.CombinedOutput()
 if err==nil||!strings.Contains(string(output),"VOLVE_PROD_MUTEX_ABANDONED_OWNER"){
  t.Fatalf("updater fixture did not terminate while holding protected mutex: %v, %s",err,output)
 }
 recoveryCtx,stopRecovery:=context.WithTimeout(context.Background(),4*time.Second)
 defer stopRecovery()
 release,err:=AcquireProtectedResidentTransitionLease(recoveryCtx)
 if err!=nil||release==nil{t.Fatalf("independent SYSTEM recovery cannot regain abandoned kernel lock: %v",err)}
 release()
 release() // idempotent even after crash recovery
}


// A real Win32 mutex is thread-owned. The finalizer may be dispatched by a
// different Go goroutine (e.g. cancellation or watchdog handoff) and MUST
// still release the original OS thread's lock. This test would time out under
// the old direct ReleaseMutex callback and is intentionally Windows-native.
func TestProtectedResidentMutexReleaseOnDifferentGoroutine(t *testing.T){
 residentProtectedCITest(t)
 ctx,cancel:=context.WithTimeout(context.Background(),5*time.Second)
 defer cancel()
 release,err:=AcquireProtectedResidentTransitionLease(ctx)
 if err!=nil||release==nil{t.Fatalf("protected lock not acquired: %v",err)}
 released:=make(chan struct{})
 go func(){release();close(released)}()
 select{
 case <-released:
 case <-ctx.Done():t.Fatal("cross-goroutine release hung")
 }
 // Another goroutine, on a distinct OS thread, must now acquire the named
 // mutex. Reentrant acquisition from the original goroutine is NOT a proof.
 acquired:=make(chan error,1)
 go func(){
  nextRelease,nextErr:=AcquireProtectedResidentTransitionLease(ctx)
  if nextRelease!=nil{nextRelease()}
  acquired<-nextErr
 }()
 select{
 case err:=<-acquired:
  if err!=nil{t.Fatalf("ReleaseMutex did not unlock across goroutines: %v",err)}
 case <-ctx.Done():
  t.Fatal("kernel mutex stayed owned by an abandoned Windows thread")
 }
 release() // idempotent, including after handoff.
}
