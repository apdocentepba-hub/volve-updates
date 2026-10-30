//go:build windows

package main

// Cross-process regression; does NOT create, modify or run any SYSTEM task.
// All mutexes are unique to the ephemeral GitHub CI run.
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

func TestWindowsBootMutexAcrossProcesses(t *testing.T) {
 if os.Getenv("VOLVE_CI_BOOT_MUTEX_CHILD")!="" {
  name:=os.Getenv("VOLVE_CI_BOOT_MUTEX_NAME")
  if os.Getenv("VOLVE_CI_BOOT_MUTEX_CHILD")=="crash" {
   release,err:=acquireCIBootMutex(context.Background(),name)
   if err!=nil{t.Fatal(err)}
   _=release // intentionally abandon OS mutex by terminating process
   os.Exit(0)
  }
  ctx,cancel:=context.WithTimeout(context.Background(),1200*time.Millisecond)
  defer cancel()
  release,err:=acquireCIBootMutex(ctx,name)
  if os.Getenv("VOLVE_CI_BOOT_MUTEX_CHILD")=="blocked" {
   if !errors.Is(err,context.DeadlineExceeded) {
    t.Fatalf("another process took a held recovery lease: %v",err)
   }
   fmt.Println("VOLVE_CI_BOOT_MUTEX_BLOCKED")
   return
  }
  if err!=nil {t.Fatalf("fresh process cannot obtain released recovery lease: %v",err)}
  release()
  fmt.Println("VOLVE_CI_BOOT_MUTEX_ACQUIRED")
  return
 }
 name:=fmt.Sprintf("VOLVE-CI-BootLock-%d",time.Now().UnixNano())
 release,err:=acquireCIBootMutex(context.Background(),name)
 if err!=nil{t.Fatal(err)}
 child:=func(mode string)string {
  ctx,cancel:=context.WithTimeout(context.Background(),15*time.Second)
  defer cancel()
  command:=exec.CommandContext(ctx,os.Args[0],"-test.run=^TestWindowsBootMutexAcrossProcesses$")
  command.Env=append(os.Environ(),
   "VOLVE_CI_BOOT_MUTEX_CHILD="+mode,"VOLVE_CI_BOOT_MUTEX_NAME="+name)
  out,err:=command.CombinedOutput()
  if err!=nil{t.Fatalf("child mutex check failed (%s): %v %s",mode,err,string(out))}
  return string(out)
 }
 if result:=child("blocked");!strings.Contains(result,"VOLVE_CI_BOOT_MUTEX_BLOCKED"){
  t.Fatalf("held mutex unexpectedly available: %s",result)
 }
 release()
 release() // repeated cleanup cannot close someone else's reused handle
 if result:=child("acquired");!strings.Contains(result,"VOLVE_CI_BOOT_MUTEX_ACQUIRED"){
  t.Fatalf("mutex not re-acquirable after owner released it: %s",result)
 }
}
func TestWindowsBootMutexInvalidNamesAndCancel(t *testing.T){
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 if _,err:=acquireCIBootMutex(ctx,"VOLVE-CI-BootLock-1793423456789");!errors.Is(err,context.Canceled){
  t.Fatalf("cancelled boot recovery attempted to take mutex: %v",err)
 }
 for _,name:=range []string{"Global\\VOLVE-DNS-SERVER-0270","VOLVE-DNS-SERVER-0270",
   "VOLVE-CI-BootLock-not-digits","VOLVE-CI-BootLock-123",
   "VOLVE-CI-BootLock-123456789012\\Other"} {
  if _,err:=acquireCIBootMutex(context.Background(),name);err==nil{
   t.Fatalf("unsafe privileged mutex name accepted: %q",name)
  }
 }
}


func TestWindowsBootMutexRecoveredAfterOwnerProcessCrash(t *testing.T) {
 name:=fmt.Sprintf("VOLVE-CI-BootLock-%d",time.Now().UnixNano())
 command:=exec.Command(os.Args[0],"-test.run=^TestWindowsBootMutexAcrossProcesses$")
 command.Env=append(os.Environ(),
  "VOLVE_CI_BOOT_MUTEX_CHILD=crash","VOLVE_CI_BOOT_MUTEX_NAME="+name)
 out,err:=command.CombinedOutput()
 if err!=nil{t.Fatalf("CI watchdog crash helper failed: %v %s",err,string(out))}
 ctx,cancel:=context.WithTimeout(context.Background(),5*time.Second)
 defer cancel()
 unlock,err:=acquireCIBootMutex(ctx,name)
 if err!=nil{t.Fatalf("orphaned Windows recovery lease cannot be reacquired: %v",err)}
 unlock()
}
func TestWindowsBootMutexContendedLeaseRespectsCancellation(t *testing.T){
 name:=fmt.Sprintf("VOLVE-CI-BootLock-%d",time.Now().UnixNano())
 release,err:=acquireCIBootMutex(context.Background(),name)
 if err!=nil{t.Fatal(err)}
 defer release()
 ctx,cancel:=context.WithTimeout(context.Background(),250*time.Millisecond)
 defer cancel()
 start:=time.Now()
 if unlock,err:=acquireCIBootMutex(ctx,name);!errors.Is(err,context.DeadlineExceeded) {
  if unlock!=nil{unlock()}
  t.Fatalf("contended recovery lock did not fail closed: %v",err)
 }
 if time.Since(start)>3*time.Second{t.Fatal("contended recovery lock ignored bounded wait")}
}
