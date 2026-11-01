//go:build windows

package motorupdate

// Windows interprocess lease for the EXPERIMENTAL DNS rollback transaction.
// Only disposable CI names are accepted. A production recovery controller
// requires its own protected, session-independent named object, SYSTEM/ACL
// validation and reboot persistence; this is NOT a production lease.
import (
 "context"
 "errors"
 "fmt"
 "os"
 "strings"
 "regexp"
 "runtime"
 "sync"
 "syscall"
 "unsafe"
)

var windowsDNSLabLeaseName=regexp.MustCompile(`^VOLVE-CI-(?:DNSLock|BootLock)-[0-9]{12,20}$`)

const (
 windowsDNSWaitObject0=0x00000000
 windowsDNSWaitAbandoned=0x00000080
 windowsDNSWaitTimeout=0x00000102
 windowsDNSWaitFailed=0xffffffff
)
var (
 windowsDNSKernel32=syscall.NewLazyDLL("kernel32.dll")
 windowsDNSCreateMutex=windowsDNSKernel32.NewProc("CreateMutexW")
 windowsDNSWaitObject=windowsDNSKernel32.NewProc("WaitForSingleObject")
 windowsDNSReleaseMutex=windowsDNSKernel32.NewProc("ReleaseMutex")
 windowsDNSCloseHandle=windowsDNSKernel32.NewProc("CloseHandle")
)

// acquireWindowsDNSLabRecoveryLease is bounded and cancellable. Windows
// mutex ownership belongs to the OS thread, so acquisition and release must
// happen on the same pinned goroutine. Releasing twice is harmless.
// An abandoned owner permits a new independently attested recovery attempt.
func acquireWindowsDNSLabRecoveryLease(ctx context.Context,name string)(func(),error){
 if err:=ctx.Err();err!=nil{return nil,err}
 if !windowsDNSLabLeaseName.MatchString(name){
  return nil,errors.New("only disposable CI Windows DNS recovery locks are allowed")
 }
 runtime.LockOSThread()
 releaseThread:=true
 defer func(){if releaseThread{runtime.UnlockOSThread()}}()
 wide,err:=syscall.UTF16PtrFromString("Global\\"+name)
 if err!=nil{return nil,err}
 handle,_,callErr:=windowsDNSCreateMutex.Call(0,0,uintptr(unsafe.Pointer(wide)))
 runtime.KeepAlive(wide)
 if handle==0{
  if callErr!=syscall.Errno(0){return nil,fmt.Errorf("CreateMutexW: %w",callErr)}
  return nil,errors.New("Windows DNS mutex returned an invalid handle")
 }
 acquired:=false
 defer func(){if !acquired{windowsDNSCloseHandle.Call(handle)}}()
 for {
  if err:=ctx.Err();err!=nil{return nil,err}
  result,_,waitErr:=windowsDNSWaitObject.Call(handle,100)
  switch uint32(result){
  case windowsDNSWaitObject0,windowsDNSWaitAbandoned:
   acquired=true
   releaseThread=false
   var once sync.Once
   return func(){once.Do(func(){
    windowsDNSReleaseMutex.Call(handle)
    windowsDNSCloseHandle.Call(handle)
    runtime.UnlockOSThread()
   })},nil
  case windowsDNSWaitTimeout:
   continue
  case windowsDNSWaitFailed:
   if waitErr!=syscall.Errno(0){return nil,fmt.Errorf("WaitForSingleObject: %w",waitErr)}
   return nil,errors.New("Windows DNS recovery mutex wait failed")
  default:
   return nil,fmt.Errorf("unexpected Windows DNS mutex wait status %d",result)
  }
 }
}

// AcquireWindowsSignedLegacyLabLease is ONLY an isolated Windows CI lease.
// It maps the disposable signed migration task to the SAME BootLock name
// consumed by the separately compiled SYSTEM watchdog. This does not prove
// correct lock handoff or publisher authorization; the integration tests must
// exercise both processes together before production can be considered.
func AcquireWindowsSignedLegacyLabLease(ctx context.Context, task string)(func(),error){
 if err:=ctx.Err();err!=nil{return nil,err}
 if os.Getenv("GITHUB_ACTIONS")!="true" ||
  os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted" {
  return nil,errors.New("signed legacy lab mutex requires hosted disposable Windows CI")
 }
 const prefix="VOLVE-CI-ManagedMotor-"
 if !strings.HasPrefix(task,prefix) {
  return nil,errors.New("signed legacy mutex refuses productive or unknown task")
 }
 id:=strings.TrimPrefix(task,prefix)
 if len(id)<12||len(id)>20{
  return nil,errors.New("signed legacy mutex nonce length invalid")
 }
 name:="VOLVE-CI-BootLock-"+id
 if !windowsDNSLabLeaseName.MatchString(name){
  return nil,errors.New("signed legacy mutex task nonce not allowlisted")
 }
 return acquireWindowsDNSLabRecoveryLease(ctx,name)
}
