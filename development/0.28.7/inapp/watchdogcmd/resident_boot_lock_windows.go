//go:build windows

package main

// Cross-process Windows recovery lease for disposable CI tasks. A real boot
// agent MUST hold this through the journal audit, rollback and health checks.
// Only VOLVE-CI-BootLock-* is accepted; productive DNS is never mutated here.
import (
 "context"
 "errors"
 "fmt"
 "regexp"
 "runtime"
 "sync"
 "syscall"
 "unsafe"
)

var ciBootMutexName=regexp.MustCompile(`^VOLVE-CI-BootLock-[0-9]{12,20}$`)
const (
 windowsWaitObject0=0x00000000
 windowsWaitAbandoned=0x00000080
 windowsWaitTimeout=0x00000102
 windowsWaitFailed=0xffffffff
)
var (
 kernel32BootDLL=syscall.NewLazyDLL("kernel32.dll")
 procCreateBootMutex=kernel32BootDLL.NewProc("CreateMutexW")
 procWaitBootObject=kernel32BootDLL.NewProc("WaitForSingleObject")
 procReleaseBootMutex=kernel32BootDLL.NewProc("ReleaseMutex")
 procCloseBootHandle=kernel32BootDLL.NewProc("CloseHandle")
)

// The lock is held at OS level, not in-process. Return a release callback
// ONLY after ownership; another process cannot enter concurrently.
// Wait in bounded slices so cancellation does not hang the recovery agent.
func acquireCIBootMutex(ctx context.Context,name string)(func(),error) {
 if err:=ctx.Err();err!=nil{return nil,err}
 if !ciBootMutexName.MatchString(name){
  return nil,errors.New("non-CI Windows recovery mutex name forbidden")
 }
 // Windows mutex ownership is per OS THREAD, not per Go goroutine.
 // Keep the acquiring goroutine pinned until its release callback runs.
 runtime.LockOSThread()
 unlockThreadOnReturn:=true
 defer func(){if unlockThreadOnReturn{runtime.UnlockOSThread()}}()
 wide,err:=syscall.UTF16PtrFromString("Global\\"+name)
 if err!=nil{return nil,err}
 h,_,e:=procCreateBootMutex.Call(0,0,uintptr(unsafe.Pointer(wide)))
 runtime.KeepAlive(wide)
 if h==0 {
  if e!=syscall.Errno(0){return nil,fmt.Errorf("CreateMutexW: %w",e)}
  return nil,errors.New("CreateMutexW returned null handle")
 }
 acquired:=false
 defer func(){if !acquired{procCloseBootHandle.Call(h)}}()
 for {
  if err:=ctx.Err();err!=nil{return nil,err}
  result,_,waitErr:=procWaitBootObject.Call(h,100)
  switch uint32(result){
  case windowsWaitObject0,windowsWaitAbandoned:
   acquired=true
   unlockThreadOnReturn=false
   var once sync.Once
   return func(){once.Do(func(){
    procReleaseBootMutex.Call(h)
    procCloseBootHandle.Call(h)
    runtime.UnlockOSThread()
   })},nil
  case windowsWaitTimeout:
   continue
  case windowsWaitFailed:
   if waitErr!=syscall.Errno(0){return nil,fmt.Errorf("WaitForSingleObject: %w",waitErr)}
   return nil,errors.New("WaitForSingleObject failed")
  default:
   return nil,fmt.Errorf("unexpected Windows mutex wait result: %d",result)
  }
 }
}
