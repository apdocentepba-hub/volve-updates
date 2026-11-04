//go:build windows

package signedstage

// The kernel mutex is process-independent and is abandoned/released by
// Windows if a worker crashes. Never use it as product installation permission.
import (
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "fmt"
 "runtime"
 "strings"
 "syscall"
 "unsafe"
)

var (
 stageKernel = syscall.NewLazyDLL("kernel32.dll")
 stageCreateMutex = stageKernel.NewProc("CreateMutexW")
 stageWaitMutex = stageKernel.NewProc("WaitForSingleObject")
 stageReleaseMutex = stageKernel.NewProc("ReleaseMutex")
 stageCloseHandle = stageKernel.NewProc("CloseHandle")
)

func acquireStageLock(destination string) (func(),error) {
 sum:=sha256.Sum256([]byte(strings.ToLower(destination)))
 name:="Local\\VOLVE-CI-0287-INACTIVE-"+hex.EncodeToString(sum[:])
 namePtr,err:=syscall.UTF16PtrFromString(name)
 if err!=nil{return nil,err}
 // Windows mutexes are owned by a THREAD, not a Go goroutine.
 runtime.LockOSThread()
 handle,_,createErr:=stageCreateMutex.Call(0,0,uintptr(unsafe.Pointer(namePtr)))
 runtime.KeepAlive(namePtr)
 if handle==0 {
  runtime.UnlockOSThread()
  return nil,fmt.Errorf("cannot create CI process mutex: %w",createErr)
 }
 status,_,waitErr:=stageWaitMutex.Call(handle,0)
 if status!=0 && status!=0x80 { // WAIT_OBJECT_0 or WAIT_ABANDONED
  stageCloseHandle.Call(handle)
  runtime.UnlockOSThread()
  if status==0x102{return nil,errors.New("another inactive staging or recovery process is active")}
  return nil,fmt.Errorf("Windows inactive stage mutex wait failed (status=%d): %w",status,waitErr)
 }
 return func(){
  stageReleaseMutex.Call(handle)
  stageCloseHandle.Call(handle)
  runtime.UnlockOSThread()
 },nil
}
