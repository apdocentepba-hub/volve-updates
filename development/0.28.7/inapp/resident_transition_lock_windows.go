//go:build windows

package motorupdate

// This is the production Windows KERNEL MUTEX primitive, not the updater or
// recovery driver. It does not inspect, start or change VOLVE, DNS or tasks.
// Both the future signed updater and the independent SYSTEM watchdog must
// use this exact identity. No caller-supplied name can reach the OS.
import (
 "context"
 "errors"
 "fmt"
 "runtime"
 "strings"
 "sync"
 "syscall"
 "unsafe"
)

const residentTransitionMutexName = "Global\\VOLVE-ResidentMotor-Transition-0287"

// Explicit protected DACL: only LOCAL SYSTEM and BUILTIN Administrators.
// The object owner is the built-in Administrators group, not the creating
// arbitrary user. An existing object must match BOTH owner and DACL.
const residentTransitionMutexSDDL = "O:BAD:P(A;;0x001f0001;;;SY)(A;;0x001f0001;;;BA)"
const residentTransitionMutexExpectedRights = "D:P(A;;0x1f0001;;;SY)(A;;0x1f0001;;;BA)"
const residentTransitionSecurityRevision = 1
const residentTransitionOwnerInfo = 0x00000001
const residentTransitionDACLInfo = 0x00000004
const residentTransitionSecurityInfo = residentTransitionOwnerInfo | residentTransitionDACLInfo
const residentTransitionWaitObject0 = 0x00000000
const residentTransitionWaitAbandoned = 0x00000080
const residentTransitionWaitTimeout = 0x00000102
const residentTransitionWaitFailed = 0xffffffff

var (
 residentKernel32 = syscall.NewLazyDLL("kernel32.dll")
 residentAdvapi32 = syscall.NewLazyDLL("advapi32.dll")
 residentConvertSDDL = residentAdvapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
 residentConvertSDToString = residentAdvapi32.NewProc("ConvertSecurityDescriptorToStringSecurityDescriptorW")
 residentGetKernelObjectSecurity = residentAdvapi32.NewProc("GetKernelObjectSecurity")
 residentConvertStringSID = residentAdvapi32.NewProc("ConvertStringSidToSidW")
 residentCheckTokenMembership = residentAdvapi32.NewProc("CheckTokenMembership")
 residentLocalFree = residentKernel32.NewProc("LocalFree")
 residentCreateMutex = residentKernel32.NewProc("CreateMutexW")
 residentWaitObject = residentKernel32.NewProc("WaitForSingleObject")
 residentReleaseMutex = residentKernel32.NewProc("ReleaseMutex")
 residentCloseHandle = residentKernel32.NewProc("CloseHandle")
)

type residentSecurityAttributes struct {
 Length uint32
 Descriptor uintptr
 InheritHandle uint32
}

func residentWinErr(caller string,last error)error{
 if last!=nil && last!=syscall.Errno(0){return fmt.Errorf("%s: %w",caller,last)}
 return fmt.Errorf("%s failed without Windows error",caller)
}

func residentCurrentIsPrivileged()error{
 // An elevated admin token or SYSTEM is required before even creating a
 // named object. In particular a UAC filtered local administrator is NOT
 // acceptable. These checks do not change the current token.
 for _,sidText:=range []string{"S-1-5-18","S-1-5-32-544"}{
  sidName,err:=syscall.UTF16PtrFromString(sidText);if err!=nil{return err}
  var sid uintptr
  ok,_,last:=residentConvertStringSID.Call(uintptr(unsafe.Pointer(sidName)),uintptr(unsafe.Pointer(&sid)))
  runtime.KeepAlive(sidName)
  if ok==0{return residentWinErr("ConvertStringSidToSidW",last)}
  var member int32
  ok,_,last=residentCheckTokenMembership.Call(0,sid,uintptr(unsafe.Pointer(&member)))
  residentLocalFree.Call(sid)
  if ok==0{return residentWinErr("CheckTokenMembership",last)}
  if member!=0{return nil}
 }
 return errors.New("resident motor transition requires elevated Administrators or SYSTEM token")
}

func residentMutexSecurityDescriptor()(uintptr,error){
 raw,err:=syscall.UTF16PtrFromString(residentTransitionMutexSDDL)
 if err!=nil{return 0,err}
 var descriptor uintptr
 ok,_,last:=residentConvertSDDL.Call(uintptr(unsafe.Pointer(raw)),residentTransitionSecurityRevision,
  uintptr(unsafe.Pointer(&descriptor)),0)
 runtime.KeepAlive(raw)
 if ok==0{return 0,residentWinErr("ConvertStringSecurityDescriptorToSecurityDescriptorW",last)}
 if descriptor==0{return 0,errors.New("Windows security descriptor unexpectedly null")}
 return descriptor,nil
}

func residentObservedSecurity(handle uintptr)(string,error){
 var required uint32
 residentGetKernelObjectSecurity.Call(handle,residentTransitionSecurityInfo,0,0,uintptr(unsafe.Pointer(&required)))
 if required==0||required>32768{return "",errors.New("unexpected resident mutex security descriptor size")}
 raw:=make([]byte,required)
 var returned uint32
 ok,_,last:=residentGetKernelObjectSecurity.Call(handle,residentTransitionSecurityInfo,
  uintptr(unsafe.Pointer(&raw[0])),uintptr(required),uintptr(unsafe.Pointer(&returned)))
 if ok==0{return "",residentWinErr("GetKernelObjectSecurity",last)}
 if returned==0||returned>required{return "",errors.New("invalid kernel security descriptor length")}
 var sdText uintptr
 var characters uint32
 ok,_,last=residentConvertSDToString.Call(uintptr(unsafe.Pointer(&raw[0])),
  residentTransitionSecurityRevision,residentTransitionSecurityInfo,
  uintptr(unsafe.Pointer(&sdText)),uintptr(unsafe.Pointer(&characters)))
 runtime.KeepAlive(raw)
 if ok==0{return "",residentWinErr("ConvertSecurityDescriptorToStringSecurityDescriptorW",last)}
 if sdText==0{return "",errors.New("kernel ACL conversion yielded null")}
 defer residentLocalFree.Call(sdText)
 text:=syscall.UTF16PtrToString((*uint16)(unsafe.Pointer(sdText)))
 return text,nil
}

func residentRequireExactSD(handle uintptr)error{
 observed,err:=residentObservedSecurity(handle)
 if err!=nil{return err}
 // Windows may render the same access mask with hexadecimal leading zeros
 // or lowercase/capitalized digits. Do NOT strip or ignore any ACE, owner,
 // inherited flag, or rights. Refuse pre-created unsafe objects.
 normalized:=strings.ToUpper(observed)
 normalized=strings.ReplaceAll(normalized,"0X001F0001","0X1F0001")
 normalized=strings.ReplaceAll(normalized,"0X001F0001","0X1F0001")
 want:=strings.ToUpper("O:BA"+residentTransitionMutexExpectedRights)
 if normalized!=want{
  return fmt.Errorf("resident transition mutex owner or DACL differs from strict SYSTEM/Admin policy: %s",observed)
 }
 return nil
}

// AcquireProtectedResidentTransitionLease is the privileged production
// synchronization PRIMITIVE. It does NOT authorize any motor migration.
//
// Kernel mutex ownership is per Windows OS thread, not per Go goroutine.
// The caller MUST invoke the returned release callback on the SAME goroutine
// after all task and network health checks. On exit release is idempotent.
// Both signed-updater and independent SYSTEM recovery must use this exact API.
// Closing or abandoning an owner cannot be interpreted as migration success.
func AcquireProtectedResidentTransitionLease(ctx context.Context)(func(),error){
 if err:=ctx.Err();err!=nil{return nil,err}
 if err:=residentCurrentIsPrivileged();err!=nil{return nil,err}
 runtime.LockOSThread()
 pinned:=true
 defer func(){if pinned{runtime.UnlockOSThread()}}()
 descriptor,err:=residentMutexSecurityDescriptor()
 if err!=nil{return nil,err}
 defer residentLocalFree.Call(descriptor)
 attributes:=residentSecurityAttributes{Length:uint32(unsafe.Sizeof(residentSecurityAttributes{})),Descriptor:descriptor}
 name,err:=syscall.UTF16PtrFromString(residentTransitionMutexName)
 if err!=nil{return nil,err}
 handle,_,last:=residentCreateMutex.Call(uintptr(unsafe.Pointer(&attributes)),0,uintptr(unsafe.Pointer(name)))
 runtime.KeepAlive(name)
 runtime.KeepAlive(attributes)
 if handle==0{return nil,residentWinErr("CreateMutexW protected resident motor",last)}
 owned:=false
 defer func(){if !owned{residentCloseHandle.Call(handle)}}()
 // A pre-existing object might have been created by an untrusted account
 // before the privileged worker started. Never use it unless ACL and
 // owner match the exact protected descriptor.
 if err:=residentRequireExactSD(handle);err!=nil{return nil,err}
 for {
  if err:=ctx.Err();err!=nil{return nil,err}
  result,_,waitErr:=residentWaitObject.Call(handle,100)
  switch uint32(result){
  case residentTransitionWaitObject0,residentTransitionWaitAbandoned:
   owned=true
   pinned=false
   var once sync.Once
   return func(){once.Do(func(){
    residentReleaseMutex.Call(handle)
    residentCloseHandle.Call(handle)
    runtime.UnlockOSThread()
   })},nil
  case residentTransitionWaitTimeout:continue
  case residentTransitionWaitFailed:return nil,residentWinErr("WaitForSingleObject resident transition",waitErr)
  default:return nil,fmt.Errorf("unexpected resident mutex wait code %d",result)
  }
 }
}
