//go:build windows

package motorupdate

// Privileged Windows kernel mutex guard for independent SYSTEM boot recovery.
// It does not implement actual task, DNS, or motor restoration.
import (
 "context"
 "errors"
 "sync"
)

// ResidentOriginalRecoveryOps intentionally omits AcquireExclusive. A test or
// OS driver cannot substitute a process-local lock for the protected mutex.
type ResidentOriginalRecoveryOps interface {
 VerifySealedOriginal(context.Context,ResidentRecoveryIntent) error
 RestoreOriginal(context.Context,ResidentRecoveryIntent) error
}

type protectedResidentBootDriver struct {
 operations ResidentOriginalRecoveryOps

 // Every call that can inspect or restore the original must hold the
 // OS-wide lease AND this state lock. The latter prevents a racing finalizer
 // from releasing the OS lock halfway through an operation.
 stateMu sync.Mutex
 currentRelease func()
 leaseSerial uint64
}

// NewProtectedResidentBootDriver binds the independent recovery policy to
// the SAME protected SYSTEM/Administrator Win32 mutex as the signed updater.
// This wrapper only enforces exclusion; publisher authorization and trusted
// original restore operations are separate mandatory security layers.
func NewProtectedResidentBootDriver(operations ResidentOriginalRecoveryOps)(ResidentBootRecoveryDriver,error){
 if operations==nil{return nil,errors.New("missing trusted resident recovery operations")}
 return &protectedResidentBootDriver{operations:operations},nil
}

func(d *protectedResidentBootDriver)AcquireExclusive(ctx context.Context)(func(),error){
 if d==nil||d.operations==nil{return nil,errors.New("missing protected resident recovery adapter")}
 d.stateMu.Lock()
 defer d.stateMu.Unlock()
 if d.currentRelease!=nil{return nil,errors.New("protected reboot recovery already owns system mutex")}
 if err:=ctx.Err();err!=nil{return nil,err}
 release,err:=AcquireProtectedResidentTransitionLease(ctx)
 if err!=nil{return nil,err}
 if release==nil{return nil,errors.New("protected recovery mutex returned no release callback")}
 d.leaseSerial++
 serial:=d.leaseSerial
 d.currentRelease=release
 return func(){
  d.stateMu.Lock()
  defer d.stateMu.Unlock()
  if d.leaseSerial!=serial{return} // stale caller must never release a later boot
  if d.currentRelease!=nil{
   d.currentRelease()
   d.currentRelease=nil
  }
 },nil
}

func(d *protectedResidentBootDriver)underProtectedLease(ctx context.Context,op func()error)error{
 if d==nil||d.operations==nil{return errors.New("missing trusted resident original operations")}
 d.stateMu.Lock()
 defer d.stateMu.Unlock()
 if d.currentRelease==nil{return errors.New("SYSTEM original operation refused without protected Windows kernel mutex")}
 if err:=ctx.Err();err!=nil{return err}
 return op()
}

func(d *protectedResidentBootDriver)VerifySealedOriginal(ctx context.Context,intent ResidentRecoveryIntent)error{
 return d.underProtectedLease(ctx,func()error{return d.operations.VerifySealedOriginal(ctx,intent)})
}
func(d *protectedResidentBootDriver)RestoreOriginal(ctx context.Context,intent ResidentRecoveryIntent)error{
 return d.underProtectedLease(ctx,func()error{return d.operations.RestoreOriginal(ctx,intent)})
}
