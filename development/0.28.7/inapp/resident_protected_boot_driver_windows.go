//go:build windows

package motorupdate

// Production-grade Windows EXCLUSIVE LOCK adapter for the resident reboot
// recovery *policy*. This is NOT an implementation of the actual recovery
// operations: supplying a trusted, independently installed SYSTEM restorer
// and validating a genuine publisher grant are separate requirements.
import (
 "context"
 "errors"
)

// ResidentOriginalRecoveryOps intentionally omits AcquireExclusive. Callers
// cannot swap a process-local mutex for the protected system-wide object.
type ResidentOriginalRecoveryOps interface {
 VerifySealedOriginal(context.Context,ResidentRecoveryIntent) error
 RestoreOriginal(context.Context,ResidentRecoveryIntent) error
}

type protectedResidentBootDriver struct {
 operations ResidentOriginalRecoveryOps
}

// NewProtectedResidentBootDriver binds the actual existing recovery policy
// to the immutable production mutex identity, enforced by the OS. Even a
// test/driver that has its own weaker AcquireExclusive implementation
// cannot override the protected lease.
func NewProtectedResidentBootDriver(operations ResidentOriginalRecoveryOps)(ResidentBootRecoveryDriver,error){
 if operations==nil{return nil,errors.New("missing trusted resident recovery operations")}
 return &protectedResidentBootDriver{operations:operations},nil
}

func(d *protectedResidentBootDriver)AcquireExclusive(ctx context.Context)(func(),error){
 if d==nil || d.operations==nil{return nil,errors.New("missing protected resident recovery adapter")}
 return AcquireProtectedResidentTransitionLease(ctx)
}
func(d *protectedResidentBootDriver)VerifySealedOriginal(ctx context.Context,intent ResidentRecoveryIntent)error{
 if d==nil || d.operations==nil{return errors.New("missing trusted resident original verifier")}
 if err:=ctx.Err();err!=nil{return err}
 return d.operations.VerifySealedOriginal(ctx,intent)
}
func(d *protectedResidentBootDriver)RestoreOriginal(ctx context.Context,intent ResidentRecoveryIntent)error{
 if d==nil || d.operations==nil{return errors.New("missing trusted resident original restorer")}
 if err:=ctx.Err();err!=nil{return err}
 return d.operations.RestoreOriginal(ctx,intent)
}
