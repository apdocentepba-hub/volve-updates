//go:build windows

package motorupdate

// Production Windows mutex adapter for the publisher-authorized legacy DNS
// transition. It does not install, switch, stop, restart or restore the actual
// motor: independently verified SYSTEM drivers must supply those operations.
import (
 "context"
 "errors"
 "fmt"
)

// ProtectedSignedRecoveryHandoff is mandatory for a production signed
// migration driver. The caller MUST have already persisted a pending,
// publisher-authorized recovery journal and armed an independent SYSTEM
// watchdog before invoking the handoff. The operation starts and waits for
// recovery WITHOUT trying to reacquire the mutex: the wrapping coordinator
// releases it just before calling, and reacquires it before any health probe.
type ProtectedSignedRecoveryHandoff interface {
 RestoreAfterProtectedHandoff(context.Context) error
}

type protectedSignedLegacyDriver struct {
 SignedLegacySwitchDriver
 handoff ProtectedSignedRecoveryHandoff
 currentRelease func()
}

// NewProtectedSignedLegacySwitchDriver makes the signed transition use the
// same SYSTEM/Admin-only OS kernel mutex as the independent boot watchdog.
// Reject an underlying driver that cannot explicitly hand off the lock during
// rollback, because waiting on a watchdog while holding its own mutex would
// deadlock. No publication or production modification is enabled here.
func NewProtectedSignedLegacySwitchDriver(operations SignedLegacySwitchDriver)(SignedLegacySwitchDriver,error){
 if operations==nil{return nil,errors.New("missing trusted signed migration operations")}
 handoff,ok:=operations.(ProtectedSignedRecoveryHandoff)
 if !ok||handoff==nil{
  return nil,errors.New("signed migration driver lacks independent protected watchdog handoff")
 }
 return &protectedSignedLegacyDriver{SignedLegacySwitchDriver:operations,handoff:handoff},nil
}

func(d *protectedSignedLegacyDriver)AcquireExclusiveMigration(ctx context.Context)(func(),error){
 if d==nil||d.SignedLegacySwitchDriver==nil||d.handoff==nil{
  return nil,errors.New("missing protected signed migration adapter")
 }
 if d.currentRelease!=nil{return nil,errors.New("signed migration already owns protected system mutex")}
 release,err:=AcquireProtectedResidentTransitionLease(ctx)
 if err!=nil{return nil,err}
 if release==nil{return nil,errors.New("protected system mutex supplied no release callback")}
 d.currentRelease=release
 // This dynamic finalizer releases the NEW lease after a rollback handoff,
 // not the original lease abandoned before the independent SYSTEM rescue.
 return func(){
  if d.currentRelease!=nil{
   d.currentRelease()
   d.currentRelease=nil
  }
 },nil
}

// Restore is called by the signed transaction's existing rollback path.
// No remaining ownership may be held while the SYSTEM watchdog waits for the
// same protected mutex. A fresh bounded recovery context is already supplied
// by restoreManagedAndVerify; reacquisition is mandatory EVEN ON ERROR.
func(d *protectedSignedLegacyDriver)Restore(ctx context.Context)error{
 if d==nil||d.handoff==nil||d.currentRelease==nil{
  return errors.New("cannot hand off recovery without protected transition mutex")
 }
 release:=d.currentRelease
 d.currentRelease=nil
 release()
 recoverErr:=d.handoff.RestoreAfterProtectedHandoff(ctx)
 // The watchdog can have just written the final journal. Do not claim a
 // healthy recovery or probe DNS from an unprotected transaction. The new
 // mutex ownership is retained until the outer deferred finalizer runs.
 nextRelease,lockErr:=AcquireProtectedResidentTransitionLease(ctx)
 if lockErr!=nil{
  return errors.Join(recoverErr,fmt.Errorf("CRÍTICO: exclusive mutex could not be reacquired after watchdog: %w",lockErr))
 }
 if nextRelease==nil{
  return errors.Join(recoverErr,errors.New("CRÍTICO: watchdog completed without a protected verification lease"))
 }
 d.currentRelease=nextRelease
 return recoverErr
}

func(d *protectedSignedLegacyDriver)Probe(ctx context.Context)error{
 if d==nil||d.currentRelease==nil{return errors.New("refusing DNS health probe without protected transition mutex")}
 return d.SignedLegacySwitchDriver.Probe(ctx)
}
func(d *protectedSignedLegacyDriver)ProbeConnectivity(ctx context.Context)error{
 if d==nil||d.currentRelease==nil{return errors.New("refusing Internet health probe without protected transition mutex")}
 return d.SignedLegacySwitchDriver.ProbeConnectivity(ctx)
}
