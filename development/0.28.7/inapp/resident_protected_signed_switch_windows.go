//go:build windows

package motorupdate

// Enforce the exact same release-independent SYSTEM/Admin Windows mutex
// for a future publisher-authorized DNS motor switch. No productive task
// operations are implemented here: these are supplied by a separate,
 // independently reviewed driver and must not be activated by this adapter.
import (
 "context"
 "errors"
)

type protectedSignedLegacyDriver struct {
 SignedLegacySwitchDriver
}

// NewProtectedSignedLegacySwitchDriver binds the existing SIGNED migration
// transaction to the same OS-wide lease as the independent boot watchdog.
// This overrides even a supplied driver's weaker AcquireExclusiveMigration.
// It does not relax any signature, rollback, health or publisher checks and
// does not authorize a production installation.
func NewProtectedSignedLegacySwitchDriver(operations SignedLegacySwitchDriver)(SignedLegacySwitchDriver,error){
 if operations==nil{return nil,errors.New("missing trusted signed migration operations")}
 return &protectedSignedLegacyDriver{SignedLegacySwitchDriver:operations},nil
}
func(d *protectedSignedLegacyDriver)AcquireExclusiveMigration(ctx context.Context)(func(),error){
 if d==nil || d.SignedLegacySwitchDriver==nil{
  return nil,errors.New("missing protected signed migration adapter")
 }
 return AcquireProtectedResidentTransitionLease(ctx)
}
