//go:build windows

package motorupdate

// Concrete SYSTEM-only bridge for the future publisher-signed installer.
// NOT called by the existing app, installer wizard, task or Windows release.
// The publisher/watchdog guard remains an unimplemented production dependency:
// this function is deliberately unexported until the pinned issuer, sealed
// backup and independent boot-watchdog receipt have real OS implementations.
import (
 "context"
 "errors"
 "fmt"
)

// activateWindowsDNSAsProtectedSYSTEM ties together the real Windows
// LocalSystem SID, native SYSTEM/Admin-only named mutex, GUID-pinned adapter
// inventory, shell-free netsh, and the independent recovery handoff. An
// Administrator (even elevated) is NOT accepted as a SYSTEM installation
// controller. The injected guard MUST itself verify independently signed
// grant, protected original journal and armed boot task on every call.
func activateWindowsDNSAsProtectedSYSTEM(
 ctx context.Context, originalJournal []byte, independentlyPinnedSHA256 string,
 guard DNSActivationSafetyGuard,
)error{
 if ctx==nil{return errors.New("SYSTEM DNS activation context required")}
 if err:=ctx.Err();err!=nil{return err}
 if guard==nil{return errors.New("publisher-authorized boot recovery guard missing")}
 if err:=VerifyWindowsCurrentSystemSIDReadOnly();err!=nil{
  return fmt.Errorf("VOLVE DNS activation requires the actual Windows LocalSystem SID: %w",err)
 }
 return activateVOLVEDNSUnderProtectedLease(
  ctx,originalJournal,independentlyPinnedSHA256,guard,
  AcquireProtectedResidentTransitionLease,
  func(ctx context.Context,guarded DNSActivationSafetyGuard)(DNSAdapterBackend,error){
   return newWindowsPinnedDNSActivationBackend(
    ctx,originalJournal,independentlyPinnedSHA256,
    DefaultWindowsReadOnlyPowerShell,runPinnedWindowsNativeDNS,guarded,
   )
  },
 )
}
