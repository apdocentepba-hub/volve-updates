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
 "time"
)

// activateWindowsDNSAsProtectedSYSTEM ties together the real Windows
// LocalSystem SID, native SYSTEM/Admin-only named mutex, GUID-pinned adapter
// inventory, shell-free netsh, and the independent recovery handoff. An
// Administrator (even elevated) is NOT accepted as a SYSTEM installation
// controller. The injected guard MUST itself verify independently signed
// grant, protected original journal and armed boot task on every call.
func activateWindowsDNSAsProtectedSYSTEM(
 ctx context.Context, originalJournal []byte, independentlyPinnedSHA256 string,
 guard DNSActivationSafetyGuard, publisherAuthorization DNSActivationPublisherAuthorization,
 protectedRecoveryParent string,
)error{
 if ctx==nil{return errors.New("SYSTEM DNS activation context required")}
 if err:=ctx.Err();err!=nil{return err}
 if guard==nil{return errors.New("publisher-authorized boot recovery guard missing")}
 if err:=VerifyWindowsCurrentSystemSIDReadOnly();err!=nil{
  return fmt.Errorf("VOLVE DNS activation requires the actual Windows LocalSystem SID: %w",err)
 }
 // A signed RESTORE or MIGRATION receipt alone cannot authorize DNS activation.
 // This admission must be bound to the current publisher, exact candidate,
 // original DNS and independently armed watchdog task. It is repeated before
 // each family-scoped native write and before durable commit.
 publisherBound,err:=newPublisherScopedDNSActivationGuard(
  ctx,originalJournal,independentlyPinnedSHA256,publisherAuthorization,
  guard,time.Now,
 )
 if err!=nil{return fmt.Errorf("VOLVE signed DNS activation rejected: %w",err)}
 // The native backend is checked against ALL current original DNS
 // interfaces before spending the signed grant. After that preflight,
 // nonce O_EXCL reservation and every DNS write occur under ONE protected
 // Windows kernel mutex, with no unlocked transition window. Recovery alone
 // can temporarily yield this mutex to the independent SYSTEM watchdog.
 return activateVOLVEDNSUnderProtectedLease(
  ctx,originalJournal,independentlyPinnedSHA256,publisherBound,
  AcquireProtectedResidentTransitionLease,
  func(ctx context.Context,guarded DNSActivationSafetyGuard)(DNSAdapterBackend,error){
   backend,err:=newWindowsPinnedDNSActivationBackend(
    ctx,originalJournal,independentlyPinnedSHA256,
    DefaultWindowsReadOnlyPowerShell,runPinnedWindowsNativeDNS,guarded,
   )
   if err!=nil{return nil,err}
   exclusive,ok:=guarded.(*exclusiveDNSActivationGuard)
   if !ok{return nil,errors.New("native DNS activation lost its protected kernel lease")}
   // No second lease acquisition here; the reserved nonce and the
   // activation's readback/commit must share one critical section.
   if _,err:=reserveSignedDNSActivationOnceUnderHeldLeaseNativeWindows(
    ctx,protectedRecoveryParent,publisherAuthorization.GrantJSON,
    publisherAuthorization.Signature,publisherAuthorization.PinnedPublisherKey,
    publisherAuthorization.PinnedEvidence,time.Now(),exclusive,
   );err!=nil{
    return nil,fmt.Errorf("protected publisher DNS nonce reservation refused: %w",err)
   }
   return backend,nil
  },
 )
}
