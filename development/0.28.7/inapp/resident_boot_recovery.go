package motorupdate

// Independent reboot-recovery policy, with NO Windows Task Scheduler commands.
// A future separately installed SYSTEM watchdog can call this contract after
// boot, with a trusted OS driver. This is NOT a production-ready restorer.
import (
 "context"
 "errors"
 "fmt"
)

// ResidentBootRecoveryDriver must enforce an OS-wide exclusive lock (e.g.
// named Windows mutex), verify the protected original and exact task identity,
// and restore ONLY the publisher-authorized VOLVE original. The policy never
// accepts a switch to a new candidate at boot and never modifies DNS directly.
type ResidentBootRecoveryDriver interface {
 AcquireExclusive(context.Context) (release func(),err error)
 VerifySealedOriginal(context.Context,ResidentRecoveryIntent) error
 RestoreOriginal(context.Context,ResidentRecoveryIntent) error
}

// RecoverPendingResidentAfterBoot is safe to invoke repeatedly after crashes:
//  - no journal: no action;
//  - valid terminal result: no action, never overwrite;
//  - pending valid intent: hold exclusive lock, re-check sealed original;
//  - if the original SYSTEM process is no longer running, invoke the
//    independent restorer exactly once;
//  - verify the restored motor identity twice, local v4/v6 DNS and network;
//  - only then publish a create-only nonce-bound "restored" terminal receipt.
// Any failure or interruption leaves the transaction PENDING, not "success".
// A separate watchdog service and real Windows reboot test remain REQUIRED.
func RecoverPendingResidentAfterBoot(
 ctx context.Context, journalDir string,
 seal, protect func(string)error, checks ResidentCompletionChecks,
 driver ResidentBootRecoveryDriver,
)(string,error){
 // A DNS-capable native driver must never be silently routed through
 // the motor-only policy, even if a caller stores it in the base interface.
 // Reject before acquiring a lease, inspecting or finalizing a journal.
 if _,requiresDNS:=driver.(ResidentDNSBootRecoveryDriver);requiresDNS{
  return "",errors.New("DNS-capable recovery driver requires the explicit original DNS policy")
 }
 return recoverPendingResidentAfterBoot(ctx,journalDir,seal,protect,checks,driver,nil)
}

// ResidentDNSBootRecoveryDriver is the stricter opt-in contract for a
// transaction that changed adapter DNS assignments. All methods execute
// under the SAME exclusive recovery lease. RestoreOriginalDNS must first
// authenticate the durable publisher binding, original full adapter census
// and independently establish that the failed candidate cannot write DNS.
// It must be idempotent even when the original motor is already running.
// VerifyOriginalDNS must reopen that signed evidence and read actual OS DNS
// assignment modes and server lists; a working resolver is not sufficient.
// No production driver or installer is authorized by this interface.
type ResidentDNSBootRecoveryDriver interface {
 ResidentBootRecoveryDriver
 // RestoreOriginalDNS and VerifyOriginalDNS run while the failed candidate
 // is fenced and before the original motor is started.
 RestoreOriginalDNS(context.Context,ResidentRecoveryIntent) error
 VerifyOriginalDNS(context.Context,ResidentRecoveryIntent) error
 // StartOriginal is a distinct final activation step. It must run only after
 // the signed original DNS snapshot has been restored and independently read
 // back, under the SAME exclusive recovery lease.
 StartOriginal(context.Context,ResidentRecoveryIntent) error
}

// RecoverPendingResidentAfterBootWithOriginalDNS is mandatory for future
// DNS-changing transactions. Do not fall back to the older motor-only API
// if this path fails. This policy never performs Windows writes itself.
func RecoverPendingResidentAfterBootWithOriginalDNS(
 ctx context.Context,journalDir string,
 seal,protect func(string)error,checks ResidentCompletionChecks,
 driver ResidentDNSBootRecoveryDriver,
)(string,error){
 if driver==nil{return "",errors.New("DNS-changing boot recovery requires explicit original DNS driver")}
 return recoverPendingResidentAfterBoot(ctx,journalDir,seal,protect,checks,driver,driver)
}

func recoverPendingResidentAfterBoot(
 ctx context.Context,journalDir string,
 seal,protect func(string)error,checks ResidentCompletionChecks,
 driver ResidentBootRecoveryDriver,dns ResidentDNSBootRecoveryDriver,
)(string,error){
 if ctx==nil{return "",errors.New("boot recovery context required")}
 if driver==nil||checks==nil||seal==nil||protect==nil {
  return "",errors.New("boot recovery missing trusted driver, probes or NTFS services")
 }
 if err:=ctx.Err();err!=nil{return "",err}
 release,err:=driver.AcquireExclusive(ctx)
 if err!=nil{
  // An acquirer can return a partial lease alongside a failure.
  // Release that ownership before returning, as in DNS activation.
  if release!=nil{release()}
  return "",fmt.Errorf("cannot obtain exclusive reboot recovery lock: %w",err)
 }
 if release==nil{return "",errors.New("recovery driver provided no exclusive lock release")}
 defer release()
 if err:=ctx.Err();err!=nil{return "",err}
 state,err:=InspectResidentRecoveryJournal(ctx,journalDir,protect)
 if err!=nil{return "",fmt.Errorf("untrusted reboot recovery journal: %w",err)}
 switch state.Status {
 case "not-armed","committed","restored":
  return state.Status,nil
 case "recovery-required":
  // Only the exact original in the sealed backup is recoverable.
 default:
  return "",errors.New("recovery journal status not allowlisted")
 }
 if err:=driver.VerifySealedOriginal(ctx,state.Intent);err!=nil {
  return "",fmt.Errorf("sealing/identity of original DNS backup rejected: %w",err)
 }
 // Prevent acting on an already-completed or replaced transaction after
 // the original bundle was inspected. The OS driver must separately guard
 // the live switch boundary with the same exclusive mutex.
 latest,err:=InspectResidentRecoveryJournal(ctx,journalDir,protect)
 if err!=nil||latest!=state {
  return "",errors.New("recovery journal changed before autonomous restoration")
 }
 if err:=ctx.Err();err!=nil{return "",err}
 // A lost process or mismatched SYSTEM identity is grounds for restoring the
 // original. A working original will be reverified, not needlessly replaced.
 if err:=checks.VerifyRunningIdentity(ctx,state.Intent,"restored");err!=nil {
  // A canceled identity probe is not evidence of a missing motor.
  // Never initiate a privileged restore after losing the caller context.
  if err:=ctx.Err();err!=nil{return "",err}
  // A failed identity probe may take time. Do not restore a stale intent
  // if a different transaction has been observed during that interval.
  current,readErr:=InspectResidentRecoveryJournal(ctx,journalDir,protect)
  if readErr!=nil||current!=state{return "",errors.New("recovery journal changed during failed identity probe")}
  if err:=driver.RestoreOriginal(ctx,state.Intent);err!=nil {
   return "",fmt.Errorf("independent original motor restore failed: %w",err)
  }
 }
 // In DNS-changing transactions, restore the original DNS assignment
 // BEFORE starting the original motor. The failed candidate must remain
 // fenced and the port-53 ownership census must be unambiguous throughout
 // both DNS operations. A healthy motor identity is checked only AFTER the
 // explicit StartOriginal step below.
 if dns!=nil{
  current,err:=InspectResidentRecoveryJournal(ctx,journalDir,protect)
  if err!=nil||current!=state{return "",errors.New("recovery journal changed before original DNS restoration")}
  if err:=ctx.Err();err!=nil{return "",err}
  if err:=dns.RestoreOriginalDNS(ctx,state.Intent);err!=nil{
   return "",fmt.Errorf("independent original DNS restoration failed: %w",err)
  }
  if err:=dns.VerifyOriginalDNS(ctx,state.Intent);err!=nil{
   return "",fmt.Errorf("original DNS assignment not independently verified: %w",err)
  }
  current,err=InspectResidentRecoveryJournal(ctx,journalDir,protect)
  if err!=nil||current!=state{return "",errors.New("recovery journal changed before starting original motor")}
  if err:=ctx.Err();err!=nil{return "",err}
  if err:=dns.StartOriginal(ctx,state.Intent);err!=nil{
   return "",fmt.Errorf("original motor start after DNS restoration failed: %w",err)
  }
 }
 // Do NOT finalize on a successful Windows task registration. The
 // original protected recovery asset must still exist, unchanged and sealed
 // AFTER DNS and Internet health probes, not only before RestoreOriginal.
 // No terminal receipt is written if another process damages the original
 // during health checks, even when the current motor seems healthy.
 audited,err:=AuditResidentRecoveryOutcome(ctx,journalDir,"restored",protect,checks)
 if err!=nil{return "",fmt.Errorf("restored motor health not proven: %w",err)}
 if audited!=state.Intent{return "",errors.New("recovery intent changed during health audit")}
 if err:=driver.VerifySealedOriginal(ctx,state.Intent);err!=nil{
  return "",fmt.Errorf("original recovery snapshot changed during health checks: %w",err)
 }
 // Repeat the exact original DNS census AFTER all health probes and sealed
 // motor evidence checks. A healthy Internet connection via another resolver
 // cannot justify consuming the pending recovery journal.
 if dns!=nil{
  if err:=dns.VerifyOriginalDNS(ctx,state.Intent);err!=nil{
   return "",fmt.Errorf("original DNS assignment changed during health verification: %w",err)
  }
 }
 finalState,err:=InspectResidentRecoveryJournal(ctx,journalDir,protect)
 if err!=nil||finalState.Status!="recovery-required"||finalState.Intent!=state.Intent{
  return "",errors.New("recovery journal changed before terminal receipt")
 }
 if err:=finishResidentRecoveryIntentBound(ctx,journalDir,"restored",&state.Intent,seal,protect);err!=nil{
  return "",fmt.Errorf("restored motor receipt not durable: %w",err)
 }
 return "restored",nil
}
