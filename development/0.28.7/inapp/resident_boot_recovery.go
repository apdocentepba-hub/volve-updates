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
 if driver==nil||checks==nil||seal==nil||protect==nil {
  return "",errors.New("boot recovery missing trusted driver, probes or NTFS services")
 }
 if err:=ctx.Err();err!=nil{return "",err}
 release,err:=driver.AcquireExclusive(ctx)
 if err!=nil{return "",fmt.Errorf("cannot obtain exclusive reboot recovery lock: %w",err)}
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
  if err:=driver.RestoreOriginal(ctx,state.Intent);err!=nil {
   return "",fmt.Errorf("independent original motor restore failed: %w",err)
  }
 }
 // Do NOT finalize on a successful Windows task registration. Confirm
 // identity, DNS and network independently or leave the journal pending.
 if err:=ConfirmResidentRecoveryOutcome(ctx,journalDir,"restored",seal,protect,checks);err!=nil {
  return "",fmt.Errorf("restored motor health not proven: %w",err)
 }
 return "restored",nil
}
