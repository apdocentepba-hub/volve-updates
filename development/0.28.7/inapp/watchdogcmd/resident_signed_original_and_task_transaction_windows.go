//go:build windows

package main

// A single publisher-verified, SYSTEM-only recovery transaction for the
// ORIGINAL installed DNS executable and its exact protected AtStartup task.
//
// SAFETY BOUNDARIES:
// - No production CLI, launcher button, watchdog startup hook or release.
// - No replacement of a candidate/unknown *existing* executable.
// - No changes to active DNS endpoints or adapters; fail closed if busy.
// - No terminal journal receipt, "recovered" status or DNS health claim.
// - The task executor is deliberately injected for isolated VM testing.
// A separately verified production SYSTEM watchdog remains required.
import (
 "context"
 "crypto/ed25519"
 "errors"
 "fmt"
 "path/filepath"

 "volve-browser-protection/motorupdate"
)

type residentSignedCombinedRecoveryDeps struct {
 File residentMissingOriginalRestoreDeps
 Task residentSignedTaskRestoreDeps
}

func recoverSignedLegacyOriginalAndSYSTEMTaskWindows(
 ctx context.Context,root string,key ed25519.PublicKey,
 deps residentSignedCombinedRecoveryDeps,
)error{
 if err:=ctx.Err();err!=nil{return err}
 if len(key)!=ed25519.PublicKeySize||
  !filepath.IsAbs(root)||filepath.Clean(root)!=root||
  deps.File.VerifySystem==nil||deps.File.VerifyACL==nil||
  deps.File.SealNew==nil||deps.File.ProbeQuiescence==nil||
  deps.Task.VerifySystem==nil||deps.Task.VerifyACL==nil||
  deps.Task.ProbeQuiescence==nil||deps.Task.RunWindowsTask==nil{
  return errors.New("complete signed original recovery requires all mandatory SYSTEM/NTFS/DNS guards")
 }
 if err:=deps.File.VerifySystem(ctx);err!=nil{return fmt.Errorf("original recovery lacks SYSTEM identity: %w",err)}
 if err:=deps.Task.VerifySystem(ctx);err!=nil{return fmt.Errorf("task recovery lacks SYSTEM identity: %w",err)}
 lease,err:=motorupdate.AcquireProtectedResidentTransitionLease(ctx)
 if err!=nil{return fmt.Errorf("cannot acquire protected original recovery transaction: %w",err)}
 if lease==nil{return errors.New("protected original recovery mutex returned nil release")}
 defer lease()
 return recoverSignedLegacyOriginalAndSYSTEMTaskLockedWindows(ctx,root,key,deps)
}

// recoverSignedLegacyOriginalAndSYSTEMTaskLockedWindows is the handoff
// for an independent boot watchdog that ALREADY OWNS the protected Windows
// transition mutex. It MUST NEVER acquire the non-reentrant lease again.
// This remains private and unavailable to the product launcher or CLI.
// The caller must hold the lease for the full file+Scheduler transition.
func recoverSignedLegacyOriginalAndSYSTEMTaskLockedWindows(
 ctx context.Context,root string,key ed25519.PublicKey,
 deps residentSignedCombinedRecoveryDeps,
)error{
 if err:=ctx.Err();err!=nil{return err}
 if len(key)!=ed25519.PublicKeySize||
  !filepath.IsAbs(root)||filepath.Clean(root)!=root||
  deps.File.VerifySystem==nil||deps.File.VerifyACL==nil||
  deps.File.SealNew==nil||deps.File.ProbeQuiescence==nil||
  deps.Task.VerifySystem==nil||deps.Task.VerifyACL==nil||
  deps.Task.ProbeQuiescence==nil||deps.Task.RunWindowsTask==nil{
  return errors.New("locked recovery requires complete SYSTEM, NTFS and DNS safeguards")
 }
 // Verify both OS identities under the already-held mutex, not only
 // before acquisition by a previous owner.
 if err:=deps.File.VerifySystem(ctx);err!=nil{return fmt.Errorf("locked file recovery lacks SYSTEM: %w",err)}
 if err:=deps.Task.VerifySystem(ctx);err!=nil{return fmt.Errorf("locked task recovery lacks SYSTEM: %w",err)}

 // An independent signed backup/journal check is deliberately repeated
 // by EACH locked primitive. Every decision stays under this one mutex.
 a,err:=auditResidentSignedBootAdmissionLocked(ctx,root,key,
  deps.File.VerifyACL,deps.File.VerifyACL,deps.File.VerifyACL,
  deps.File.ProbeQuiescence)
 if err!=nil{return fmt.Errorf("signed original recovery preflight denied: %w",err)}
 if a.Status!="recovery-required"||
  !a.PublisherVerified||!a.QuiescenceVerified||
  a.Action!="signed-evidence-verified-read-only"{
  return errors.New("no publisher-authorized quiescent pending recovery transaction")
 }
 switch a.OriginalFileState {
 case "missing-original":
  if err:=restoreSignedMissingOriginalLocked(ctx,root,key,deps.File);err!=nil{
   return fmt.Errorf("protected missing-original reconstruction failed: %w",err)
  }
 case "original-intact":
  // Resume after an interrupted earlier file restoration; do NOT rewrite
  // an already installed original executable.
 default:
  return errors.New("signed combined recovery refuses any candidate or unknown live executable")
 }
 // The task restorer re-verifies actual installed SHA-256, publisher grant,
 // XML checksum, Windows task, motor process and DNS port 53 while SAME
 // lease is held. No terminal journal receipt is generated here.
 if err:=restoreSignedOriginalSYSTEMTaskLocked(ctx,root,key,deps.Task);err!=nil{
  return fmt.Errorf("signed original SYSTEM task reimport failed: %w",err)
 }
 if err:=ctx.Err();err!=nil{return err}
 // The task still needs to START and answer actual DNS queries before a
 // separate watchdog can write an authoritative recovery receipt.
 return nil
}
