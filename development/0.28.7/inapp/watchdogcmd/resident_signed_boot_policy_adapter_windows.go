//go:build windows

package main

// Adapt the signed original-file + SYSTEM-task recovery transaction to the
// existing boot-policy interface. This is a private bridge for integration
// tests and a future independent, publisher-authorized SYSTEM watchdog.
//
// IMPORTANT: motorupdate.NewProtectedResidentBootDriver must own the shared
// Windows kernel mutex for the ENTIRE boot policy transaction. Neither
// method acquires that non-reentrant mutex. No CLI, Task Scheduler startup
// registration, release channel or launcher button uses this bridge.
import (
 "context"
 "crypto/ed25519"
 "errors"
 "fmt"
 "path/filepath"

 "volve-browser-protection/motorupdate"
)

type residentSignedBootOriginalOps struct {
 root string
 publisher ed25519.PublicKey
 deps residentSignedCombinedRecoveryDeps
}

var _ motorupdate.ResidentOriginalRecoveryOps = (*residentSignedBootOriginalOps)(nil)

func newResidentSignedBootOriginalOps(
 root string,publisher ed25519.PublicKey,deps residentSignedCombinedRecoveryDeps,
)(motorupdate.ResidentOriginalRecoveryOps,error){
 if !filepath.IsAbs(root)||filepath.Clean(root)!=root||
  len(publisher)!=ed25519.PublicKeySize||
  deps.File.VerifySystem==nil||deps.File.VerifyACL==nil||
  deps.File.SealNew==nil||deps.File.ProbeQuiescence==nil||
  deps.Task.VerifySystem==nil||deps.Task.VerifyACL==nil||
  deps.Task.ProbeQuiescence==nil||deps.Task.RunWindowsTask==nil{
  return nil,errors.New("signed boot original operations require pinned publisher, canonical root and complete privileged guards")
 }
 return &residentSignedBootOriginalOps{
  root:root,publisher:append(ed25519.PublicKey(nil),publisher...),deps:deps,
 },nil
}

// The policy calls VerifySealedOriginal after obtaining the protected mutex.
// Verify publication identity, journal nonce and complete signed authorization,
// not just the backup bytes. The actual Windows task is not modified here.
func(o *residentSignedBootOriginalOps)VerifySealedOriginal(
 ctx context.Context,intent motorupdate.ResidentRecoveryIntent,
)error{
 if o==nil{return errors.New("signed boot original verifier unavailable")}
 if err:=ctx.Err();err!=nil{return err}
 if err:=o.deps.File.VerifySystem(ctx);err!=nil{
  return fmt.Errorf("signed boot recovery requires SYSTEM: %w",err)
 }
 // Compare the immutable journal/backup identity first. A different
 // transaction nonce is rejected before expensive signed-grant and ACL
 // admission checks, but no mutation occurs until BOTH checks succeed.
 evidence,err:=auditPostSwitchResidentRecovery(ctx,o.root)
 if err!=nil{return err}
 if evidence.LegacySHA256!=intent.LegacySHA256||
  evidence.TaskXMLSHA256!=intent.TaskXMLSHA256||
  evidence.TargetSHA256!=intent.TargetSHA256||
  evidence.TargetVersion!=intent.TargetVersion||
  evidence.IntentNonce!=intent.Nonce{
  return errors.New("signed boot original differs from policy recovery intent")
 }
 // Signed backup verification must be READ-ONLY and permit an already
 // healthy original DNS motor to be running after boot. The live SYSTEM
 // process/DNS53 quiescence fence belongs to RestoreOriginal immediately
 // before MUTATION, and is rechecked there under the same held mutex.
 a,err:=auditResidentSignedBootAdmissionLocked(ctx,o.root,o.publisher,
  o.deps.File.VerifyACL,o.deps.File.VerifyACL,o.deps.File.VerifyACL,nil)
 if err!=nil{return fmt.Errorf("signed boot evidence refused: %w",err)}
 if a.Status!="recovery-required"||
  a.Action!="signed-evidence-verified-read-only"||
  !a.PublisherVerified||
  (a.OriginalFileState!="missing-original"&&
   a.OriginalFileState!="original-intact"&&
   a.OriginalFileState!="exact-pinned-target-still-present")||
  evidence.LegacySHA256!=a.OriginalSHA256{
  return errors.New("boot original is not recoverable under signed quiescent grant")
 }
 return ctx.Err()
}

// Called ONLY after the same boot-policy mutex has been acquired and the
// policy has decided that its running-original identity check failed.
// Only this mutating stage enforces task/process/DNS53 quiescence.
// The coordinator itself re-checks SYSTEM, publisher, ACL, quiescence, hashes
// and the journal before touching the original EXE or Scheduler action.
// A successful import leaves the journal PENDING until DNS + Internet health.
func(o *residentSignedBootOriginalOps)RestoreOriginal(
 ctx context.Context,intent motorupdate.ResidentRecoveryIntent,
)error{
 if err:=o.VerifySealedOriginal(ctx,intent);err!=nil{return err}
 if err:=recoverSignedLegacyOriginalAndSYSTEMTaskLockedWindows(
  ctx,o.root,o.publisher,o.deps);err!=nil{return err}
 // The exact original EXE and signed SYSTEM task are now restored, but DNS
 // is still stopped. Request one original-only start while the SAME
 // protected kernel lock remains held. Health and the durable receipt are
 // checked by RecoverPendingResidentAfterBoot AFTER this returns.
 return startSignedRestoredOriginalTaskLockedWindows(ctx,o.root,o.publisher,o.deps.Task)
}
