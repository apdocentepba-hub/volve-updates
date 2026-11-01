//go:build windows

package main

// Recovery-only, read-only evidence for an interrupted switch. The legacy
// live executable can be missing, replaced or corrupt after the upgrade.
// Unlike auditPendingResidentChain, this function MUST NOT demand that the
// legacy executable is still installed. It relies on a sealed rollback copy
// AND a separately verified pending recovery intent, read twice.
//
// THIS DOES NOT authorize a Scheduler operation, installation, DNS change,
// or use of any publisher key. A production restore driver must separately
// verify a publisher-signed migration permit, protect exclusive SYSTEM task
// ownership, retain a persistent mutex and re-check the original using
// opened/immutable handles at the actual switch boundary.
import (
 "context"
 "errors"
 "fmt"
 "path/filepath"
)

func auditPostSwitchResidentRecovery(ctx context.Context, root string) (residentChainEvidence,error) {
 var zero residentChainEvidence
 if err:=ctx.Err();err!=nil{return zero,err}
 if !filepath.IsAbs(root)||filepath.Clean(root)!=root{
  return zero,errors.New("recovery root not canonical and absolute")
 }
 // Re-read ACLs, bytes, receipt, canonical single-action SYSTEM XML and
 // SHA-256 of the ORIGINAL recovery copy, never of the replaced active EXE.
 fallback,err:=auditResidentRollback(ctx,root)
 if err!=nil{return zero,fmt.Errorf("original protected fallback untrusted: %w",err)}
 journalDir:=filepath.Join(root,residentRecoveryParent,residentJournalDirName)
 pending,err:=auditResidentJournal(ctx,journalDir)
 if err!=nil{return zero,fmt.Errorf("pending recovery intent untrusted: %w",err)}
 if pending.Status!="recovery-required"{
  return zero,fmt.Errorf("recovery journal is not pending: %s",pending.Status)
 }
 if pending.Intent.LegacySHA256!=fallback.LegacySHA256||
  pending.Intent.TaskXMLSHA256!=fallback.TaskXMLSHA256{
  return zero,errors.New("fallback original differs from recovery intent")
 }
 if err:=ctx.Err();err!=nil{return zero,err}
 // Detect a swapped fallback or journal after the first inspection. This
 // audit never accesses the installed executable or assumes it is intact.
 repeated,err:=auditResidentRollback(ctx,root)
 if err!=nil||repeated!=fallback{
  return zero,errors.New("protected fallback changed during recovery audit")
 }
 latest,err:=auditResidentJournal(ctx,journalDir)
 if err!=nil||latest!=pending{
  return zero,errors.New("recovery intent changed during protected fallback audit")
 }
 return residentChainEvidence{
  LegacySHA256:fallback.LegacySHA256,
  TaskXMLSHA256:fallback.TaskXMLSHA256,
  TargetSHA256:pending.Intent.TargetSHA256,
  TargetVersion:pending.Intent.TargetVersion,
  IntentNonce:pending.Intent.Nonce,
 },nil
}
