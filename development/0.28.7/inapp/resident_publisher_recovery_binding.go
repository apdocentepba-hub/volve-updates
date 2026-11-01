package motorupdate

// Publisher-bound authorization for an INDEPENDENT recovery of an already
// armed, protected Windows DNS-engine transition. It NEVER starts an update,
// modifies DNS, writes any files or changes a Scheduled Task.
//
// A hash in a local recovery journal is not a signature. Verify this binding
// again after a crash and BEFORE a SYSTEM watchdog is permitted to restore
// the sealed old executable and task. This verification permits an expired
// publisher grant ONLY for reversal of an existing pending transaction.
import (
 "context"
 "crypto/ed25519"
 "errors"
 "fmt"
 "path/filepath"
)

// VerifyResidentPublisherRecoveryBinding authenticates the exact signed
// publisher bridge against the protected pending journal AND independently
// verified original backup bytes. All three identities must agree.
//
// The publisher public key must be pinned by the installed program, not
// supplied by a remote manifest or recovered journal. The caller must hold
// the protected Windows kernel transition lock for the entire transaction,
// ensure the journal and backup were created under strict SYSTEM/Admin ACLs,
// and verify the live SYSTEM task before changing it.
//
// The returned permit is recovery evidence only and CANNOT be used to start
// a new migration. New updates must use VerifySignedUnversionedLegacyMigration,
// which does not accept expired authorizations.
func VerifyResidentPublisherRecoveryBinding(
 ctx context.Context, journalDir,backupDir string,
 permitJSON,permitSignature []byte,publisherKey ed25519.PublicKey,
 protectJournal,protectBackup func(string)error,
)(LegacyMigrationPermit,error){
 var zero LegacyMigrationPermit
 if err:=ctx.Err();err!=nil{return zero,err}
 if protectJournal==nil||protectBackup==nil{
  return zero,errors.New("independent recovery needs protected journal and original ACL verifiers")
 }
 if !filepath.IsAbs(journalDir)||!filepath.IsAbs(backupDir) {
  return zero,errors.New("resident recovery journal/backup locations must be absolute")
 }
 // Reject a wrong directory even if its contents contain apparently valid
 // hashes. The original bundle must be a sibling of the protected journal.
 parent:=filepath.Dir(journalDir)
 if filepath.Base(journalDir)!="motor-recovery-transaction" ||
  filepath.Base(backupDir)!="original-before-upgrade" ||
  filepath.Base(parent)!="legacy-engine-recovery" ||
  filepath.Clean(filepath.Dir(backupDir))!=filepath.Clean(parent) {
  return zero,errors.New("publisher recovery journal/backup directories are not siblings under the expected protected root")
 }
 // An ordinary signed migration permit parser rejects expired grants, which
 // would deadlock crash recovery after a long outage. This recovery-only
 // parser still rejects forged signatures, unknown task names, future-dated
 // issuances and unbounded permit lifetimes.
 permit,err:=parseSignedMigrationPermitAtRecovery(permitJSON,permitSignature,publisherKey,true)
 if err!=nil{return zero,fmt.Errorf("publisher recovery permit refused: %w",err)}
 if cmp,err:=compareVersions(permit.ToVersion,"0.28.7");err!=nil||cmp<0{
  return zero,errors.New("recovery permit targets unsupported old updater generation")
 }
 state,err:=InspectResidentRecoveryJournal(ctx,journalDir,protectJournal)
 if err!=nil{return zero,fmt.Errorf("pending protected recovery journal refused: %w",err)}
 if state.Status!="recovery-required"{
  return zero,fmt.Errorf("publisher recovery authorization only valid for pending transaction, got %s",state.Status)
 }
 sealed,err:=VerifyUnversionedLegacyRecovery(backupDir,protectBackup)
 if err!=nil{return zero,fmt.Errorf("protected original cannot be verified: %w",err)}
 if state.Intent.Task!=permit.FromTask||
  state.Intent.LegacySHA256!=permit.FromSHA256||
  state.Intent.TaskXMLSHA256!=permit.FromTaskXMLSHA256||
  state.Intent.TargetSHA256!=permit.ToSHA256||
  state.Intent.TargetVersion!=permit.ToVersion||
  sealed.OriginalTask!=permit.FromTask||
  sealed.OriginalArgs!=permit.FromArgs||
  sealed.OriginalName!=permit.FromExecutable||
  sealed.ExeSHA256!=permit.FromSHA256||
  sealed.ExeSize!=permit.FromSize||
  sealed.XMLSHA256!=permit.FromTaskXMLSHA256 {
  return zero,errors.New("publisher signature, protected original, and pending recovery intent do not match exactly")
 }
 // Avoid trusting snapshots taken at disjoint times after expensive hashing.
 // Both protected objects must be unchanged at the final authorization
 // boundary, while the caller keeps the single production OS-wide mutex.
 if err:=ctx.Err();err!=nil{return zero,err}
 journalAgain,err:=InspectResidentRecoveryJournal(ctx,journalDir,protectJournal)
 if err!=nil||journalAgain!=state{
  return zero,errors.New("pending recovery journal changed during signed verification")
 }
 snapshotAgain,err:=VerifyUnversionedLegacyRecovery(backupDir,protectBackup)
 if err!=nil||snapshotAgain!=sealed{
  return zero,errors.New("sealed original changed during signed recovery authorization")
 }
 return permit,nil
}
