//go:build windows

package motorupdate

// Signed DNS-original receipt for a specific pending resident transaction.
// This does not authorize a DNS mutation, start an installer, or arm recovery.
// The public key must be hard-pinned in the independently signed watchdog;
// the private signing key must never be embedded in VOLVE or CI releases.
import (
 "bytes"
 "context"
 "crypto/ed25519"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "path/filepath"
 "reflect"
)

const signedDNSReceiptMaxBytes=4096
const signedDNSReceiptComponent="volve-publisher-dns-original-binding-v1"

type SignedDNSOriginalBinding struct {
 Schema int `json:"schema"`
 Component string `json:"component"`
 IntentNonce string `json:"intent_nonce"`
 LegacyMotorSHA256 string `json:"legacy_motor_sha256"`
 LegacyTaskXMLSHA256 string `json:"legacy_task_xml_sha256"`
 TargetMotorSHA256 string `json:"target_motor_sha256"`
 TargetMotorVersion string `json:"target_motor_version"`
 SignedMigrationPermitSHA256 string `json:"signed_migration_permit_sha256"`
 OriginalDNSJournalSHA256 string `json:"original_dns_journal_sha256"`
}

type SignedDNSOriginalReadOnlyReview struct {
 Schema int `json:"schema"`
 Component string `json:"component"`
 PublisherBindingVerified bool `json:"publisher_binding_verified"`
 MotorAndTaskBindingVerified bool `json:"motor_and_task_binding_verified"`
 OriginalDNSReadbackVerified bool `json:"original_dns_readback_verified"`
 NativeNTFSACLVerified bool `json:"native_ntfs_acl_verified"`
 ProtectedKernelMutexHeld bool `json:"protected_kernel_mutex_held"`
 ReviewedFamilies int `json:"reviewed_families"`
 PerformedDNSWrites bool `json:"performed_dns_writes"`
 InstallAuthorized bool `json:"install_authorized"`
 RestoreAuthorized bool `json:"restore_authorized"`
}

// VerifySignedDNSOriginalBinding authenticates the exact original DNS digest,
// signed migration permit digest and the nonce of the pending motor journal.
// Ed25519 prevents a local hash recomputation from silently authorizing a
// different configuration. An expired migration grant may still be used to
// verify rollback evidence, but never to begin a new migration.
func VerifySignedDNSOriginalBinding(
 ctx context.Context,raw,signature []byte,pub ed25519.PublicKey,
 intent ResidentRecoveryIntent,signedPermitJSON []byte,
)(SignedDNSOriginalBinding,error){
 var denied SignedDNSOriginalBinding
 if ctx==nil{return denied,errors.New("DNS binding context required")}
 if err:=ctx.Err();err!=nil{return denied,err}
 if err:=validResidentIntent(intent);err!=nil{return denied,err}
 if len(pub)!=ed25519.PublicKeySize||len(raw)<2||len(raw)>signedDNSReceiptMaxBytes||
  len(signature)<64||len(signature)>256||len(signedPermitJSON)<2||
  len(signedPermitJSON)>maxMigrationPermitBytes{
  return denied,errors.New("signed DNS receipt or publisher identity missing or excessive")
 }
 decoded,err:=base64.StdEncoding.Strict().DecodeString(string(bytes.TrimSpace(signature)))
 if err!=nil||len(decoded)!=ed25519.SignatureSize||!ed25519.Verify(pub,raw,decoded){
  return denied,errors.New("original DNS journal receipt has invalid publisher signature")
 }
 dec:=json.NewDecoder(bytes.NewReader(raw))
 dec.DisallowUnknownFields()
 var value SignedDNSOriginalBinding
 if err:=dec.Decode(&value);err!=nil{return denied,fmt.Errorf("DNS signed receipt not canonical: %w",err)}
 var extra any
 if err:=dec.Decode(&extra);err!=io.EOF{return denied,errors.New("DNS signed receipt has trailing JSON")}
 canonical,err:=json.Marshal(value)
 if err!=nil||!bytes.Equal(raw,canonical){
  return denied,errors.New("DNS signed receipt encoding duplicated, reordered or altered")
 }
 permitDigest:=sha256.Sum256(signedPermitJSON)
 if value.Schema!=1||value.Component!=signedDNSReceiptComponent||
  value.IntentNonce!=intent.Nonce||
  value.LegacyMotorSHA256!=intent.LegacySHA256||
  value.LegacyTaskXMLSHA256!=intent.TaskXMLSHA256||
  value.TargetMotorSHA256!=intent.TargetSHA256||
  value.TargetMotorVersion!=intent.TargetVersion||
  value.SignedMigrationPermitSHA256!=hex.EncodeToString(permitDigest[:])||
  !residentSHA.MatchString(value.OriginalDNSJournalSHA256){
  return denied,errors.New("signed DNS receipt not bound to exact publisher grant, motor, task, nonce and original DNS")
 }
 if err:=ctx.Err();err!=nil{return denied,err}
 return value,nil
}

// ReviewSignedDNSOriginalBackupNativeWindows combines the existing publisher
// permit (durably stored under strict NTFS), the armed recovery journal, the
// publisher-signed DNS receipt and the independently reread DNS backup under
// the SAME protected native Win32 kernel mutex. Every observation is repeated
// before the lock is released. No DNS writer or Task Scheduler API is called.
// The receipt is an INPUT here, NOT YET a persisted boot-time receipt.
func ReviewSignedDNSOriginalBackupNativeWindows(
 ctx context.Context,root string,pub ed25519.PublicKey,receiptJSON,receiptSignature []byte,
)(SignedDNSOriginalReadOnlyReview,error){
 var denied SignedDNSOriginalReadOnlyReview
 if ctx==nil{return denied,errors.New("missing signed DNS backup review context")}
 if err:=ctx.Err();err!=nil{return denied,err}
 if len(pub)!=ed25519.PublicKeySize{return denied,errors.New("missing pinned publisher key")}
 if !filepath.IsAbs(root)||filepath.Clean(root)!=root{
  return denied,errors.New("untrusted recovery root")
 }
 // Only a privileged Windows process may acquire this protected mutex;
 // this is a read-only reviewer, not proof of a LocalSystem watchdog.
 release,err:=AcquireProtectedResidentTransitionLease(ctx)
 if err!=nil{return denied,err}
 defer release()
 verify:=func(path string)error{return nativeDNSOriginalBackupACL(ctx,path)}
 first,err:=LoadResidentDurablePublisherGrant(ctx,root,pub,verify,verify,verify)
 if err!=nil{return denied,fmt.Errorf("durable publisher recovery grant untrusted: %w",err)}
 pending,err:=InspectResidentRecoveryJournal(ctx,first.JournalDir,verify)
 if err!=nil||pending.Status!="recovery-required"{
  return denied,errors.New("publisher DNS receipt requires an armed pending transaction")
 }
 receipt,err:=VerifySignedDNSOriginalBinding(ctx,receiptJSON,receiptSignature,pub,pending.Intent,first.Permit)
 if err!=nil{return denied,err}
 parent:=filepath.Join(root,"legacy-engine-recovery")
 records,err:=ReadDNSOriginalBackupNativeWindows(ctx,parent,receipt.OriginalDNSJournalSHA256)
 if err!=nil{return denied,fmt.Errorf("protected original DNS backup untrusted: %w",err)}
 if len(records)<2{return denied,errors.New("original DNS backup missing IPv4/IPv6 assignment")}
 // No error or cancelled review may leave a success indicator.
 if err:=ctx.Err();err!=nil{return denied,err}
 again,err:=LoadResidentDurablePublisherGrant(ctx,root,pub,verify,verify,verify)
 if err!=nil||!bytes.Equal(first.Permit,again.Permit)||
  !bytes.Equal(first.Signature,again.Signature)||
  first.BackupDir!=again.BackupDir||first.JournalDir!=again.JournalDir{
  return denied,errors.New("publisher grant changed during protected DNS backup verification")
 }
 pendingAgain,err:=InspectResidentRecoveryJournal(ctx,first.JournalDir,verify)
 if err!=nil||pendingAgain!=pending{
  return denied,errors.New("pending motor journal changed during DNS backup review")
 }
 reloaded,err:=ReadDNSOriginalBackupNativeWindows(ctx,parent,receipt.OriginalDNSJournalSHA256)
 if err!=nil||!reflect.DeepEqual(records,reloaded){
  return denied,errors.New("original DNS backup changed during protected signed review")
 }
 if err:=ctx.Err();err!=nil{return denied,err}
 return SignedDNSOriginalReadOnlyReview{
  Schema:1,Component:"volve-signed-dns-original-backup-review-only",
  PublisherBindingVerified:true,MotorAndTaskBindingVerified:true,
  OriginalDNSReadbackVerified:true,NativeNTFSACLVerified:true,
  ProtectedKernelMutexHeld:true,ReviewedFamilies:len(records),
  PerformedDNSWrites:false,InstallAuthorized:false,RestoreAuthorized:false,
 },nil
}
