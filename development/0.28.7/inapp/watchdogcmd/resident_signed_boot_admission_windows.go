//go:build windows

package main

// Publisher-signed admission gate for a protected boot recovery intent.
// NO TASK, MOTOR, DNS, JOURNAL OR NTFS MUTATION occurs in this module.
// It can only certify the evidence needed before a future independent
// SYSTEM restoration driver is allowed to be written or wired into startup.
import (
 "context"
 "crypto/ed25519"
 "encoding/base64"
 "errors"
 "fmt"
 "path/filepath"

 "volve-browser-protection/motorupdate"
)

type residentSignedBootAdmission struct {
 Status string
 Action string
 OriginalSHA256 string
 PublisherVerified bool
}

// auditResidentSignedBootAdmission takes the SAME OS-wide mutex as a future
// privileged migration and the independent boot watchdog. Incomplete and
// tampered transactions fail closed. A terminal journal requires no publisher
// grant because it cannot initiate a second recovery.
func auditResidentSignedBootAdmission(
 ctx context.Context,root string,key ed25519.PublicKey,
 protectGrant,protectJournal,protectBackup func(string)error,
)(residentSignedBootAdmission,error){
 var zero residentSignedBootAdmission
 if err:=ctx.Err();err!=nil{return zero,err}
 if !filepath.IsAbs(root)||filepath.Clean(root)!=root||
  len(key)!=ed25519.PublicKeySize||
  protectGrant==nil||protectJournal==nil||protectBackup==nil{
  return zero,errors.New("signed boot audit requires canonical root, pinned editorial key and Windows ACL checks")
 }
 release,err:=motorupdate.AcquireProtectedResidentTransitionLease(ctx)
 if err!=nil{return zero,fmt.Errorf("protected boot mutex denied: %w",err)}
 if release==nil{return zero,errors.New("protected boot mutex has no release callback")}
 defer release()
 if err:=ctx.Err();err!=nil{return zero,err}
 before,err:=auditResidentBootPlan(ctx,root)
 if err!=nil{return zero,fmt.Errorf("boot journal/backup invalid: %w",err)}
 if before.Action=="no-action"{
  // This is NOT an affirmative publisher verification. No grant is needed
  // to avoid restoration of an already committed or restored transaction.
  return residentSignedBootAdmission{
   Status:before.Status,Action:"no-action",OriginalSHA256:before.LegacySHA256,
  },nil
 }
 if before.Status!="recovery-required"||before.Action!="recover-original"{
  return zero,errors.New("unknown pending recovery decision")
 }
 // Only a canonical sibling of the journal and sealed backup is accepted.
 // Load checks strict SYSTEM/Admin NTFS ACL on every ancestor and file,
 // authenticates Ed25519 and binds both exact SHA-256 identities and nonce.
 grant,err:=motorupdate.LoadResidentDurablePublisherGrant(
  ctx,root,key,protectGrant,protectJournal,protectBackup)
 if err!=nil{return zero,fmt.Errorf("pending rollback has no trusted publisher authorization: %w",err)}
 state,err:=motorupdate.InspectResidentRecoveryJournal(ctx,grant.JournalDir,protectJournal)
 if err!=nil||state.Status!="recovery-required"||
  state.Intent.LegacySHA256!=before.LegacySHA256{
  return zero,errors.New("signed recovery grant and boot plan disagree")
 }
 // The OS-wide lease prevents our cooperating updater from changing state.
 // Re-read the backup and journal after expensive grant signature checks.
 after,err:=auditResidentBootPlan(ctx,root)
 if err!=nil||after!=before{
  return zero,errors.New("protected boot intent changed during editorial admission audit")
 }
 if err:=ctx.Err();err!=nil{return zero,err}
 return residentSignedBootAdmission{
  Status:"recovery-required",
  Action:"signed-evidence-verified-read-only",
  OriginalSHA256:before.LegacySHA256,
  PublisherVerified:true,
 },nil
}

// This is the only production-identity wrapper. No key is accepted from the
// CLI, filesystem, network, or journal: it is pinned inside the signed binary.
func auditResidentSignedBootAdmissionWithPinnedPublisher(ctx context.Context,root string)(
 residentSignedBootAdmission,error,
){
 const pinnedPublicKeyB64="6pa2qoWNv+J7u0ulDXvqlBd7qEeDzPBdxmU6NpqTGHk="
 key,err:=base64.StdEncoding.DecodeString(pinnedPublicKeyB64)
 if err!=nil{return residentSignedBootAdmission{},err}
 acl:=func(p string)error{return checkResidentJournalNTFS(ctx,p)}
 return auditResidentSignedBootAdmission(ctx,root,ed25519.PublicKey(key),acl,acl,acl)
}
