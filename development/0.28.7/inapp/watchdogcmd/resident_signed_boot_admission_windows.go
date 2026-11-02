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
 "os"
 "path/filepath"

 "volve-browser-protection/motorupdate"
)

type residentSignedBootAdmission struct {
 Status string
 Action string
 OriginalSHA256 string
 OriginalFileState string
 PublisherVerified bool
 QuiescenceVerified bool
}

// classifyResidentOriginalFile is a READ-ONLY restoration input, not
// permission to overwrite an executable. An unrecognized or linked file is
// a hard stop, even when the signed journal and original backup are valid.
// The future SYSTEM restorer must separately prove the exact live task,
// process identity and that no candidate still owns port 53.
func classifyResidentOriginalFile(ctx context.Context,root string,
 intent motorupdate.ResidentRecoveryIntent)(string,error){
 if err:=ctx.Err();err!=nil{return "",err}
 if !filepath.IsAbs(root)||filepath.Clean(root)!=root{
  return "",errors.New("installed motor root not canonical")
 }
 if intent.LegacySHA256==""||intent.TargetSHA256==""||
  intent.LegacySHA256==intent.TargetSHA256{
  return "",errors.New("original and candidate must have distinct signed identities")
 }
 path:=filepath.Join(root,residentLegacyExe)
 info,err:=os.Lstat(path)
 if errors.Is(err,os.ErrNotExist){return "missing-original",nil}
 if err!=nil{return "",fmt.Errorf("installed motor cannot be observed: %w",err)}
 if !info.Mode().IsRegular()||info.Mode()&os.ModeSymlink!=0||
  info.Size()<1||info.Size()>chainLegacyMax{
  return "",errors.New("installed motor is a link or an unsupported file")
 }
 hash,err:=digestResidentLive(ctx,path)
 if err!=nil{return "",err}
 switch hash{
 case intent.LegacySHA256:return "original-intact",nil
 case intent.TargetSHA256:return "exact-pinned-target-still-present",nil
 default:return "",errors.New("unknown installed motor hash: refuse autonomous rollback")
 }
}

// auditResidentSignedBootAdmission takes the SAME OS-wide mutex as a future
// privileged migration and the independent boot watchdog. Incomplete and
// tampered transactions fail closed. A terminal journal requires no publisher
// grant because it cannot initiate a second recovery.
func auditResidentSignedBootAdmission(
 ctx context.Context,root string,key ed25519.PublicKey,
 protectGrant,protectJournal,protectBackup func(string)error,
)(residentSignedBootAdmission,error){
 return auditResidentSignedBootAdmissionWithQuiescenceProbe(ctx,root,key,
  protectGrant,protectJournal,protectBackup,nil)
}

// The OS-wide mutex stays owned across publisher/backup verification, both
// on-disk executable hashes AND the live SYSTEM task/process/port53 fence.
// No authority to mutate the installation is returned by this read-only gate.
func auditResidentSignedBootAdmissionWithQuiescenceProbe(
 ctx context.Context,root string,key ed25519.PublicKey,
 protectGrant,protectJournal,protectBackup func(string)error,
 probe func(context.Context,string)(residentQuiescenceDecision,error),
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
 return auditResidentSignedBootAdmissionLocked(ctx,root,key,
  protectGrant,protectJournal,protectBackup,probe)
}

// Never call this without holding the original shared protected kernel mutex.
// It exists so a future resident restorer can keep SAME mutex across signed
// authorization, live process/DNS check and one bounded recovery mutation.
// It must NOT itself acquire that non-reentrant mutex again.
func auditResidentSignedBootAdmissionLocked(
 ctx context.Context,root string,key ed25519.PublicKey,
 protectGrant,protectJournal,protectBackup func(string)error,
 probe func(context.Context,string)(residentQuiescenceDecision,error),
)(residentSignedBootAdmission,error){
 var zero residentSignedBootAdmission
 if err:=ctx.Err();err!=nil{return zero,err}
 if !filepath.IsAbs(root)||filepath.Clean(root)!=root||
  len(key)!=ed25519.PublicKeySize||
  protectGrant==nil||protectJournal==nil||protectBackup==nil{
  return zero,errors.New("locked signed audit requires canonical root, key and trusted ACL checks")
 }
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
 // A signed permission never authorizes overwriting an arbitrary executable.
 // Distinguish a missing old image, an already restored old image and only the
 // exact signed candidate hash. The future live task/process still needs a
 // separate independent SYSTEM gate before any recovery mutation.
 originalState,err:=classifyResidentOriginalFile(ctx,root,state.Intent)
 if err!=nil{return zero,fmt.Errorf("installed old motor identity unsafe: %w",err)}
 // The OS-wide lease prevents our cooperating updater from changing state.
 // Re-read the backup and journal after expensive grant signature checks.
 after,err:=auditResidentBootPlan(ctx,root)
 if err!=nil||after!=before{
  return zero,errors.New("protected boot intent changed during editorial admission audit")
 }
 secondState,err:=classifyResidentOriginalFile(ctx,root,state.Intent)
 if err!=nil||secondState!=originalState {
  return zero,errors.New("installed motor changed during signed recovery decision")
 }
 // A future production recovery cannot be admitted if the exact scheduled
 // task is unknown or a motor/port53 socket remains active. Keep this
 // proof inside the SAME global mutex as the signed grant and file checks.
 quiescenceVerified:=false
 if probe!=nil {
  observation,probeErr:=probe(ctx,root)
  if probeErr!=nil||!observation.ReadyForFurtherChecks||
   !observation.TaskIdentityVerified||!observation.DNSPortFree||
   !observation.MotorProcessesStopped{
   return zero,fmt.Errorf("Windows SYSTEM motor is not quiescent for signed rollback: %v",probeErr)
  }
  // A probe is only an observation. The future mutator MUST keep owning the
  // mutex, disable the exact task and recheck live process/sockets again.
  quiescenceVerified=true
 }
 if err:=ctx.Err();err!=nil{return zero,err}
 return residentSignedBootAdmission{
  Status:"recovery-required",
  Action:"signed-evidence-verified-read-only",
  OriginalSHA256:before.LegacySHA256,
  OriginalFileState:originalState,
  PublisherVerified:true,
  QuiescenceVerified:quiescenceVerified,
 },nil
}

const pinnedPublicKeyB64="6pa2qoWNv+J7u0ulDXvqlBd7qEeDzPBdxmU6NpqTGHk="

// This is the only production-identity wrapper. No key is accepted from the
// CLI, filesystem, network, or journal: it is pinned inside the signed binary.
func auditResidentSignedBootAdmissionWithPinnedPublisher(ctx context.Context,root string)(
 residentSignedBootAdmission,error,
){
 key,err:=base64.StdEncoding.DecodeString(pinnedPublicKeyB64)
 if err!=nil{return residentSignedBootAdmission{},err}
 acl:=func(p string)error{return checkResidentJournalNTFS(ctx,p)}
 return auditResidentSignedBootAdmission(ctx,root,ed25519.PublicKey(key),acl,acl,acl)
}

 
// This second read-only entrypoint checks a REAL Windows scheduled SYSTEM
// task, local motor processes and port53 ownership under the protected lease.
// It does not start a service or publish a recovery receipt.
func auditResidentSignedBootAdmissionWithPinnedPublisherAndQuiescence(
 ctx context.Context,root string,
)(residentSignedBootAdmission,error){
 key,err:=base64.StdEncoding.DecodeString(pinnedPublicKeyB64)
 if err!=nil{return residentSignedBootAdmission{},err}
 acl:=func(p string)error{return checkResidentJournalNTFS(ctx,p)}
 return auditResidentSignedBootAdmissionWithQuiescenceProbe(ctx,root,ed25519.PublicKey(key),
  acl,acl,acl,auditResidentQuiescenceReadOnly)
}
