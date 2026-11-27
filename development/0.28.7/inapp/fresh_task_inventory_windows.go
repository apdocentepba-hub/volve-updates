//go:build windows

package motorupdate

// Windows Task Scheduler read-only inventory for distinguishing a NEW motor
// installation from an upgrade of an existing protected DNS engine.
// This source NEVER registers, changes, runs or deletes a task or DNS setting.
// It is only ONE input to the full fresh-install readiness policy.
import (
 "bytes"
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "os/exec"
 "path/filepath"
 "reflect"
 "strings"
)

// This is a fixed internal query. Never interpolate candidate file paths,
// names or UI input into a privileged PowerShell script.
const WindowsVOLVETaskInventoryQuery = `$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';
$items=@(Get-ScheduledTask -ErrorAction Stop | Where-Object {
 # A renamed task could still launch an old VOLVE motor. Name-only
 # filtering must never classify that installation as "motor absent".
 $named=([string]$_.TaskName -match '(?i)^VOLVE(?:-|_|$)');
 $linked=@($_.Actions | Where-Object {
   ([string]$_.Execute -match '(?i)[\\/]VOLVE(?:[\\/]|[_.-]|[0-9]|$)') -or
   ([string]$_.Arguments -match '(?i)[\\/]VOLVE(?:[\\/]|[_.-]|[0-9]|$)')
 });
 $named -or $linked.Count -gt 0
} | ForEach-Object {
 $task=$_;$action=@($task.Actions | ForEach-Object {
   [pscustomobject]@{Execute=[string]$_.Execute;Arguments=[string]$_.Arguments;WorkingDirectory=[string]$_.WorkingDirectory}
 });
 $xml=Export-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop;
 $hasher=[Security.Cryptography.SHA256]::Create();
 try{$hash=[BitConverter]::ToString($hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($xml))).Replace('-','').ToLowerInvariant()}
 finally{$hasher.Dispose()}
 [pscustomobject]@{Name=[string]$task.TaskName;TaskPath=[string]$task.TaskPath;Principal=[string]$task.Principal.UserId;Actions=@($action);DefinitionSHA256=$hash}
});ConvertTo-Json -InputObject $items -Compress -Depth 7`

type WindowsFreshTaskInspect func(context.Context,string)([]byte,error)

func DefaultWindowsFreshTaskInspect(ctx context.Context,query string)([]byte,error){
 if query!=WindowsVOLVETaskInventoryQuery{return nil,errors.New("only fixed read-only VOLVE task inventory allowed")}
 if err:=ctx.Err();err!=nil{return nil,err}
 root:=os.Getenv("SystemRoot")
 if !filepath.IsAbs(root){return nil,errors.New("Windows system root unavailable")}
 ps:=filepath.Join(root,"System32","WindowsPowerShell","v1.0","powershell.exe")
 out,err:=exec.CommandContext(ctx,ps,"-NoLogo","-NoProfile","-NonInteractive","-Command",query).Output()
 if err!=nil{return nil,fmt.Errorf("Windows VOLVE task inventory unavailable: %w",err)}
 return out,nil
}

type windowsVOLVETaskAction struct {
 Execute string `json:"Execute"`
 Arguments string `json:"Arguments"`
 WorkingDirectory *string `json:"WorkingDirectory"`
}
type windowsVOLVETaskRecord struct {
 Name string `json:"Name"`
 TaskPath string `json:"TaskPath"`
 Principal string `json:"Principal"`
 Actions []windowsVOLVETaskAction `json:"Actions"`
 DefinitionSHA256 string `json:"DefinitionSHA256"`
}

type WindowsFreshVOLVETaskInventory struct {
 VOLVETaskCount int
 VerifiedCatalogTask *VerifiedFreshCatalogTask
 // Unknowns cannot be treated as a valid fresh motor installation.
 UnknownTaskNames []string
}

// InspectWindowsVOLVETasksReadOnly accepts an explicitly pinned expected
// auxiliary task executable + argv from a trusted installed manifest.
// Until those exact bytes are known, the task can be observed, but never
// classified as a VERIFIED catalog task by matching a guessed path.
// This is NOT an authorization to install or change a DNS server.
func InspectWindowsVOLVETasksReadOnly(ctx context.Context,
 expectedCatalogExecutable,expectedCatalogArguments string,
 inspect WindowsFreshTaskInspect,
)(WindowsFreshVOLVETaskInventory,error){
 var zero WindowsFreshVOLVETaskInventory
 if err:=ctx.Err();err!=nil{return zero,err}
 if inspect==nil{return zero,errors.New("missing independent Windows task inspector")}
 if expectedCatalogExecutable!="" && (!filepath.IsAbs(expectedCatalogExecutable)||
   filepath.Clean(expectedCatalogExecutable)!=expectedCatalogExecutable){
  return zero,errors.New("expected catalog executable must be a canonical absolute path")
 }
 raw,err:=inspect(ctx,WindowsVOLVETaskInventoryQuery)
 if err!=nil{return zero,err}
 if len(raw)<2 || len(raw)>1<<20{return zero,errors.New("VOLVE task inventory absent or oversized")}
 decoder:=json.NewDecoder(bytes.NewReader(raw))
 decoder.DisallowUnknownFields()
 var records []windowsVOLVETaskRecord
 if err:=decoder.Decode(&records);err!=nil{return zero,fmt.Errorf("invalid Windows task inventory: %w",err)}
 var trailing any
 if err:=decoder.Decode(&trailing);err!=io.EOF{return zero,errors.New("trailing or invalid Windows task inventory")}
 if records==nil || len(records)>64{return zero,errors.New("missing/overlarge Windows VOLVE task inventory")}
 result:=WindowsFreshVOLVETaskInventory{VOLVETaskCount:len(records)}
 seen:=map[string]bool{}
 for _,task:=range records{
  if task.Name=="" || !strings.HasPrefix(strings.ToUpper(task.Name),"VOLVE") ||
   task.TaskPath=="" || !freshTaskSHA256.MatchString(task.DefinitionSHA256) {
   return zero,errors.New("incomplete/unrecognized VOLVE task evidence")
  }
  key:=strings.ToLower(task.TaskPath+"\x00"+task.Name)
  if seen[key]{return zero,errors.New("duplicate Windows VOLVE task identity")}
  seen[key]=true
  if task.Name!="VOLVE-CATALOGO-0230" || task.TaskPath!="\\"{
   result.UnknownTaskNames=append(result.UnknownTaskNames,task.TaskPath+task.Name)
   continue
  }
  verified:=&VerifiedFreshCatalogTask{
   Name:task.Name,TaskPath:task.TaskPath,ActionCount:len(task.Actions),
   DefinitionSHA256:task.DefinitionSHA256,
   PrincipalVerified:task.Principal=="SYSTEM"||task.Principal=="S-1-5-18",
  }
  if len(task.Actions)==1 && expectedCatalogExecutable!="" {
   act:=task.Actions[0]
   verified.ActionVerified=strings.EqualFold(filepath.Clean(act.Execute),expectedCatalogExecutable) &&
    filepath.IsAbs(act.Execute) && act.Arguments==expectedCatalogArguments &&
    act.WorkingDirectory!=nil && *act.WorkingDirectory=="" // Missing or unpinned working dir must fail closed.
  }
  result.VerifiedCatalogTask=verified
 }
 return result,nil
}

// Read-only capture of the exact fixed catalog task definition. The original
// trusted census must already have verified its action and identity. No task
// is registered, executed, repaired or removed by this module.
const catalogOriginalXMLLimit=1<<20
const catalogOriginalCaptureQuery=`$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';
$tasks=@(Get-ScheduledTask -ErrorAction Stop | Where-Object {$_.TaskName -ceq 'VOLVE-CATALOGO-0230' -and $_.TaskPath -ceq '\'});
if($tasks.Count -gt 1){throw 'Ambiguous catalog task'};
if($tasks.Count -eq 0){
 [pscustomobject]@{Present=$false;PayloadBase64=''} | ConvertTo-Json -Compress
}else{
 $xml=Export-ScheduledTask -TaskName 'VOLVE-CATALOGO-0230' -TaskPath '\' -ErrorAction Stop;
 $bytes=[Text.Encoding]::UTF8.GetBytes($xml);
 if($bytes.Length -lt 1 -or $bytes.Length -gt 1048576){throw 'Catalog definition size invalid'};
 [pscustomobject]@{Present=$true;PayloadBase64=[Convert]::ToBase64String($bytes)} | ConvertTo-Json -Compress
}`

type originalCatalogDefinition struct{
 Present bool
 // Private XML, never exported to diagnostic JSON.
 XML []byte `json:"-"`
}

func readOriginalCatalogDefinitionLocal(ctx context.Context)([]byte,error){
 if ctx==nil{return nil,errors.New("catalog capture context required")}
 if err:=ctx.Err();err!=nil{return nil,err}
 root:=os.Getenv("SystemRoot")
 if !filepath.IsAbs(root)||strings.HasPrefix(root,`\\`){return nil,errors.New("local Windows SystemRoot unavailable")}
 ps:=filepath.Join(root,"System32","WindowsPowerShell","v1.0","powershell.exe")
 raw,err:=exec.CommandContext(ctx,ps,"-NoLogo","-NoProfile","-NonInteractive","-Command",catalogOriginalCaptureQuery).Output()
 if err!=nil{return nil,errors.New("local catalog definition capture failed")}
 return raw,nil
}

func captureOriginalCatalogDefinition(ctx context.Context,baseline ProtectionSnapshot,
 taskInventory WindowsFreshVOLVETaskInventory,reader func(context.Context)([]byte,error))(originalCatalogDefinition,error){
 var denied originalCatalogDefinition
 if ctx==nil||reader==nil{return denied,errors.New("catalog backup requires context and local reader")}
 if err:=ctx.Err();err!=nil{return denied,err}
 if !validProtectionSnapshot(baseline)||len(taskInventory.UnknownTaskNames)!=0{return denied,errors.New("independent original task census required")}
 absentHash:=sha256.Sum256([]byte(catalogTaskAbsentMarker))
 absent:=hex.EncodeToString(absentHash[:])
 expectedPresent:=false
 switch{
 case taskInventory.VOLVETaskCount==0&&taskInventory.VerifiedCatalogTask==nil:
  if !strings.EqualFold(baseline.CatalogTaskDefinitionSHA256,absent){return denied,errors.New("catalog absence differs from original census")}
 case taskInventory.VOLVETaskCount==1&&allowedFreshAuxiliaryTask(taskInventory.VerifiedCatalogTask):
  expectedPresent=true
  if strings.EqualFold(baseline.CatalogTaskDefinitionSHA256,absent)||!strings.EqualFold(baseline.CatalogTaskDefinitionSHA256,taskInventory.VerifiedCatalogTask.DefinitionSHA256){return denied,errors.New("catalog task differs from original census")}
 default:return denied,errors.New("catalog task identity or action unverified")
 }
 raw,err:=reader(ctx)
 if err!=nil||len(raw)<2||len(raw)>2*catalogOriginalXMLLimit{return denied,errors.New("local catalog capture unavailable")}
 dec:=json.NewDecoder(bytes.NewReader(raw));dec.DisallowUnknownFields()
 var row struct{Present *bool;PayloadBase64 *string}
 if err:=dec.Decode(&row);err!=nil||row.Present==nil||row.PayloadBase64==nil{return denied,errors.New("catalog capture evidence incomplete")}
 var trailing any
 if err:=dec.Decode(&trailing);err!=io.EOF||*row.Present!=expectedPresent{return denied,errors.New("catalog presence changed after original census")}
 if !expectedPresent{
  if *row.PayloadBase64!=""{return denied,errors.New("absent catalog supplied unexpected bytes")}
  if err:=ctx.Err();err!=nil{return denied,err}
  return originalCatalogDefinition{Present:false},nil
 }
 payload,err:=base64.StdEncoding.Strict().DecodeString(*row.PayloadBase64)
 if err!=nil||len(payload)==0||len(payload)>catalogOriginalXMLLimit{return denied,errors.New("invalid local catalog bytes")}
 sum:=sha256.Sum256(payload)
 if !strings.EqualFold(hex.EncodeToString(sum[:]),baseline.CatalogTaskDefinitionSHA256){return denied,errors.New("catalog definition changed since original census")}
 if err:=ctx.Err();err!=nil{return denied,err}
 return originalCatalogDefinition{Present:true,XML:payload},nil
}

// Local catalog definition archive. The bytes are solely for preserving the
// pre-install state; this module cannot register or start a task. Existing
// archives are never overwritten. Administrators retain repair access.
const catalogOriginalArchiveDir="catalog-original-backup-v1"
const catalogOriginalArchiveFile="original-catalog-definition.json"

func catalogOriginalArchivePaths(parent string)(string,string,error){
 if !filepath.IsAbs(parent)||filepath.Clean(parent)!=parent||
  filepath.Base(parent)!="original-protection-recovery"||strings.HasPrefix(parent,`\\`){
  return "","",errors.New("dedicated local recovery directory required")
 }
 dir:=filepath.Join(parent,catalogOriginalArchiveDir)
 return dir,filepath.Join(dir,catalogOriginalArchiveFile),nil
}

func storeOriginalCatalogArchiveUnarmed(ctx context.Context,parent string,baseline ProtectionSnapshot,
 inventory WindowsFreshVOLVETaskInventory,original originalCatalogDefinition,seal,check func(string)error)error{
 if ctx==nil||seal==nil||check==nil{return errors.New("catalog archive requires context and ACL callbacks")}
 if err:=ctx.Err();err!=nil{return err}
 if len(original.XML)>catalogOriginalXMLLimit{return errors.New("catalog definition exceeds size bound")}
 raw,err:=json.Marshal(struct{Present bool;PayloadBase64 string}{original.Present,base64.StdEncoding.EncodeToString(original.XML)})
 if err!=nil{return errors.New("catalog archive encoding failed")}
 if _,err:=captureOriginalCatalogDefinition(ctx,baseline,inventory,func(context.Context)([]byte,error){return raw,nil});err!=nil{return err}
 dir,file,err:=catalogOriginalArchivePaths(parent);if err!=nil{return err}
 if err:=verifyOriginalHostsBackupNode(parent,true,check);err!=nil{return err}
 if err:=os.Mkdir(dir,0700);err!=nil{return errors.New("catalog archive stage must be new")}
 if err:=seal(dir);err!=nil{return err}
 if err:=verifyOriginalHostsBackupNode(dir,true,check);err!=nil{return err}
 if err:=verifyOriginalHostsBackupNode(parent,true,check);err!=nil{return err}
 if err:=ctx.Err();err!=nil{return err}
 f,err:=os.OpenFile(file,os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600)
 if err!=nil{return err}
 n,writeErr:=f.Write(raw)
 if writeErr==nil&&n!=len(raw){writeErr=io.ErrShortWrite}
 if writeErr==nil{writeErr=f.Sync()}
 closeErr:=f.Close()
 if writeErr!=nil{return writeErr}
 if closeErr!=nil{return closeErr}
 if err:=seal(file);err!=nil{return err}
 _,err=readOriginalCatalogArchiveUnarmed(ctx,parent,baseline,inventory,check)
 return err
}

func readOriginalCatalogArchiveUnarmed(ctx context.Context,parent string,baseline ProtectionSnapshot,
 inventory WindowsFreshVOLVETaskInventory,check func(string)error)(originalCatalogDefinition,error){
 var denied originalCatalogDefinition
 if ctx==nil||check==nil{return denied,errors.New("catalog archive requires context and ACL verifier")}
 if err:=ctx.Err();err!=nil{return denied,err}
 dir,file,err:=catalogOriginalArchivePaths(parent);if err!=nil{return denied,err}
 verify:=func()error{
  if err:=verifyOriginalHostsBackupNode(parent,true,check);err!=nil{return err}
  if err:=verifyOriginalHostsBackupNode(dir,true,check);err!=nil{return err}
  if err:=verifyOriginalHostsBackupNode(file,false,check);err!=nil{return err}
  nodes,err:=os.ReadDir(dir)
  if err!=nil{return err}
  if len(nodes)!=1||nodes[0].Name()!=catalogOriginalArchiveFile{return errors.New("unexpected catalog archive contents")}
  return nil
 }
 if err:=verify();err!=nil{return denied,err}
 before,err:=os.Lstat(file);if err!=nil{return denied,err}
 if !before.Mode().IsRegular()||before.Size()<2||before.Size()>2*catalogOriginalXMLLimit{return denied,errors.New("catalog archive size or type invalid")}
 f,err:=os.Open(file);if err!=nil{return denied,err}
 opened,err:=f.Stat()
 if err!=nil||!os.SameFile(before,opened){f.Close();return denied,errors.New("catalog archive replaced before read")}
 raw,readErr:=io.ReadAll(io.LimitReader(f,2*catalogOriginalXMLLimit+1))
 end,statErr:=f.Stat()
 closeErr:=f.Close()
 if readErr!=nil||statErr!=nil||closeErr!=nil{return denied,errors.New("catalog archive read failed")}
 after,err:=os.Lstat(file);if err!=nil{return denied,err}
 if !after.Mode().IsRegular()||!os.SameFile(before,after)||!os.SameFile(opened,end)||
  before.Size()!=end.Size()||before.Size()!=after.Size()||before.Size()!=int64(len(raw))||
  !before.ModTime().Equal(end.ModTime())||!before.ModTime().Equal(after.ModTime()){
  return denied,errors.New("catalog archive changed during read")
 }
 if err:=verify();err!=nil{return denied,err}
 return captureOriginalCatalogDefinition(ctx,baseline,inventory,func(context.Context)([]byte,error){return raw,nil})
}

// Verifies all four original backup components, within the scope of the
// existing census. This is strictly a read-only review, NOT proof of full
// browser coverage, atomicity, restoration, or installation authorization.
// A separately authenticated transaction controller must establish those
// prerequisites. No private payload is included in the receipt.
func verifyOriginalProtectionArchivesUnarmed(ctx context.Context,protectionParent,dnsParent string,
 baseline ProtectionSnapshot,browser WindowsBrowserPolicyEvidence,inventory WindowsFreshVOLVETaskInventory,
 dnsJournalPin string,check func(string)error)(originalProtectionPairReceipt,error){
 var denied originalProtectionPairReceipt
 if ctx==nil||check==nil{return denied,errors.New("archive review requires context and ACL verifier")}
 if err:=ctx.Err();err!=nil{return denied,err}
 receipt,err:=verifyOriginalProtectionTripleUnarmed(ctx,protectionParent,dnsParent,baseline,browser,dnsJournalPin,check)
 if err!=nil{return denied,err}
 if _,err:=readOriginalCatalogArchiveUnarmed(ctx,protectionParent,baseline,inventory,check);err!=nil{
  return denied,errors.New("original catalog archive not verified")
 }
 // Recheck the prior three archives after catalog I/O. This catches drift
 // during the sequential review; it does NOT establish atomicity or grant
 // permission to restore. The future controller still needs its own lock.
 again,err:=verifyOriginalProtectionTripleUnarmed(ctx,protectionParent,dnsParent,baseline,browser,dnsJournalPin,check)
 if err!=nil||again!=receipt{return denied,errors.New("original protection archives changed during catalog review")}
 if err:=ctx.Err();err!=nil{return denied,err}
 receipt.CatalogBackupVerified=true
 return receipt,nil
}

// WindowsOriginalBackupReview is a display-only result. It contains no paths,
// XML, DNS addresses, raw registry values or authorization. A zero-value
// result is not proof of anything. Administrators retain legitimate access.
type WindowsOriginalBackupReview struct {
 Status string `json:"status"`
 HostsVerified bool `json:"hosts_verified"`
 BrowserKeysVerified int `json:"browser_keys_verified"`
 DNSBackupVerified bool `json:"dns_backup_verified"`
 CatalogBackupVerified bool `json:"catalog_backup_verified"`
 CompleteRecoverySnapshot bool `json:"complete_recovery_snapshot"`
 RestoreAuthorized bool `json:"restore_authorized"`
 InstallAuthorized bool `json:"install_authorized"`
}

// InspectOriginalBackupArchivesNativeReadOnly reopens existing local archives
// with native Windows ACL verification. The input pins must come from a
// separate trusted census; this function does not authenticate that census,
// assert transaction atomicity or modify any files, ACLs, tasks or DNS.
func InspectOriginalBackupArchivesNativeReadOnly(ctx context.Context,protectionParent,dnsParent string,
 baseline ProtectionSnapshot,browser WindowsBrowserPolicyEvidence,inventory WindowsFreshVOLVETaskInventory,
 dnsJournalPin string)(WindowsOriginalBackupReview,error){
 denied:=WindowsOriginalBackupReview{Status:"UNVERIFIED"}
 if ctx==nil{return denied,errors.New("original archive review requires context")}
 if err:=ctx.Err();err!=nil{return denied,err}
 receipt,err:=verifyOriginalProtectionArchivesUnarmed(ctx,protectionParent,dnsParent,baseline,browser,inventory,dnsJournalPin,
  func(path string)error{return nativeDNSOriginalBackupACL(ctx,path)})
 if err!=nil{return denied,errors.New("local original archive verification failed")}
 if !receipt.HostsVerified||receipt.BrowserKeysVerified!=3||!receipt.DNSBackupVerified||!receipt.CatalogBackupVerified||
  receipt.CompleteRecoverySnapshot||receipt.InstallAuthorized||receipt.RestoreAuthorized{
  return denied,errors.New("inconsistent original archive observation")
 }
 return WindowsOriginalBackupReview{Status:"FOUR_ARCHIVES_VERIFIED_READ_ONLY",HostsVerified:true,BrowserKeysVerified:3,
  DNSBackupVerified:true,CatalogBackupVerified:true},nil
}

// originalRecoveryReviewPin binds the independent census and DNS journal
// digest to a caller-supplied transaction identifier. This is a consistency
// check only: the trusted controller must persist and authenticate the pin
// independently, hold its transaction lock and recheck live state.
// A digest alone is never installation or restoration authorization.
func originalRecoveryReviewPin(transactionID string,baseline ProtectionSnapshot,dnsJournalPin string)(string,error){
 if len(transactionID)!=32||strings.ToLower(transactionID)!=transactionID{return "",errors.New("canonical transaction identity required")}
 if b,err:=hex.DecodeString(transactionID);err!=nil||len(b)!=16||transactionID==strings.Repeat("0",32){return "",errors.New("invalid transaction identity")}
 if !validProtectionSnapshot(baseline)||!protectionDigest.MatchString(dnsJournalPin){return "",errors.New("independent recovery pins incomplete")}
 raw,err:=json.Marshal(struct{
  Domain string
  TransactionID string
  Baseline ProtectionSnapshot
  DNSJournalSHA256 string
 }{"VOLVE-original-recovery-review-v1",transactionID,baseline,dnsJournalPin})
 if err!=nil{return "",errors.New("recovery binding encoding failed")}
 sum:=sha256.Sum256(raw)
 return hex.EncodeToString(sum[:]),nil
}

// verifyBoundOriginalRecoveryArchivesUnarmed rejects mixed transaction
// identifiers or census pins before opening any archive. A successful
// result remains an unarmed four-component observation.
func verifyBoundOriginalRecoveryArchivesUnarmed(ctx context.Context,transactionID,expectedPin,protectionParent,dnsParent string,
 baseline ProtectionSnapshot,browser WindowsBrowserPolicyEvidence,inventory WindowsFreshVOLVETaskInventory,dnsJournalPin string,check func(string)error)(originalProtectionPairReceipt,error){
 var denied originalProtectionPairReceipt
 if ctx==nil||check==nil{return denied,errors.New("bound review requires context and ACL verifier")}
 if err:=ctx.Err();err!=nil{return denied,err}
 got,err:=originalRecoveryReviewPin(transactionID,baseline,dnsJournalPin)
 if err!=nil||got!=expectedPin{return denied,errors.New("independent recovery transaction pin mismatch")}
 if !filepath.IsAbs(protectionParent)||!filepath.IsAbs(dnsParent)||
  filepath.Clean(protectionParent)!=protectionParent||filepath.Clean(dnsParent)!=dnsParent||
  !strings.EqualFold(filepath.Dir(protectionParent),filepath.Dir(dnsParent))||
  filepath.Base(filepath.Dir(protectionParent))!=transactionID{return denied,errors.New("recovery archives outside bound transaction directory")}
 return verifyOriginalProtectionArchivesUnarmed(ctx,protectionParent,dnsParent,baseline,browser,inventory,dnsJournalPin,check)
}

const originalRecoveryReviewFile="original-recovery-review.json"
type originalRecoveryReviewEvidence struct{
 Schema int
 Component string
 TransactionID string
 ReviewSHA256 string
}

func originalRecoveryEvidencePath(root,id string)(string,error){
 if !filepath.IsAbs(root)||filepath.Clean(root)!=root||strings.HasPrefix(root,string(filepath.Separator)+string(filepath.Separator))||
  filepath.Base(root)!=id||!residentNonce.MatchString(id)||id==strings.Repeat("0",32){return "",errors.New("invalid local recovery transaction root")}
 return filepath.Join(root,originalRecoveryReviewFile),nil
}

// The independent expected pin must be retained by the trusted controller,
// outside this record. The record alone cannot authenticate or arm recovery.
// Caller must hold the appropriate transaction lease; no OS settings changed.
func loadOriginalRecoveryReviewEvidenceUnarmed(ctx context.Context,root,id,expectedPin string,check func(string)error)error{
 if ctx==nil||check==nil||!residentSHA.MatchString(expectedPin){return errors.New("independent recovery evidence pin required")}
 if err:=ctx.Err();err!=nil{return err}
 path,err:=originalRecoveryEvidencePath(root,id)
 if err!=nil{return err}
 verify:=func()error{
  if err:=verifyOriginalHostsBackupNode(root,true,check);err!=nil{return err}
  return verifyOriginalHostsBackupNode(path,false,check)
 }
 if err:=verify();err!=nil{return err}
 before,err:=os.Lstat(path)
 if err!=nil||!before.Mode().IsRegular()||before.Size()<2||before.Size()>residentJournalLimit{return errors.New("invalid recovery evidence file")}
 raw,err:=residentFile(path)
 if err!=nil{return err}
 after,err:=os.Lstat(path)
 if err!=nil||!os.SameFile(before,after)||before.Size()!=after.Size()||before.Size()!=int64(len(raw))||!before.ModTime().Equal(after.ModTime()){return errors.New("recovery evidence changed during read")}
 var got originalRecoveryReviewEvidence
 if err:=residentCanonical(raw,&got);err!=nil{return err}
 if got!=(originalRecoveryReviewEvidence{1,"original-recovery-review-unarmed",id,expectedPin}){return errors.New("recovery evidence differs from independent pin")}
 if err:=verify();err!=nil{return err}
 return ctx.Err()
}

// Stage only after reviewing all four archives. Create-only journal semantics
// leave partial writes refused; an existing slot is never repaired or reused.
func persistOriginalRecoveryReviewEvidenceUnarmed(ctx context.Context,root,id,expectedPin string,
 baseline ProtectionSnapshot,browser WindowsBrowserPolicyEvidence,inventory WindowsFreshVOLVETaskInventory,dnsPin string,
 seal,check func(string)error)error{
 if ctx==nil||seal==nil||check==nil{return errors.New("recovery evidence staging requires trusted ACL callbacks")}
 if err:=ctx.Err();err!=nil{return err}
 path,err:=originalRecoveryEvidencePath(root,id)
 if err!=nil{return err}
 if err:=verifyOriginalHostsBackupNode(root,true,check);err!=nil{return err}
 receipt,err:=verifyBoundOriginalRecoveryArchivesUnarmed(ctx,id,expectedPin,filepath.Join(root,"original-protection-recovery"),filepath.Join(root,"legacy-engine-recovery"),baseline,browser,inventory,dnsPin,check)
 if err!=nil||!receipt.HostsVerified||receipt.BrowserKeysVerified!=3||!receipt.DNSBackupVerified||!receipt.CatalogBackupVerified||
  receipt.CompleteRecoverySnapshot||receipt.InstallAuthorized||receipt.RestoreAuthorized{return errors.New("four unarmed archives not verified")}
 raw,err:=json.Marshal(originalRecoveryReviewEvidence{1,"original-recovery-review-unarmed",id,expectedPin})
 if err!=nil{return err}
 if err:=ctx.Err();err!=nil{return err}
 if err:=verifyOriginalHostsBackupNode(root,true,check);err!=nil{return err}
 if err:=residentCreate(path,raw,seal,check);err!=nil{return err}
 return loadOriginalRecoveryReviewEvidenceUnarmed(ctx,root,id,expectedPin,check)
}

// A durable review is historical evidence only. Reopening it for a current
// observation must also reverify the four underlying archives, and reread the
// review afterward. The external expected pin and transaction lease remain
// prerequisites; this function cannot arm or authorize restoration.
func reopenOriginalRecoveryReviewUnarmed(ctx context.Context,root,id,expectedPin string,
 baseline ProtectionSnapshot,browser WindowsBrowserPolicyEvidence,inventory WindowsFreshVOLVETaskInventory,dnsPin string,
 check func(string)error)(originalProtectionPairReceipt,error){
 var denied originalProtectionPairReceipt
 if err:=loadOriginalRecoveryReviewEvidenceUnarmed(ctx,root,id,expectedPin,check);err!=nil{return denied,err}
 receipt,err:=verifyBoundOriginalRecoveryArchivesUnarmed(ctx,id,expectedPin,filepath.Join(root,"original-protection-recovery"),filepath.Join(root,"legacy-engine-recovery"),baseline,browser,inventory,dnsPin,check)
 if err!=nil||!receipt.HostsVerified||receipt.BrowserKeysVerified!=3||!receipt.DNSBackupVerified||!receipt.CatalogBackupVerified||
  receipt.CompleteRecoverySnapshot||receipt.InstallAuthorized||receipt.RestoreAuthorized{return denied,errors.New("current original archives not verified")}
 if err:=loadOriginalRecoveryReviewEvidenceUnarmed(ctx,root,id,expectedPin,check);err!=nil{return denied,err}
 return receipt,nil
}

// InspectBoundOriginalRecoveryNativeReadOnly coordinates with the existing
// resident transition mutex and verifies durable evidence using native ACLs.
// The caller supplies an independently trusted expected pin and census;
// this is not a signature verifier, authorization, or a restoration driver.
// Call only outside an existing resident transition lease.
func InspectBoundOriginalRecoveryNativeReadOnly(ctx context.Context,root,id,expectedPin string,
 baseline ProtectionSnapshot,browser WindowsBrowserPolicyEvidence,inventory WindowsFreshVOLVETaskInventory,dnsPin string)(WindowsOriginalBackupReview,error){
 denied:=WindowsOriginalBackupReview{Status:"UNVERIFIED"}
 if ctx==nil{return denied,errors.New("native recovery review requires context")}
 if err:=ctx.Err();err!=nil{return denied,err}
 pin,err:=originalRecoveryReviewPin(id,baseline,dnsPin)
 if err!=nil||pin!=expectedPin{return denied,errors.New("independent recovery pin mismatch")}
 if _,err:=originalRecoveryEvidencePath(root,id);err!=nil{return denied,err}
 release,err:=AcquireProtectedResidentTransitionLease(ctx)
 if err!=nil||release==nil{return denied,errors.New("protected recovery review lease unavailable")}
 defer release()
 receipt,err:=reopenOriginalRecoveryReviewUnarmed(ctx,root,id,expectedPin,baseline,browser,inventory,dnsPin,
  func(path string)error{return nativeDNSOriginalBackupACL(ctx,path)})
 if err!=nil||!receipt.HostsVerified||receipt.BrowserKeysVerified!=3||!receipt.DNSBackupVerified||!receipt.CatalogBackupVerified||
  receipt.CompleteRecoverySnapshot||receipt.InstallAuthorized||receipt.RestoreAuthorized{return denied,errors.New("bound original archives not currently verified")}
 if err:=ctx.Err();err!=nil{return denied,err}
 return WindowsOriginalBackupReview{Status:"BOUND_FOUR_ARCHIVES_VERIFIED_READ_ONLY",HostsVerified:true,BrowserKeysVerified:3,DNSBackupVerified:true,CatalogBackupVerified:true},nil
}

// PersistBoundOriginalRecoveryNativeUnarmed is the staging counterpart to
// InspectBoundOriginalRecoveryNativeReadOnly. It uses the existing protected
// transition lease, exact native ACL checks and create-only persistence.
// It requires an already protected transaction root with existing archives;
// no system configuration is changed, no permit is issued. Call outside
// any existing transition lease. The expected pin is independently trusted.
func PersistBoundOriginalRecoveryNativeUnarmed(ctx context.Context,root,id,expectedPin string,
 baseline ProtectionSnapshot,browser WindowsBrowserPolicyEvidence,inventory WindowsFreshVOLVETaskInventory,dnsPin string)error{
 if ctx==nil{return errors.New("native recovery staging requires context")}
 if err:=ctx.Err();err!=nil{return err}
 pin,err:=originalRecoveryReviewPin(id,baseline,dnsPin)
 if err!=nil||pin!=expectedPin{return errors.New("independent recovery pin mismatch")}
 if _,err:=originalRecoveryEvidencePath(root,id);err!=nil{return err}
 release,err:=AcquireProtectedResidentTransitionLease(ctx)
 if err!=nil||release==nil{return errors.New("protected recovery staging lease unavailable")}
 defer release()
 check:=func(p string)error{return nativeDNSOriginalBackupACL(ctx,p)}
 seal:=func(p string)error{return nativeSealNewOriginalRecoveryReviewNode(ctx,root,id,p)}
 if err:=persistOriginalRecoveryReviewEvidenceUnarmed(ctx,root,id,expectedPin,baseline,browser,inventory,dnsPin,seal,check);err!=nil{return err}
 // Revalidate the full snapshot before reporting completion, without
 // recursively acquiring the lease already held by this operation.
 receipt,err:=reopenOriginalRecoveryReviewUnarmed(ctx,root,id,expectedPin,baseline,browser,inventory,dnsPin,check)
 if err!=nil||!receipt.HostsVerified||receipt.BrowserKeysVerified!=3||!receipt.DNSBackupVerified||!receipt.CatalogBackupVerified||
  receipt.CompleteRecoverySnapshot||receipt.InstallAuthorized||receipt.RestoreAuthorized{return errors.New("staged original archives not currently verified")}
 return ctx.Err()
}

// A publisher-authenticated four-archive review digest, NOT a migration or
// recovery permit. The trusted public key must come from an independently
// pinned controller; never read it from the transaction directory.
const signedOriginalRecoveryReviewComponent="volve-publisher-original-recovery-review-v1"
type SignedOriginalRecoveryReview struct{
 Schema int `json:"schema"`
 Component string `json:"component"`
 TransactionID string `json:"transaction_id"`
 ReviewSHA256 string `json:"review_sha256"`
}

// VerifySignedOriginalRecoveryReview accepts only the exact canonical bytes
// signed by the trusted publisher and recomputes the transaction binding.
// The verified digest cannot by itself authorize install or restore.
func VerifySignedOriginalRecoveryReview(ctx context.Context,raw,signature []byte,pub ed25519.PublicKey,
 id string,baseline ProtectionSnapshot,dnsPin string)(SignedOriginalRecoveryReview,error){
 var denied SignedOriginalRecoveryReview
 if ctx==nil{return denied,errors.New("signed review context required")}
 if err:=ctx.Err();err!=nil{return denied,err}
 if len(pub)!=ed25519.PublicKeySize||len(signature)!=ed25519.SignatureSize||len(raw)<2||len(raw)>residentJournalLimit{
  return denied,errors.New("signed review input invalid")
 }
 if !ed25519.Verify(pub,raw,signature){return denied,errors.New("original recovery review signature invalid")}
 var got SignedOriginalRecoveryReview
 if err:=residentCanonical(raw,&got);err!=nil{return denied,errors.New("signed review encoding invalid")}
 canonical,err:=json.Marshal(got)
 if err!=nil||!bytes.Equal(raw,canonical){return denied,errors.New("signed review bytes not canonical")}
 pin,err:=originalRecoveryReviewPin(id,baseline,dnsPin)
 if err!=nil||got!=(SignedOriginalRecoveryReview{1,signedOriginalRecoveryReviewComponent,id,pin}){
  return denied,errors.New("signed review not bound to independent transaction census")
 }
 if err:=ctx.Err();err!=nil{return denied,err}
 return got,nil
}

// Review only; successful signature and current archive verification still
// return false for every installation, restoration and completion flag.
func InspectSignedBoundOriginalRecoveryNativeReadOnly(ctx context.Context,root,id string,
 raw,signature []byte,pub ed25519.PublicKey,baseline ProtectionSnapshot,browser WindowsBrowserPolicyEvidence,
 inventory WindowsFreshVOLVETaskInventory,dnsPin string)(WindowsOriginalBackupReview,error){
 denied:=WindowsOriginalBackupReview{Status:"UNVERIFIED"}
 evidence,err:=VerifySignedOriginalRecoveryReview(ctx,raw,signature,pub,id,baseline,dnsPin)
 if err!=nil{return denied,err}
 return InspectBoundOriginalRecoveryNativeReadOnly(ctx,root,id,evidence.ReviewSHA256,baseline,browser,inventory,dnsPin)
}


// This wrapper authorizes ACL changes only to the exact newly created
// review record, never to the transaction root or another component.
// It is internal to the create-exclusive staging workflow.
func nativeSealNewOriginalRecoveryReviewNode(ctx context.Context,root,id,path string)error{
 if ctx==nil{return errors.New("review seal context required")}
 if err:=ctx.Err();err!=nil{return err}
 expected,err:=originalRecoveryEvidencePath(root,id)
 if err!=nil||path!=expected{return errors.New("review seal refused unrelated path")}
 if err:=residentCurrentIsPrivileged();err!=nil{return err}
 if err:=verifyOriginalHostsBackupNode(root,true,func(p string)error{return nativeDNSOriginalBackupACL(ctx,p)});err!=nil{return err}
 stat,err:=os.Lstat(path)
 if err!=nil||!stat.Mode().IsRegular()||stat.Mode()&os.ModeSymlink!=0{return errors.New("review seal refused nonregular file")}
 return nativeSealApprovedOriginalBackupNode(ctx,path)
}

// One create-exclusive envelope avoids an independently replaceable
// signature sidecar. A production caller must pin its trusted public key
// independently. No private key or authorization is stored here.
const signedOriginalRecoveryEnvelopeFile="original-recovery-review-signed.json"
type signedOriginalRecoveryEnvelope struct{
 Payload []byte `json:"payload"`
 Signature []byte `json:"signature"`
}

func signedOriginalRecoveryEnvelopePath(root,id string)(string,error){
 if _,err:=originalRecoveryEvidencePath(root,id);err!=nil{return "",err}
 return filepath.Join(root,signedOriginalRecoveryEnvelopeFile),nil
}

// Caller holds the protected resident transition lease. Verify the
// independently supplied key, the exact signed payload and the four
// archives before reporting current evidence.
func readSignedOriginalRecoveryEnvelopeUnderLease(ctx context.Context,root,id string,pub ed25519.PublicKey,
 baseline ProtectionSnapshot,dnsPin string)(SignedOriginalRecoveryReview,error){
 var denied SignedOriginalRecoveryReview
 if err:=ctx.Err();err!=nil{return denied,err}
 path,err:=signedOriginalRecoveryEnvelopePath(root,id)
 if err!=nil{return denied,err}
 check:=func(p string)error{return nativeDNSOriginalBackupACL(ctx,p)}
 verify:=func()error{
  if err:=verifyOriginalHostsBackupNode(root,true,check);err!=nil{return err}
  return verifyOriginalHostsBackupNode(path,false,check)
 }
 if err:=verify();err!=nil{return denied,err}
 before,err:=os.Lstat(path)
 if err!=nil{return denied,err}
 raw,err:=residentFile(path)
 if err!=nil{return denied,err}
 after,err:=os.Lstat(path)
 if err!=nil||!os.SameFile(before,after)||before.Size()!=after.Size()||int64(len(raw))!=before.Size()||!before.ModTime().Equal(after.ModTime()){
  return denied,errors.New("signed review envelope changed during read")
 }
 var env signedOriginalRecoveryEnvelope
 if err:=residentCanonical(raw,&env);err!=nil{return denied,errors.New("signed review envelope invalid")}
 got,err:=VerifySignedOriginalRecoveryReview(ctx,env.Payload,env.Signature,pub,id,baseline,dnsPin)
 if err!=nil{return denied,err}
 if err:=verify();err!=nil{return denied,err}
 return got,ctx.Err()
}

// Caller already owns the lease; no nested acquisition.
func inspectPersistedSignedReviewUnderLease(ctx context.Context,root,id string,pub ed25519.PublicKey,
 baseline ProtectionSnapshot,browser WindowsBrowserPolicyEvidence,inventory WindowsFreshVOLVETaskInventory,dnsPin string)(WindowsOriginalBackupReview,error){
 denied:=WindowsOriginalBackupReview{Status:"UNVERIFIED"}
 evidence,err:=readSignedOriginalRecoveryEnvelopeUnderLease(ctx,root,id,pub,baseline,dnsPin)
 if err!=nil{return denied,err}
 receipt,err:=reopenOriginalRecoveryReviewUnarmed(ctx,root,id,evidence.ReviewSHA256,baseline,browser,inventory,dnsPin,
  func(p string)error{return nativeDNSOriginalBackupACL(ctx,p)})
 if err!=nil||!receipt.HostsVerified||receipt.BrowserKeysVerified!=3||!receipt.DNSBackupVerified||!receipt.CatalogBackupVerified||
  receipt.CompleteRecoverySnapshot||receipt.InstallAuthorized||receipt.RestoreAuthorized{return denied,errors.New("signed durable review archives not verified")}
 again,err:=readSignedOriginalRecoveryEnvelopeUnderLease(ctx,root,id,pub,baseline,dnsPin)
 if err!=nil||again!=evidence{return denied,errors.New("signed review changed during verification")}
 if err:=ctx.Err();err!=nil{return denied,err}
 return WindowsOriginalBackupReview{Status:"SIGNED_BOUND_FOUR_ARCHIVES_VERIFIED_READ_ONLY",HostsVerified:true,BrowserKeysVerified:3,DNSBackupVerified:true,CatalogBackupVerified:true},nil
}

func InspectPersistedSignedOriginalRecoveryNativeReadOnly(ctx context.Context,root,id string,pub ed25519.PublicKey,
 baseline ProtectionSnapshot,browser WindowsBrowserPolicyEvidence,inventory WindowsFreshVOLVETaskInventory,dnsPin string)(WindowsOriginalBackupReview,error){
 denied:=WindowsOriginalBackupReview{Status:"UNVERIFIED"}
 if ctx==nil||len(pub)!=ed25519.PublicKeySize{return denied,errors.New("trusted signed review context and key required")}
 if _,err:=signedOriginalRecoveryEnvelopePath(root,id);err!=nil{return denied,err}
 release,err:=AcquireProtectedResidentTransitionLease(ctx)
 if err!=nil||release==nil{return denied,errors.New("protected signed review lease unavailable")}
 defer release()
 return inspectPersistedSignedReviewUnderLease(ctx,root,id,pub,baseline,browser,inventory,dnsPin)
}

// Stage an externally signed review only after verifying the existing
// unarmed review and all four archives. Never replace a partial envelope.
func PersistSignedOriginalRecoveryNativeUnarmed(ctx context.Context,root,id string,raw,signature []byte,pub ed25519.PublicKey,
 baseline ProtectionSnapshot,browser WindowsBrowserPolicyEvidence,inventory WindowsFreshVOLVETaskInventory,dnsPin string)error{
 evidence,err:=VerifySignedOriginalRecoveryReview(ctx,raw,signature,pub,id,baseline,dnsPin)
 if err!=nil{return err}
 path,err:=signedOriginalRecoveryEnvelopePath(root,id)
 if err!=nil{return err}
 release,err:=AcquireProtectedResidentTransitionLease(ctx)
 if err!=nil||release==nil{return errors.New("protected signed staging lease unavailable")}
 defer release()
 check:=func(p string)error{return nativeDNSOriginalBackupACL(ctx,p)}
 if err:=verifyOriginalHostsBackupNode(root,true,check);err!=nil{return err}
 if _,err:=os.Lstat(path);!errors.Is(err,os.ErrNotExist){return errors.New("signed review envelope slot already exists or is unavailable")}
 receipt,err:=reopenOriginalRecoveryReviewUnarmed(ctx,root,id,evidence.ReviewSHA256,baseline,browser,inventory,dnsPin,check)
 if err!=nil||!receipt.HostsVerified||receipt.BrowserKeysVerified!=3||!receipt.DNSBackupVerified||!receipt.CatalogBackupVerified||
  receipt.CompleteRecoverySnapshot||receipt.InstallAuthorized||receipt.RestoreAuthorized{return errors.New("unsigned original archives not verified")}
 data,err:=json.Marshal(signedOriginalRecoveryEnvelope{raw,signature})
 if err!=nil||len(data)>=residentJournalLimit{return errors.New("signed review envelope too large")}
 seal:=func(p string)error{
  if p!=path{return errors.New("signed review seal refused unrelated path")}
  if err:=verifyOriginalHostsBackupNode(root,true,check);err!=nil{return err}
  if err:=ctx.Err();err!=nil{return err}
  stat,err:=os.Lstat(p)
  if err!=nil||!stat.Mode().IsRegular()||stat.Mode()&os.ModeSymlink!=0{return errors.New("signed review seal refused nonregular file")}
  return nativeSealApprovedOriginalBackupNode(ctx,p)
 }
 if err:=ctx.Err();err!=nil{return err}
 if err:=residentCreate(path,data,seal,check);err!=nil{return err}
 _,err=inspectPersistedSignedReviewUnderLease(ctx,root,id,pub,baseline,browser,inventory,dnsPin)
 return err
}


// RehearseNativeOriginalArchiveReviewCI captures the four actual original
// components against the independently observed signed-package preview.
// Only a disposable hosted runner with no installed VOLVE task is supported.
// The protected mutex is reacquired here and the earlier baseline must still
// match before any archive is written. The temporary unarmed archives are
// reopened, verified and removed; no restore authority or production backup
// completion is issued. Never call while already holding the native mutex.
func RehearseNativeOriginalArchiveReviewCI(ctx context.Context,baseline ProtectionSnapshot,browser WindowsBrowserPolicyEvidence,overrides WindowsDNSOverrideCensus)(report WindowsOriginalBackupReview,err error){
 denied:=WindowsOriginalBackupReview{Status:"UNVERIFIED"}
 if ctx==nil||os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{return denied,errors.New("original archive rehearsal requires disposable hosted CI")}
 if err:=ctx.Err();err!=nil{return denied,err}
 runner:=os.Getenv("RUNNER_TEMP")
 if !filepath.IsAbs(runner)||filepath.Clean(runner)!=runner||strings.HasPrefix(runner,string(filepath.Separator)+string(filepath.Separator)){return denied,errors.New("invalid hosted temporary root")}
 release,err:=AcquireProtectedResidentTransitionLease(ctx)
 if err!=nil||release==nil{return denied,errors.New("original archive rehearsal lease unavailable")}
 defer release()
 // Do not silently accept another baseline after a concurrent change.
 recensus:=func()error{
  snap,b,err:=InspectWindowsProtectionSnapshotReadOnly(ctx,"","",DefaultWindowsProtectionSnapshotInspectors())
  if err!=nil{return fmt.Errorf("original archive rehearsal census failed: %w",err)}
  if snap!=baseline||!reflect.DeepEqual(b,browser){return errors.New("original protection changed since signed preview")}
  policy,err:=InspectWindowsDNSOverrideCensusReadOnly(ctx,DefaultWindowsReadOnlyPowerShell)
  if err!=nil{return err}
  if policy!=overrides{return errors.New("DNS override content changed since signed preview")}
  return ctx.Err()
 }
 if err:=recensus();err!=nil{return denied,err}
 inventory,err:=InspectWindowsVOLVETasksReadOnly(ctx,"","",DefaultWindowsFreshTaskInspect)
 if err!=nil||inventory.VOLVETaskCount!=0||len(inventory.UnknownTaskNames)!=0||inventory.VerifiedCatalogTask!=nil{return denied,errors.New("archive rehearsal requires independently verified absence of VOLVE tasks")}
 hostsPin:=WindowsHostsFileEvidence{SHA256:baseline.HostsSHA256,BlockedRuleCount:baseline.HostsBlockedRuleCount}
 hosts,err:=captureOriginalWindowsHostsBackup(ctx,filepath.Join(os.Getenv("SystemRoot"),"System32","drivers","etc","hosts"),hostsPin)
 if err!=nil{return denied,fmt.Errorf("original hosts capture failed: %w",err)}
 policies,err:=captureOriginalBrowserPolicyBytes(ctx,browser,readOriginalBrowserPolicyLocal)
 if err!=nil{return denied,fmt.Errorf("original browser capture failed: %w",err)}
 observed,err:=InspectWindowsDNSAssignmentProvenanceReadOnly(ctx,DefaultWindowsReadOnlyPowerShell)
 if err!=nil||observed.SHA256!=baseline.DNSAdaptersSHA256{return denied,errors.New("original DNS source changed before capture")}
 journal,pin,err:=BuildDNSOriginalJournal(ctx,observed.States)
 if err!=nil{return denied,err}
 definition,err:=captureOriginalCatalogDefinition(ctx,baseline,inventory,readOriginalCatalogDefinitionLocal)
 if err!=nil||definition.Present{return denied,errors.New("original catalog absence not proven")}
 var nonce [16]byte
 if _,err:=rand.Read(nonce[:]);err!=nil{return denied,err}
 id:=hex.EncodeToString(nonce[:])
 outer,err:=os.MkdirTemp(runner,"VOLVE-CI-ArchiveReview-")
 if err!=nil{return denied,err}
 defer func(){
  if cleanup:=os.RemoveAll(outer);cleanup!=nil{report=denied;err=errors.Join(err,errors.New("temporary original archive cleanup failed"))}
 }()
 root:=filepath.Join(outer,id)
 protection:=filepath.Join(root,"original-protection-recovery")
 dns:=filepath.Join(root,"legacy-engine-recovery")
 seal:=func(p string)error{return nativeSealApprovedOriginalBackupNode(ctx,p)}
 check:=func(p string)error{return nativeDNSOriginalBackupACL(ctx,p)}
 if err:=seal(outer);err!=nil{return denied,err}
 for _,dir:=range []string{root,protection,dns}{
  if err:=os.Mkdir(dir,0700);err!=nil{return denied,err}
  if err:=seal(dir);err!=nil{return denied,err}
 }
 if err:=storeOriginalWindowsHostsBackupUnarmed(ctx,protection,hosts,hostsPin,seal,check);err!=nil{return denied,err}
 if err:=storeBrowserOriginalArchiveUnarmed(ctx,protection,browser,policies,seal,check);err!=nil{return denied,err}
 if _,err:=StoreDNSOriginalBackupUnarmed(ctx,dns,journal,pin,seal,check);err!=nil{return denied,err}
 if err:=storeOriginalCatalogArchiveUnarmed(ctx,protection,baseline,inventory,definition,seal,check);err!=nil{return denied,err}
 binding,err:=originalRecoveryReviewPin(id,baseline,pin)
 if err!=nil{return denied,err}
 if err:=persistOriginalRecoveryReviewEvidenceUnarmed(ctx,root,id,binding,baseline,browser,inventory,pin,
  func(p string)error{return nativeSealNewOriginalRecoveryReviewNode(ctx,root,id,p)},check);err!=nil{return denied,err}
 receipt,err:=reopenOriginalRecoveryReviewUnarmed(ctx,root,id,binding,baseline,browser,inventory,pin,check)
 if err!=nil||!receipt.HostsVerified||receipt.BrowserKeysVerified!=3||!receipt.DNSBackupVerified||!receipt.CatalogBackupVerified||receipt.CompleteRecoverySnapshot||receipt.RestoreAuthorized||receipt.InstallAuthorized{return denied,errors.New("temporary original archive reopen refused")}
 if err:=recensus();err!=nil{return denied,err}
 return WindowsOriginalBackupReview{Status:"FOUR_TEMPORARY_ARCHIVES_VERIFIED_UNARMED",HostsVerified:true,BrowserKeysVerified:3,DNSBackupVerified:true,CatalogBackupVerified:true},nil
}
