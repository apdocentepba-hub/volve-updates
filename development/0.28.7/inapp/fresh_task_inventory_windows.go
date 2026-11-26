//go:build windows

package motorupdate

// Windows Task Scheduler read-only inventory for distinguishing a NEW motor
// installation from an upgrade of an existing protected DNS engine.
// This source NEVER registers, changes, runs or deletes a task or DNS setting.
// It is only ONE input to the full fresh-install readiness policy.
import (
 "bytes"
 "context"
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
