//go:build windows

package motorupdate

// Windows Task Scheduler read-only inventory for distinguishing a NEW motor
// installation from an upgrade of an existing protected DNS engine.
// This source NEVER registers, changes, runs or deletes a task or DNS setting.
// It is only ONE input to the full fresh-install readiness policy.
import (
 "bytes"
 "context"
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
   ([string]$_.Execute -match '(?i)[\\/]VOLVE(?:[\\/]|[_-])') -or
   ([string]$_.Arguments -match '(?i)[\\/]VOLVE(?:[\\/]|[_-])')
 });
 $named -or $linked.Count -gt 0
} | ForEach-Object {
 $task=$_;$action=@($task.Actions | ForEach-Object {
   [pscustomobject]@{Execute=[string]$_.Execute;Arguments=[string]$_.Arguments}
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
    filepath.IsAbs(act.Execute) && act.Arguments==expectedCatalogArguments
  }
  result.VerifiedCatalogTask=verified
 }
 return result,nil
}
