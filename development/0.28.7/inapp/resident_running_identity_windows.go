//go:build windows

package main

// Read-only Windows identity adapter. No task switch, process launch,
// DNS mutation or changes to the production installation.
import (
 "bytes"
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "regexp"

 "volve-browser-protection/motorupdate"
)

var residentObservedMotorName=regexp.MustCompile(`^VOLVE_DNS_Motor_[0-9]+_[0-9]+_[0-9]+\.exe$`)

func allowedResidentObservedExecutable(path string) bool {
 if !filepath.IsAbs(path){return false}
 name:=filepath.Base(path)
 return name==dnsServiceFile || residentObservedMotorName.MatchString(name)
}

// query is injected for harmless Windows unit tests. Its production variant
// executes read-only Task Scheduler/Win32_Process/Get-FileHash commands only.
func readResidentRunningEvidenceWithQuery(
 ctx context.Context,exe string,query func(context.Context,string)(string,error),
)(motorupdate.ResidentRunningEvidence,error){
 var empty motorupdate.ResidentRunningEvidence
 if err:=ctx.Err();err!=nil{return empty,err}
 if query==nil || !allowedResidentObservedExecutable(exe) {
  return empty,errors.New("untrusted Windows evidence reader or motor executable")
 }
 info,err:=os.Lstat(exe);if err!=nil{return empty,err}
 if !info.Mode().IsRegular() || info.Size()<1 || info.Size()>80<<20 {
  return empty,errors.New("motor image on disk is missing, linked or outside size bound")
 }
 script:=`$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';`+
  `$exe=`+psQuote(exe)+`;`+
  `$task=Get-ScheduledTask -TaskName 'VOLVE-DNS-SERVER-0270' -TaskPath '\' -ErrorAction Stop;`+
  `$name=[IO.Path]::GetFileName($exe);`+
  `$candidates=@(Get-CimInstance Win32_Process -Filter ("Name='"+$name+"'") -ErrorAction Stop|`+
  `Where-Object { [string]$_.ExecutablePath -ieq $exe });`+
  `if($candidates.Count -ne 1){throw 'Expected exactly one motor process'};`+
  `$proc=$candidates[0];`+
  `$owner=Invoke-CimMethod -InputObject $proc -MethodName GetOwnerSid -ErrorAction Stop;`+
  `if($owner.ReturnValue -ne 0){throw 'Cannot attest process owner SID'};`+
  `$ipv4=@(Get-NetUDPEndpoint -LocalAddress '127.0.0.1' -LocalPort 53 -ErrorAction Stop);`+
  `$ipv6=@(Get-NetUDPEndpoint -LocalAddress '::1' -LocalPort 53 -ErrorAction Stop);`+
  `if($ipv4.Count -ne 1 -or $ipv6.Count -ne 1){throw 'DNS listener ownership ambiguous'};`+
  `$digest=(Get-FileHash -LiteralPath $exe -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant();`+
  `$result=[ordered]@{task_name=[string]$task.TaskName;task_folder=[string]$task.TaskPath;`+
  `task_principal=[string]$task.Principal.UserId;task_state=[string]$task.State;`+
  `task_action_count=[int]@($task.Actions).Count;`+
  `task_action_execute=[string]$task.Actions[0].Execute;`+
  `task_action_arguments=[string]$task.Actions[0].Arguments;`+
  `process_count=[int]$candidates.Count;process_id=[int]$proc.ProcessId;`+
  `dns_ipv4_owner_pid=[int]$ipv4[0].OwningProcess;`+
  `dns_ipv6_owner_pid=[int]$ipv6[0].OwningProcess;`+
  `process_path=[string]$proc.ExecutablePath;`+
  `process_command_line=[string]$proc.CommandLine;`+
  `process_owner_sid=[string]$owner.Sid;disk_sha256=[string]$digest};`+
  `$result|ConvertTo-Json -Compress -Depth 3`
 output,err:=query(ctx,script)
 if err!=nil{return empty,fmt.Errorf("read-only Windows motor observation failed: %w",err)}
 if len(output)<20 || len(output)>8192{return empty,errors.New("motor process evidence outside size bound")}
 decoder:=json.NewDecoder(bytes.NewReader([]byte(output)))
 decoder.DisallowUnknownFields()
 var data motorupdate.ResidentRunningEvidence
 if err:=decoder.Decode(&data);err!=nil{return empty,fmt.Errorf("invalid process evidence: %w",err)}
 var tail any
 if err:=decoder.Decode(&tail);err!=io.EOF{return empty,errors.New("extra Windows motor evidence data")}
 return data,nil
}

// This is not an authorization to switch or restore the productive task.
// Disk SHA does not prove loaded process image bytes; task/process co-presence
// does not prove parentage. Signature/watchdog/boot tests remain mandatory.
func verifyResidentRunningMotorReadOnly(ctx context.Context,exe,expectedSHA string)error {
 observed,err:=readResidentRunningEvidenceWithQuery(ctx,exe,
  func(ctx context.Context,script string)(string,error){
   if err:=ctx.Err();err!=nil{return "",err}
   return runPS(script)
  })
 if err!=nil{return err}
 return motorupdate.CheckResidentRunningEvidence(observed,exe,expectedSHA)
}
