//go:build windows

package main

// Step-2 rehearsal: restore a disposable Task Scheduler job using the EXACT
// protected resident backup + create-only journal that the future production
// watchdog will consume. This operation never accepts VOLVE-DNS-SERVER-0270,
// has no production CLI, and never changes DNS, adapters or browser policy.
import (
 "context"
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "strings"
)

func residentPilotTargetPath(root,version string) (string,error) {
 if !filepath.IsAbs(root) || version=="" {return "",errors.New("pilot target path must be absolute")}
 for _,part:=range strings.Split(version,".") {
  if part=="" {return "",errors.New("invalid pilot motor version")}
  for _,ch:=range part {if ch<'0'||ch>'9'{return "",errors.New("invalid pilot motor version")}}
 }
 return filepath.Join(root,"VOLVE_DNS_Motor_"+strings.ReplaceAll(version,".","_")+".exe"),nil
}

// restoreResidentPilotSYSTEMTask requires journal/backup/live motor agreement,
// validates the original XML again, and restores ONLY a CI-name task. Even if
// the new executable disappeared or became corrupted, rollback still works
// because the installed original motor and immutable fallback are reverified.
// The recovery journal stays PENDING until a separate trusted health checker
// confirms the restored motor and writes a protected terminal receipt.
func restoreResidentPilotSYSTEMTask(ctx context.Context,root,pilotTask string) error {
 // The independent recovery executor must never run concurrently with a
 // second process restoring the same disposable SYSTEM task.
 if !pilotTaskPattern.MatchString(pilotTask){
  return errors.New("production or unrelated tasks forbidden by rehearsal")
 }
 suffix:=strings.TrimPrefix(pilotTask,"VOLVE-CI-ManagedMotor-")
 release,err:=acquireCIBootMutex(ctx,"VOLVE-CI-BootLock-"+suffix)
 if err!=nil{return fmt.Errorf("resident recovery exclusive Windows lock unavailable: %w",err)}
 defer release()
 return restoreResidentPilotSYSTEMTaskWithRunner(ctx,root,pilotTask,ps)
}

// The injected runner is only for tests that must not touch Task Scheduler.
func restoreResidentPilotSYSTEMTaskWithRunner(ctx context.Context,root,pilotTask string,
 runPS func(context.Context,string)(string,error)) error {
 if runPS==nil{return errors.New("missing SYSTEM recovery executor")}
 if !pilotTaskPattern.MatchString(pilotTask){
  return errors.New("production or unrelated tasks forbidden by rehearsal")
 }
 evidence,err:=auditPendingResidentChain(ctx,root)
 if err!=nil{return fmt.Errorf("untrusted resident recovery chain: %w",err)}
 target,err:=residentPilotTargetPath(root,evidence.TargetVersion)
 if err!=nil{return err}
 original:=filepath.Join(root,residentLegacyExe)
 snapshot:=filepath.Join(root,residentRecoveryParent,residentRecoveryFolder,residentRecoveryTask)
 raw,err:=os.ReadFile(snapshot)
 if err!=nil{return err}
 if err:=validateResidentTaskXML(raw,original);err!=nil{return err}
 if err:=ctx.Err();err!=nil{return err}
 // The backup hash and original-motor hash are verified INSIDE the same
 // PowerShell process immediately before Register-ScheduledTask. The live
 // task must be ROOT/SYSTEM/single Exec with precisely the expected target.
 // Register-ScheduledTask reads only the already-verified snapshot XML.
 script:=`$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';`+
  `$taskName=`+q(pilotTask)+`;`+
  `$original=`+q(original)+`;`+
  `$target=`+q(target)+`;`+
  `$xmlFile=`+q(snapshot)+`;`+
  `$xmlHash=`+q(evidence.TaskXMLSHA256)+`;`+
  `$oldHash=`+q(evidence.LegacySHA256)+`;`+
  `$live=Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction Stop;`+
  `if($live.TaskPath -ne '\' -or $live.Principal.UserId -notin @('SYSTEM','S-1-5-18') `+
   `-or @($live.Actions).Count -ne 1){throw 'Unexpected pilot SYSTEM task identity'};`+
  `if([string]$live.Actions[0].Execute -ine $target -or `+
   `[string]$live.Actions[0].Arguments -cne '--dns-service'){throw 'Pilot target action changed'};`+
  `if(-not [IO.File]::Exists($original)){throw 'Legacy motor missing'};`+
  `$motorDigest=(Get-FileHash -LiteralPath $original -Algorithm SHA256).Hash.ToLowerInvariant();`+
  `if($motorDigest -cne $oldHash){throw 'Legacy motor changed before restore'};`+
  // Hash the exact XML byte array being imported; two separate file reads
  // would leave a change-between-check-and-use window.
  `$xmlBytes=[IO.File]::ReadAllBytes($xmlFile);`+
  `$hasher=[Security.Cryptography.SHA256]::Create();`+
  `try{$xmlDigest=[BitConverter]::ToString($hasher.ComputeHash($xmlBytes)).Replace('-','').ToLowerInvariant()}`+
  `finally{$hasher.Dispose()};`+
  `if($xmlDigest -cne $xmlHash){throw 'Original task XML changed before import'};`+
  `$bom16=($xmlBytes.Length -ge 2 -and `+
   `(($xmlBytes[0] -eq 255 -and $xmlBytes[1] -eq 254) -or `+
   `($xmlBytes[0] -eq 254 -and $xmlBytes[1] -eq 255)));`+
  `if($bom16){`+
  `if($xmlBytes[0] -eq 255){$enc=[Text.Encoding]::Unicode}`+
  `else{$enc=[Text.Encoding]::BigEndianUnicode};`+
  `$saved=$enc.GetString($xmlBytes,2,$xmlBytes.Length-2)`+
  `}else{$utf8=[Text.UTF8Encoding]::new($false,$true);$saved=$utf8.GetString($xmlBytes)};`+
  `$saved=[regex]::Replace($saved,'(?i)(encoding\s*=\s*["''])(UTF-16LE|UTF-16BE|UTF-16)(["''])','$1UTF-8$3');`+
  `Register-ScheduledTask -TaskName $taskName -TaskPath '\' -Xml $saved -Force -ErrorAction Stop|Out-Null;`+
  `$restored=Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction Stop;`+
  `if($restored.TaskPath -ne '\' -or $restored.Principal.UserId -notin @('SYSTEM','S-1-5-18') `+
   `-or @($restored.Actions).Count -ne 1 -or `+
   `[string]$restored.Actions[0].Execute -ine $original -or `+
   `[string]$restored.Actions[0].Arguments -cne '--dns-service'){throw 'Restored task identity mismatch'};`+
  `Write-Output 'VOLVE_CI_RESIDENT_RESTORED'`
 out,err:=runPS(ctx,script)
 if err!=nil{return fmt.Errorf("pilot SYSTEM recovery failed: %w (%s)",err,out)}
 if out!="VOLVE_CI_RESIDENT_RESTORED" {return fmt.Errorf("ambiguous pilot recovery result: %q",out)}
 // No journal finalization here: the DNS/Internet health criteria are NOT
 // proven by a Scheduler-action-only test.
 return nil
}
