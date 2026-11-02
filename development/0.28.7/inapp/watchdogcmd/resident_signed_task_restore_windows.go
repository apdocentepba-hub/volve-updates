//go:build windows

package main

// Signed, read-only-admitted restoration of the EXACT legacy DNS SYSTEM task.
// This file is deliberately NOT exposed from main(), a release, or a launcher.
// The operation must not run until a separately deployed, verified SYSTEM
// watchdog and persistent Windows reboot recovery are fully accepted.
//
// Task Scheduler restore is the second step AFTER the exact original image
// is present. Failure leaves the protected recovery journal PENDING, never
// reports that DNS or network health has recovered.
import (
 "context"
 "crypto/ed25519"
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "strings"

 "volve-browser-protection/motorupdate"
)

type residentSignedTaskRestoreDeps struct {
 VerifySystem func(context.Context)error
 VerifyACL func(string)error
 ProbeQuiescence func(context.Context,string)(residentQuiescenceDecision,error)
 RunWindowsTask func(context.Context,string)(string,error)
}

func restoreSignedOriginalSYSTEMTaskWindows(ctx context.Context,root string,
 publisher ed25519.PublicKey,deps residentSignedTaskRestoreDeps)error {
 if err:=ctx.Err();err!=nil{return err}
 if deps.VerifySystem==nil||deps.VerifyACL==nil||
  deps.ProbeQuiescence==nil||deps.RunWindowsTask==nil{
  return errors.New("missing SYSTEM identity, NTFS verification, DNS53 guard or Scheduler executor")
 }
 if len(publisher)!=ed25519.PublicKeySize||
  !filepath.IsAbs(root)||filepath.Clean(root)!=root{
  return errors.New("unknown publisher or noncanonical installation root")
 }
 if err:=deps.VerifySystem(ctx);err!=nil{
  return fmt.Errorf("independent restorer lacks SYSTEM identity: %w",err)
 }
 lease,err:=motorupdate.AcquireProtectedResidentTransitionLease(ctx)
 if err!=nil{return fmt.Errorf("cannot lock recovery transition: %w",err)}
 if lease==nil{return errors.New("no protected transition lock release")}
 defer lease()

 admission,err:=auditResidentSignedBootAdmissionLocked(ctx,root,publisher,
  deps.VerifyACL,deps.VerifyACL,deps.VerifyACL,deps.ProbeQuiescence)
 if err!=nil{return fmt.Errorf("publisher protected rollback not authorized: %w",err)}
 if !admission.PublisherVerified||!admission.QuiescenceVerified||
  admission.Status!="recovery-required"||admission.OriginalFileState!="original-intact"{
  return errors.New("original motor is not present, verified and fully quiescent")
 }
 original:=filepath.Join(root,residentLegacyExe)
 xmlPath:=filepath.Join(root,residentRecoveryParent,residentRecoveryFolder,residentRecoveryTask)
 if err:=deps.VerifyACL(root);err!=nil{return fmt.Errorf("original root DACL not trusted: %w",err)}
 if err:=deps.VerifyACL(original);err!=nil{return fmt.Errorf("original motor DACL not trusted: %w",err)}
 if err:=deps.VerifyACL(xmlPath);err!=nil{return fmt.Errorf("protected SYSTEM task XML not trusted: %w",err)}
 backup,err:=auditPostSwitchResidentRecovery(ctx,root)
 if err!=nil{return err}
 info,err:=os.Lstat(xmlPath)
 if err!=nil{return err}
 if !info.Mode().IsRegular()||info.Size()<32||info.Size()>2<<20{
  return errors.New("protected SYSTEM XML not a regular bounded file")
 }
 xml,err:=os.ReadFile(xmlPath)
 if err!=nil{return err}
 hash:=sha256.Sum256(xml)
 if hex.EncodeToString(hash[:])!=backup.TaskXMLSHA256||
  int64(len(xml))!=info.Size()||
  backup.LegacySHA256!=admission.OriginalSHA256||
  backup.TargetVersion!="0.28.7"{
  return errors.New("original SYSTEM XML or migration identity changed")
 }
 if err:=validateResidentTaskXML(xml,original);err!=nil{
  return fmt.Errorf("original SYSTEM task XML not trustworthy: %w",err)
 }
 live,err:=digestResidentLive(ctx,original)
 if err!=nil||live!=admission.OriginalSHA256{
  return errors.New("installed original EXE not exact publisher-authorized SHA-256")
 }
 // Re-inspect signed grant and LIVE Scheduler/process/port 53 under the
 // SAME kernel lock immediately before touching the Task Scheduler.
 repeated,err:=auditResidentSignedBootAdmissionLocked(ctx,root,publisher,
  deps.VerifyACL,deps.VerifyACL,deps.VerifyACL,deps.ProbeQuiescence)
 if err!=nil||repeated!=admission{
  return fmt.Errorf("publisher, backup or DNS53 state changed before Scheduler restore: %w",err)
 }
 if err:=deps.VerifySystem(ctx);err!=nil{return err}
 if err:=ctx.Err();err!=nil{return err}

 // The final check and Register-ScheduledTask are in one elevated Windows
 // PowerShell execution; no downloaded or caller-supplied XML is accepted.
 // The command never stops a task, kills a process or changes adapter DNS.
 taskName:="VOLVE-DNS-SERVER-0270"
 target:=filepath.Join(root,"VOLVE_DNS_Motor_0_28_7.exe")
 altTarget:=filepath.Join(root,"installed-engines","VOLVE_DNS_Motor_0_28_7.exe")
 script:="$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';"+
  "$task="+q(taskName)+";$old="+q(original)+";"+
  "$target="+q(target)+";$altTarget="+q(altTarget)+";"+
  "$xmlFile="+q(xmlPath)+";$oldSHA="+q(admission.OriginalSHA256)+";"+
  "$xmlSHA="+q(backup.TaskXMLSHA256)+";"+
  "$identity=[Security.Principal.WindowsIdentity]::GetCurrent();"+
  "if($identity.User.Value -ne 'S-1-5-18'){throw 'Only SYSTEM may restore DNS task'};"+
  "$t=Get-ScheduledTask -TaskName $task -TaskPath '\\' -ErrorAction Stop;"+
  "if($t.TaskPath -ne '\\' -or $t.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or @($t.Actions).Count -ne 1){throw 'Unexpected live SYSTEM task'};"+
  "$act=[string]$t.Actions[0].Execute;$arg=[string]$t.Actions[0].Arguments;"+
  "if($arg -cne '--dns-service' -or $act -inotmatch '.*'){throw 'Wrong DNS task args'};"+
  "$isOriginal=($act -ieq $old);"+
  "$isTarget=($act -ieq $target -or $act -ieq $altTarget);"+
  "if(-not ($isOriginal -or $isTarget)){throw 'Unrecognized SYSTEM executable action'};"+
  "$all=@(Get-CimInstance Win32_Process -ErrorAction Stop);"+
  "$prefix="+q(root)+"+'\\';"+
  "$running=@($all|Where-Object{([string]$_.ExecutablePath).StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase) -and ([string]$_.Name -like 'VOLVE_DNS_*')});"+
  "$udp=@(Get-NetUDPEndpoint -ErrorAction Stop|Where-Object{[int]$_.LocalPort -eq 53});"+
  "$tcp=@(Get-NetTCPConnection -State Listen -ErrorAction Stop|Where-Object{[int]$_.LocalPort -eq 53});"+
  "if($running.Count -ne 0 -or $udp.Count -ne 0 -or $tcp.Count -ne 0){throw 'DNS port 53 or VOLVE DNS process still active'};"+
  "if(-not [IO.File]::Exists($old)){throw 'Legacy motor disappeared'};"+
  "$actualOld=(Get-FileHash -LiteralPath $old -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant();"+
  "if($actualOld -cne $oldSHA){throw 'Original executable bytes changed'};"+
  "$bytes=[IO.File]::ReadAllBytes($xmlFile);"+
  "$sha=[Security.Cryptography.SHA256]::Create();"+
  "try{$actualXML=[BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()};"+
  "if($actualXML -cne $xmlSHA){throw 'Sealed original Scheduler XML changed'};"+
  "if($isOriginal){Write-Output 'VOLVE_SIGNED_ORIGINAL_TASK_RESTORED';return};"+
  "$isUTF16=($bytes.Length -ge 2 -and (($bytes[0] -eq 255 -and $bytes[1] -eq 254) -or ($bytes[0] -eq 254 -and $bytes[1] -eq 255)));"+
  "if($isUTF16){if($bytes[0] -eq 255){$enc=[Text.Encoding]::Unicode}else{$enc=[Text.Encoding]::BigEndianUnicode};$xml=$enc.GetString($bytes,2,$bytes.Length-2)}"+
  "else{$enc=[Text.UTF8Encoding]::new($false,$true);$xml=$enc.GetString($bytes)};"+
  "$xml=[regex]::Replace($xml,'(?s)\\A\\s*<\\?xml[^>]*\\?>\\s*','');"+
  "Register-ScheduledTask -TaskName $task -TaskPath '\\' -Xml $xml -Force -ErrorAction Stop|Out-Null;"+
  "$restored=Get-ScheduledTask -TaskName $task -TaskPath '\\' -ErrorAction Stop;"+
  "if($restored.TaskPath -ne '\\' -or $restored.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or @($restored.Actions).Count -ne 1 -or "+
   "[string]$restored.Actions[0].Execute -ine $old -or [string]$restored.Actions[0].Arguments -cne '--dns-service'){throw 'Restored SYSTEM task identity differs from original'};"+
  "Write-Output 'VOLVE_SIGNED_ORIGINAL_TASK_RESTORED'"
 result,err:=deps.RunWindowsTask(ctx,script)
 if err!=nil{return fmt.Errorf("signed original SYSTEM task import failed: %w (%s)",err,result)}
 if strings.TrimSpace(result)!="VOLVE_SIGNED_ORIGINAL_TASK_RESTORED"{
  return fmt.Errorf("unexpected Scheduler recovery response: %q",result)
 }
 // No receipt, no Process Start, no DNS health claim. A separate privileged
 // watchdog must prove startup/Internet after the next task execution.
 return nil
}
