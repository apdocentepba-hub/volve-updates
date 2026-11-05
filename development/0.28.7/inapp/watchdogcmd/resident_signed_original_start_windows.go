//go:build windows

package main

// Completes the protected ORIGINAL recovery sequence: after the exact old
// executable AND its original AtStartup SYSTEM task have been restored under
// the SAME Windows kernel mutex, request one Task Scheduler start. This
// routine does NOT activate a new candidate and DOES NOT claim DNS health.
// The independent boot policy still verifies identity/DNS/Internet twice and
// creates a terminal receipt only on actual restored health.
import (
 "context"
 "crypto/ed25519"
 "errors"
 "fmt"
 "path/filepath"
 "strings"
)

// Caller MUST already hold the global protected motor-transition mutex.
// Never use this function as a standalone CLI or from the ordinary panel.
// Every mandatory attestor is the same one that approved the signed task
// restoration; no opt-out flag, user-supplied script, task name or key.
func startSignedRestoredOriginalTaskLockedWindows(
 ctx context.Context, root string, publisher ed25519.PublicKey,
 deps residentSignedTaskRestoreDeps,
) error {
 if err:=ctx.Err();err!=nil{return err}
 if len(publisher)!=ed25519.PublicKeySize ||
  !filepath.IsAbs(root)||filepath.Clean(root)!=root ||
  deps.VerifySystem==nil||deps.VerifyACL==nil||
  deps.ProbeQuiescence==nil||deps.RunWindowsTask==nil{
  return errors.New("signed original start requires exact publisher, canonical installation and protected SYSTEM gates")
 }
 if err:=deps.VerifySystem(ctx);err!=nil{return fmt.Errorf("original restart requires SYSTEM: %w",err)}
 evidence,err:=auditResidentSignedBootAdmissionLocked(
  ctx,root,publisher,deps.VerifyACL,deps.VerifyACL,deps.VerifyACL,deps.ProbeQuiescence)
 if err!=nil{return fmt.Errorf("signed original startup grant rejected: %w",err)}
 if evidence.Status!="recovery-required"||evidence.Action!="signed-evidence-verified-read-only"||
  !evidence.PublisherVerified||!evidence.QuiescenceVerified||
  evidence.OriginalFileState!="original-intact" {
  return errors.New("only an exact original with pending signed grant and inactive DNS can be restarted")
 }
 original:=filepath.Join(root,residentLegacyExe)
 if err:=deps.VerifyACL(root);err!=nil{return fmt.Errorf("installed motor root ACL unsafe: %w",err)}
 if err:=deps.VerifyACL(original);err!=nil{return fmt.Errorf("original executable ACL unsafe: %w",err)}
 oldHash,err:=digestResidentLive(ctx,original)
 if err!=nil||oldHash!=evidence.OriginalSHA256{
  return errors.New("installed original executable differs from publisher-pinned recovery hash")
 }
 // Re-check the signed grant and every process/DNS53 quiescence fence after
 // all disk reads, keeping the same Windows kernel lease.
 last,err:=auditResidentSignedBootAdmissionLocked(
  ctx,root,publisher,deps.VerifyACL,deps.VerifyACL,deps.VerifyACL,deps.ProbeQuiescence)
 if err!=nil||last!=evidence{
  return fmt.Errorf("signed recovery or DNS ownership changed just before original restart: %w",err)
 }
 if err:=deps.VerifySystem(ctx);err!=nil{return err}
 if err:=ctx.Err();err!=nil{return err}

 // Under one privileged command revalidate actual SYSTEM identity, the
 // exact restored task action/AtStartup trigger, absent motor processes and
 // unoccupied port53, and the backed-up EXE hash immediately before START.
 // The only writable action here is Start-ScheduledTask on this ONE name.
 script:="$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';"+
  "$identity=[Security.Principal.WindowsIdentity]::GetCurrent();"+
  "if($identity.User.Value -ne 'S-1-5-18'){throw 'original start requires actual SYSTEM'};"+
  "$task='VOLVE-DNS-SERVER-0270';$old="+q(original)+";$sha="+q(evidence.OriginalSHA256)+";"+
  "$t=Get-ScheduledTask -TaskName $task -TaskPath '\\' -ErrorAction Stop;"+
  "$triggers=@($t.Triggers|Where-Object{$null -ne $_});"+
  "$boot=@($triggers|Where-Object{$_.CimClass.CimClassName -eq 'MSFT_TaskBootTrigger'});"+
  "if($t.TaskPath -ne '\\' -or $t.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or "+
  "@($t.Actions).Count -ne 1 -or [string]$t.Actions[0].Execute -ine $old -or "+
  "[string]$t.Actions[0].Arguments -cne '--dns-service' -or $boot.Count -lt 1 -or "+
  "-not $t.Settings.Enabled -or $t.State -ne 'Ready'){throw 'signed original task not exactly restored/ready'};"+
  "$h=[IO.File]::OpenRead($old);$a=[Security.Cryptography.SHA256]::Create();"+
  "try{$actual=[BitConverter]::ToString($a.ComputeHash($h)).Replace('-','').ToLowerInvariant()}finally{$h.Dispose();$a.Dispose()};"+
  "if($actual -cne $sha){throw 'original executable changed at startup boundary'};"+
  "$prefix="+q(root+"\\")+";"+
  "$processes=@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object{"+
  "([string]$_.ExecutablePath).StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase) -and "+
  "([string]$_.Name -like 'VOLVE_DNS_*')});"+
  "$udp=@(Get-NetUDPEndpoint -ErrorAction Stop|Where-Object{[int]$_.LocalPort -eq 53});"+
  "$tcp=@(Get-NetTCPConnection -State Listen -ErrorAction Stop|Where-Object{[int]$_.LocalPort -eq 53});"+
  "if($processes.Count -ne 0 -or $udp.Count -ne 0 -or $tcp.Count -ne 0){throw 'DNS port53/process restarted before protected original task start'};"+
  "Start-ScheduledTask -TaskName $task -TaskPath '\\' -ErrorAction Stop;"+
  "Write-Output 'VOLVE_SIGNED_ORIGINAL_START_REQUESTED'"
 out,err:=deps.RunWindowsTask(ctx,script)
 if err!=nil{return fmt.Errorf("restored original task start failed: %w (%s)",err,out)}
 if strings.TrimSpace(out)!="VOLVE_SIGNED_ORIGINAL_START_REQUESTED"{
  return fmt.Errorf("ambiguous original SYSTEM task start response: %q",out)
 }
 // Do not create a terminal receipt, and do not claim recovered connectivity.
 return ctx.Err()
}
