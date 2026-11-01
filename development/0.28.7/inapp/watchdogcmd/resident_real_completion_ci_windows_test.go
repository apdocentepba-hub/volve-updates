//go:build windows

package main

// Hosted Windows CI ONLY. This observes a REAL disposable SYSTEM process,
// Scheduler action, byte-exact restored EXE, actual UDP/53 IPv4+IPv6 responses
// and external numeric-IP TCP connectivity. It does not authorize or touch a
// production task or an installed Windows DNS adapter.
import (
 "context"
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "time"

 "volve-browser-protection/dnsproxy"
 "volve-browser-protection/motorupdate"
)

type residentCIActualCompletion struct {
 root string
 disposableTask string
 identityChecks int
 dnsProbes int
 internetProbes int
}

func (h *residentCIActualCompletion) VerifyRunningIdentity(
 ctx context.Context,intent motorupdate.ResidentRecoveryIntent,outcome string,
) error {
 if h==nil || outcome!="restored" ||
  os.Getenv("GITHUB_ACTIONS")!="true" ||
  os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted" ||
  !pilotTaskPattern.MatchString(h.disposableTask) {
  return errors.New("only restored disposable hosted-Windows CI SYSTEM identity is permitted")
 }
 path:=filepath.Join(h.root,residentLegacyExe)
 hash,err:=digestResidentLive(ctx,path)
 if err!=nil{return fmt.Errorf("restored legacy executable unreadable: %w",err)}
 if hash!=intent.LegacySHA256 {
  return errors.New("restored executable does not match sealed journal's original SHA-256")
 }
 // Validate the actual scheduler action, process SID and socket ownership
 // together in Windows, not only the Go hash. A different DNS service on
 // port 53 may NOT impersonate a recovered VOLVE task.
 script:="$ErrorActionPreference='Stop';"+
  "$task="+q(h.disposableTask)+";$exe="+q(path)+";"+
  "$s=Get-ScheduledTask -TaskName $task -TaskPath '\\' -ErrorAction Stop;"+
  "if($s.TaskPath -ne '\\' -or $s.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or @($s.Actions).Count -ne 1 -or "+
  "[string]$s.Actions[0].Execute -ine $exe -or [string]$s.Actions[0].Arguments -cne '--dns-service'){throw 'task identity changed'};"+
  "$p=@(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {[string]$_.ExecutablePath -ieq $exe});"+
  "if($p.Count -ne 1){throw 'expected one exact restored process'};"+
  "$owner=Invoke-CimMethod -InputObject $p[0] -MethodName GetOwnerSid -ErrorAction Stop;"+
  "if($owner.ReturnValue -ne 0 -or $owner.Sid -ne 'S-1-5-18'){throw 'DNS process does not run as SYSTEM'};"+
  "foreach($ip in @('127.0.0.1','::1')){"+
  "$ports=@(Get-NetUDPEndpoint -LocalAddress $ip -LocalPort 53 -ErrorAction Stop);"+
  "if($ports.Count -ne 1 -or $ports[0].OwningProcess -ne $p[0].ProcessId){throw ('wrong UDP/53 owner: '+$ip)}};"+
  "Write-Output 'CI_ACTUAL_SYSTEM_DNS_IDENTITY_OK'"
 answer,err:=ps(ctx,script)
 if err!=nil || answer!="CI_ACTUAL_SYSTEM_DNS_IDENTITY_OK" {
  return fmt.Errorf("real Windows Scheduler/process/socket identity untrusted: %s %w",answer,err)
 }
 h.identityChecks++
 return nil
}

func (h *residentCIActualCompletion) ProbeLocalDNS(ctx context.Context) error {
 for _,endpoint:=range []string{"127.0.0.1:53","[::1]:53"} {
  for _,test:=range []struct{name string;rcode byte}{
   {"stake.com",3},{"betwarrior.bet.ar",3},{"example.org",0},
  } {
   probeCtx,cancel:=context.WithTimeout(ctx,2*time.Second)
   rcode,err:=dnsproxy.QueryRCode(probeCtx,endpoint,test.name)
   cancel()
   if err!=nil || rcode!=test.rcode {
    return fmt.Errorf("real recovered DNS query %s via %s: rcode=%d expected=%d err=%v",
     test.name,endpoint,rcode,test.rcode,err)
   }
  }
 }
 h.dnsProbes++
 return nil
}

func (h *residentCIActualCompletion) ProbeConnectivity(ctx context.Context)error{
 // This is real external TCP reachability from the disposable runner,
 // not an injected positive result, not an HTTP content or DNS-resolution
 // proof. Missing Internet MUST leave the protected journal pending.
 if err:=motorupdate.ProbeResidentExternalInternet(ctx);err!=nil {
  return fmt.Errorf("hosted Windows external direct-TCP health not proven: %w",err)
 }
 h.internetProbes++
 return nil
}

func certifyActualCIResidentOutcome(
 ctx context.Context,root,journalDir,task string,
 seal,protect func(string)error,
) error{
 if os.Getenv("GITHUB_ACTIONS")!="true" ||
  os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted" ||
  !pilotTaskPattern.MatchString(task) {
  return errors.New("real completion audit restricted to hosted disposable SYSTEM task")
 }
 checks:=&residentCIActualCompletion{root:root,disposableTask:task}
 if err:=motorupdate.ConfirmResidentRecoveryOutcome(
  ctx,journalDir,"restored",seal,protect,checks);err!=nil {
  return fmt.Errorf("real recovered motor health did not qualify for terminal receipt: %w",err)
 }
 if checks.identityChecks!=2 || checks.dnsProbes!=1 || checks.internetProbes!=1{
  return fmt.Errorf("incomplete independent real health chain: %+v",checks)
 }
 after,err:=motorupdate.InspectResidentRecoveryJournal(ctx,journalDir,protect)
 if err!=nil||after.Status!="restored"{
  return fmt.Errorf("verified real SYSTEM/DNS/Internet recovery has no terminal journal: %+v %v",after,err)
 }
 // Terminal state may not be accepted as a fresh transaction a second time.
 // No duplicate receipt can be made by retries or crashes.
 if err:=motorupdate.ConfirmResidentRecoveryOutcome(
  ctx,journalDir,"restored",seal,protect,checks);err==nil {
  return errors.New("terminal journal incorrectly accepted a second finish")
 }
 if checks.identityChecks!=2 || checks.dnsProbes!=1 || checks.internetProbes!=1{
  return errors.New("terminal retry unnecessarily re-ran health or rewrote receipt")
 }
 if _,err:=os.Stat(filepath.Join(journalDir,motorupdate.ResidentResultFile));err!=nil{
  return fmt.Errorf("create-only terminal recovery receipt absent: %w",err)
 }
 return nil
}

// The constructor and probe interface are test-scoped only; the production
// watchdog is deliberately NOT wired to this CI adapter.
var _ motorupdate.ResidentCompletionChecks=(*residentCIActualCompletion)(nil)
