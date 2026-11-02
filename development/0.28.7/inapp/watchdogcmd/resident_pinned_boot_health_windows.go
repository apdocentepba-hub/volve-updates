//go:build windows

package main

// PRIVATE production-identity health adapter for a FUTURE signed reboot
// recovery watchdog. Construction and all probes are READ-ONLY; this file
// does not install/start a task, alter adapters, register a service, or
// activate the productive recovery CLI. It does not imply reboot acceptance.
import (
 "context"
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "strings"
 "time"

 "volve-browser-protection/dnsproxy"
 "volve-browser-protection/motorupdate"
)

type residentPinnedBootHealthWindows struct {
 root string
 verifySystem func(context.Context)error
 verifyACL func(string)error
 queryWindows func(context.Context,string)(string,error)
}
var _ motorupdate.ResidentCompletionChecks = (*residentPinnedBootHealthWindows)(nil)

// newPinnedResidentBootHealthWindows NEVER accepts a caller-provided
// publisher, task, identity predicate or PowerShell executor. The actual
// token must be LocalSystem even to construct the check object, and identity
// is independently re-attested on every subsequent health operation.
func newPinnedResidentBootHealthWindows(ctx context.Context,root string)(
 motorupdate.ResidentCompletionChecks,error,
){
 if err:=ctx.Err();err!=nil{return nil,err}
 if !filepath.IsAbs(root)||filepath.Clean(root)!=root{
  return nil,errors.New("recovery health root must be canonical and absolute")
 }
 if err:=verifyResidentActualSYSTEM(ctx);err!=nil{
  return nil,fmt.Errorf("recovery health requires actual LocalSystem token: %w",err)
 }
 return &residentPinnedBootHealthWindows{
  root:root,
  verifySystem:verifyResidentActualSYSTEM,
  verifyACL:func(path string)error{return checkResidentJournalNTFS(ctx,path)},
  queryWindows:ps,
 },nil
}

// VerifyRunningIdentity must be called by the boot policy under its existing
// protected kernel mutex. It checks the PHYSICAL original binary, full SYSTEM
// Scheduler action, live process owner SID and both loopback UDP53 owners.
// It is not a replacement for the independently signed journal/grant audit.
func(h *residentPinnedBootHealthWindows)VerifyRunningIdentity(
 ctx context.Context,intent motorupdate.ResidentRecoveryIntent,outcome string,
)error{
 if err:=ctx.Err();err!=nil{return err}
 if h==nil||h.verifySystem==nil||h.verifyACL==nil||h.queryWindows==nil||
  !filepath.IsAbs(h.root)||filepath.Clean(h.root)!=h.root||
  outcome!="restored"||intent.Task!="VOLVE-DNS-SERVER-0270"||
  intent.TargetVersion!="0.28.7"||!validSHA.MatchString(intent.LegacySHA256){
  return errors.New("restored original SYSTEM health lacks exact trusted identity")
 }
 if err:=h.verifySystem(ctx);err!=nil{return fmt.Errorf("original DNS process check requires SYSTEM: %w",err)}
 old:=filepath.Join(h.root,residentLegacyExe)
 for _,p:=range []string{h.root,old}{
  if err:=h.verifyACL(p);err!=nil{return fmt.Errorf("original DNS health NTFS ACL refused: %w",err)}
 }
 info,err:=os.Lstat(old)
 if err!=nil{return fmt.Errorf("restored original absent: %w",err)}
 if !info.Mode().IsRegular()||info.Size()<1||info.Size()>chainLegacyMax{
  return errors.New("restored executable is linked, empty or outside bounds")
 }
 hash,err:=digestResidentLive(ctx,old)
 if err!=nil||hash!=intent.LegacySHA256{
  return errors.New("live original binary does not equal journal-pinned SHA-256")
 }
 script:="$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';"+
  "$ident=[Security.Principal.WindowsIdentity]::GetCurrent();"+
  "if($ident.User.Value -ne 'S-1-5-18'){throw 'SYSTEM identity required for original health'};"+
  "$old="+q(old)+";$sha="+q(intent.LegacySHA256)+";"+
  "$t=Get-ScheduledTask -TaskName 'VOLVE-DNS-SERVER-0270' -TaskPath '\\' -ErrorAction Stop;"+
  "if(@($t).Count -ne 1 -or $t.TaskPath -ne '\\' -or "+
  "$t.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or "+
  "$t.State -ne 'Running' -or @($t.Actions).Count -ne 1 -or "+
  "[string]$t.Actions[0].Execute -ine $old -or "+
  "[string]$t.Actions[0].Arguments -cne '--dns-service'){throw 'original SYSTEM task is not exact and Running'};"+
  "$now=(Get-FileHash -LiteralPath $old -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant();"+
  "if($now -cne $sha){throw 'original bytes changed during health'};"+
  "$p=@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object{[string]$_.ExecutablePath -ieq $old});"+
  "if($p.Count -ne 1){throw 'restored original has no unique running process'};"+
  "$owner=Invoke-CimMethod -InputObject $p[0] -MethodName GetOwnerSid -ErrorAction Stop;"+
  "if($owner.ReturnValue -ne 0 -or $owner.Sid -ne 'S-1-5-18'){throw 'restored DNS process owner is not SYSTEM'};"+
  "foreach($ip in @('127.0.0.1','::1')){"+
  "$port=@(Get-NetUDPEndpoint -LocalAddress $ip -LocalPort 53 -ErrorAction Stop);"+
  "if($port.Count -ne 1 -or $port[0].OwningProcess -ne $p[0].ProcessId){throw ('original DNS UDP53 owner mismatch: '+$ip)}};"+
  "Write-Output 'VOLVE_ORIGINAL_SYSTEM_DNS53_IDENTITY_VERIFIED'"
 out,err:=h.queryWindows(ctx,script)
 if err!=nil||strings.TrimSpace(out)!="VOLVE_ORIGINAL_SYSTEM_DNS53_IDENTITY_VERIFIED"{
  return fmt.Errorf("restored Windows task/process/DNS53 identity not proven: %w",errors.Join(err,errors.New("unexpected or absent signed health token")))
 }
 return ctx.Err()
}

func(h *residentPinnedBootHealthWindows)ProbeLocalDNS(ctx context.Context)error{
 if err:=ctx.Err();err!=nil{return err}
 if h==nil||h.verifySystem==nil{return errors.New("no SYSTEM health observer")}
 if err:=h.verifySystem(ctx);err!=nil{return err}
 // Must prove actual A/AAAA answers (not a fabricated NOERROR response),
 // and that the DNS filter actively rejects two independent gambling sites
 // on BOTH families. No Windows DNS adapter is changed.
 if err:=motorupdate.ProbeResidentDNSLoopbacks(ctx,"127.0.0.1:53","[::1]:53");err!=nil{
  return fmt.Errorf("restored loopback DNS A/AAAA answers not proven: %w",err)
 }
 for _,endpoint:=range []string{"127.0.0.1:53","[::1]:53"}{
  for _,domain:=range []string{"stake.com","betwarrior.bet.ar"}{
   bounded,cancel:=context.WithTimeout(ctx,3*time.Second)
   rcode,err:=dnsproxy.QueryRCode(bounded,endpoint,domain)
   cancel()
   if err!=nil||rcode!=3{return fmt.Errorf("restored motor did not deny gambling DNS on %s: %w",endpoint,errors.Join(err,errors.New("unexpected DNS RCODE")))}
  }
 }
 return ctx.Err()
}

func(h *residentPinnedBootHealthWindows)ProbeConnectivity(ctx context.Context)error{
 if err:=ctx.Err();err!=nil{return err}
 if h==nil||h.verifySystem==nil{return errors.New("no SYSTEM health observer")}
 if err:=h.verifySystem(ctx);err!=nil{return err}
 // IP-only direct TCP reachability: independent of DNS, no HTTP requests.
 return motorupdate.ProbeResidentExternalInternet(ctx)
}
