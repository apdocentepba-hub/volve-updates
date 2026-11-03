//go:build windows && volveci

package main

// CI ONLY: runs the real Full VOLVE DNS engine from an ephemeral-signed
// candidate under a disposable SYSTEM task, then lets an independent SYSTEM
// watchdog restore that task's protected original. Never accesses real
// VOLVE tasks, adapter DNS configuration or the installed user's motor.
import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "net"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"

 "volve-browser-protection/dnsproxy"
 "volve-browser-protection/motorupdate"
)

func signedFullDNSHostSnapshot()(string,error){
 return labPS("$dns=(Get-DnsClientServerAddress -ErrorAction Stop | Sort-Object InterfaceIndex,AddressFamily | Select-Object InterfaceIndex,AddressFamily,ServerAddresses | ConvertTo-Json -Depth 6 -Compress);"+
  "$path=Join-Path $env:WINDIR 'System32\\drivers\\etc\\hosts';"+
  "$file=[IO.File]::OpenRead($path);$sha=[Security.Cryptography.SHA256]::Create();"+
  "try{$hostHash=[BitConverter]::ToString($sha.ComputeHash($file)).Replace('-','')}finally{$file.Dispose();$sha.Dispose()};"+
  "Write-Output ($dns+'|'+$hostHash)")
}

func TestSignedFullDNS53SYSTEMTaskAndIndependentRollback(t *testing.T){
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{
  t.Fatal("refusing live DNS53 lab outside disposable GitHub-hosted Windows")
 }
 if !isAdmin(){t.Fatal("actual Windows admin token required for isolated SYSTEM lab")}
 source:=os.Getenv("VOLVE_CI_FRESH_DNS53_EXE")
 watchdog:=os.Getenv("VOLVE_CI_MANAGED_WATCHDOG_EXE")
 for _,p:=range []string{source,watchdog}{
  if !filepath.IsAbs(p){t.Fatal("absolute precompiled candidate and independent watchdog required")}
  info,err:=os.Lstat(p)
  if err!=nil||!info.Mode().IsRegular()||info.Size()<1<<20{
   t.Fatalf("unverified original CI candidate or watchdog %q: %v",p,err)
  }
 }
 // Also requires a separate VM-only opt-in token; reject any preexisting 53.
 requireHostedVMPort53(t)
 provePort53Available(t)
 before,err:=signedFullDNSHostSnapshot();if err!=nil{t.Fatal(err)}
 id:=time.Now().UnixNano()
 programData:=os.Getenv("ProgramData")
 if !filepath.IsAbs(programData){t.Fatal("missing actual Windows ProgramData")}
 dnsRoot:=filepath.Join(programData,fmt.Sprintf("VOLVE-CI-FreshDNS53-%d",id))
 if _,err:=os.Lstat(dnsRoot);!errors.Is(err,os.ErrNotExist){t.Fatal("disposable DNS root collision or unsafe lstat")}
 name:=fmt.Sprintf("VOLVE-CI-ManagedMotor-%d",id)
 original:=filepath.Join(os.Getenv("WINDIR"),"System32","cmd.exe")
 if err:=createDisposableTask(name,original);err!=nil{t.Fatal(err)}
 root:=t.TempDir()
 candidate,key,_:=signedCompleteApplicationCandidate(t,root,source)
 d:=&managedWindowsTaskLab{
  name:name,root:filepath.Join(root,"transaction"),original:original,
  backup:filepath.Join(root,"transaction","original-task.xml"),publicKey:key,
 }
 watcherName:=fmt.Sprintf("VOLVE-CI-ManagedWatchdog-%d",time.Now().UnixNano())
 watcherCreated:=false
 t.Cleanup(func(){
  current,_,readErr:=d.currentAction()
  if readErr==nil&&d.installedExe!=""&&strings.EqualFold(filepath.Clean(current),filepath.Clean(d.installedExe)){
   if _,err:=labPS("Stop-ScheduledTask -TaskName "+labQuote(name)+" -ErrorAction Stop");err!=nil{
    t.Errorf("cannot stop exact disposable signed DNS candidate: %v",err)
   }
   if watcherCreated{
    if err:=startSYSTEMWatchdogLabTask(watcherName);err!=nil{t.Errorf("emergency independent SYSTEM recovery start failed: %v",err)}
   }
  }
  if watcherCreated{
   if err:=removeSYSTEMWatchdogLabTask(watcherName);err!=nil{t.Errorf("watchdog cleanup failed: %v",err)}
  }
  if err:=removeDisposableTask(name);err!=nil{t.Errorf("disposable motor task cleanup failed: %v",err)}
  after,err:=signedFullDNSHostSnapshot()
  if err!=nil{t.Errorf("network after trial unavailable: %v",err)
  }else if after!=before{t.Error("Windows DNS adapters or hosts changed in signed Full DNS trial")}
 })
 if err:=d.Snapshot(context.Background());err!=nil{t.Fatal(err)}
 journalPath:=filepath.Join(root,"recovery.json")
 writeCIWatchdogJournal(t,journalPath,ciWatchdogJournal{
  Schema:1,Phase:"pending",TaskName:name,OriginalExe:original,OriginalArgs:"/C exit 0",
  SnapshotFile:d.backup,SnapshotSHA256:d.originalHash,
 })
 secureCIPilotRecovery(t,journalPath,d.backup)
 if err:=createSYSTEMWatchdogLabTask(watcherName,watchdog,journalPath);err!=nil{t.Fatal(err)}
 watcherCreated=true
 if err:=d.InstallVersionedCandidate(context.Background(),candidate);err!=nil{t.Fatal(err)}
 signed,err:=motorupdate.VerifyStaged(d.installedExe,key)
 if err!=nil||signed.Version!="0.28.7"{t.Fatalf("installed real motor signature invalid: %v",err)}
 args:=fmt.Sprintf("--ci-fresh-dns53 %q %s",dnsRoot,ciFreshToken)
 if err:=switchVerifiedMotorTaskAction(context.Background(),name,original,
  "/C exit 0",d.installedExe,args,key);err!=nil{t.Fatal(err)}
 selected,selectedArgs,err:=d.currentAction()
 if err!=nil||!strings.EqualFold(filepath.Clean(selected),filepath.Clean(d.installedExe))||selectedArgs!=args{
  t.Fatalf("signed task action/arguments are wrong: %q %q %v",selected,selectedArgs,err)
 }
 if _,err:=labPS("Start-ScheduledTask -TaskName "+labQuote(name)+" -ErrorAction Stop");err!=nil{t.Fatal(err)}
 deadline:=time.Now().Add(45*time.Second)
 for _,host:=range []string{"127.0.0.1","::1"}{
  endpoint:=net.JoinHostPort(host,"53")
  for {
   ctx,stop:=context.WithTimeout(context.Background(),900*time.Millisecond)
   rcode,e:=dnsproxy.QueryRCode(ctx,endpoint,"stake.com");stop()
   if e==nil&&rcode==3{break}
   if time.Now().After(deadline){t.Fatalf("signed SYSTEM Full DNS did not start on %s: %v",endpoint,e)}
   time.Sleep(300*time.Millisecond)
  }
  for _,q:=range []struct{domain string;code byte}{
   {"stake.com",3},{"betwarrior.bet.ar",3},{"www.betwarrior.bet.ar",3},
   {"vm-ci-dns-400001.bet.ar",3},{"example.org",0},
  }{
   ctx,stop:=context.WithTimeout(context.Background(),3*time.Second)
   rc,e:=dnsproxy.QueryRCode(ctx,endpoint,q.domain);stop()
   if e!=nil||rc!=q.code{t.Fatalf("Full DNS %s %s code=%d expected=%d err=%v",endpoint,q.domain,rc,q.code,e)}
  }
 }
 // Require the exact signed executable process to own BOTH IPv4 and IPv6
 // UDP53 sockets as LOCAL SYSTEM, not a foreign DNS server on this runner.
 script:="$p=@(Get-CimInstance Win32_Process -Filter \"Name='VOLVE_DNS_Motor_0_28_7.exe'\" -ErrorAction Stop | Where-Object {$_.ExecutablePath -ieq "+labQuote(d.installedExe)+"});"+
  "if($p.Count -ne 1){throw 'Signed DNS process missing or duplicated'};"+
  "$o=Invoke-CimMethod -InputObject $p[0] -MethodName GetOwnerSid -ErrorAction Stop;"+
  "if($o.ReturnValue -ne 0 -or $o.Sid -ne 'S-1-5-18'){throw 'Signed motor did not run as SYSTEM'};"+
  "foreach($ip in @('127.0.0.1','::1')){$ep=@(Get-NetUDPEndpoint -LocalAddress $ip -LocalPort 53 -ErrorAction Stop);"+
  "if($ep.Count -ne 1 -or $ep[0].OwningProcess -ne $p[0].ProcessId){throw 'Wrong real SYSTEM DNS53 socket owner: '+$ip}};"+
  "Write-Output 'SIGNED_FULL_DNS53_SYSTEM_VERIFIED'"
 owner,err:=labPS(script)
 if err!=nil||owner!="SIGNED_FULL_DNS53_SYSTEM_VERIFIED"{t.Fatalf("live SYSTEM DNS53 identity not proven: %q %v",owner,err)}
 t.Log("PASS: signed real 400005-rule Full DNS motor answered IPv4+IPv6 UDP53, owned by SYSTEM")
 if _,err:=labPS("Stop-ScheduledTask -TaskName "+labQuote(name)+" -ErrorAction Stop");err!=nil{t.Fatal(err)}
 // The external watchdog, not the updater test process, restores Scheduler.
 if err:=startSYSTEMWatchdogLabTask(watcherName);err!=nil{t.Fatal(err)}
 until:=time.Now().Add(50*time.Second)
 for time.Now().Before(until){
  raw,readErr:=os.ReadFile(journalPath)
  if readErr==nil{
   var j ciWatchdogJournal
   if json.Unmarshal(raw,&j)==nil&&j.Phase=="restored"&&j.TaskName==name&&j.SnapshotSHA256==d.originalHash{
    action,actionArgs,e:=d.currentAction()
    if e!=nil||!strings.EqualFold(filepath.Clean(action),filepath.Clean(original))||actionArgs!="/C exit 0"{
     t.Fatalf("watchdog claimed restoration without original task action: %q %q %v",action,actionArgs,e)
    }
    xml,e:=os.ReadFile(d.backup);if e!=nil{t.Fatal(e)}
    hash:=sha256.Sum256(xml)
    if hex.EncodeToString(hash[:])!=d.originalHash{t.Fatal("sealed task XML changed during rollback")}
    if _,e:=motorupdate.VerifyStaged(d.installedExe,key);e!=nil{t.Fatalf("watchdog altered signed candidate: %v",e)}
    t.Log("PASS: independently scheduled SYSTEM watchdog restored exact protected task; signed candidate remains intact")
    return
   }
  }
  time.Sleep(450*time.Millisecond)
 }
 t.Fatal("independent SYSTEM watchdog did not restore original after signed real DNS53")
}
