//go:build windows

package main

// Hosted Windows VM ONLY: exercise a real SYSTEM task, an actual executable
// restored from a sealed NTFS snapshot and real dual-stack UDP/53 responses.
// The executable compiled here is a MINIMAL CI DNS fixture, NOT VOLVE's
// production motor. No host adapter, production task or journal receipt
// may be changed by this test.
import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "testing"
 "time"

 "volve-browser-protection/dnsproxy"
 "volve-browser-protection/motorupdate"
)

const disposableDualStackDNSSource=`package main
import("net";"os";"strings")
func main(){
 if len(os.Args)!=2||os.Args[1]!="--dns-service"{os.Exit(2)}
 a,e:=net.ListenPacket("udp4","127.0.0.1:53");if e!=nil{os.Exit(3)}
 b,e:=net.ListenPacket("udp6","[::1]:53");if e!=nil{a.Close();os.Exit(4)}
 go serve(a);serve(b)
}
func serve(p net.PacketConn){
 defer p.Close()
 buf:=make([]byte,2048)
 for{
  n,peer,e:=p.ReadFrom(buf);if e!=nil{return};if n<17{continue}
  name,off:="",12
  for off<n{size:=int(buf[off]);off++;if size==0{break}
   if size>63||off+size>n{off=n;break}
   if name!=""{name+="."};name+=string(buf[off:off+size]);off+=size
  }
  if off+4>n{continue}
  response:=append([]byte(nil),buf[:off+4]...)
  response[2]=0x81;response[3]=0x83
  if strings.EqualFold(name,"example.org"){response[3]=0x80}
  for i:=6;i<12;i++{response[i]=0}
  _,_=p.WriteTo(response,peer)
 }
}
`

func installCILiveDNSBytesIntoProtectedFixture(t *testing.T,root,journalDir string){
 t.Helper()
 old:=filepath.Join(root,residentLegacyExe)
 source:=filepath.Join(root,"ci-disposable-dns.go")
 if err:=os.WriteFile(source,[]byte(disposableDualStackDNSSource),0600);err!=nil{t.Fatal(err)}
 t.Cleanup(func(){_ = os.Remove(source)})
 // Build a real Windows binary with NO network-access code beyond the
 // isolated UDP reply loop; it does NOT use the installed VOLVE engine.
 cmd:=exec.Command("go","build","-trimpath","-o",old,source)
 cmd.Dir=root
 if out,err:=cmd.CombinedOutput();err!=nil{t.Fatalf("CI DNS fixture compile failed: %v %s",err,out)}
 data,err:=os.ReadFile(old);if err!=nil{t.Fatal(err)}
 hash:=sha256.Sum256(data)
 actualSHA:=hex.EncodeToString(hash[:])
 backup:=filepath.Join(root,residentRecoveryParent,residentRecoveryFolder)
 if err:=os.WriteFile(filepath.Join(backup,residentRecoveryExe),data,0600);err!=nil{t.Fatal(err)}
 recordPath:=filepath.Join(backup,residentRecoveryReceipt)
 raw,err:=os.ReadFile(recordPath);if err!=nil{t.Fatal(err)}
 var receipt motorupdate.LegacyRecoveryRecord
 if err:=json.Unmarshal(raw,&receipt);err!=nil{t.Fatal(err)}
 receipt.ExeSHA256=actualSHA
 receipt.ExeSize=int64(len(data))
 output,err:=json.Marshal(receipt);if err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(recordPath,output,0600);err!=nil{t.Fatal(err)}
 journalPath:=filepath.Join(journalDir,motorupdate.ResidentIntentFile)
 raw,err=os.ReadFile(journalPath);if err!=nil{t.Fatal(err)}
 var intent motorupdate.ResidentRecoveryIntent
 if err:=json.Unmarshal(raw,&intent);err!=nil{t.Fatal(err)}
 intent.LegacySHA256=actualSHA
 output,err=json.Marshal(intent);if err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(journalPath,append(output,'\n'),0600);err!=nil{t.Fatal(err)}
 // Re-confirm every original/journal ACL and digest before making ANY
 // Windows Scheduler change. This is synthetic local CI trust only.
 if _,err:=auditPostSwitchResidentRecovery(context.Background(),root);err!=nil{
  t.Fatalf("repacked CI DNS fixture not protected: %v",err)
 }
}

func probeCIRestoredDNS(t *testing.T) {
 t.Helper()
 for _,addr:=range []string{"127.0.0.1:53","[::1]:53"} {
  for _,item:=range []struct{name string;rcode byte}{
   {"stake.com",3},{"betwarrior.bet.ar",3},{"example.org",0},
  }{
   good:=false
   for i:=0;i<22;i++{
    ctx,cancel:=context.WithTimeout(context.Background(),600*time.Millisecond)
    got,err:=dnsproxy.QueryRCode(ctx,addr,item.name)
    cancel()
    if err==nil&&got==item.rcode{good=true;break}
    time.Sleep(200*time.Millisecond)
   }
   if !good{t.Fatalf("restored SYSTEM fixture failed dual-stack DNS: %s %s rcode=%d",addr,item.name,item.rcode)}
  }
 }
}

func TestPostSwitchRestoredSystemTaskActuallyServesDualStackDNS53CILab(t *testing.T){
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{
  t.Skip("hosted disposable VM only")
 }
 ctx,cancel:=context.WithTimeout(context.Background(),240*time.Second)
 defer cancel()
 // Native OS verification and bind preflight: no production task
 // and no existing local DNS53 owner may be displaced.
 before:="$ErrorActionPreference='Stop';"+
  "$id=[Security.Principal.WindowsIdentity]::GetCurrent();"+
  "$p=[Security.Principal.WindowsPrincipal]::new($id);"+
  "if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'CI not admin'};"+
  "$vm=Get-CimInstance Win32_ComputerSystem;"+
  "if(($vm.Manufacturer+' '+$vm.Model) -notmatch '(?i:virtual machine|vmware|hyper-v|kvm|qemu|virtualbox)'){throw 'not isolated VM'};"+
  "if(Get-ScheduledTask -TaskName 'VOLVE-DNS-SERVER-0270' -ErrorAction SilentlyContinue){throw 'productive task present'};"+
  "foreach($ip in @('127.0.0.1','::1')){if(@(Get-NetUDPEndpoint -LocalAddress $ip -LocalPort 53 -ErrorAction SilentlyContinue).Count -ne 0){throw ('DNS port busy: '+$ip)}};"+
  "Write-Output 'CI_DNS_VM_READY'"
 out,err:=ps(ctx,before)
 if err!=nil||out!="CI_DNS_VM_READY"{t.Fatalf("unsafe hosted Windows DNS state: %s %v",out,err)}
 root,journalDir,_,protect:=chainFixture(t,false)
 installCILiveDNSBytesIntoProtectedFixture(t,root,journalDir)
 old:=filepath.Join(root,residentLegacyExe)
 task:=fmt.Sprintf("VOLVE-CI-ManagedMotor-%d",time.Now().UnixNano())
 if !pilotTaskPattern.MatchString(task){t.Fatal("unsafe task ID")}
 target,err:=residentPilotTargetPath(root,"0.28.7")
 if err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(target,[]byte("CI_NEW_TARGET_INERT"),0600);err!=nil{t.Fatal(err)}
 setup:="$ErrorActionPreference='Stop';$n="+q(task)+";"+
  "if(Get-ScheduledTask -TaskName $n -TaskPath '\\' -ErrorAction SilentlyContinue){throw 'disposable task already exists'};"+
  "$a=New-ScheduledTaskAction -Execute "+q(target)+" -Argument '--dns-service';"+
  "$p=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest;"+
  "$tr=New-ScheduledTaskTrigger -AtStartup;"+
  "Register-ScheduledTask -TaskName $n -TaskPath '\\' -Action $a -Principal $p -Trigger $tr -ErrorAction Stop|Out-Null;"+
  "Write-Output 'CI_TARGET_SYSTEM_TASK_READY'"
 cleanup:="$ErrorActionPreference='Stop';$n="+q(task)+";"+
  "$s=Get-ScheduledTask -TaskName $n -TaskPath '\\' -ErrorAction SilentlyContinue;"+
  "if($null -ne $s){if($s.Principal.UserId -notin @('SYSTEM','S-1-5-18')){throw 'foreign task owner'};"+
  "if($s.State -eq 'Running'){Stop-ScheduledTask -TaskName $n -ErrorAction Stop};"+
  "Unregister-ScheduledTask -TaskName $n -TaskPath '\\' -Confirm:$false -ErrorAction Stop};"+
  "Write-Output 'CI_DNS_TEMP_TASK_CLEAN'"
 t.Cleanup(func(){
  cleanCtx,done:=context.WithTimeout(context.Background(),30*time.Second);defer done()
  result,err:=ps(cleanCtx,cleanup)
  if err!=nil||result!="CI_DNS_TEMP_TASK_CLEAN"{t.Errorf("CI DNS task cleanup failed: %s %v",result,err)}
  // Only our verified CI root binary is eligible for forced termination.
  safety:="$ErrorActionPreference='Stop';"+
   "$path="+q(old)+";"+
   "$running=@(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {[string]$_.ExecutablePath -ieq $path});"+
   "foreach($p in $running){Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop};"+
   "Write-Output 'CI_NO_OWN_DNS_PROCESS'"
  if v,e:=ps(cleanCtx,safety);e!=nil||v!="CI_NO_OWN_DNS_PROCESS"{t.Errorf("CI process cleanup not proven: %s %v",v,e)}
 })
 if out,err:=ps(ctx,setup);err!=nil||out!="CI_TARGET_SYSTEM_TASK_READY"{
  t.Fatalf("failed registering disposable SYSTEM target: %s %v",out,err)
 }
 if err:=os.Remove(old);err!=nil{t.Fatal(err)}
 if err:=restoreMissingOriginalAndDisposableTaskCILab(ctx,root,task,ps);err!=nil{
  t.Fatalf("combined protected EXE+Scheduler restore failed: %v",err)
 }
 start:="$ErrorActionPreference='Stop';$n="+q(task)+";"+
  "$s=Get-ScheduledTask -TaskName $n -TaskPath '\\' -ErrorAction Stop;"+
  "if($s.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or @($s.Actions).Count -ne 1 -or [string]$s.Actions[0].Execute -ine "+q(old)+"){throw 'restored task not exact'};"+
  "Start-ScheduledTask -TaskName $n -TaskPath '\\' -ErrorAction Stop;"+
  "Write-Output 'CI_RECOVERED_TASK_STARTED'"
 if out,err:=ps(ctx,start);err!=nil||out!="CI_RECOVERED_TASK_STARTED"{
  t.Fatalf("cannot start verified restored SYSTEM DNS task: %s %v",out,err)
 }
 probeCIRestoredDNS(t)
 owner:="$ErrorActionPreference='Stop';$path="+q(old)+";"+
  "$p=@(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {[string]$_.ExecutablePath -ieq $path});"+
  "if($p.Count -ne 1){throw 'expected exactly one restored DNS process'};"+
  "$owner=Invoke-CimMethod -InputObject $p[0] -MethodName GetOwnerSid -ErrorAction Stop;"+
  "if($owner.ReturnValue -ne 0 -or $owner.Sid -ne 'S-1-5-18'){throw 'restored DNS motor not SYSTEM'};"+
  "foreach($ip in @('127.0.0.1','::1')){"+
  "$listeners=@(Get-NetUDPEndpoint -LocalAddress $ip -LocalPort 53 -ErrorAction Stop);"+
  "if($listeners.Count -ne 1 -or $listeners[0].OwningProcess -ne $p[0].ProcessId){throw ('DNS port owner changed: '+$ip)}};"+
  "Write-Output 'CI_RESTORED_SYSTEM_OWNS_BOTH_DNS53'"
 if out,err:=ps(ctx,owner);err!=nil||out!="CI_RESTORED_SYSTEM_OWNS_BOTH_DNS53"{
  t.Fatalf("DNS answered but SYSTEM or socket ownership unverified: %s %v",out,err)
 }
 state,err:=motorupdate.InspectResidentRecoveryJournal(ctx,journalDir,protect)
 if err!=nil||state.Status!="recovery-required"{
  t.Fatalf("synthetic DNS network health incorrectly finalized migration: %+v %v",state,err)
 }
 t.Log("PASS: protected original EXE+real SYSTEM Task Scheduler restored; real UDP/53 IPv4+IPv6 responses; blocked/allowed DNS cases; journal pending")
}
