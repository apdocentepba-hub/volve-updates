//go:build windows

package main

// Windows hosted CI: a REAL disposable Task Scheduler job is changed from a
// synthetic target action back to a protected original SYSTEM action.
// The old EXE is also physically restored from the sealed CI snapshot.
// No DNS motor is started; no actual VOLVE product task is touched.
import (
 "context"
 "errors"
 "encoding/base64"
 "unicode/utf16"
 "fmt"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "testing"
 "time"

 "volve-browser-protection/motorupdate"
)

func TestPostSwitchSystemTaskCILabRestoresRealDisposableSystemTaskAndOriginalBytes(t *testing.T){
 for _,scenario:=range []string{"missing","journal-pinned-replacement"}{
  t.Run(scenario,func(t *testing.T){
 if os.Getenv("GITHUB_ACTIONS")!="true"||
  os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{
  t.Skip("hosted Windows disposable GitHub runner required")
 }
 ctx,cancel:=context.WithTimeout(context.Background(),170*time.Second)
 defer cancel()
 // Reject non-admin/non-VM contexts before any Scheduler change.
 check:="$ErrorActionPreference='Stop';"+
  "$id=[Security.Principal.WindowsIdentity]::GetCurrent();"+
  "$p=[Security.Principal.WindowsPrincipal]::new($id);"+
  "if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'CI runner lacks administrator'};"+
  "$vm=Get-CimInstance Win32_ComputerSystem;"+
  "if(($vm.Manufacturer+' '+$vm.Model) -notmatch '(?i:virtual machine|vmware|hyper-v|kvm|qemu|virtualbox)'){throw 'not disposable virtual machine'};"+
  "Write-Output 'CI_VM_ADMIN_OK'"
 if result,err:=ps(ctx,check);err!=nil||result!="CI_VM_ADMIN_OK"{
  t.Fatalf("refusing Scheduler test outside verified disposable VM: %s %v",result,err)
 }
 root,journalDir,_,protect:=chainFixture(t,false)
 task:=fmt.Sprintf("VOLVE-CI-ManagedMotor-%d",time.Now().UnixNano())
 if !pilotTaskPattern.MatchString(task){t.Fatal("generated task not disposable")}
 target,err:=residentPilotTargetPath(root,"0.28.7")
 if err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(target,[]byte("CI_INERT_NEW_TARGET_NOT_EXECUTABLE"),0600);err!=nil{t.Fatal(err)}
 old:=filepath.Join(root,residentLegacyExe)
 original,err:=os.ReadFile(old);if err!=nil{t.Fatal(err)}
 create:="$ErrorActionPreference='Stop';"+
  "$n="+q(task)+";"+
  "$existing=Get-ScheduledTask -TaskName $n -TaskPath '\\' -ErrorAction SilentlyContinue;"+
  "if($null -ne $existing){throw 'CI task name already exists'};"+
  "$action=New-ScheduledTaskAction -Execute "+q(target)+" -Argument '--dns-service';"+
  "$principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest;"+
  "$trigger=New-ScheduledTaskTrigger -AtStartup;"+
  "Register-ScheduledTask -TaskName $n -TaskPath '\\' -Action $action -Principal $principal -Trigger $trigger -ErrorAction Stop|Out-Null;"+
  "$t=Get-ScheduledTask -TaskName $n -TaskPath '\\' -ErrorAction Stop;"+
  "if($t.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or @($t.Actions).Count -ne 1 -or [string]$t.Actions[0].Execute -ine "+q(target)+"){throw 'unexpected disposable task after registration'};"+
  "Write-Output 'CI_DISPOSABLE_TARGET_REGISTERED'"
 cleanup:="$ErrorActionPreference='Stop';"+
  "$n="+q(task)+";"+
  "$t=Get-ScheduledTask -TaskName $n -TaskPath '\\' -ErrorAction SilentlyContinue;"+
  "if($null -ne $t){"+
  "if($t.Principal.UserId -notin @('SYSTEM','S-1-5-18')){throw 'refusing to delete unrelated task'};"+
  "Unregister-ScheduledTask -TaskName $n -TaskPath '\\' -Confirm:$false -ErrorAction Stop};"+
  "if($null -ne (Get-ScheduledTask -TaskName $n -TaskPath '\\' -ErrorAction SilentlyContinue)){throw 'disposable task cleanup incomplete'};"+
  "Write-Output 'CI_DISPOSABLE_TASK_REMOVED'"
 t.Cleanup(func(){
  cleanCtx,cc:=context.WithTimeout(context.Background(),25*time.Second)
  defer cc()
  out,err:=ps(cleanCtx,cleanup)
  if err!=nil||out!="CI_DISPOSABLE_TASK_REMOVED"{t.Errorf("CI Scheduler cleanup failed: %s %v",out,err)}
 })
 if result,err:=ps(ctx,create);err!=nil||result!="CI_DISPOSABLE_TARGET_REGISTERED"{
  t.Fatalf("disposable SYSTEM task registration failed: %s %v",result,err)
 }
 switch scenario{
 case "missing":
  if err:=os.Remove(old);err!=nil{t.Fatal(err)}
 case "journal-pinned-replacement":
  // SHA-256 of these inert bytes is pinned in the protected CI journal.
  // Do not confuse this fixture with an authentic publisher-signed binary.
  if err:=os.WriteFile(old,[]byte("publisher-signed candidate CI bytes"),0600);err!=nil{t.Fatal(err)}
 }
 // The recovery helper must be a genuinely different OS process from
 // this test's parent/updater. This proves the sealed NTFS snapshot and
 // pending journal can be reread without parent process memory.
 output,childErr:=runIndependentCIRecovery(ctx,root,task)
 if childErr!=nil || !strings.Contains(string(output),"CI_EXTERNAL_RECOVERY_OK") {
  t.Fatalf("separate process file + real SYSTEM task restoration failed: %v %s",
   childErr,output)
 }
 restored,err:=os.ReadFile(old)
 if err!=nil||string(restored)!=string(original){
  t.Fatalf("physical original not restored byte-for-byte: %v",err)
 }
 validate:="$ErrorActionPreference='Stop';"+
  "$n="+q(task)+";"+
  "$t=Get-ScheduledTask -TaskName $n -TaskPath '\\' -ErrorAction Stop;"+
  "if($t.TaskPath -ne '\\' -or $t.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or @($t.Actions).Count -ne 1 -or [string]$t.Actions[0].Execute -ine "+q(old)+" -or [string]$t.Actions[0].Arguments -cne '--dns-service'){throw 'real SYSTEM task not restored'};"+
  "Write-Output 'CI_REAL_SYSTEM_TASK_RESTORED'"
 if result,err:=ps(ctx,validate);err!=nil||result!="CI_REAL_SYSTEM_TASK_RESTORED"{
  t.Fatalf("real Windows task not restored correctly: %s %v",result,err)
 }
 // Model a second reboot/crash BEFORE any healthy terminal result: run the
 // SAME independent watchdog process again while the real SYSTEM task is
 // ALREADY restored. This must succeed without re-importing or changing it.
 retryOutput,retryErr:=runIndependentCIRecovery(ctx,root,task)
 if retryErr!=nil || !strings.Contains(string(retryOutput),"CI_EXTERNAL_RECOVERY_OK"){
  t.Fatalf("already-restored SYSTEM task refused safe independent retry: %v %s",retryErr,retryOutput)
 }
 if result,err:=ps(ctx,validate);err!=nil||result!="CI_REAL_SYSTEM_TASK_RESTORED"{
  t.Fatalf("second recovery damaged exact SYSTEM task: %s %v",result,err)
 }
 current,err:=motorupdate.InspectResidentRecoveryJournal(ctx,journalDir,protect)
 if err!=nil||current.Status!="recovery-required"{
  t.Fatalf("task+file restore falsely published DNS success: %+v %v",current,err)
 }
 if _,err:=os.Lstat(filepath.Join(journalDir,motorupdate.ResidentResultFile));!os.IsNotExist(err){
  t.Fatalf("restored task falsely wrote DNS/Internet health receipt: %v",err)
 }
 // Anti-clobber regression: deliberately point ONLY our disposable test task
 // at the synthetic target with unauthorized arguments. An independent
 // retry must reject it before ANY task registration or terminal receipt.
 tamper:="$ErrorActionPreference='Stop';$n="+q(task)+";"+
  "$action=New-ScheduledTaskAction -Execute "+q(target)+" -Argument '--wrong-untrusted-arguments';"+
  "Set-ScheduledTask -TaskName $n -TaskPath '\\' -Action $action -ErrorAction Stop|Out-Null;"+
  "$s=Get-ScheduledTask -TaskName $n -TaskPath '\\' -ErrorAction Stop;"+
  "if([string]$s.Actions[0].Arguments -cne '--wrong-untrusted-arguments'){throw 'disposable tamper fixture not set'};"+
  "Write-Output 'CI_TEMPORARY_TASK_TAMPERED'"
 if out,err:=ps(ctx,tamper);err!=nil||out!="CI_TEMPORARY_TASK_TAMPERED"{
  t.Fatalf("could not prepare controlled disposable task tamper case: %s %v",out,err)
 }
 rejected,rejectErr:=runIndependentCIRecovery(ctx,root,task)
 if rejectErr==nil || strings.Contains(string(rejected),"CI_EXTERNAL_RECOVERY_OK"){
  t.Fatalf("unknown SYSTEM task arguments incorrectly authorized automatic rollback: %v %s",rejectErr,rejected)
 }
 verifyTamper:="$ErrorActionPreference='Stop';$n="+q(task)+";"+
  "$s=Get-ScheduledTask -TaskName $n -TaskPath '\\' -ErrorAction Stop;"+
  "if([string]$s.Actions[0].Arguments -cne '--wrong-untrusted-arguments'){throw 'unknown task unexpectedly overwritten'};"+
  "Write-Output 'CI_UNKNOWN_ACTION_UNTOUCHED'"
 if out,err:=ps(ctx,verifyTamper);err!=nil||out!="CI_UNKNOWN_ACTION_UNTOUCHED"{
  t.Fatalf("rejected retry changed another SYSTEM task action: %s %v",out,err)
 }
 still,err:=motorupdate.InspectResidentRecoveryJournal(ctx,journalDir,protect)
 if err!=nil||still.Status!="recovery-required"{
  t.Fatalf("rejected task tamper falsely closed pending recovery: %+v %v",still,err)
 }
 t.Logf("PASS: already-restored SYSTEM task independent retry idempotent, but unknown task arguments rejected without modification (scenario=%s); journal pending",scenario)
  })
 }
}

func TestPostSwitchSystemTaskCILabFailsBeforeSchedulerWhenOriginalIsDifferent(t *testing.T){
 root,_,_,_:=chainFixture(t,false)
 old:=filepath.Join(root,residentLegacyExe)
 if err:=os.WriteFile(old,[]byte("MZ_CI_DIFFERENT_ACTIVE_EXE"),0600);err!=nil{t.Fatal(err)}
 called:=0
 runner:=func(context.Context,string)(string,error){called++;return "",errors.New("should never run")}
 err:=restoreMissingOriginalAndDisposableTaskCILab(context.Background(),root,disposableResidentTask,runner)
 if err==nil||!strings.Contains(err.Error(),"different installed executable")||called!=0{
  t.Fatalf("different original bypassed no-clobber gate or reached Scheduler: %v calls=%d",err,called)
 }
}

func TestPostSwitchSystemTaskCILabRejectsProductiveTaskAndNonHostedRunner(t *testing.T){
 root,_,_,_:=chainFixture(t,false)
 called:=0
 runner:=func(context.Context,string)(string,error){called++;return "",errors.New("must not run")}
 for _,task:=range []string{"VOLVE-DNS-SERVER-0270","VOLVE-CI-ManagedMotor-42","unrelated"}{
  if err:=restoreMissingOriginalAndDisposableTaskCILab(context.Background(),root,task,runner);err==nil{
   t.Fatalf("unsafe Scheduler identity accepted: %q",task)
  }
 }
 if called!=0{t.Fatal("unsafe task invoked external Scheduler runner")}
}

func TestPostSwitchSystemTaskCILabExternalChild(t *testing.T){
 if os.Getenv("VOLVE_CI_TASK_RESTORE_CHILD")!="1"{return}
 if os.Getenv("GITHUB_ACTIONS")!="true" ||
  os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{
  t.Fatal("independent recovery child requires ephemeral GitHub-hosted Windows runner")
 }
 root:=os.Getenv("VOLVE_CI_TASK_RESTORE_ROOT")
 task:=os.Getenv("VOLVE_CI_TASK_RESTORE_NAME")
 if !pilotTaskPattern.MatchString(task) || !filepath.IsAbs(root) ||
  filepath.Clean(root)!=root {
  t.Fatal("external recovery child target is not an allowlisted CI task and canonical root")
 }
 ctx,cancel:=context.WithTimeout(context.Background(),110*time.Second)
 defer cancel()
 if err:=restoreMissingOriginalAndDisposableTaskCILab(ctx,root,task,ps);err!=nil{
  t.Fatalf("fresh process could not restore protected original and SYSTEM task: %v",err)
 }
 t.Log("CI_EXTERNAL_RECOVERY_OK: separate process restored original EXE and real disposable SYSTEM task")
}

func runIndependentCIRecovery(ctx context.Context,root,task string)([]byte,error){
 binary:=os.Getenv("VOLVE_CI_STANDALONE_RECOVERY_EXE")
 if binary!=""{
  // The dedicated workflow MUST supply a real, separately compiled EXE in
  // the runner's temporary directory. Do not trust a caller-provided path.
  allowed:=filepath.Join(os.Getenv("RUNNER_TEMP"),"VOLVE_CI_Standalone_Recovery_Watchdog.exe")
  if !filepath.IsAbs(binary) || !strings.EqualFold(filepath.Clean(binary),filepath.Clean(allowed)) {
   return nil,errors.New("untrusted compiled watchdog location")
  }
  file,err:=os.Lstat(binary)
  if err!=nil||!file.Mode().IsRegular()||file.Size()<100000{
   return nil,errors.New("compiled standalone watchdog is absent, linked or incomplete")
  }
  cmd:=exec.CommandContext(ctx,binary,"--recover-resident-ci-task",root,task)
  output,err:=cmd.CombinedOutput()
  if err==nil{
   if !strings.Contains(string(output),"VOLVE_CI_STANDALONE_RECOVERED"){
    return output,errors.New("standalone watchdog did not report verified CI recovery")
   }
   return append([]byte("CI_EXTERNAL_RECOVERY_OK: separate compiled watchdog EXE\n"),output...),nil
  }
  return output,err
 }
 if os.Getenv("VOLVE_CI_REQUIRE_STANDALONE")=="1"{
  return nil,errors.New("dedicated workflow did not provide compiled independent watchdog")
 }
 // Older workflows continue testing the new-process policy as a separate
 // test executable, but cannot claim they tested the compiled watchdog.
 cmd:=exec.CommandContext(ctx,os.Args[0],
  "-test.run=^TestPostSwitchSystemTaskCILabExternalChild$","-test.v")
 cmd.Env=append(os.Environ(),
  "VOLVE_CI_TASK_RESTORE_CHILD=1",
  "VOLVE_CI_TASK_RESTORE_ROOT="+root,
  "VOLVE_CI_TASK_RESTORE_NAME="+task)
 return cmd.CombinedOutput()
}

func TestStandaloneCIRecoveryCLIRejectsNonHostedRunner(t *testing.T){
 t.Setenv("RUNNER_ENVIRONMENT","self-hosted")
 if err:=recoverResidentCIFromStandalone(context.Background(),
  t.TempDir(),disposableResidentTask);err==nil{
  t.Fatal("standalone CI watchdog accepted a non-hosted environment")
 }
 t.Setenv("RUNNER_ENVIRONMENT","github-hosted")
 if err:=recoverResidentCIFromStandalone(context.Background(),
  t.TempDir(),"VOLVE-DNS-SERVER-0270");err==nil{
  t.Fatal("standalone CI watchdog accepted production motor task")
 }
}

func TestStandaloneCIRecoveryCLIExecutableRejectsUnsafeInvocation(t *testing.T){
 binary:=os.Getenv("VOLVE_CI_STANDALONE_RECOVERY_EXE")
 if binary==""{
  if os.Getenv("VOLVE_CI_REQUIRE_STANDALONE")=="1"{t.Fatal("standalone CLI binary mandatory in dedicated Windows job")}
  t.Skip("dedicated compiled watchdog CLI only")
 }
 root:=t.TempDir()
 for _,scenario:=range []struct{name,task string;runner string}{
  {"productive-system-task","VOLVE-DNS-SERVER-0270","github-hosted"},
  {"non-hosted-runner",disposableResidentTask,"self-hosted"},
 }{
  t.Run(scenario.name,func(t *testing.T){
   ctx,cancel:=context.WithTimeout(context.Background(),20*time.Second)
   defer cancel()
   cmd:=exec.CommandContext(ctx,binary,"--recover-resident-ci-task",root,scenario.task)
   env:=[]string{}
   for _,item:=range os.Environ(){
    if !strings.HasPrefix(item,"RUNNER_ENVIRONMENT="){env=append(env,item)}
   }
   cmd.Env=append(env,"RUNNER_ENVIRONMENT="+scenario.runner)
   out,err:=cmd.CombinedOutput()
   if err==nil || strings.Contains(string(out),"VOLVE_CI_STANDALONE_RECOVERED"){
    t.Fatalf("compiled watchdog authorized forbidden scenario %s: %s",scenario.name,out)
   }
  })
 }
}

 // TestStandaloneCIWatchdogAtStartupSYSTEMTaskCILab creates a REAL additional
 // AtStartup Scheduler task running the separately compiled watchdog as
 // NT AUTHORITY\SYSTEM. It manually triggers the task in the hosted VM.
 // NO OS reboot is claimed, and NO production task or adapter is modified.
func TestStandaloneCIWatchdogAtStartupSYSTEMTaskCILab(t *testing.T){
 if os.Getenv("VOLVE_CI_REQUIRE_STANDALONE")!="1"{
  t.Skip("dedicated hosted Windows watchdog executable and task required")
 }
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{
  t.Fatal("real SYSTEM watchdog boot task attempted outside authorized GitHub hosted VM")
 }
 binary:=os.Getenv("VOLVE_CI_STANDALONE_RECOVERY_EXE")
 allowed:=filepath.Join(os.Getenv("RUNNER_TEMP"),"VOLVE_CI_Standalone_Recovery_Watchdog.exe")
 if !filepath.IsAbs(binary)||!strings.EqualFold(filepath.Clean(binary),filepath.Clean(allowed)){
  t.Fatal("untrusted path for compiled watchdog SYSTEM boot task")
 }
 ctx,cancel:=context.WithTimeout(context.Background(),150*time.Second)
 defer cancel()
 preflight:="$ErrorActionPreference='Stop';"+
  "$p=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent());"+
  "if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'not elevated'};"+
  "$vm=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop;"+
  "if(($vm.Manufacturer+' '+$vm.Model) -notmatch '(?i:virtual machine|vmware|hyper-v|kvm|qemu|virtualbox)'){throw 'not a verified hosted VM'};"+
  "if(Get-ScheduledTask -TaskName 'VOLVE-DNS-SERVER-0270' -ErrorAction SilentlyContinue){throw 'production motor present'};"+
  "Write-Output 'CI_SYSTEM_BOOT_VM_CONFIRMED'"
 if out,err:=ps(ctx,preflight);err!=nil||out!="CI_SYSTEM_BOOT_VM_CONFIRMED"{
  t.Fatalf("refusing independent SYSTEM boot task outside verified disposable VM: %s %v",out,err)
 }
 // GetTempPath2W isolates the SYSTEM account in Windows\\SystemTemp.
 // A runner-user TEMP root is deliberately rejected by the standalone
 // watchdog after privilege transition. Place this disposable fixture in
 // the trusted SYSTEM temp hierarchy instead of weakening the policy.
 systemTemp:=filepath.Join(os.Getenv("WINDIR"),"SystemTemp")
 systemInfo,systemErr:=os.Stat(systemTemp)
 if systemErr!=nil || !systemInfo.IsDir(){
  t.Fatalf("Windows SYSTEM temp directory not available for test: %s %v",systemTemp,systemErr)
 }
 t.Setenv("TMP",systemTemp)
 t.Setenv("TEMP",systemTemp)
 root,journalDir,_,protect:=chainFixture(t,false)
 relative,relErr:=filepath.Rel(systemTemp,root)
 if relErr!=nil || relative=="." || relative==".." ||
  strings.HasPrefix(relative,".."+string(filepath.Separator)) || filepath.IsAbs(relative){
  t.Fatalf("CI SYSTEM recovery fixture not inside verified SystemTemp root: %s",root)
 }
 suffix:=time.Now().UnixNano()
 motorTask:=fmt.Sprintf("VOLVE-CI-ManagedMotor-%d",suffix)
 bootTask:=fmt.Sprintf("VOLVE-CI-WatchdogBoot-%d",suffix)
 if !pilotTaskPattern.MatchString(motorTask) || !strings.HasPrefix(bootTask,"VOLVE-CI-WatchdogBoot-"){
  t.Fatal("invalid temporary Scheduler task names")
 }
 target,err:=residentPilotTargetPath(root,"0.28.7")
 if err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(target,[]byte("CI_TARGET_NOT_RUN"),0600);err!=nil{t.Fatal(err)}
 old:=filepath.Join(root,residentLegacyExe)
 protected,err:=digestResidentLive(ctx,old)
 if err!=nil{t.Fatal(err)}
 // The Windows Task Scheduler does not inherit GitHub Actions' process
 // environment. Preserve the original STRICT executable CI guards by using
 // a dedicated SYSTEM-only lab bootstrap to recreate ephemeral env values
 // and the runner's temp root. This is a LAB bridge, NOT production boot
 // deployment. The actual separately compiled watchdog runs as SYSTEM.
 // Windows SYSTEM can always access its own Windows\\Temp; its token
 // may NOT have traversal rights on the runner user's private temp root.
 // This log is DIAGNOSTIC ONLY, never authorization, and is removed by test.
 logPath:=filepath.Join(os.Getenv("WINDIR"),"Temp",fmt.Sprintf("VOLVE-CI-WATCHDOG-%d.log",suffix))
 t.Cleanup(func(){_ = os.Remove(logPath)})
 bootstrap:="$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';"+
  "$log="+q(logPath)+";"+
  "try{Set-Content -LiteralPath $log -Value ('CI_SYSTEM_BOOTSTRAP_SID='+[Security.Principal.WindowsIdentity]::GetCurrent().User.Value) -Encoding UTF8;"+
  "$env:GITHUB_ACTIONS='true';$env:RUNNER_ENVIRONMENT='github-hosted';"+
  "$env:TMP="+q(filepath.Dir(root))+";$env:TEMP="+q(filepath.Dir(root))+";"+
  "& "+q(binary)+" '--recover-resident-ci-task' "+q(root)+" "+q(motorTask)+" *>> $log;"+
  "$ciExit=$LASTEXITCODE;"+
  "Add-Content -LiteralPath $log -Value ('CI_WATCHDOG_EXIT='+$ciExit);"+
  "if($ciExit -ne 0){exit $ciExit}"+
  "}catch{Add-Content -LiteralPath $log -Value ('CI_BOOTSTRAP_EXCEPTION='+$_.Exception.Message);exit 99}"
 unicodeUnits:=utf16.Encode([]rune(bootstrap))
 buf:=make([]byte,len(unicodeUnits)*2)
 for i,u:=range unicodeUnits{buf[2*i]=byte(u);buf[2*i+1]=byte(u>>8)}
 bootArgs:="-NoProfile -NonInteractive -EncodedCommand "+base64.StdEncoding.EncodeToString(buf)
 create:="$ErrorActionPreference='Stop';"+
  "$motor="+q(motorTask)+";$boot="+q(bootTask)+";"+
  "$exe="+q(binary)+";$target="+q(target)+";"+
  "foreach($n in @($motor,$boot)){if(Get-ScheduledTask -TaskName $n -TaskPath '\\' -ErrorAction SilentlyContinue){throw 'collision with existing task'}};"+
  "$principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest;"+
  "$startup=New-ScheduledTaskTrigger -AtStartup;"+
  "$motorAction=New-ScheduledTaskAction -Execute $target -Argument '--dns-service';"+
  "Register-ScheduledTask -TaskName $motor -TaskPath '\\' -Principal $principal -Trigger $startup -Action $motorAction -ErrorAction Stop|Out-Null;"+
  "$bootAction=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "+q(bootArgs)+";"+
  "Register-ScheduledTask -TaskName $boot -TaskPath '\\' -Principal $principal -Trigger $startup -Action $bootAction -ErrorAction Stop|Out-Null;"+
  "Write-Output 'CI_INDEPENDENT_WATCHDOG_SYSTEM_BOOT_TASK_CREATED'"
 cleanup:="$ErrorActionPreference='Stop';"+
  "foreach($n in @("+q(bootTask)+","+q(motorTask)+")){"+
  "$task=Get-ScheduledTask -TaskName $n -TaskPath '\\' -ErrorAction SilentlyContinue;"+
  "if($null -eq $task){continue};"+
  "if($task.Principal.UserId -notin @('SYSTEM','S-1-5-18')){throw 'refusing foreign task cleanup'};"+
  "if($task.State -eq 'Running'){Stop-ScheduledTask -TaskName $n -TaskPath '\\' -ErrorAction Stop};"+
  "Unregister-ScheduledTask -TaskName $n -TaskPath '\\' -Confirm:$false -ErrorAction Stop};"+
  "Write-Output 'CI_INDEPENDENT_WATCHDOG_TASKS_CLEANED'"
 t.Cleanup(func(){
  cleanupCtx,done:=context.WithTimeout(context.Background(),35*time.Second)
  defer done()
  out,err:=ps(cleanupCtx,cleanup)
  if err!=nil||out!="CI_INDEPENDENT_WATCHDOG_TASKS_CLEANED"{
   t.Errorf("disposable SYSTEM watchdog task cleanup not verified: %s %v",out,err)
  }
 })
 if out,err:=ps(ctx,create);err!=nil||out!="CI_INDEPENDENT_WATCHDOG_SYSTEM_BOOT_TASK_CREATED"{
  t.Fatalf("cannot register independent SYSTEM watchdog with boot trigger: %s %v",out,err)
 }
 // The journal and immutable backup were armed before the simulated crash.
 // Delete ONLY the disposable lab original to require actual restoration.
 if err:=os.Remove(old);err!=nil{t.Fatal(err)}
 start:="$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';"+
  "$watch="+q(bootTask)+";$motor="+q(motorTask)+";$original="+q(old)+";"+
  "$w=Get-ScheduledTask -TaskName $watch -TaskPath '\\' -ErrorAction Stop;"+
  "if($w.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or @($w.Triggers).Count -ne 1 -or "+
  "[string]$w.Triggers[0].CimClass.CimClassName -notmatch 'BootTrigger'){throw 'watchdog is not a SYSTEM AtStartup task'};"+
  "Start-ScheduledTask -TaskName $watch -TaskPath '\\' -ErrorAction Stop;"+
  "$good=$false;"+
  "for($i=0;$i -lt 80;$i++){Start-Sleep -Milliseconds 750;"+
  "$info=Get-ScheduledTaskInfo -TaskName $watch -TaskPath '\\' -ErrorAction Stop;"+
  "$m=Get-ScheduledTask -TaskName $motor -TaskPath '\\' -ErrorAction Stop;"+
  "if($info.LastRunTime.Year -ge 2020 -and $info.LastTaskResult -eq 0 -and "+
  "[string]$m.Actions[0].Execute -ieq $original -and "+
  "[string]$m.Actions[0].Arguments -ceq '--dns-service'){$good=$true;break};"+
  "if($info.LastRunTime.Year -ge 2020 -and $info.LastTaskResult -notin @(0,267009) -and "+
  "(Get-ScheduledTask -TaskName $watch -TaskPath '\\').State -ne 'Running'){break}};"+
  "if(-not $good){$last=Get-ScheduledTaskInfo -TaskName $watch -TaskPath '\\' -ErrorAction Stop;"+
  "$lastMotor=Get-ScheduledTask -TaskName $motor -TaskPath '\\' -ErrorAction Stop;"+
  "Write-Output ('CI_WATCHDOG_NOT_RESTORED: EXIT='+$last.LastTaskResult+' ACTION='+$lastMotor.Actions[0].Execute)}"+
  "else{Write-Output 'CI_BOOT_WATCHDOG_RAN_AS_SYSTEM_AND_RESTORED'}"
 if out,err:=ps(ctx,start);err!=nil||out!="CI_BOOT_WATCHDOG_RAN_AS_SYSTEM_AND_RESTORED"{
  diag,_:=os.ReadFile(logPath)
  t.Fatalf("actual independent SYSTEM AtStartup task did not recover: %s %v; watchdog diagnostic=%s",out,err,diag)
 }
 if hash,err:=digestResidentLive(ctx,old);err!=nil||hash!=protected{
  t.Fatalf("independent SYSTEM watchdog restored incorrect original: %s %v",hash,err)
 }
 state,err:=motorupdate.InspectResidentRecoveryJournal(ctx,journalDir,protect)
 if err!=nil||state.Status!="recovery-required"{
  t.Fatalf("watchdog task improperly finalized without DNS/Internet checks: %+v %v",state,err)
 }
 if _,err:=os.Lstat(filepath.Join(journalDir,motorupdate.ResidentResultFile));!os.IsNotExist(err){
  t.Fatalf("real SYSTEM watchdog created false terminal receipt: %v",err)
 }
 t.Log("PASS: SYSTEM AtStartup task launched compiled watchdog through lab-only environment bootstrap; manual trigger restored exact motor, journal pending; NO VM reboot and NOT a production boot service")
}
