//go:build windows

package main

// Windows hosted CI: a REAL disposable Task Scheduler job is changed from a
// synthetic target action back to a protected original SYSTEM action.
// The old EXE is also physically restored from the sealed CI snapshot.
// No DNS motor is started; no actual VOLVE product task is touched.
import (
 "context"
 "errors"
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
 child:=exec.CommandContext(ctx,os.Args[0],
  "-test.run=^TestPostSwitchSystemTaskCILabExternalChild$","-test.v")
 child.Env=append(os.Environ(),
  "VOLVE_CI_TASK_RESTORE_CHILD=1",
  "VOLVE_CI_TASK_RESTORE_ROOT="+root,
  "VOLVE_CI_TASK_RESTORE_NAME="+task)
 output,childErr:=child.CombinedOutput()
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
 retry:=exec.CommandContext(ctx,os.Args[0],
  "-test.run=^TestPostSwitchSystemTaskCILabExternalChild$","-test.v")
 retry.Env=append(os.Environ(),
  "VOLVE_CI_TASK_RESTORE_CHILD=1",
  "VOLVE_CI_TASK_RESTORE_ROOT="+root,
  "VOLVE_CI_TASK_RESTORE_NAME="+task)
 retryOutput,retryErr:=retry.CombinedOutput()
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
 untrusted:=exec.CommandContext(ctx,os.Args[0],
  "-test.run=^TestPostSwitchSystemTaskCILabExternalChild$","-test.v")
 untrusted.Env=append(os.Environ(),
  "VOLVE_CI_TASK_RESTORE_CHILD=1",
  "VOLVE_CI_TASK_RESTORE_ROOT="+root,
  "VOLVE_CI_TASK_RESTORE_NAME="+task)
 rejected,rejectErr:=untrusted.CombinedOutput()
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
