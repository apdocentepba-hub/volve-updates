//go:build windows

package main

// Real SYSTEM token + NTFS DACL lab on an independently launched compiled
// Go test binary. No product motor/DNS/Scheduler name may be changed.
// This test is only enabled in a disposable GitHub-hosted Windows VM.
import (
 "context"
 "flag"
 "fmt"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"
)

func TestResidentCIStageSealerSYSTEMChild(t *testing.T){
 rootFlag:=flag.Lookup("test.outputdir")
 if rootFlag==nil{return}
 root:=rootFlag.Value.String()
 if root==""||!filepath.IsAbs(root){return}
 req:=filepath.Join(root,"ci-system-stage-request")
 if _,err:=os.Stat(req);err!=nil{return} // Never run as regular test.
 if err:=verifyResidentActualSYSTEM(context.Background());err!=nil{
  t.Fatalf("independent scheduled process was not SYSTEM: %v",err)
 }
 path:=filepath.Join(root,".volve-signed-original-recovery-system-ci")
 ctx,cancel:=context.WithTimeout(context.Background(),65*time.Second)
 defer cancel()
 // Positive half of the production-identity constructor contract. This
 // executable is actually launched from a DISPOSABLE Windows LocalSystem
 // Scheduled Task, not merely an elevated administrator test process.
 // Construct only; NEVER invoke RestoreOriginal or register product tasks.
 driver,err:=newPinnedResidentBootRecoveryDriverWindows(ctx,root)
 if err!=nil||driver==nil{
  t.Fatalf("actual SYSTEM could not construct sealed publisher boot driver: %v",err)
 }
 if err:=sealResidentOriginalRecoveryStageNTFS(ctx,root,path);err!=nil{
  t.Fatalf("SYSTEM could not seal bounded original stage with protected ACL: %v",err)
 }
 if err:=os.WriteFile(filepath.Join(root,"ci-system-stage-passed"),
  []byte("VOLVE_CI_PROTECTED_STAGE_SYSTEM_OK"),0600);err!=nil{t.Fatal(err)}
}

func TestResidentCIStageSealerActualDisposableSYSTEMTask(t *testing.T){
 if os.Getenv("GITHUB_ACTIONS")!="true"||
  os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{
  t.Skip("actual SYSTEM stage test requires a hosted disposable Windows CI VM")
 }
 if os.Getenv("VOLVE_CI_STAGE_EXEC")!="1"{
  t.Skip("compile test runner separately and opt in from a CI-only workflow")
 }
 ctx,cancel:=context.WithTimeout(context.Background(),130*time.Second)
 defer cancel()
 exe,err:=os.Executable()
 if err!=nil{t.Fatal(err)}
 if filepath.Ext(exe)!=".exe"{t.Fatal("not a Windows executable")}
 check:="$ErrorActionPreference='Stop';"+
  "$id=[Security.Principal.WindowsIdentity]::GetCurrent();"+
  "$admin=[Security.Principal.WindowsPrincipal]::new($id);"+
  "if(-not $admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Hosted CI lacks admin'};"+
  "$vm=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop;"+
  "if(($vm.Manufacturer+' '+$vm.Model) -notmatch '(?i:virtual machine|vmware|hyper-v|kvm|qemu|virtualbox)'){throw 'Not disposable VM'};"+
  "if(Get-ScheduledTask -TaskName 'VOLVE-DNS-SERVER-0270' -ErrorAction SilentlyContinue){throw 'Real product task exists'};"+
  "Write-Output 'SAFE_DISPOSABLE_WINDOWS_VM'"
 out,err:=ps(ctx,check)
 if err!=nil||out!="SAFE_DISPOSABLE_WINDOWS_VM"{
  t.Fatalf("unsafe Windows environment for SYSTEM fixture: %q %v",out,err)
 }
 root:=t.TempDir()
 staged:=filepath.Join(root,".volve-signed-original-recovery-system-ci")
 if err:=os.WriteFile(staged,[]byte("MZ-INERT-CI-SYNTHETIC-ORIGINAL"),0600);err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(filepath.Join(root,"ci-system-stage-request"),[]byte("CI ONLY"),0600);err!=nil{t.Fatal(err)}
 taskName:=fmt.Sprintf("VOLVE-CI-STAGE-NTFS-%d",time.Now().UnixNano())
 if !strings.HasPrefix(taskName,"VOLVE-CI-STAGE-NTFS-"){t.Fatal("unsafe task name")}
 args:="-test.run=^TestResidentCIStageSealerSYSTEMChild$ -test.outputdir=\""+root+"\" -test.v"
 create:="$ErrorActionPreference='Stop';"+
  "$n="+q(taskName)+";$exe="+q(exe)+";$args="+q(args)+";"+
  "if(Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue){throw 'Task collision'};"+
  "$action=New-ScheduledTaskAction -Execute $exe -Argument $args;"+
  "$principal=New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest;"+
  "$trigger=New-ScheduledTaskTrigger -Once -At ((Get-Date).AddYears(3));"+
  "Register-ScheduledTask -TaskName $n -TaskPath '\\' -Action $action -Principal $principal -Trigger $trigger -ErrorAction Stop|Out-Null;"+
  "Start-ScheduledTask -TaskName $n -TaskPath '\\' -ErrorAction Stop;"+
  "Write-Output 'VOLVE_CI_DISPOSABLE_STAGE_TASK_STARTED'"
 t.Cleanup(func(){
  cleanupCtx,done:=context.WithTimeout(context.Background(),20*time.Second)
  defer done()
  cleanup:="$ErrorActionPreference='Stop';$n="+q(taskName)+";"+
   "$t=Get-ScheduledTask -TaskName $n -TaskPath '\\' -ErrorAction SilentlyContinue;"+
   "if($null -ne $t){"+
   "if($t.Principal.UserId -notin @('SYSTEM','S-1-5-18')){throw 'Task identity altered'};"+
   "Unregister-ScheduledTask -TaskName $n -TaskPath '\\' -Confirm:$false -ErrorAction Stop};"+
   "Write-Output 'VOLVE_CI_STAGE_TASK_REMOVED'"
  output,err:=ps(cleanupCtx,cleanup)
  if err!=nil||output!="VOLVE_CI_STAGE_TASK_REMOVED"{
   t.Errorf("disposable SYSTEM stage task cleanup error: %q %v",output,err)
  }
 })
 out,err=ps(ctx,create)
 if err!=nil||out!="VOLVE_CI_DISPOSABLE_STAGE_TASK_STARTED"{
  t.Fatalf("did not start isolated SYSTEM token stage lab: %q %v",out,err)
 }
 marker:=filepath.Join(root,"ci-system-stage-passed")
 for ctx.Err()==nil{
  b,err:=os.ReadFile(marker)
  if err==nil{
   if string(b)!="VOLVE_CI_PROTECTED_STAGE_SYSTEM_OK"{t.Fatal("unclear SYSTEM test result")}
   if err:=checkResidentJournalNTFS(ctx,staged);err!=nil{
    t.Fatalf("SYSTEM stage file was not sealed and readable by admin: %v",err)
   }
   t.Log("PASS: independently scheduled SYSTEM task sealed synthetic original stage on NTFS")
   return
  }
  time.Sleep(350*time.Millisecond)
 }
 t.Fatalf("SYSTEM child did not confirm NTFS seal within test context: %v",ctx.Err())
}
