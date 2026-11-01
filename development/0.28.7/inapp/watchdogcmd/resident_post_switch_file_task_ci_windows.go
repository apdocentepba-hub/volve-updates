//go:build windows

package main

// Isolated Windows CI-only integration for a missing original executable or
// an exact journal-pinned inert candidate, then disposable SYSTEM task restore.
// No product
// task, adapters, DNS, live motor or terminal recovery receipts are touched.
//
// NOT a production restorer: replacing the exact lab candidate does NOT prove
// publisher authorization, process lockout or active DNS health.
import (
 "context"
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "strings"
)

func restoreMissingOriginalAndDisposableTaskCILab(
 ctx context.Context,root,pilotTask string,
 runPS func(context.Context,string)(string,error),
)error{
 if err:=ctx.Err();err!=nil{return err}
 if os.Getenv("GITHUB_ACTIONS")!="true"||
  os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"||
  !pilotTaskPattern.MatchString(pilotTask)||
  runPS==nil||!filepath.IsAbs(root)||filepath.Clean(root)!=root{
  return errors.New("integrated file/task restoration reserved for hosted Windows CI only")
 }
 suffix:=strings.TrimPrefix(pilotTask,"VOLVE-CI-ManagedMotor-")
 release,err:=acquireCIBootMutex(ctx,"VOLVE-CI-BootLock-"+suffix)
 if err!=nil{return fmt.Errorf("cannot lock disposable restoration: %w",err)}
 defer release()
 // Recreate missing bytes, or atomically restore only the exact candidate
 // SHA-256 pinned by the disposable lab journal. Unknown existing binaries
 // remain untouched; Task Scheduler import then requires the old bytes.
 if err:=restoreMissingLegacyExecutableCILab(ctx,root,pilotTask);err!=nil{
  return fmt.Errorf("original bytes cannot be reconstructed: %w",err)
 }
 if err:=ctx.Err();err!=nil{return err}
 // Revalidates the original snapshot/journal and the disposable live task,
 // then imports only the expected single-SYSTEM-action original XML.
 if err:=restoreResidentPilotSYSTEMTaskWithRunner(ctx,root,pilotTask,runPS);err!=nil{
  return fmt.Errorf("original disposable SYSTEM task not restored: %w",err)
 }
 // The journal must remain pending until separate SYSTEM identity, DNS v4/v6
 // and Internet health checks succeed; this function writes no receipt.
 return nil
}

 // recoverResidentCIFromStandalone is the only mutating resident CLI of the
 // separately compiled watchdog. All permissions are deliberately bounded to
 // a disposable hosted GitHub Windows VM. The production DNS task is never
 // named in a mutation command. It does NOT certify DNS/Internet health or
 // publish a terminal receipt.
func recoverResidentCIFromStandalone(ctx context.Context,root,task string)error {
 if err:=ctx.Err();err!=nil{return err}
 if os.Getenv("GITHUB_ACTIONS")!="true" ||
  os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted" ||
  !pilotTaskPattern.MatchString(task) ||
  !filepath.IsAbs(root) || filepath.Clean(root)!=root {
  return errors.New("standalone restoration CLI restricted to hosted Windows CI fixture")
 }
 // A user can spoof CI environment variables. Recheck the actual VM,
 // administrator token and ABSENCE of a real production motor task before
 // running any PowerShell command which changes a disposable task.
 const hostCheck=`$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';
$id=[Security.Principal.WindowsIdentity]::GetCurrent();
$p=[Security.Principal.WindowsPrincipal]::new($id);
if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'CI administrator required'};
$vm=Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop;
if(($vm.Manufacturer+' '+$vm.Model) -notmatch '(?i:virtual machine|vmware|hyper-v|kvm|qemu|virtualbox)'){throw 'host is not isolated VM'};
if(Get-ScheduledTask -TaskName 'VOLVE-DNS-SERVER-0270' -ErrorAction SilentlyContinue){throw 'production motor task exists'};
if(Get-ScheduledTask -TaskName 'VOLVE-DNS-RESCUE-0270' -ErrorAction SilentlyContinue){throw 'production rescue task exists'};
Write-Output 'VOLVE_CI_HOST_VERIFIED'`
 out,err:=ps(ctx,hostCheck)
 if err!=nil||out!="VOLVE_CI_HOST_VERIFIED"{
  return fmt.Errorf("standalone Windows VM preflight rejected: %s %w",out,err)
 }
 return restoreMissingOriginalAndDisposableTaskCILab(ctx,root,task,ps)
}
