//go:build windows

package main

// Tests ONLY disposable VOLVE-CI-* Task Scheduler objects. No production
// VOLVE task, DNS adapter, user machine or installation is modified.
import (
 "context"
 "encoding/json"
 "fmt"
 "os"
 "path/filepath"
 "regexp"
 "strings"
 "testing"
 "time"
)

var watchdogLabName=regexp.MustCompile(`^VOLVE-CI-ManagedWatchdog-[0-9]{12,20}$`)

func createSYSTEMWatchdogLabTask(taskName, helper, journal string) error{
 if !watchdogLabName.MatchString(taskName) || !filepath.IsAbs(helper) || !filepath.IsAbs(journal){
  return fmt.Errorf("refusing untrusted watchdog lab task parameters")
 }
 arguments:=`--recover-pilot-journal "`+journal+`"`
 script:=`$ErrorActionPreference='Stop';`+
  `$action=New-ScheduledTaskAction -Execute `+labQuote(helper)+` -Argument `+labQuote(arguments)+`;`+
  `$startup=New-ScheduledTaskTrigger -AtStartup;`+
  `$manual=New-ScheduledTaskTrigger -Once -At ((Get-Date).AddYears(1));`+
  `Register-ScheduledTask -TaskName `+labQuote(taskName)+` -Action $action -Trigger @($startup,$manual) -User 'SYSTEM' -RunLevel Highest -ErrorAction Stop | Out-Null;`+
  `$task=Get-ScheduledTask -TaskName `+labQuote(taskName)+` -ErrorAction Stop;`+
  `if($task.TaskPath -ne '\' -or $task.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or @($task.Actions).Count -ne 1){throw 'Unexpected watchdog task ownership'};`+
  `$boots=@($task.Triggers | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_TaskBootTrigger' });`+
  `if($boots.Count -ne 1){throw 'Independent watchdog lacks exactly one boot trigger'};`+
  `if($task.Actions[0].Execute -ine `+labQuote(helper)+`){throw 'Watchdog executable mismatch'};`
 _,err:=labPS(script);return err
}

// Arm recovery BEFORE changing the motor. The Task Scheduler boot trigger
// must exist and be inspected before the risky switch. Only the CI trial
// explicitly starts it now, rather than waiting for an OS boot.
func startSYSTEMWatchdogLabTask(taskName string) error {
 if !watchdogLabName.MatchString(taskName){return fmt.Errorf("not a disposable watchdog task")}
 _,err:=labPS(`$ErrorActionPreference='Stop';Start-ScheduledTask -TaskName `+labQuote(taskName)+` -ErrorAction Stop`)
 return err
}

func removeSYSTEMWatchdogLabTask(taskName string) error{
 if !watchdogLabName.MatchString(taskName){return fmt.Errorf("not a disposable watchdog task")}
 script:=`$task=Get-ScheduledTask -TaskName `+labQuote(taskName)+` -ErrorAction SilentlyContinue;`+
  `if($null -ne $task){`+
  `if($task.TaskPath -ne '\' -or $task.Principal.UserId -notin @('SYSTEM','S-1-5-18')){throw 'Refuse unrelated task removal'};`+
  `Unregister-ScheduledTask -TaskName `+labQuote(taskName)+` -Confirm:$false -ErrorAction Stop}`
 _,err:=labPS(script);return err
}

func TestIndependentMotorWatchdogRunsAsSYSTEM(t *testing.T){
 helper:=os.Getenv("VOLVE_CI_MANAGED_WATCHDOG_EXE")
 if helper==""{t.Fatal("CI did not provide a separately compiled watchdog binary")}
 oldName:=fmt.Sprintf("VOLVE-CI-ManagedMotor-%d",time.Now().UnixNano())
 original:=filepath.Join(os.Getenv("WINDIR"),"System32","cmd.exe")
 if err:=createDisposableTask(oldName,original);err!=nil{t.Fatal(err)}
 t.Cleanup(func(){if err:=removeDisposableTask(oldName);err!=nil{t.Errorf("cleanup engine task: %v",err)}})
 root:=t.TempDir()
 candidate,key:=prepareSignedLabCandidate(t,root)
 d:=&managedWindowsTaskLab{name:oldName,root:filepath.Join(root,"transaction"),
  backup:filepath.Join(root,"transaction","original-task.xml"),original:original,publicKey:key}
 if err:=d.Snapshot(context.Background());err!=nil{t.Fatal(err)}
 jpath:=filepath.Join(root,"watchdog-system.json")
 writeCIWatchdogJournal(t,jpath,ciWatchdogJournal{Schema:1,Phase:"pending",TaskName:oldName,
  OriginalExe:original,OriginalArgs:"/C exit 0",SnapshotFile:d.backup,SnapshotSHA256:d.originalHash})
 secureCIPilotRecovery(t,jpath,d.backup)
 watcherName:=fmt.Sprintf("VOLVE-CI-ManagedWatchdog-%d",time.Now().UnixNano())
 // Crucial ordering: the durable pending journal and the SYSTEM boot-recovery
 // task must exist BEFORE the candidate is installed or the task is switched.
 if err:=createSYSTEMWatchdogLabTask(watcherName,helper,jpath);err!=nil{t.Fatal(err)}
 t.Cleanup(func(){if err:=removeSYSTEMWatchdogLabTask(watcherName);err!=nil{t.Errorf("cleanup watchdog task: %v",err)}})
 if err:=d.InstallVersionedCandidate(context.Background(),candidate);err!=nil{t.Fatal(err)}
 if err:=switchVerifiedMotorTaskAction(context.Background(),oldName,original,"/C exit 0",d.installedExe,"",key);err!=nil{t.Fatal(err)}
 if err:=startSYSTEMWatchdogLabTask(watcherName);err!=nil{t.Fatal(err)}
 deadline:=time.Now().Add(35*time.Second)
 for time.Now().Before(deadline){
  data,err:=os.ReadFile(jpath)
  if err==nil{
   var j ciWatchdogJournal
   if json.Unmarshal(data,&j)==nil && j.Phase=="restored" {
    exe,args,verifyErr:=d.currentAction()
    if verifyErr!=nil || !strings.EqualFold(filepath.Clean(exe),filepath.Clean(original)) || args!="/C exit 0"{
     t.Fatalf("SYSTEM watchdog committed journal but did not restore task: %q %q %v",exe,args,verifyErr)
    }
    return
   }
  }
  time.Sleep(450*time.Millisecond)
 }
 details,_:=labPS(`$t=Get-ScheduledTaskInfo -TaskName `+labQuote(watcherName)+` -ErrorAction SilentlyContinue; if($t){Write-Output ("last_task_result="+$t.LastTaskResult)}`)
 t.Fatalf("SYSTEM watchdog did not restore temporary task; %s",details)
}

func TestIndependentMotorWatchdogSYSTEMLeavesCommittedUpgradeIntact(t *testing.T){
 helper:=os.Getenv("VOLVE_CI_MANAGED_WATCHDOG_EXE")
 if helper==""{t.Fatal("separate CI watchdog not available")}
 name:=fmt.Sprintf("VOLVE-CI-ManagedMotor-%d",time.Now().UnixNano())
 original:=filepath.Join(os.Getenv("WINDIR"),"System32","cmd.exe")
 if err:=createDisposableTask(name,original);err!=nil{t.Fatal(err)}
 t.Cleanup(func(){if err:=removeDisposableTask(name);err!=nil{t.Errorf("cleanup original task: %v",err)}})
 root:=t.TempDir()
 candidate,key:=prepareSignedLabCandidate(t,root)
 d:=&managedWindowsTaskLab{name:name,root:filepath.Join(root,"transaction"),
   backup:filepath.Join(root,"transaction","original-task.xml"),original:original,publicKey:key}
 if err:=d.Snapshot(context.Background());err!=nil{t.Fatal(err)}
 journalPath:=filepath.Join(root,"watchdog-committed.json")
 writeCIWatchdogJournal(t,journalPath,ciWatchdogJournal{Schema:1,Phase:"committed",TaskName:name,
   OriginalExe:original,OriginalArgs:"/C exit 0",SnapshotFile:d.backup,SnapshotSHA256:d.originalHash})
 secureCIPilotRecovery(t,journalPath,d.backup)
 watcherName:=fmt.Sprintf("VOLVE-CI-ManagedWatchdog-%d",time.Now().UnixNano())
 if err:=createSYSTEMWatchdogLabTask(watcherName,helper,journalPath);err!=nil{t.Fatal(err)}
 t.Cleanup(func(){if err:=removeSYSTEMWatchdogLabTask(watcherName);err!=nil{t.Errorf("cleanup watchdog task: %v",err)}})
 if err:=d.InstallVersionedCandidate(context.Background(),candidate);err!=nil{t.Fatal(err)}
 if err:=switchVerifiedMotorTaskAction(context.Background(),name,original,"/C exit 0",d.installedExe,"",key);err!=nil{t.Fatal(err)}
 if err:=startSYSTEMWatchdogLabTask(watcherName);err!=nil{t.Fatal(err)}
 // A completed transaction must NEVER be rolled back by an otherwise valid
 // watchdog trigger on Windows startup or via manual recovery invocation.
 deadline:=time.Now().Add(30*time.Second)
 completed:=false
 for time.Now().Before(deadline) {
   output,err:=labPS(`$r=Get-ScheduledTaskInfo -TaskName `+labQuote(watcherName)+` -ErrorAction Stop; `+
      `if($r.LastRunTime.Year -ge 2026 -and $r.LastTaskResult -eq 0){Write-Output 'DONE'}else{Write-Output 'PENDING'}`)
   if err==nil && output=="DONE"{completed=true;break}
   time.Sleep(450*time.Millisecond)
 }
 if !completed {t.Fatal("committed SYSTEM watchdog never completed")}
 exe,args,err:=d.currentAction()
 if err!=nil || !strings.EqualFold(filepath.Clean(exe),filepath.Clean(d.installedExe)) || args!="" {
    t.Fatalf("committed new engine task reverted unexpectedly: %q %q %v",exe,args,err)
 }
 raw,err:=os.ReadFile(journalPath);if err!=nil{t.Fatal(err)}
 var current ciWatchdogJournal
 if err:=json.Unmarshal(raw,&current);err!=nil{t.Fatal(err)}
 if current.Phase!="committed"{t.Fatalf("committed journal changed: %q",current.Phase)}
}
