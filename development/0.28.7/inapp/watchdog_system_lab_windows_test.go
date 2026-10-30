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
  `$trigger=New-ScheduledTaskTrigger -Once -At ((Get-Date).AddYears(1));`+
  `Register-ScheduledTask -TaskName `+labQuote(taskName)+` -Action $action -Trigger $trigger -User 'SYSTEM' -RunLevel Highest -ErrorAction Stop | Out-Null;`+
  `$task=Get-ScheduledTask -TaskName `+labQuote(taskName)+` -ErrorAction Stop;`+
  `if($task.TaskPath -ne '\\' -or $task.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or @($task.Actions).Count -ne 1){throw 'Unexpected watchdog task ownership'};`+
  `Start-ScheduledTask -TaskName `+labQuote(taskName)+` -ErrorAction Stop;`
 _,err:=labPS(script);return err
}

func removeSYSTEMWatchdogLabTask(taskName string) error{
 if !watchdogLabName.MatchString(taskName){return fmt.Errorf("not a disposable watchdog task")}
 script:=`$task=Get-ScheduledTask -TaskName `+labQuote(taskName)+` -ErrorAction SilentlyContinue;`+
  `if($null -ne $task){`+
  `if($task.TaskPath -ne '\\' -or $task.Principal.UserId -notin @('SYSTEM','S-1-5-18')){throw 'Refuse unrelated task removal'};`+
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
 if err:=d.InstallVersionedCandidate(context.Background(),candidate);err!=nil{t.Fatal(err)}
 if err:=switchVerifiedMotorTaskAction(context.Background(),oldName,original,"/C exit 0",d.installedExe,"",key);err!=nil{t.Fatal(err)}
 jpath:=filepath.Join(root,"watchdog-system.json")
 writeCIWatchdogJournal(t,jpath,ciWatchdogJournal{Schema:1,Phase:"pending",TaskName:oldName,
  OriginalExe:original,OriginalArgs:"/C exit 0",SnapshotFile:d.backup,SnapshotSHA256:d.originalHash})
 watcherName:=fmt.Sprintf("VOLVE-CI-ManagedWatchdog-%d",time.Now().UnixNano())
 if err:=createSYSTEMWatchdogLabTask(watcherName,helper,jpath);err!=nil{t.Fatal(err)}
 t.Cleanup(func(){if err:=removeSYSTEMWatchdogLabTask(watcherName);err!=nil{t.Errorf("cleanup watchdog task: %v",err)}})
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
