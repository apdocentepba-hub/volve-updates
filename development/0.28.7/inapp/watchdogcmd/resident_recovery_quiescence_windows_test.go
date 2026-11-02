//go:build windows

package main

import (
 "context"
 "encoding/json"
 "errors"
 "path/filepath"
 "os"
 "time"
 "strings"
 "testing"
)

func quiescentFixture(root string)residentQuiescenceObservation{
 return residentQuiescenceObservation{TaskName:"VOLVE-DNS-SERVER-0270",
  TaskPath:"\\",Principal:"SYSTEM",ActionCount:1,
  ActionExecute:filepath.Join(root,residentLegacyExe),ActionArguments:"--dns-service"}
}

func TestResidentQuiescenceAcceptsExactStoppedSYSTEMTaskOnly(t *testing.T){
 root:=filepath.Join(t.TempDir(),"VOLVE-LAB")
 for _,name:=range []string{residentLegacyExe,"VOLVE_DNS_Motor_0_28_7.exe",
  filepath.Join("installed-engines","VOLVE_DNS_Motor_0_28_7.exe")}{
  o:=quiescentFixture(root);o.ActionExecute=filepath.Join(root,name)
  decision,err:=validateResidentQuiescence(root,"0.28.7",o)
  if err!=nil||!decision.ReadyForFurtherChecks||!decision.DNSPortFree{
   t.Fatalf("exact quiescent executable %s was rejected: %+v %v",name,decision,err)
  }
 }
}
func TestResidentQuiescenceFailsClosedOnUnknownOrRunningMotor(t *testing.T){
 root:=filepath.Join(t.TempDir(),"VOLVE-LAB")
 cases:=map[string]func(*residentQuiescenceObservation){
  "unexpected-task":func(o *residentQuiescenceObservation){o.TaskName="VOLVE-CI-PILOT"},
  "foreign-task-folder":func(o *residentQuiescenceObservation){o.TaskPath="\\Windows\\"},
  "non-SYSTEM-principal":func(o *residentQuiescenceObservation){o.Principal="S-1-5-21-101"},
  "extra-action":func(o *residentQuiescenceObservation){o.ActionCount=2},
  "wrong-arguments":func(o *residentQuiescenceObservation){o.ActionArguments="--launcher"},
  "foreign-executable":func(o *residentQuiescenceObservation){o.ActionExecute=filepath.Join(root,"other.exe")},
  "active-process":func(o *residentQuiescenceObservation){o.MotorProcessCount=1},
  "udp53-in-use":func(o *residentQuiescenceObservation){o.UDP53Count=1},
  "tcp53-in-use":func(o *residentQuiescenceObservation){o.TCP53Count=1},
  "bad-count":func(o *residentQuiescenceObservation){o.TCP53Count=-1},
 }
 for name,f:=range cases {t.Run(name,func(t *testing.T){
  o:=quiescentFixture(root);f(&o)
  result,err:=validateResidentQuiescence(root,"0.28.7",o)
  if err==nil||result.ReadyForFurtherChecks{t.Fatalf("unsafe state admitted: %+v %v",result,err)}
 })}
}
func TestResidentQuiescenceQueryFailClosedAndContainsRealWindowsProbes(t *testing.T){
 root:=filepath.Join(t.TempDir(),"VOLVE-LAB")
 o:=quiescentFixture(root)
 raw,err:=json.Marshal(o);if err!=nil{t.Fatal(err)}
 for _,tc:=range []struct{body string;err error}{
  {"",errors.New("access denied")},{"",nil},{"{",nil},
  {string(raw)+"{}",nil},
  {string(raw[:len(raw)-1])+`,"Extra":1}`,nil},
 }{
  r,err:=residentQuiescenceWithQuery(context.Background(),root,"0.28.7",
   func(context.Context,string)(string,error){return tc.body,tc.err})
  if err==nil||r.ReadyForFurtherChecks{t.Fatalf("malformed/denied report accepted: %+v %v",r,err)}
 }
 r,err:=residentQuiescenceWithQuery(context.Background(),root,"0.28.7",
  func(ctx context.Context,script string)(string,error){
   for _,name:=range []string{"Get-ScheduledTask","Get-CimInstance","Get-NetUDPEndpoint","Get-NetTCPConnection"}{
    if !strings.Contains(script,name){t.Fatalf("missing probe %s",name)}
   }
   return string(raw),nil
  })
 if err!=nil||!r.ReadyForFurtherChecks{t.Fatalf("valid observation rejected: %+v %v",r,err)}
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 _,err=residentQuiescenceWithQuery(ctx,root,"0.28.7",
  func(context.Context,string)(string,error){t.Fatal("canceled probe invoked");return "",nil})
 if !errors.Is(err,context.Canceled){t.Fatalf("context cancellation ignored: %v",err)}
}

func TestResidentQuiescenceUsesActualDisposableWindowsTaskAndPortInventory(t *testing.T){
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{
  t.Skip("requires an elevated disposable Windows GitHub runner")
 }
 ctx,cancel:=context.WithTimeout(context.Background(),65*time.Second)
 defer cancel()
 // No test is permitted to touch an existing real installation.
 host:="$ErrorActionPreference='Stop';"+
  "$vm=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop;"+
  "if(($vm.Manufacturer+' '+$vm.Model) -notmatch '(?i:virtual machine|hyper-v|vmware|kvm|qemu|virtualbox)'){throw 'Host is not a disposable VM'};"+
  "if(Get-ScheduledTask -TaskName 'VOLVE-DNS-SERVER-0270' -ErrorAction SilentlyContinue){throw 'Refusing to overwrite an existing motor task'};"+
  "if(Get-ScheduledTask -TaskName 'VOLVE-DNS-RESCUE-0270' -ErrorAction SilentlyContinue){throw 'Refusing to coexist with real recovery task'};"+
  "Write-Output 'ISOLATED_VM_CLEAN'"
 if result,err:=ps(ctx,host);err!=nil||result!="ISOLATED_VM_CLEAN"{
  t.Fatalf("CI fixture cannot establish isolated empty Windows state: %q %v",result,err)
 }
 root:=filepath.Join(t.TempDir(),"VOLVE-QUIESCE-VM")
 if err:=os.MkdirAll(root,0700);err!=nil{t.Fatal(err)}
 exe:=filepath.Join(root,residentLegacyExe)
 // Future-dated task is not invoked. It supplies genuine Windows Scheduler
 // XML, SYSTEM principal and a single --dns-service action for observation.
 stage:="$ErrorActionPreference='Stop';"+
  "$exe="+q(exe)+";"+
  "$trigger=New-ScheduledTaskTrigger -Once -At ((Get-Date).AddYears(3));"+
  "$action=New-ScheduledTaskAction -Execute $exe -Argument '--dns-service';"+
  "Register-ScheduledTask -TaskName 'VOLVE-DNS-SERVER-0270' -Action $action -Trigger $trigger -User SYSTEM -RunLevel Highest -ErrorAction Stop|Out-Null;"+
  "Write-Output 'STAGED_DISPOSABLE_SYSTEM_TASK'"
 result,err:=ps(ctx,stage)
 if err!=nil||result!="STAGED_DISPOSABLE_SYSTEM_TASK"{t.Fatalf("temporary SYSTEM task refused: %q %v",result,err)}
 t.Cleanup(func(){
  cleanCtx,cleanCancel:=context.WithTimeout(context.Background(),15*time.Second)
  defer cleanCancel()
  out,err:=ps(cleanCtx,"Unregister-ScheduledTask -TaskName 'VOLVE-DNS-SERVER-0270' -Confirm:$false -ErrorAction Stop;Write-Output 'CLEANED'")
  if err!=nil||out!="CLEANED"{t.Errorf("failed to remove disposable system task: %q %v",out,err)}
 })
 actual,err:=ps(ctx,"$ErrorActionPreference='Stop';"+
  "$r=Get-ScheduledTask -TaskName 'VOLVE-DNS-SERVER-0270' -TaskPath '\\' -ErrorAction Stop;"+
  "Write-Output ([string]$r.Actions[0].Execute)")
 if err!=nil||!strings.EqualFold(actual,exe){
  t.Fatalf("Windows registered unexpected task action %q: %v",actual,err)
 }
 // Exercise the actual Windows process, Task Scheduler and port queries.
 decision,err:=auditResidentQuiescenceReadOnly(ctx,root)
 if err!=nil && !strings.Contains(err.Error(),"still active"){
  t.Fatalf("real OS quiescence command errored: %+v %v",decision,err)
 }
 if !decision.TaskIdentityVerified || !decision.MotorProcessesStopped{
  t.Fatalf("isolated inactive SYSTEM task not recognized: %+v %v",decision,err)
 }
 if decision.DNSPortFree!=(err==nil)||decision.ReadyForFurtherChecks!=(err==nil){
  t.Fatalf("quiescence incorrectly interpreted DNS port 53 ownership: %+v %v",decision,err)
 }
 // Task Scheduler changes are allowed only for this disposable test fixture.
 // Prove a foreign executable is rejected by the independent Go verifier.
 altered:="$ErrorActionPreference='Stop';"+
  "$exe=Join-Path $env:WINDIR 'System32\\cmd.exe';"+
  "Set-ScheduledTask -TaskName 'VOLVE-DNS-SERVER-0270' -Action (New-ScheduledTaskAction -Execute $exe -Argument '--dns-service') -ErrorAction Stop|Out-Null;"+
  "Write-Output 'DISPOSABLE_TASK_ALTERED'"
 out,alterErr:=ps(ctx,altered)
 if alterErr!=nil||out!="DISPOSABLE_TASK_ALTERED"{t.Fatalf("cannot alter CI fixture: %q %v",out,alterErr)}
 rejected,rejectedErr:=auditResidentQuiescenceReadOnly(ctx,root)
 if rejectedErr==nil||rejected.ReadyForFurtherChecks{
  t.Fatalf("actual Windows foreign SYSTEM task action was accepted: %+v %v",rejected,rejectedErr)
 }
}
