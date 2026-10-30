//go:build windows

package main

// Unit tests for the recovery plan using a fake PowerShell executor. No
// ScheduledTask is ever created, switched, imported or started by this file.
import (
 "context"
 "errors"
 "os"
 "path/filepath"
 "strings"
 "testing"

 "volve-browser-protection/motorupdate"
)

const disposableResidentTask="VOLVE-CI-ManagedMotor-1793321319528439500"

func TestResidentPilotRecoveryRequiresSafeNameAndImmutableEvidence(t *testing.T){
 root,_,_,_:=chainFixture(t,false)
 calls:=0
 runner:=func(context.Context,string)(string,error){
  calls++
  return "VOLVE_CI_RESIDENT_RESTORED",nil
 }
 if err:=restoreResidentPilotSYSTEMTaskWithRunner(context.Background(),root,
  "VOLVE-DNS-SERVER-0270",runner);err==nil{
  t.Fatal("real VOLVE SYSTEM task was accepted by CI-only recovery")
 }
 if calls!=0{t.Fatal("unsafe task reached runner")}
 if err:=restoreResidentPilotSYSTEMTaskWithRunner(context.Background(),root,
  disposableResidentTask,nil);err==nil{
  t.Fatal("missing independent executor was accepted")
 }
 if calls!=0{t.Fatal("missing executor unexpectedly invoked")}
 
 xml:=filepath.Join(root,residentRecoveryParent,residentRecoveryFolder,residentRecoveryTask)
 if err:=os.WriteFile(xml,[]byte("tampered task XML"),0600);err!=nil{t.Fatal(err)}
 if err:=restoreResidentPilotSYSTEMTaskWithRunner(context.Background(),root,
  disposableResidentTask,runner);err==nil{
  t.Fatal("corrupt original SYSTEM backup was accepted")
 }
 if calls!=0{t.Fatal("corrupt backup reached privileged executor")}
}

func TestResidentPilotRecoveryScriptBindsLiveTaskAndBackup(t *testing.T){
 root,dir,seal,protect:=chainFixture(t,false)
 executed:=0
 var script string
 runner:=func(_ context.Context,source string)(string,error){
  executed++
  script=source
  return "VOLVE_CI_RESIDENT_RESTORED",nil // simulates success, NO actual Task Scheduler call
 }
 err:=restoreResidentPilotSYSTEMTaskWithRunner(context.Background(),root,
  disposableResidentTask,runner)
 if err!=nil{t.Fatalf("safe rehearsal fixture refused: %v",err)}
 if executed!=1 {t.Fatalf("unsafe executor call count: %d",executed)}
 for _,literal:=range []string{
  "Get-ScheduledTask","Register-ScheduledTask",
  "Get-FileHash","$xmlHash","$oldHash","$target",
  "SYSTEM","--dns-service","VOLVE_CI_RESIDENT_RESTORED",
  disposableResidentTask,
 }{
  if !strings.Contains(script,literal){t.Fatalf("recovery plan omitted %q",literal)}
 }
 if !strings.Contains(script,"Original task XML changed before import") ||
    !strings.Contains(script,"Restored task identity mismatch"){
  t.Fatal("recovery plan omits before/after verification")
 }
 // The runner's synthetic success must NOT consume the real journal.
 state,err:=auditResidentJournal(context.Background(),dir)
 if err!=nil||state.Status!="recovery-required"{
  t.Fatalf("rehearsal changed the journal: %+v %v",state,err)
 }
 // A terminal receipt means a new attempt must not invoke recovery again.
 if err:=motorupdate.FinishResidentRecoveryIntent(context.Background(),dir,
   "committed",seal,protect);err!=nil{t.Fatal(err)}
 if err:=restoreResidentPilotSYSTEMTaskWithRunner(context.Background(),root,
  disposableResidentTask,runner);err==nil{
  t.Fatal("committed transaction was considered a recoverable pending transaction")
 }
 if executed!=1 {t.Fatal("closed transaction reached execution")}
}

func TestResidentPilotRecoveryPowerShellFailureDoesNotClaimRestore(t *testing.T){
 root,_,_,_:=chainFixture(t,false)
 calls:=0
 run:=func(context.Context,string)(string,error){
  calls++
  return "",errors.New("simulated Register-ScheduledTask failure")
 }
 if err:=restoreResidentPilotSYSTEMTaskWithRunner(context.Background(),root,
  disposableResidentTask,run);err==nil{
  t.Fatal("PowerShell restoration failure was reported as success")
 }
 if calls!=1{t.Fatalf("unexpected recovery calls: %d",calls)}
 run=func(context.Context,string)(string,error){
  return "NOT_RESTORED",nil
 }
 if err:=restoreResidentPilotSYSTEMTaskWithRunner(context.Background(),root,
  disposableResidentTask,run);err==nil{
  t.Fatal("ambiguous PowerShell output reported restoration success")
 }
}

func TestResidentPilotTargetPathStrictVersion(t *testing.T){
 root:=t.TempDir()
 path,err:=residentPilotTargetPath(root,"0.28.7")
 if err!=nil||filepath.Base(path)!="VOLVE_DNS_Motor_0_28_7.exe"{
  t.Fatalf("unexpected sandbox target path: %q %v",path,err)
 }
 for _,v:=range []string{"","0.28.7-rc","1.2/3","1..2","../../0.28.7"}{
  if _,err:=residentPilotTargetPath(root,v);err==nil{
   t.Fatalf("invalid version accepted: %q",v)
  }
 }
}
