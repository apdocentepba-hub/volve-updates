//go:build windows

package main

import (
 "context"
 "crypto/ed25519"
 "errors"
 "os"
 "path/filepath"
 "strings"
 "testing"

 "volve-browser-protection/motorupdate"
)

// The task-restore path is intentionally stricter than the missing-file
// path: an already installed EXE must have an explicit protected Windows DACL.
// The fixture must model that property rather than weakening production checks.
func signedTaskRecoveryFixture(t *testing.T)(
 string,ed25519.PublicKey,residentMissingOriginalRestoreDeps){
 t.Helper()
 root,key,deps:=signedMissingRecoveryFixture(t)
 installed:=filepath.Join(root,residentLegacyExe)
 hardenedTestACL(t,installed,installed)
 if err:=deps.VerifyACL(installed);err!=nil{
  t.Fatalf("signed task fixture installed EXE DACL is not protected: %v",err)
 }
 return root,key,deps
}

func TestSignedOriginalSYSTEMTaskRestoresOnlyAuthenticatedPendingXMLAndDoesNotFinish(t *testing.T){
 root,key,d:=signedTaskRecoveryFixture(t)
 xmlPath:=filepath.Join(root,residentRecoveryParent,residentRecoveryFolder,residentRecoveryTask)
 xml,err:=os.ReadFile(xmlPath);if err!=nil{t.Fatal(err)}
 calls:=0
 d2:=residentSignedTaskRestoreDeps{
  VerifySystem:d.VerifySystem,
  VerifyACL:d.VerifyACL,
  ProbeQuiescence:d.ProbeQuiescence,
  RunWindowsTask:func(_ context.Context,script string)(string,error){
   calls++
   required:=[]string{
    "VOLVE-DNS-SERVER-0270","Register-ScheduledTask","Get-ScheduledTask",
    "Get-NetUDPEndpoint","Get-NetTCPConnection","Get-CimInstance",
    "Sealed original Scheduler XML changed","Original executable bytes changed",
    "VOLVE_SIGNED_ORIGINAL_TASK_RESTORED","--dns-service",
    "Restored SYSTEM task identity differs from original",
    "$validTriggers.Count -lt 1", "$bootTriggers.Count -lt 1", "MSFT_TaskBootTrigger", "Where-Object{ $null -ne $_ }", "-not $restored.Settings.Enabled",
   }
   for _,q:=range required{if !strings.Contains(script,q){t.Errorf("missing required privilege check: %s",q)}}
   if strings.Contains(script,"Get-FileHash"){
    t.Error("signed task recovery still depends on optional Get-FileHash cmdlet")
   }
   for _,token:=range []string{"[IO.File]::OpenRead($old)","[Security.Cryptography.SHA256]::Create()","finally{$oldHandle.Dispose();$oldHasher.Dispose()}"}{
    if !strings.Contains(script,token){t.Errorf("signed task recovery native hash missing %s",token)}
   }
   if strings.Contains(script,"if($isOriginal){Write-Output 'VOLVE_SIGNED_ORIGINAL_TASK_RESTORED';return}"){
    t.Error("already-original task wrongly skipped sealed XML re-import / trigger restoration")
   }
   return "VOLVE_SIGNED_ORIGINAL_TASK_RESTORED",nil
  },
 }
 if err:=restoreSignedOriginalSYSTEMTaskWindows(context.Background(),root,key,d2);err!=nil{
  t.Fatalf("signed pending original task recovery refused: %v",err)
 }
 if calls!=1{t.Fatalf("unexpected import invocation count: %d",calls)}
 after,err:=os.ReadFile(xmlPath)
 if err!=nil||string(after)!=string(xml){t.Fatalf("protected original task XML changed: %v",err)}
 state,err:=auditResidentJournal(context.Background(),filepath.Join(root,residentRecoveryParent,residentJournalDirName))
 if err!=nil||state.Status!="recovery-required"{
  t.Fatalf("task-only import wrote false terminal DNS health: %+v %v",state,err)
 }
 if _,err:=os.Lstat(filepath.Join(root,residentRecoveryParent,residentJournalDirName,motorupdate.ResidentResultFile));!os.IsNotExist(err){
  t.Fatalf("task-only original restore published a false healthy recovery: %v",err)
 }
}

func TestSignedOriginalSYSTEMTaskNeverReachesSchedulerWhenOriginalMissingOrModified(t *testing.T){
 for _,scenario:=range []string{"missing","foreign","bad-xml"}{
  t.Run(scenario,func(t *testing.T){
   root,key,d:=signedTaskRecoveryFixture(t)
   old:=filepath.Join(root,residentLegacyExe)
   xml:=filepath.Join(root,residentRecoveryParent,residentRecoveryFolder,residentRecoveryTask)
   switch scenario{
   case "missing":if err:=os.Remove(old);err!=nil{t.Fatal(err)}
   case "foreign":if err:=os.WriteFile(old,[]byte("MZ-UNTRUSTED-EXE"),0600);err!=nil{t.Fatal(err)}
   case "bad-xml":if err:=os.WriteFile(xml,[]byte("ALTERED XML"),0600);err!=nil{t.Fatal(err)}
   }
   attempts:=0
   deps:=residentSignedTaskRestoreDeps{VerifySystem:d.VerifySystem,VerifyACL:d.VerifyACL,
    ProbeQuiescence:d.ProbeQuiescence,
    RunWindowsTask:func(context.Context,string)(string,error){attempts++;return "VOLVE_SIGNED_ORIGINAL_TASK_RESTORED",nil}}
   if err:=restoreSignedOriginalSYSTEMTaskWindows(context.Background(),root,key,deps);err==nil{
    t.Fatal("untrusted original recovered a SYSTEM task")
   }
   if attempts!=0{t.Fatal("untrusted file reached Scheduler mutation")}
  })
 }
}

func TestSignedOriginalSYSTEMTaskRejectsPort53AndUnprivilegedToken(t *testing.T){
 root,key,probe:=signedTaskRecoveryFixture(t)
 tried:=0
 deps:=residentSignedTaskRestoreDeps{
  VerifySystem:func(context.Context)error{return errors.New("not SYSTEM")},
  VerifyACL:probe.VerifyACL,ProbeQuiescence:probe.ProbeQuiescence,
  RunWindowsTask:func(context.Context,string)(string,error){tried++;return "VOLVE_SIGNED_ORIGINAL_TASK_RESTORED",nil},
 }
 if err:=restoreSignedOriginalSYSTEMTaskWindows(context.Background(),root,key,deps);err==nil{
  t.Fatal("non-SYSTEM principal allowed to recover task")
 }
 deps.VerifySystem=probe.VerifySystem
 deps.ProbeQuiescence=func(context.Context,string)(residentQuiescenceDecision,error){
  return residentQuiescenceDecision{TaskIdentityVerified:true,DNSPortFree:false,MotorProcessesStopped:true},
   errors.New("port 53 occupied")
 }
 if err:=restoreSignedOriginalSYSTEMTaskWindows(context.Background(),root,key,deps);err==nil{
  t.Fatal("active DNS motor permitted Scheduler mutation")
 }
 if tried!=0{t.Fatal("invalid SYSTEM or live DNS reached task import")}
}

func TestSignedOriginalSYSTEMTaskRechecksQuiescenceAndRefusesAmbiguousPowerShell(t *testing.T){
 root,key,p:=signedTaskRecoveryFixture(t)
 checks:=0
 runs:=0
 deps:=residentSignedTaskRestoreDeps{
  VerifySystem:p.VerifySystem,VerifyACL:p.VerifyACL,
  ProbeQuiescence:func(context.Context,string)(residentQuiescenceDecision,error){
   checks++
   if checks>=2{return residentQuiescenceDecision{},errors.New("port 53 activated during verification")}
   return residentQuiescenceDecision{TaskIdentityVerified:true,DNSPortFree:true,
    MotorProcessesStopped:true,ReadyForFurtherChecks:true},nil
  },
  RunWindowsTask:func(context.Context,string)(string,error){runs++;return "VOLVE_SIGNED_ORIGINAL_TASK_RESTORED",nil},
 }
 if err:=restoreSignedOriginalSYSTEMTaskWindows(context.Background(),root,key,deps);err==nil{
  t.Fatal("task restore accepted changing DNS status during final admission")
 }
 if checks!=2||runs!=0{t.Fatalf("mutating import after %d observations / %d calls",checks,runs)}
 deps.ProbeQuiescence=p.ProbeQuiescence
 deps.RunWindowsTask=func(context.Context,string)(string,error){runs++;return "PARTIAL",nil}
 if err:=restoreSignedOriginalSYSTEMTaskWindows(context.Background(),root,key,deps);err==nil{
  t.Fatal("ambiguous Scheduler result was considered success")
 }
}
