//go:build windows

package main

import (
 "context"
 "errors"
 "os"
 "path/filepath"
 "testing"
 "strings"
 "time"

 "volve-browser-protection/motorupdate"
)

func combinedRecoveryFixture(t *testing.T)(
 root string,deps residentSignedCombinedRecoveryDeps,key []byte){
 t.Helper()
 installed,keyTyped,file:=signedTaskRecoveryFixture(t)
 task:=residentSignedTaskRestoreDeps{
  VerifySystem:file.VerifySystem,
  VerifyACL:file.VerifyACL,
  ProbeQuiescence:file.ProbeQuiescence,
  RunWindowsTask:func(context.Context,string)(string,error){
   return "VOLVE_SIGNED_ORIGINAL_TASK_RESTORED",nil
  },
 }
 return installed,residentSignedCombinedRecoveryDeps{File:file,Task:task},[]byte(keyTyped)
}

func TestSignedCombinedRecoveryMissingExeThenTaskOneMutexNoReceipt(t *testing.T){
 root,deps,publicKey:=combinedRecoveryFixture(t)
 old:=filepath.Join(root,residentLegacyExe)
 expected,err:=os.ReadFile(old);if err!=nil{t.Fatal(err)}
 if err:=os.Remove(old);err!=nil{t.Fatal(err)}
 taskCalls:=0
 deps.Task.RunWindowsTask=func(_ context.Context,script string)(string,error){
  taskCalls++
  // An alternate writer must not acquire the protected mutex between
  // file reconstruction and task import, nor during final task callback.
  tryCtx,cancel:=context.WithTimeout(context.Background(),80*time.Millisecond)
  defer cancel()
  ch:=make(chan error,1)
  go func(){
   unlock,err:=motorupdate.AcquireProtectedResidentTransitionLease(tryCtx)
   if unlock!=nil{unlock()}
   ch<-err
  }()
  if err:=<-ch;!errors.Is(err,context.DeadlineExceeded){
   t.Fatalf("combined recovery mutex was released before Scheduler import: %v",err)
  }
  if len(script)<100 || !containsCombinedTokens(script){
   t.Fatal("signed SYSTEM task import missing fixed identity checks")
  }
  return "VOLVE_SIGNED_ORIGINAL_TASK_RESTORED",nil
 }
 err=recoverSignedLegacyOriginalAndSYSTEMTaskWindows(context.Background(),
  root,publicKey,deps)
 if err!=nil{t.Fatalf("missing file + signed task transaction denied: %v",err)}
 if taskCalls!=1{t.Fatalf("expected one protected task import, got %d",taskCalls)}
 actual,err:=os.ReadFile(old);if err!=nil||string(actual)!=string(expected){
  t.Fatalf("original restored bytes differ: %v",err)
 }
 journal:=filepath.Join(root,residentRecoveryParent,residentJournalDirName)
 state,err:=auditResidentJournal(context.Background(),journal)
 if err!=nil||state.Status!="recovery-required"{
  t.Fatalf("combined recovery falsely marked DNS healthy: %+v %v",state,err)
 }
 if _,err:=os.Lstat(filepath.Join(journal,motorupdate.ResidentResultFile));!os.IsNotExist(err){
  t.Fatalf("combined recovery produced false terminal receipt: %v",err)
 }
}

func containsCombinedTokens(s string)bool{
 return strings.Contains(s,"Get-ScheduledTask")&&
  strings.Contains(s,"Register-ScheduledTask")&&
  strings.Contains(s,"Get-NetUDPEndpoint")
}

func TestSignedCombinedRecoveryAlreadyOriginalRetriesTaskWithoutOverwritingExe(t *testing.T){
 root,deps,key:=combinedRecoveryFixture(t)
 old:=filepath.Join(root,residentLegacyExe)
 info,err:=os.Stat(old);if err!=nil{t.Fatal(err)}
 calls:=0
 deps.Task.RunWindowsTask=func(context.Context,string)(string,error){
  calls++
  return "VOLVE_SIGNED_ORIGINAL_TASK_RESTORED",nil
 }
 if err:=recoverSignedLegacyOriginalAndSYSTEMTaskWindows(
  context.Background(),root,key,deps);err!=nil{t.Fatal(err)}
 after,err:=os.Stat(old)
 if err!=nil||!os.SameFile(info,after){
  t.Fatalf("retry replaced a valid original EXE: %v",err)
 }
 if calls!=1{t.Fatalf("retry skipped restore of task XML and startup trigger: %d",calls)}
}

func TestSignedCombinedRecoveryUnknownExistingImageNoTaskMutation(t *testing.T){
 root,deps,key:=combinedRecoveryFixture(t)
 old:=filepath.Join(root,residentLegacyExe)
 untrusted:=[]byte("MZ-UNKNOWN-UNAUTHORIZED-MOTOR")
 if err:=os.WriteFile(old,untrusted,0600);err!=nil{t.Fatal(err)}
 calls:=0
 deps.Task.RunWindowsTask=func(context.Context,string)(string,error){calls++;return "",nil}
 err:=recoverSignedLegacyOriginalAndSYSTEMTaskWindows(context.Background(),root,key,deps)
 if err==nil||calls!=0{t.Fatalf("foreign live executable was accepted: %v (task calls %d)",err,calls)}
 actual,_:=os.ReadFile(old)
 if string(actual)!=string(untrusted){t.Fatal("foreign original EXE overwritten")}
}

func TestSignedCombinedRecoveryRejectsLiveDNS53NoTaskOrExeChanges(t *testing.T){
 root,deps,key:=combinedRecoveryFixture(t)
 old:=filepath.Join(root,residentLegacyExe)
 if err:=os.Remove(old);err!=nil{t.Fatal(err)}
 deps.File.ProbeQuiescence=func(context.Context,string)(residentQuiescenceDecision,error){
  return residentQuiescenceDecision{TaskIdentityVerified:true,DNSPortFree:false,
   MotorProcessesStopped:true},errors.New("active DNS53")
 }
 attempts:=0
 deps.Task.RunWindowsTask=func(context.Context,string)(string,error){attempts++;return "",nil}
 if err:=recoverSignedLegacyOriginalAndSYSTEMTaskWindows(context.Background(),root,key,deps);err==nil{
  t.Fatal("active DNS listener allowed recovery")
 }
 if attempts!=0{t.Fatal("port53 busy reached Task Scheduler import")}
 if _,err:=os.Lstat(old);!os.IsNotExist(err){t.Fatalf("quiescence rejection modified original EXE: %v",err)}
}

func TestSignedCombinedRecoveryTaskFailureLeavesOriginalAndPendingJournal(t *testing.T){
 root,deps,key:=combinedRecoveryFixture(t)
 old:=filepath.Join(root,residentLegacyExe)
 if err:=os.Remove(old);err!=nil{t.Fatal(err)}
 deps.Task.RunWindowsTask=func(context.Context,string)(string,error){
  return "",errors.New("simulated task Scheduler failure")
 }
 if err:=recoverSignedLegacyOriginalAndSYSTEMTaskWindows(context.Background(),root,key,deps);err==nil{
  t.Fatal("task import failure reported a completed restoration")
 }
 if _,err:=os.Stat(old);err!=nil{t.Fatalf("restored original bytes lost after task failure: %v",err)}
 state,err:=auditResidentJournal(context.Background(),
  filepath.Join(root,residentRecoveryParent,residentJournalDirName))
 if err!=nil||state.Status!="recovery-required"{
  t.Fatalf("task failure wrote a false terminal journal: %+v %v",state,err)
 }
}

func TestSignedCombinedRecoveryWithoutSYSTEMOrCancelledCannotMutate(t *testing.T){
 root,deps,key:=combinedRecoveryFixture(t)
 deps.File.VerifySystem=func(context.Context)error{return errors.New("not SYSTEM")}
 calls:=0
 deps.Task.RunWindowsTask=func(context.Context,string)(string,error){calls++;return "",nil}
 if err:=recoverSignedLegacyOriginalAndSYSTEMTaskWindows(
  context.Background(),root,key,deps);err==nil{t.Fatal("non-SYSTEM recovery accepted")}
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 if err:=recoverSignedLegacyOriginalAndSYSTEMTaskWindows(
  ctx,root,key,deps);!errors.Is(err,context.Canceled){t.Fatalf("cancelled recovery accepted: %v",err)}
 if calls!=0{t.Fatal("SYSTEM/cancellation failed closed after task import")}
}


func TestSignedCombinedRecoveryLockedHandoffDoesNotReacquireMutex(t *testing.T){
 root,deps,key:=combinedRecoveryFixture(t)
 ctx,cancel:=context.WithTimeout(context.Background(),20*time.Second)
 defer cancel()
 release,err:=motorupdate.AcquireProtectedResidentTransitionLease(ctx)
 if err!=nil||release==nil{t.Fatalf("CI watchdog cannot acquire shared OS transition lock: %v",err)}
 defer release()
 taskCalls:=0
 deps.Task.RunWindowsTask=func(_ context.Context,script string)(string,error){
  taskCalls++
  if !containsCombinedTokens(script){t.Fatal("lock-held task import lost its live DNS and Scheduler guards")}
  return "VOLVE_SIGNED_ORIGINAL_TASK_RESTORED",nil
 }
 // If the locked handoff accidentally tries to acquire the same non-
 // reentrant Windows mutex again, it blocks until this test's deadline.
 if err:=recoverSignedLegacyOriginalAndSYSTEMTaskLockedWindows(ctx,root,key,deps);err!=nil{
  t.Fatalf("signed watchdog handoff under existing mutex failed: %v",err)
 }
 if taskCalls!=1{t.Fatalf("expected one signed task operation under held lease, got %d",taskCalls)}
 if state,err:=auditResidentJournal(ctx,
  filepath.Join(root,residentRecoveryParent,residentJournalDirName));err!=nil ||
  state.Status!="recovery-required"{
  t.Fatalf("lock-held handoff falsely finalized DNS health: %+v %v",state,err)
 }
}
