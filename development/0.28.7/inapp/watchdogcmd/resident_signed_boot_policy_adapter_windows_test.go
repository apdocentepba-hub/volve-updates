//go:build windows

package main

// A disposable, synthetic-publisher Windows fixture proves that the signed
// recovery operations satisfy the existing boot-driver contract while its
// protected OS mutex is ALREADY owned. No real DNS53, production task,
// startup hook or release is installed.
import (
 "context"
 "crypto/ed25519"
 "errors"
 "os"
 "path/filepath"
 "testing"
 "time"

 "volve-browser-protection/motorupdate"
)

func TestSignedBootOriginalOpsRejectMissingTrustBeforeOSChanges(t *testing.T){
 root,deps,key:=combinedRecoveryFixture(t)
 if ops,err:=newResidentSignedBootOriginalOps(root,nil,deps);err==nil||ops!=nil{
  t.Fatal("boot ops accepted absent publisher key")
 }
 broken:=deps
 broken.Task.RunWindowsTask=nil
 if ops,err:=newResidentSignedBootOriginalOps(root,key,broken);err==nil||ops!=nil{
  t.Fatal("boot ops accepted absent Scheduler executor")
 }
 if ops,err:=newResidentSignedBootOriginalOps("relative",key,deps);err==nil||ops!=nil{
  t.Fatal("boot ops accepted nonabsolute installation root")
 }
}

func TestSignedBootOriginalOpsUnderProtectedPolicyLeaseLeavesPendingJournal(t *testing.T){
 root,deps,key:=combinedRecoveryFixture(t)
 ctx,cancel:=context.WithTimeout(context.Background(),240*time.Second)
 defer cancel()
 journalDir:=filepath.Join(root,residentRecoveryParent,residentJournalDirName)
 state,err:=motorupdate.InspectResidentRecoveryJournal(ctx,journalDir,func(p string)error{
  return deps.File.VerifyACL(p)
 })
 if err!=nil||state.Status!="recovery-required"{t.Fatalf("test has no protected pending journal: %v",err)}
 calls:=0
 deps.Task.RunWindowsTask=func(context.Context,string)(string,error){
  calls++
  return "VOLVE_SIGNED_ORIGINAL_TASK_RESTORED",nil
 }
 ops,err:=newResidentSignedBootOriginalOps(root,ed25519.PublicKey(key),deps)
 if err!=nil{t.Fatal(err)}
 // This is the REAL immutable Windows mutex used by the production updater.
 // Our operations MUST NOT reacquire it, which would block to ctx deadline.
 release,err:=motorupdate.AcquireProtectedResidentTransitionLease(ctx)
 if err!=nil||release==nil{t.Fatalf("protected boot-policy mutex unavailable: %v",err)}
 defer release()
 if err:=ops.VerifySealedOriginal(ctx,state.Intent);err!=nil{
  t.Fatalf("signed immutable recovery proof refused under held policy lock: %v",err)
 }
 forged:=state.Intent
 forged.Nonce="different-authorization-nonce"
 if err:=ops.VerifySealedOriginal(ctx,forged);err==nil{
  t.Fatal("boot original ops trusted a different recovery transaction nonce")
 }
 if calls!=0{t.Fatal("read-only publisher audit reached Scheduler")}
 if err:=ops.RestoreOriginal(ctx,state.Intent);err!=nil{
  t.Fatalf("boot policy original restore failed while holding protected lock: %v",err)
 }
 if calls!=1{t.Fatalf("expected precisely one original task restoration, got %d",calls)}
 pending,err:=auditResidentJournal(ctx,journalDir)
 if err!=nil||pending.Status!="recovery-required"{
  t.Fatalf("policy original ops incorrectly marked DNS or Internet healthy: %+v %v",pending,err)
 }
 if _,err:=os.Lstat(filepath.Join(journalDir,motorupdate.ResidentResultFile));!errors.Is(err,os.ErrNotExist){
  t.Fatalf("false terminal recovery receipt created without real DNS health: %v",err)
 }
}


func TestSignedBootOriginalOpsHealthyRunningOriginalCanBeAuditedButNotMutated(t *testing.T){
 root,deps,key:=combinedRecoveryFixture(t)
 ctx,cancel:=context.WithTimeout(context.Background(),200*time.Second)
 defer cancel()
 journalDir:=filepath.Join(root,residentRecoveryParent,residentJournalDirName)
 state,err:=motorupdate.InspectResidentRecoveryJournal(ctx,journalDir,deps.File.VerifyACL)
 if err!=nil||state.Status!="recovery-required"{t.Fatalf("missing signed recovery intent: %v",err)}
 // A correct already-running DNS service MUST NOT block a read-only signed
 // recovery attestation. It MUST block actual task/EXE modification.
 portBusy:=func(context.Context,string)(residentQuiescenceDecision,error){
  return residentQuiescenceDecision{TaskIdentityVerified:true,
   DNSPortFree:false,MotorProcessesStopped:false,ReadyForFurtherChecks:false},
   errors.New("healthy original already owns DNS53")
 }
 deps.File.ProbeQuiescence=portBusy
 deps.Task.ProbeQuiescence=portBusy
 schedulerWrites:=0
 deps.Task.RunWindowsTask=func(context.Context,string)(string,error){
  schedulerWrites++
  return "VOLVE_SIGNED_ORIGINAL_TASK_RESTORED",nil
 }
 ops,err:=newResidentSignedBootOriginalOps(root,key,deps)
 if err!=nil{t.Fatal(err)}
 lease,err:=motorupdate.AcquireProtectedResidentTransitionLease(ctx)
 if err!=nil||lease==nil{t.Fatalf("cannot lock signed boot admission: %v",err)}
 defer lease()
 if err:=ops.VerifySealedOriginal(ctx,state.Intent);err!=nil{
  t.Fatalf("healthy original blocked immutable signed publisher verification: %v",err)
 }
 if err:=ops.RestoreOriginal(ctx,state.Intent);err==nil{
  t.Fatal("active DNS listener allowed a mutating signed recovery")
 }
 if schedulerWrites!=0{t.Fatal("read-only healthy audit reached Windows task mutation")}
 pending,err:=auditResidentJournal(ctx,journalDir)
 if err!=nil||pending.Status!="recovery-required"{
  t.Fatalf("busy DNS rejection modified pending recovery evidence: %+v %v",pending,err)
 }
}


// The policy-level contract is materially stronger than separately calling
// VerifySealedOriginal and RestoreOriginal. It holds one actual Windows kernel
// lease across signed grant verification, task import, synthetic DNS/Internet
// health and terminal receipt, then refuses to replay the recovery on retry.
// This lab fixture has REAL NTFS ACL verification and a signed disposable
// publisher grant, but simulated identity/health/Scheduler operations.
// It does NOT prove a real reboot, start a DNS process or touch product tasks.
func TestSignedBootPolicyFullRecoveryUnderSharedMutexSealsExactlyOnce(t *testing.T){
 root,deps,key:=combinedRecoveryFixture(t)
 ctx,cancel:=context.WithTimeout(context.Background(),280*time.Second)
 defer cancel()
 journalDir:=filepath.Join(root,residentRecoveryParent,residentJournalDirName)
 before,err:=motorupdate.InspectResidentRecoveryJournal(ctx,journalDir,durableWindowsACL)
 if err!=nil||before.Status!="recovery-required"{
  t.Fatalf("test fixture missing pending protected journal: %+v %v",before,err)
 }
 calls:=0
 deps.Task.RunWindowsTask=func(_ context.Context,script string)(string,error){
  calls++
  if !containsCombinedTokens(script){
   return "",errors.New("policy original task re-import lost signed SYSTEM/DNS53 fences")
  }
  // Prove the policy still holds the global Win32 mutex at the actual
  // Scheduler mutation boundary, not only during its initial audit.
  blockedCtx,done:=context.WithTimeout(context.Background(),90*time.Millisecond)
  defer done()
  blocked:=make(chan error,1)
  go func(){
   unlock,err:=motorupdate.AcquireProtectedResidentTransitionLease(blockedCtx)
   if unlock!=nil{unlock()}
   blocked<-err
  }()
  if err:=<-blocked;!errors.Is(err,context.DeadlineExceeded){
   return "",errors.New("policy released transition mutex before signed Scheduler restore")
  }
  return "VOLVE_SIGNED_ORIGINAL_TASK_RESTORED",nil
 }
 ops,err:=newResidentSignedBootOriginalOps(root,ed25519.PublicKey(key),deps)
 if err!=nil{t.Fatal(err)}
 driver,err:=motorupdate.NewProtectedResidentBootDriver(ops)
 if err!=nil{t.Fatal(err)}
 sealed:=func(path string)error{
  hardenedTestACL(t,path,path)
  return nil
 }
 health:=&ciBootHealth{firstOriginalMissing:true}
 result,err:=motorupdate.RecoverPendingResidentAfterBoot(ctx,journalDir,
  sealed,durableWindowsACL,health,driver)
 if err!=nil||result!="restored"||calls!=1{
  t.Fatalf("signed protected boot policy did not finish once: result=%q tasks=%d err=%v",result,calls,err)
 }
 if health.identityChecks<3{
  t.Fatalf("boot policy did not verify running original identity after signed restore: %d",health.identityChecks)
 }
 journal,err:=motorupdate.InspectResidentRecoveryJournal(ctx,journalDir,durableWindowsACL)
 if err!=nil||journal.Status!="restored"{
  t.Fatalf("synthetic healthy DNS/Internet did not yield terminal protected receipt: %+v %v",journal,err)
 }
 again,err:=motorupdate.RecoverPendingResidentAfterBoot(ctx,journalDir,
  sealed,durableWindowsACL,&ciBootHealth{},driver)
 if err!=nil||again!="restored"||calls!=1{
  t.Fatalf("terminal original boot recovery replayed or rejected: %q calls=%d err=%v",again,calls,err)
 }
}
