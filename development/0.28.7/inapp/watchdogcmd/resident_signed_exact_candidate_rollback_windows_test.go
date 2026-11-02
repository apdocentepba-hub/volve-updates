//go:build windows

package main

// All test files live only in a disposable NTFS fixture. Windows Scheduler
// execution is mocked; real publisher-signature, ACL, SHA-256 and OS-wide
// mutex checks are kept, with NO product motor or port53 mutation.
import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "os"
 "path/filepath"
 "testing"
 "time"

 "volve-browser-protection/motorupdate"
)

func installExactSignedCandidateFixture(t *testing.T,root string)[]byte{
 t.Helper()
 original:=filepath.Join(root,residentLegacyExe)
 candidate:=[]byte("publisher-signed candidate CI bytes")
 digest:=sha256.Sum256(candidate)
 intent,err:=auditPostSwitchResidentRecovery(context.Background(),root)
 if err!=nil{t.Fatal(err)}
 if hex.EncodeToString(digest[:])!=intent.TargetSHA256{
  t.Fatal("fixture candidate is not the exact SHA-256 bound to durable publisher grant")
 }
 if err:=os.WriteFile(original,candidate,0600);err!=nil{t.Fatal(err)}
 if err:=durableWindowsACL(original);err!=nil{
  t.Fatalf("test candidate lost protected NTFS DACL: %v",err)
 }
 return candidate
}

func TestSignedExactCandidateRollbackRestoresOriginalThenTaskAndLeavesPending(t *testing.T){
 root,deps,key:=combinedRecoveryFixture(t)
 original:=filepath.Join(root,residentLegacyExe)
 backup:=filepath.Join(root,residentRecoveryParent,residentRecoveryFolder,residentRecoveryExe)
 expected,err:=os.ReadFile(backup);if err!=nil{t.Fatal(err)}
 installExactSignedCandidateFixture(t,root)
 calls:=0
 deps.Task.RunWindowsTask=func(context.Context,string)(string,error){
  calls++
  return "VOLVE_SIGNED_ORIGINAL_TASK_RESTORED",nil
 }
 ctx,cancel:=context.WithTimeout(context.Background(),240*time.Second);defer cancel()
 if err:=recoverSignedLegacyOriginalAndSYSTEMTaskWindows(ctx,root,key,deps);err!=nil{
  t.Fatalf("publisher-signed exact target cannot rollback: %v",err)
 }
 after,err:=os.ReadFile(original)
 if err!=nil||string(after)!=string(expected){
  t.Fatalf("candidate not replaced by byte-exact sealed original: %v",err)
 }
 if err:=durableWindowsACL(original);err!=nil{
  t.Fatalf("restored signed original inherited untrusted NTFS ACL: %v",err)
 }
 if calls!=1{t.Fatalf("required original SYSTEM task import missing: %d",calls)}
 journalDir:=filepath.Join(root,residentRecoveryParent,residentJournalDirName)
 journal,err:=motorupdate.InspectResidentRecoveryJournal(ctx,journalDir,durableWindowsACL)
 if err!=nil||journal.Status!="recovery-required"{
  t.Fatalf("file/task rollback falsely proves DNS health: %+v %v",journal,err)
 }
 if _,err:=os.Lstat(filepath.Join(journalDir,motorupdate.ResidentResultFile));!errors.Is(err,os.ErrNotExist){
  t.Fatalf("false restored terminal receipt written: %v",err)
 }
 // A retry must never overwrite an already restored original EXE.
 prior,err:=os.Stat(original);if err!=nil{t.Fatal(err)}
 if err:=recoverSignedLegacyOriginalAndSYSTEMTaskWindows(ctx,root,key,deps);err!=nil{
  t.Fatalf("idempotent retry of signed original task was refused: %v",err)
 }
 subsequent,err:=os.Stat(original)
 if err!=nil||!os.SameFile(prior,subsequent){
  t.Fatalf("repeat recovery unnecessarily replaced the correct original: %v",err)
 }
}

func TestSignedExactCandidateRollbackRejectsActiveDNSWithoutTouchingCandidate(t *testing.T){
 root,deps,key:=combinedRecoveryFixture(t)
 original:=filepath.Join(root,residentLegacyExe)
 expected:=installExactSignedCandidateFixture(t,root)
 busy:=func(context.Context,string)(residentQuiescenceDecision,error){
  return residentQuiescenceDecision{TaskIdentityVerified:true,DNSPortFree:false,
   MotorProcessesStopped:false,ReadyForFurtherChecks:false},
   errors.New("DNS53 occupied by running motor")
 }
 deps.File.ProbeQuiescence=busy
 deps.Task.ProbeQuiescence=busy
 calls:=0
 deps.Task.RunWindowsTask=func(context.Context,string)(string,error){calls++;return "",nil}
 ctx,cancel:=context.WithTimeout(context.Background(),180*time.Second);defer cancel()
 if err:=recoverSignedLegacyOriginalAndSYSTEMTaskWindows(ctx,root,key,deps);err==nil{
  t.Fatal("live DNS53 could not prevent candidate rollback")
 }
 if calls!=0{t.Fatal("busy DNS reached SYSTEM task replacement")}
 actual,err:=os.ReadFile(original)
 if err!=nil||string(actual)!=string(expected){t.Fatalf("busy DNS changed installed candidate: %v",err)}
}

func TestSignedBootPolicyAuditsExactCandidateUnderProtectedMutexButRejectsUnknown(t *testing.T){
 root,deps,key:=combinedRecoveryFixture(t)
 original:=filepath.Join(root,residentLegacyExe)
 exact:=installExactSignedCandidateFixture(t,root)
 journalDir:=filepath.Join(root,residentRecoveryParent,residentJournalDirName)
 ctx,cancel:=context.WithTimeout(context.Background(),180*time.Second);defer cancel()
 state,err:=motorupdate.InspectResidentRecoveryJournal(ctx,journalDir,durableWindowsACL)
 if err!=nil||state.Status!="recovery-required"{t.Fatalf("missing protected pending policy: %v",err)}
 ops,err:=newResidentSignedBootOriginalOps(root,key,deps);if err!=nil{t.Fatal(err)}
 unlock,err:=motorupdate.AcquireProtectedResidentTransitionLease(ctx)
 if err!=nil||unlock==nil{t.Fatalf("shared publisher boot mutex unavailable: %v",err)}
 defer unlock()
 if err:=ops.VerifySealedOriginal(ctx,state.Intent);err!=nil{
  t.Fatalf("exact candidate rejected from read-only publisher-signed boot audit: %v",err)
 }
 observed,err:=os.ReadFile(original)
 if err!=nil||string(observed)!=string(exact){t.Fatalf("audit modified live candidate: %v",err)}
 if err:=os.WriteFile(original,[]byte("MZ-UNKNOWN-CANDIDATE"),0600);err!=nil{t.Fatal(err)}
 if err:=ops.VerifySealedOriginal(ctx,state.Intent);err==nil{
  t.Fatal("unknown replacement binary wrongly permitted by signed boot audit")
 }
}


// This exercises the FULL boot policy rather than invoking the candidate
// helper alone. Real NTFS protection and the fixed Windows transition mutex
// remain active, but the SYSTEM task executor and post-boot probes are
// simulated. No task, DNS adapter, production binary or real port53 changes.
func TestSignedExactCandidateBootPolicyFinalizesOnlyAfterHealthyProbes(t *testing.T){
 root,deps,key:=combinedRecoveryFixture(t)
 old:=filepath.Join(root,residentLegacyExe)
 sealedBackup:=filepath.Join(root,residentRecoveryParent,residentRecoveryFolder,residentRecoveryExe)
 expected,err:=os.ReadFile(sealedBackup)
 if err!=nil{t.Fatal(err)}
 installExactSignedCandidateFixture(t,root)
 ctx,cancel:=context.WithTimeout(context.Background(),320*time.Second)
 defer cancel()
 journalDir:=filepath.Join(root,residentRecoveryParent,residentJournalDirName)
 actions:=0
 deps.Task.RunWindowsTask=func(context.Context,string)(string,error){
  actions++
  got,err:=os.ReadFile(old)
  if err!=nil||string(got)!=string(expected){
   return "",errors.New("policy reached task restore before signed original file rollback")
  }
  return "VOLVE_SIGNED_ORIGINAL_TASK_RESTORED",nil
 }
 ops,err:=newResidentSignedBootOriginalOps(root,key,deps)
 if err!=nil{t.Fatal(err)}
 driver,err:=motorupdate.NewProtectedResidentBootDriver(ops)
 if err!=nil{t.Fatal(err)}
 seal:=func(path string)error{hardenedTestACL(t,path,path);return nil}
 health:=&ciBootHealth{firstOriginalMissing:true}
 status,err:=motorupdate.RecoverPendingResidentAfterBoot(ctx,journalDir,
  seal,durableWindowsACL,health,driver)
 if err!=nil||status!="restored"||actions!=1||health.identityChecks<3{
  t.Fatalf("signed candidate did not recover through complete boot policy: status=%q actions=%d identity=%d err=%v",
   status,actions,health.identityChecks,err)
 }
 restored,err:=os.ReadFile(old)
 if err!=nil||string(restored)!=string(expected){
  t.Fatalf("terminal receipt preceded original byte-exact restoration: %v",err)
 }
 after,err:=motorupdate.InspectResidentRecoveryJournal(ctx,journalDir,durableWindowsACL)
 if err!=nil||after.Status!="restored"{
  t.Fatalf("healthy signed candidate did not leave terminal receipt: %+v %v",after,err)
 }
 repeat,err:=motorupdate.RecoverPendingResidentAfterBoot(ctx,journalDir,
  seal,durableWindowsACL,&ciBootHealth{},driver)
 if err!=nil||repeat!="restored"||actions!=1{
  t.Fatalf("completed candidate recovery replayed: status=%q actions=%d err=%v",repeat,actions,err)
 }
}

func TestSignedExactCandidateBootPolicyUnhealthyDNSLeavesPendingOriginal(t *testing.T){
 root,deps,key:=combinedRecoveryFixture(t)
 old:=filepath.Join(root,residentLegacyExe)
 backup:=filepath.Join(root,residentRecoveryParent,residentRecoveryFolder,residentRecoveryExe)
 expected,err:=os.ReadFile(backup)
 if err!=nil{t.Fatal(err)}
 installExactSignedCandidateFixture(t,root)
 ctx,cancel:=context.WithTimeout(context.Background(),320*time.Second)
 defer cancel()
 journalDir:=filepath.Join(root,residentRecoveryParent,residentJournalDirName)
 calls:=0
 deps.Task.RunWindowsTask=func(context.Context,string)(string,error){
  calls++
  return "VOLVE_SIGNED_ORIGINAL_TASK_RESTORED",nil
 }
 ops,err:=newResidentSignedBootOriginalOps(root,key,deps)
 if err!=nil{t.Fatal(err)}
 driver,err:=motorupdate.NewProtectedResidentBootDriver(ops)
 if err!=nil{t.Fatal(err)}
 seal:=func(path string)error{hardenedTestACL(t,path,path);return nil}
 status,err:=motorupdate.RecoverPendingResidentAfterBoot(ctx,journalDir,
  seal,durableWindowsACL,&ciBootHealth{firstOriginalMissing:true,rejectDNS:true},driver)
 if err==nil||status!=""||calls!=1{
  t.Fatalf("unhealthy post-rollback DNS incorrectly finished: status=%q calls=%d err=%v",status,calls,err)
 }
 got,err:=os.ReadFile(old)
 if err!=nil||string(got)!=string(expected){
  t.Fatalf("failed DNS probe discarded recovered original bytes: %v",err)
 }
 state,err:=motorupdate.InspectResidentRecoveryJournal(ctx,journalDir,durableWindowsACL)
 if err!=nil||state.Status!="recovery-required"{
  t.Fatalf("unhealthy DNS wrote terminal signed recovery: %+v %v",state,err)
 }
 if _,err:=os.Lstat(filepath.Join(journalDir,motorupdate.ResidentResultFile));!errors.Is(err,os.ErrNotExist){
  t.Fatalf("false receipt after DNS health rejection: %v",err)
 }
}

func TestSignedExactCandidateRollbackQuiescenceChangesBeforeRenameCannotMutate(t *testing.T){
 root,deps,key:=combinedRecoveryFixture(t)
 old:=filepath.Join(root,residentLegacyExe)
 exact:=installExactSignedCandidateFixture(t,root)
 checks:=0
 changing:=func(context.Context,string)(residentQuiescenceDecision,error){
  checks++
  if checks>=3 {
   return residentQuiescenceDecision{TaskIdentityVerified:true,DNSPortFree:false,
    MotorProcessesStopped:false,ReadyForFurtherChecks:false},
    errors.New("DNS53 became active before signed rename")
  }
  return residentQuiescenceDecision{TaskIdentityVerified:true,DNSPortFree:true,
   MotorProcessesStopped:true,ReadyForFurtherChecks:true},nil
 }
 deps.File.ProbeQuiescence=changing
 deps.Task.ProbeQuiescence=changing
 writes:=0
 deps.Task.RunWindowsTask=func(context.Context,string)(string,error){
  writes++
  return "VOLVE_SIGNED_ORIGINAL_TASK_RESTORED",nil
 }
 ctx,cancel:=context.WithTimeout(context.Background(),240*time.Second)
 defer cancel()
 if err:=recoverSignedLegacyOriginalAndSYSTEMTaskWindows(ctx,root,key,deps);err==nil{
  t.Fatal("late DNS53 activation allowed publisher-signed candidate overwrite")
 }
 after,err:=os.ReadFile(old)
 if err!=nil||string(after)!=string(exact)||writes!=0||checks<3{
  t.Fatalf("candidate changed after late quiescence refusal: err=%v scheduler=%d checks=%d",err,writes,checks)
 }
 journalDir:=filepath.Join(root,residentRecoveryParent,residentJournalDirName)
 state,err:=motorupdate.InspectResidentRecoveryJournal(ctx,journalDir,durableWindowsACL)
 if err!=nil||state.Status!="recovery-required"{
  t.Fatalf("late DNS change consumed pending journal: %+v %v",state,err)
 }
}


// The last quiescence observation is separate from the two signed-journal
// audits: a real task can restart asynchronously while we verify the old
// backup. It must never race the final NTFS executable rename.
func TestSignedExactCandidateRollbackRefusesLastMomentDNS53Restart(t *testing.T){
 root,deps,key:=combinedRecoveryFixture(t)
 original:=filepath.Join(root,residentLegacyExe)
 candidate:=installExactSignedCandidateFixture(t,root)
 observations:=0
 deps.File.ProbeQuiescence=func(context.Context,string)(residentQuiescenceDecision,error){
  observations++
  if observations>=3{
   return residentQuiescenceDecision{
    TaskIdentityVerified:true,DNSPortFree:false,
    MotorProcessesStopped:false,ReadyForFurtherChecks:false,
   },errors.New("Task Scheduler restarted DNS at last mutation boundary")
  }
  return residentQuiescenceDecision{
   TaskIdentityVerified:true,DNSPortFree:true,
   MotorProcessesStopped:true,ReadyForFurtherChecks:true,
  },nil
 }
 ctx,cancel:=context.WithTimeout(context.Background(),240*time.Second)
 defer cancel()
 unlock,err:=motorupdate.AcquireProtectedResidentTransitionLease(ctx)
 if err!=nil||unlock==nil{t.Fatalf("cannot enter signed Windows recovery lease: %v",err)}
 defer unlock()
 if err:=restoreSignedExactCandidateLockedWindows(ctx,root,key,deps.File);err==nil{
  t.Fatal("real DNS53 activation just before atomic rename went unobserved")
 }
 if observations!=3{t.Fatalf("expected both signed audits and final live DNS53 fence; got %d",observations)}
 seen,err:=os.ReadFile(original)
 if err!=nil||string(seen)!=string(candidate){
  t.Fatalf("last-moment DNS restart nevertheless rewrote original path: %v",err)
 }
 journalDir:=filepath.Join(root,residentRecoveryParent,residentJournalDirName)
 status,err:=motorupdate.InspectResidentRecoveryJournal(ctx,journalDir,durableWindowsACL)
 if err!=nil||status.Status!="recovery-required"{
  t.Fatalf("last-moment DNS restart consumed original signed intent: %+v %v",status,err)
 }
}
