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
