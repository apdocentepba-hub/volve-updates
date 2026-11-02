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
