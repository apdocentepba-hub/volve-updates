//go:build windows

package motorupdate

import (
 "context"
 "os"
 "path/filepath"
 "testing"
)

type publisherBoundRecoveryOpsFixture struct{ verified,restored int }
func(f *publisherBoundRecoveryOpsFixture)VerifySealedOriginal(context.Context,ResidentRecoveryIntent)error{
 f.verified++
 return nil
}
func(f *publisherBoundRecoveryOpsFixture)RestoreOriginal(context.Context,ResidentRecoveryIntent)error{
 f.restored++
 return nil
}
func makePublisherEvidence(f signedRecoveryFixture)PublisherBoundResidentRecoveryEvidence{
 allow:=func(string)error{return nil} // synthetic disposable CI fixture
 return PublisherBoundResidentRecoveryEvidence{
  JournalDir:f.journal,BackupDir:f.backup,
  SignedPermit:f.permit,Signature:f.sig,PublisherKey:f.pub,
  ProtectJournal:allow,ProtectBackup:allow,
 }
}
func TestPublisherBoundProtectedBootRejectsForgedGrantBeforeRestoringOriginal(t *testing.T){
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{
  t.Skip("privileged Windows kernel mutex integration only in hosted CI")
 }
 for _,variant:=range []string{"valid-expired","forged","missing-snapshot","different-intent"}{
  t.Run(variant,func(t *testing.T){
   f:=makeSignedRecoveryFixture(t,true)
   evidence:=makePublisherEvidence(f)
   if variant=="forged"{evidence.Signature=[]byte("not a publisher signature")}
   if variant=="missing-snapshot"{
    if err:=os.Remove(filepath.Join(f.backup,legacyBackupExe));err!=nil{t.Fatal(err)}
   }
   state,err:=InspectResidentRecoveryJournal(context.Background(),f.journal,evidence.ProtectJournal)
   if err!=nil{t.Fatal(err)}
   intent:=state.Intent
   if variant=="different-intent"{intent.TargetSHA256="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
   ops:=&publisherBoundRecoveryOpsFixture{}
   driver,err:=NewPublisherBoundProtectedResidentBootDriver(ops,evidence)
   if err!=nil{t.Fatal(err)}
   unlock,err:=driver.AcquireExclusive(context.Background())
   if err!=nil{t.Fatal(err)}
   if err:=driver.VerifySealedOriginal(context.Background(),intent);variant=="valid-expired" && err!=nil{
    unlock();t.Fatalf("signed expired but previously armed grant blocked original restore: %v",err)
   }else if variant!="valid-expired"&&err==nil{
    unlock();t.Fatal("unauthorized grant approved original")
   }
   restoreErr:=driver.RestoreOriginal(context.Background(),intent)
   unlock()
   if variant=="valid-expired"{
    if restoreErr!=nil||ops.restored!=1||ops.verified!=1{
     t.Fatalf("valid recovery did not delegate under exact publisher grant: %v %+v",restoreErr,ops)
    }
   }else if restoreErr==nil||ops.restored!=0||ops.verified!=0{
    t.Fatalf("forged recovery reached real SYSTEM operator: %v %+v",restoreErr,ops)
   }
  })
 }
}
func TestPublisherBoundProtectedBootRequiresSignerAndCopiesGrant(t *testing.T){
 f:=makeSignedRecoveryFixture(t,false)
 ops:=&publisherBoundRecoveryOpsFixture{}
 evidence:=makePublisherEvidence(f)
 bad:=evidence;bad.PublisherKey=nil
 if driver,err:=NewPublisherBoundProtectedResidentBootDriver(ops,bad);err==nil||driver!=nil{
  t.Fatal("boot driver accepted missing trusted publisher key")
 }
 driver,err:=NewPublisherBoundProtectedResidentBootDriver(ops,evidence)
 if err!=nil{t.Fatal(err)}
 state,err:=InspectResidentRecoveryJournal(context.Background(),f.journal,evidence.ProtectJournal)
 if err!=nil{t.Fatal(err)}
 // Corrupt the caller's buffers AFTER constructing the driver. A deep
 // copy must keep its original signed permit/key intact.
 evidence.SignedPermit[0]='!'
 evidence.Signature[0]='!'
 evidence.PublisherKey[0]=0
 // Valid publisher evidence alone must never bypass the protected OS-wide
 // lease. This check previously invoked VerifySealedOriginal directly.
 if err:=driver.VerifySealedOriginal(context.Background(),state.Intent);err==nil{
  t.Fatal("publisher proof read allowed without owning protected mutex")
 }
 if err:=driver.RestoreOriginal(context.Background(),state.Intent);err==nil||ops.restored!=0{
  t.Fatalf("publisher-bound restorer bypassed Windows mutex: %v ops=%+v",err,ops)
 }
 unlock,err:=driver.AcquireExclusive(context.Background())
 if err!=nil{t.Fatal(err)}
 defer unlock()
 if err:=driver.VerifySealedOriginal(context.Background(),state.Intent);err!=nil{
  t.Fatalf("immutable signed authority changed via mutable caller slices: %v",err)
 }
}
