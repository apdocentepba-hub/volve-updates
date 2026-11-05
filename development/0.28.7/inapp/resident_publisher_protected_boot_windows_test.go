//go:build windows

package motorupdate

import (
 "context"
 "os"
 "path/filepath"
 "testing"
 "sync"
 "time"
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


// The publisher signature, backup and journal must NOT be read, even by a
// read-only verification, without the very same OS lease as the restoration.
func TestPublisherBoundBootEvidenceRequiresLeaseBeforeAnyACLReader(t *testing.T){
 residentProtectedCITest(t)
 f:=makeSignedRecoveryFixture(t,false)
 evidence:=makePublisherEvidence(f)
 reads:=0
 evidence.ProtectJournal=func(string)error{reads++;return nil}
 evidence.ProtectBackup=func(string)error{reads++;return nil}
 state,err:=InspectResidentRecoveryJournal(context.Background(),f.journal,func(string)error{return nil})
 if err!=nil{t.Fatal(err)}
 ops:=&publisherBoundRecoveryOpsFixture{}
 driver,err:=NewPublisherBoundProtectedResidentBootDriver(ops,evidence)
 if err!=nil{t.Fatal(err)}
 if err:=driver.VerifySealedOriginal(context.Background(),state.Intent);err==nil{
  t.Fatal("publisher evidence read without exclusive Windows mutex")
 }
 if err:=driver.RestoreOriginal(context.Background(),state.Intent);err==nil{
  t.Fatal("publisher restore admitted without exclusive Windows mutex")
 }
 if reads!=0||ops.verified!=0||ops.restored!=0{
  t.Fatalf("unlocked publisher evidence/operation leaked: ACL=%d operations=%+v",reads,ops)
 }
 unlock,err:=driver.AcquireExclusive(context.Background())
 if err!=nil{t.Fatal(err)}
 if err:=driver.VerifySealedOriginal(context.Background(),state.Intent);err!=nil{
  unlock();t.Fatal(err)
 }
 unlock()
 if reads==0||ops.verified!=1{t.Fatalf("signed verification never ran under native lease: ACL=%d ops=%+v",reads,ops)}
 reads=0
 if err:=driver.VerifySealedOriginal(context.Background(),state.Intent);err==nil||reads!=0{
  t.Fatalf("publisher file read after mutex release: ACL=%d err=%v",reads,err)
 }
}

// A finalizer must wait until signature/journal proof and the protected
// underlying verification both finish, not release between these operations.
func TestPublisherBoundBootFinalizerWaitsForSignedEvidence(t *testing.T){
 residentProtectedCITest(t)
 f:=makeSignedRecoveryFixture(t,false)
 evidence:=makePublisherEvidence(f)
 started:=make(chan struct{})
 proceed:=make(chan struct{})
 var once sync.Once
 evidence.ProtectJournal=func(string)error{
  once.Do(func(){close(started);<-proceed})
  return nil
 }
 state,err:=InspectResidentRecoveryJournal(context.Background(),f.journal,func(string)error{return nil})
 if err!=nil{t.Fatal(err)}
 ops:=&publisherBoundRecoveryOpsFixture{}
 driver,err:=NewPublisherBoundProtectedResidentBootDriver(ops,evidence)
 if err!=nil{t.Fatal(err)}
 ctx,cancel:=context.WithTimeout(context.Background(),9*time.Second)
 defer cancel()
 unlock,err:=driver.AcquireExclusive(ctx)
 if err!=nil{t.Fatal(err)}
 defer unlock()
 verified:=make(chan error,1)
 go func(){verified<-driver.VerifySealedOriginal(ctx,state.Intent)}()
 select{
 case <-started:
 case <-ctx.Done():t.Fatal("publisher ACL proof did not start")
 }
 released:=make(chan struct{})
 go func(){unlock();close(released)}()
 select{
 case <-released:t.Fatal("kernel mutex released during publisher signature/journal verification")
 case <-time.After(150*time.Millisecond):
 }
 close(proceed)
 select{
 case err:=<-verified:if err!=nil{t.Fatal(err)}
 case <-ctx.Done():t.Fatal("publisher proof hung")
 }
 select{
 case <-released:
 case <-ctx.Done():t.Fatal("publisher finalizer failed to release after verified proof")
 }
 newLease,err:=AcquireProtectedResidentTransitionLease(ctx)
 if err!=nil{t.Fatalf("publisher verifier leaked native kernel mutex: %v",err)}
 newLease()
 if ops.verified!=1||ops.restored!=0{t.Fatalf("unexpected protected original operations: %+v",ops)}
}
