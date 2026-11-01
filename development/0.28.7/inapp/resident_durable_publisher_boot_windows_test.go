//go:build windows

package motorupdate

// Publisher-bound protected boot policy with evidence loaded from disk.
// Test-only synthetic binary/ACL fixture: no actual motor or task changes.
import (
 "context"
 "os"
 "path/filepath"
 "testing"
)

func TestDurablePublisherBoundWindowsBootUsesSignedDiskGrantOnlyForPending(t *testing.T){
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{
  t.Skip("protected native Windows SYSTEM/Admin kernel mutex requires isolated CI")
 }
 f:=makeSignedRecoveryFixture(t,false)
 allow:=func(string)error{return nil} // synthetic test proof; not a production ACL
 if err:=PersistResidentDurablePublisherGrant(context.Background(),f.root,
  f.permit,f.sig,f.pub,allow,allow,allow,allow);err!=nil{t.Fatal(err)}
 ops:=&publisherBoundRecoveryOpsFixture{}
 driver,err:=NewDurablePublisherBoundProtectedResidentBootDriver(ops,f.root,f.pub,allow,allow,allow)
 if err!=nil{t.Fatal(err)}
 pending,err:=InspectResidentRecoveryJournal(context.Background(),f.journal,allow)
 if err!=nil{t.Fatal(err)}
 lock,err:=driver.AcquireExclusive(context.Background())
 if err!=nil{t.Fatal(err)}
 if err:=driver.VerifySealedOriginal(context.Background(),pending.Intent);err!=nil{
  lock();t.Fatalf("separately stored signed publisher grant could not authorize original verification: %v",err)
 }
 if err:=driver.RestoreOriginal(context.Background(),pending.Intent);err!=nil{
  lock();t.Fatalf("separately stored signed publisher grant could not authorize test-only original restore: %v",err)
 }
 lock()
 if ops.verified!=1||ops.restored!=1{
  t.Fatalf("trusted operations not called exactly once: %+v",ops)
 }
 if err:=os.WriteFile(filepath.Join(f.root,"legacy-engine-recovery","publisher-authorization","migration-permit.sig"),
  []byte("changed after previous verification"),0600);err!=nil{t.Fatal(err)}
 lock,err=driver.AcquireExclusive(context.Background())
 if err!=nil{t.Fatal(err)}
 rejectErr:=driver.RestoreOriginal(context.Background(),pending.Intent)
 lock()
 if rejectErr==nil||ops.restored!=1{
  t.Fatalf("modified stored signature reached privileged recovery after initial approval: %v %+v",rejectErr,ops)
 }
}

func TestDurablePublisherBoundWindowsBootTerminalNoOpWithoutSignedGrant(t *testing.T){
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{
  t.Skip("protected native Windows mutex requires disposable CI")
 }
 f:=makeSignedRecoveryFixture(t,false)
 allow:=func(string)error{return nil}
 if err:=FinishResidentRecoveryIntent(context.Background(),f.journal,"committed",allow,allow);err!=nil{t.Fatal(err)}
 ops:=&publisherBoundRecoveryOpsFixture{}
 driver,err:=NewDurablePublisherBoundProtectedResidentBootDriver(ops,f.root,f.pub,allow,allow,allow)
 if err!=nil{t.Fatal(err)}
 state,err:=RecoverPendingResidentAfterBoot(context.Background(),f.journal,allow,allow,
  &bootIdentityLab{failForever:true},driver)
 if err!=nil||state!="committed"||ops.verified!=0||ops.restored!=0{
  t.Fatalf("already completed boot incorrectly required a missing signed grant or restored original: %s %v %+v",state,err,ops)
 }
}
func TestDurablePublisherBoundWindowsBootRequiresPinnedTrust(t *testing.T){
 f:=makeSignedRecoveryFixture(t,false)
 allow:=func(string)error{return nil}
 ops:=&publisherBoundRecoveryOpsFixture{}
 for _,scenario:=range []struct{ root string;pub []byte;protect func(string)error}{
  {"",f.pub,allow},{"relative",f.pub,allow},{f.root,nil,allow},{f.root,f.pub,nil},
 }{
  driver,err:=NewDurablePublisherBoundProtectedResidentBootDriver(ops,scenario.root,scenario.pub,
   scenario.protect,allow,allow)
  if err==nil||driver!=nil{t.Fatal("untrusted durable boot configuration accepted")}
 }
 if driver,err:=NewDurablePublisherBoundProtectedResidentBootDriver(nil,f.root,f.pub,allow,allow,allow);err==nil||driver!=nil{
  t.Fatal("nil recovery operations accepted")
 }
}
