//go:build windows

package motorupdate

// Publisher-bound protected boot policy with evidence loaded from disk.
// Test-only synthetic binary/ACL fixture: no actual motor or task changes.
import (
 "context"
 "errors"
 "strings"
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


// Loading a sealed on-disk grant and reading the pending journal are part
// of the privileged transaction, never permitted before acquiring the
// protected Win32 lease. A failed earlier verification also may not pin
// its first signed permit as the successful transaction's authorization.
func TestDurablePublisherBootEvidenceRequiresLeaseBeforeDiskRead(t *testing.T){
 residentProtectedCITest(t)
 f:=makeSignedRecoveryFixture(t,false)
 noop:=func(string)error{return nil}
 if err:=PersistResidentDurablePublisherGrant(context.Background(),f.root,
  f.permit,f.sig,f.pub,noop,noop,noop,noop);err!=nil{t.Fatal(err)}
 state,err:=InspectResidentRecoveryJournal(context.Background(),f.journal,noop)
 if err!=nil{t.Fatal(err)}
 reads:=0
 count:=func(string)error{reads++;return nil}
 ops:=&publisherBoundRecoveryOpsFixture{}
 driver,err:=NewDurablePublisherBoundProtectedResidentBootDriver(ops,f.root,f.pub,count,count,count)
 if err!=nil{t.Fatal(err)}
 if err:=driver.VerifySealedOriginal(context.Background(),state.Intent);err==nil{
  t.Fatal("durable publisher grant was readable before native mutex acquisition")
 }
 if err:=driver.RestoreOriginal(context.Background(),state.Intent);err==nil{
  t.Fatal("durable original restore accepted without native SYSTEM mutex")
 }
 if reads!=0||ops.restored!=0||ops.verified!=0{
  t.Fatalf("unleased durable evidence reader/restore executed: reads=%d ops=%+v",reads,ops)
 }
 release,err:=driver.AcquireExclusive(context.Background())
 if err!=nil{t.Fatal(err)}
 if err:=driver.VerifySealedOriginal(context.Background(),state.Intent);err!=nil{
  release();t.Fatal(err)
 }
 if err:=driver.RestoreOriginal(context.Background(),state.Intent);err!=nil{
  release();t.Fatal(err)
 }
 release()
 if reads==0||ops.verified!=1||ops.restored!=1{
  t.Fatalf("durable publisher grant did not bind both native-lease operations: reads=%d ops=%+v",reads,ops)
 }
 reads=0
 if err:=driver.RestoreOriginal(context.Background(),state.Intent);err==nil||reads!=0{
  t.Fatalf("post-release durable grant read or recovery admitted: reads=%d err=%v",reads,err)
 }
}


// Native NTFS/mutex + simulated DNS writer and stopped-candidate evidence.
// This test does NOT validate a real Windows task/process fence or real DNS.
func TestDurableDNSAwareBootDriverRejectsUnleasedAndUnfencedWrites(t *testing.T){
 residentProtectedCITest(t)
 f:=makeSignedDNSBootRecoveryFixture(t)
 ctx:=context.Background()
 if err:=PersistSignedOriginalDNSEvidenceNativeWindows(ctx,f.root,f.pub,f.binding,f.signature);err!=nil{t.Fatal(err)}
 state,err:=InspectResidentRecoveryJournal(ctx,filepath.Join(f.parent,"motor-recovery-transaction"),func(p string)error{return nativeDNSOriginalBackupACL(ctx,p)})
 if err!=nil{t.Fatal(err)}
 ops:=&publisherBoundRecoveryOpsFixture{}
 fenced:=false
 fenceCalls:=0
 fence:=func(context.Context,ResidentRecoveryIntent)error{
  fenceCalls++
  if !fenced{return errors.New("candidate still running")}
  return nil
 }
 driver,err:=newDurablePublisherDNSBootDriver(ops,f.root,f.pub,fence,func()error{return nil},f.host.inspect,f.invoke)
 if err!=nil{t.Fatal(err)}
 if err:=driver.RestoreOriginalDNS(ctx,state.Intent);err==nil||f.writes!=0||fenceCalls!=0{t.Fatal("DNS mutation or guard called outside lease")}
 release,err:=driver.AcquireExclusive(ctx)
 if err!=nil{t.Fatal(err)}
 defer release()
 if err:=driver.VerifySealedOriginal(ctx,state.Intent);err!=nil{t.Fatal(err)}
 if err:=driver.RestoreOriginalDNS(ctx,state.Intent);err==nil||f.writes!=0{t.Fatal("unfenced candidate permitted DNS mutation")}
 fenced=true
 if err:=driver.RestoreOriginalDNS(ctx,state.Intent);err!=nil{t.Fatal(err)}
 if f.writes!=3||fenceCalls<5{t.Fatalf("DNS writer did not revalidate fence for each command: writes=%d calls=%d",f.writes,fenceCalls)}
 if err:=driver.VerifyOriginalDNS(ctx,state.Intent);err!=nil{t.Fatal(err)}
 f.expectOriginal(t)
 f.expectStillPending(t)
 if err:=driver.RestoreOriginalDNS(ctx,state.Intent);err!=nil||f.writes!=3{t.Fatal("restoration not idempotent under resident lease")}
 fenced=false
 if err:=driver.VerifyOriginalDNS(ctx,state.Intent);err==nil{t.Fatal("failed candidate returned during health checks")}
}
func TestDurableDNSAwareBootDriverRejectsTamperedBindingBeforeMotorOperations(t *testing.T){
 residentProtectedCITest(t)
 f:=makeSignedDNSBootRecoveryFixture(t)
 ctx:=context.Background()
 if err:=PersistSignedOriginalDNSEvidenceNativeWindows(ctx,f.root,f.pub,f.binding,f.signature);err!=nil{t.Fatal(err)}
 journal:=filepath.Join(f.parent,"motor-recovery-transaction")
 state,err:=InspectResidentRecoveryJournal(ctx,journal,func(p string)error{return nativeDNSOriginalBackupACL(ctx,p)})
 if err!=nil{t.Fatal(err)}
 ops:=&publisherBoundRecoveryOpsFixture{}
 driver,err:=newDurablePublisherDNSBootDriver(ops,f.root,f.pub,func(context.Context,ResidentRecoveryIntent)error{return nil},func()error{return nil},f.host.inspect,f.invoke)
 if err!=nil{t.Fatal(err)}
 release,err:=driver.AcquireExclusive(ctx)
 if err!=nil{t.Fatal(err)}
 defer release()
 _,_,sigPath,err:=dnsOriginalBindingEvidencePaths(f.root)
 if err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(sigPath,[]byte("tampered"),0600);err!=nil{t.Fatal(err)}
 if err:=driver.VerifySealedOriginal(ctx,state.Intent);err==nil{t.Fatal("forged DNS evidence admitted to original motor verification")}
 if err:=driver.RestoreOriginal(ctx,state.Intent);err==nil{t.Fatal("forged DNS evidence admitted to original motor restoration")}
 if err:=driver.RestoreOriginalDNS(ctx,state.Intent);err==nil{t.Fatal("forged DNS evidence admitted to DNS restoration")}
 if ops.verified!=0||ops.restored!=0||f.writes!=0{t.Fatalf("tamper reached trusted operation: %+v writes=%d",ops,f.writes)}
 f.expectStillPending(t)
}
func TestDurableDNSAwareBootDriverRechecksSystemAndRefusesMissingFence(t *testing.T){
 residentProtectedCITest(t)
 f:=makeSignedDNSBootRecoveryFixture(t)
 ops:=&publisherBoundRecoveryOpsFixture{}
 fence:=func(context.Context,ResidentRecoveryIntent)error{return nil}
 deny:=func()error{return errors.New("not SYSTEM")}
 if d,err:=newDurablePublisherDNSBootDriver(ops,f.root,f.pub,fence,deny,f.host.inspect,f.invoke);err==nil||d!=nil||!strings.Contains(err.Error(),"LocalSystem"){t.Fatal("non-SYSTEM construction accepted")}
 if d,err:=newDurablePublisherDNSBootDriver(ops,f.root,f.pub,nil,func()error{return nil},f.host.inspect,f.invoke);err==nil||d!=nil{t.Fatal("missing candidate fence accepted")}
 system:=true
 d,err:=newDurablePublisherDNSBootDriver(ops,f.root,f.pub,fence,func()error{if !system{return deny()};return nil},f.host.inspect,f.invoke)
 if err!=nil{t.Fatal(err)}
 system=false
 if release,err:=d.AcquireExclusive(context.Background());err==nil||release!=nil{if release!=nil{release()};t.Fatal("lost SYSTEM token still acquired lease")}
 if f.writes!=0{t.Fatal("invalid token triggered DNS writes")}
}
