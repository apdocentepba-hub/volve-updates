//go:build windows

package main

// Negative tests only. They cannot instantiate or start a production DNS
// watchdog on ordinary Windows, nor install tasks or alter DNS adapters.
import (
 "context"
 "errors"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"

 "volve-browser-protection/motorupdate"
)

func TestPinnedResidentBootDriverRejectsCancelledOrRelativeRoot(t *testing.T){
 cancelled,stop:=context.WithCancel(context.Background())
 stop()
 if driver,err:=newPinnedResidentBootRecoveryDriverWindows(cancelled,t.TempDir());driver!=nil||
  !errors.Is(err,context.Canceled){
  t.Fatalf("cancelled signed watchdog constructor not refused: driver=%v err=%v",driver,err)
 }
 ctx,done:=context.WithTimeout(context.Background(),15*time.Second)
 defer done()
 if driver,err:=newPinnedResidentBootRecoveryDriverWindows(ctx,"relative");driver!=nil||err==nil {
  t.Fatalf("noncanonical root permitted to construct signed SYSTEM driver: driver=%v err=%v",driver,err)
 }
 if driver,err:=newPinnedResidentBootRecoveryDriverWindows(ctx,t.TempDir()+string(filepath.Separator)+"..");driver!=nil||err==nil {
  t.Fatalf("non-clean root permitted to construct signed SYSTEM driver: driver=%v err=%v",driver,err)
 }
}

func TestPinnedResidentBootDriverRejectsInteractiveWindowsToken(t *testing.T){
 ctx,cancel:=context.WithTimeout(context.Background(),25*time.Second)
 defer cancel()
 // CI normally runs as elevated Admin, not SYSTEM. On a SYSTEM runner the
 // test skips rather than constructing a production-identity controller.
 if err:=verifyResidentActualSYSTEM(ctx);err==nil{
  t.Skip("SYSTEM identity: skip constructor instead of creating productive-identity driver")
 }
 driver,err:=newPinnedResidentBootRecoveryDriverWindows(ctx,t.TempDir())
 if err==nil||driver!=nil{
  t.Fatalf("admin/user token constructed privileged boot driver: %v",err)
 }
}


type motorOnlyPinnedBootOpsFixture struct{
 verified,restored int
 afterVerify,afterRestore func()error
}
func(f *motorOnlyPinnedBootOpsFixture)VerifySealedOriginal(context.Context,motorupdate.ResidentRecoveryIntent)error{
 f.verified++
 if f.afterVerify!=nil{return f.afterVerify()}
 return nil
}
func(f *motorOnlyPinnedBootOpsFixture)RestoreOriginal(context.Context,motorupdate.ResidentRecoveryIntent)error{
 f.restored++
 if f.afterRestore!=nil{return f.afterRestore()}
 return nil
}

func TestMotorOnlyPinnedBootRefusesCompleteOrPartialDNSEvidence(t *testing.T){
 for _,name:=range []string{motorupdate.DNSOriginalBackupDirectoryName,"dns-original-binding.json","dns-original-binding.sig"}{
  t.Run(name,func(t *testing.T){
   root:=t.TempDir()
   parent:=filepath.Join(root,residentRecoveryParent)
   if err:=os.Mkdir(parent,0700);err!=nil{t.Fatal(err)}
   fake:=&motorOnlyPinnedBootOpsFixture{}
   ops:=&motorOnlyPinnedBootOps{root:root,original:fake,verifyScope:func(context.Context,motorupdate.ResidentRecoveryIntent)error{return nil}}
   ctx:=context.Background()
   intent:=motorupdate.ResidentRecoveryIntent{}
   if err:=ops.VerifySealedOriginal(ctx,intent);err!=nil{t.Fatal(err)}
   if err:=ops.RestoreOriginal(ctx,intent);err!=nil{t.Fatal(err)}
   if fake.verified!=1||fake.restored!=1{t.Fatal("clean motor-only operation not delegated")}
   node:=filepath.Join(parent,name)
   if name==motorupdate.DNSOriginalBackupDirectoryName{
    if err:=os.Mkdir(node,0700);err!=nil{t.Fatal(err)}
   }else{
    if err:=os.WriteFile(node,nil,0600);err!=nil{t.Fatal(err)}
   }
   for _,fn:=range []func(context.Context,motorupdate.ResidentRecoveryIntent)error{ops.VerifySealedOriginal,ops.RestoreOriginal}{
    err:=fn(ctx,intent)
    if err==nil||!strings.Contains(err.Error(),"DNS evidence present"){t.Fatalf("partial DNS staging admitted: %v",err)}
   }
   if fake.verified!=1||fake.restored!=1{t.Fatal("DNS-changing transaction reached motor-only operations")}
  })
 }
}

func TestMotorOnlyPinnedBootRechecksEvidenceAfterDelegation(t *testing.T){
 for _,restore:=range []bool{false,true}{
  root:=t.TempDir()
  parent:=filepath.Join(root,residentRecoveryParent)
  if err:=os.Mkdir(parent,0700);err!=nil{t.Fatal(err)}
  inject:=func()error{return os.WriteFile(filepath.Join(parent,"dns-original-binding.sig"),nil,0600)}
  fake:=&motorOnlyPinnedBootOpsFixture{}
  ops:=&motorOnlyPinnedBootOps{root:root,original:fake,verifyScope:func(context.Context,motorupdate.ResidentRecoveryIntent)error{return nil}}
  fn:=ops.VerifySealedOriginal
  if restore{fn=ops.RestoreOriginal;fake.afterRestore=inject}else{fake.afterVerify=inject}
  if err:=fn(context.Background(),motorupdate.ResidentRecoveryIntent{});err==nil{t.Fatal("new DNS evidence missed at return boundary")}
 }
}
func TestMotorOnlyPinnedBootFailsClosedOnMissingAncestryOrContext(t *testing.T){
 root:=t.TempDir()
 if err:=rejectDNSStagingForMotorOnlyBoot(context.Background(),root);err==nil{t.Fatal("missing recovery parent accepted")}
 if err:=rejectDNSStagingForMotorOnlyBoot(nil,root);err==nil{t.Fatal("nil context accepted")}
 ctx,done:=context.WithCancel(context.Background());done()
 if err:=rejectDNSStagingForMotorOnlyBoot(ctx,root);!errors.Is(err,context.Canceled){t.Fatal("cancelled recovery accepted")}
}

func TestMotorOnlyPinnedBootRejectsUnprovenScopeEvenWithNoDNSArtifacts(t *testing.T){
 root:=t.TempDir()
 if err:=os.Mkdir(filepath.Join(root,residentRecoveryParent),0700);err!=nil{t.Fatal(err)}
 fake:=&motorOnlyPinnedBootOpsFixture{}
 ops:=&motorOnlyPinnedBootOps{root:root,original:fake}
 for _,verify:=range []func(context.Context,motorupdate.ResidentRecoveryIntent)error{
  nil,func(context.Context,motorupdate.ResidentRecoveryIntent)error{return errors.New("signed scope requires original DNS")},
 }{
  ops.verifyScope=verify
  if err:=ops.VerifySealedOriginal(context.Background(),motorupdate.ResidentRecoveryIntent{});err==nil{t.Fatal("scope not enforced before verification")}
  if err:=ops.RestoreOriginal(context.Background(),motorupdate.ResidentRecoveryIntent{});err==nil{t.Fatal("scope not enforced before restore")}
 }
 if fake.verified!=0||fake.restored!=0{t.Fatal("unproven recovery scope reached motor operation")}
}
