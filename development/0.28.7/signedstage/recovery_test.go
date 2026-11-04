package signedstage
import (
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "errors"
 "os"
 "path/filepath"
 "testing"
 "volve.local/installer/unifiedbundle"
)
func TestRecoverInterruptedFileThenRetrySignedStaging(t *testing.T){
 src,dst,pub:=signedFixture(t);p:=dst+".pending"
 if err:=os.Mkdir(p,0700);err!=nil{t.Fatal(err)}
 original,err:=os.ReadFile(filepath.Join(src,"VOLVE_Full_Catalog.txt"));if err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(filepath.Join(p,"VOLVE_Full_Catalog.txt"),original[:len(original)/2],0600);err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(filepath.Join(p,"manifest.ed25519"),[]byte{},0600);err!=nil{t.Fatal(err)}
 out,err:=RecoverAbandonedInactiveLabStage(context.Background(),src,dst,pub)
 if err!=nil||out!=RecoveryRemovedPending{t.Fatalf("safe cleanup rejected: %s %v",out,err)}
 requireAbsent(t,p)
 m,err:=PrepareInactiveLabVersion(context.Background(),src,dst,pub)
 if err!=nil||len(m.Components)!=7{t.Fatalf("retry failed: %+v %v",m,err)}
}
func TestNoAbandonedStageNoOp(t *testing.T){
 src,dst,pub:=signedFixture(t)
 out,err:=RecoverAbandonedInactiveLabStage(context.Background(),src,dst,pub)
 if err!=nil||out!=RecoveryAlreadyClean{t.Fatalf("unexpected outcome: %s %v",out,err)}
 requireAbsent(t,dst,dst+".pending")
}
func TestRefuseTamperedOrForeignPendingWithoutDeletion(t *testing.T){
 cases:=[]struct{name string;change func(string)error}{
  {"altered-catalog",func(p string)error{return os.WriteFile(filepath.Join(p,"VOLVE_Full_Catalog.txt"),[]byte("evil"),0600)}},
  {"private-uninstaller",func(p string)error{return os.WriteFile(filepath.Join(p,"VOLVE_Uninstall.exe"),[]byte("owner only"),0600)}},
  {"foreign-file",func(p string)error{return os.WriteFile(filepath.Join(p,"unexpected.exe"),[]byte("unknown"),0600)}},
 }
 for _,tc:=range cases{t.Run(tc.name,func(t *testing.T){
  src,dst,pub:=signedFixture(t);p:=dst+".pending"
  if err:=os.Mkdir(p,0700);err!=nil{t.Fatal(err)}
  if err:=tc.change(p);err!=nil{t.Fatal(err)}
  if _,err:=RecoverAbandonedInactiveLabStage(context.Background(),src,dst,pub);err==nil{t.Fatal("removed untrusted pending")}
  if _,err:=os.Stat(p);err!=nil{t.Fatal("foreign pending was deleted:",err)}
 })}
}
func TestExistingDestinationAndWrongPublisherAreProtected(t *testing.T){
 src,dst,pub:=signedFixture(t);p:=dst+".pending"
 if err:=os.Mkdir(p,0700);err!=nil{t.Fatal(err)}
 if err:=os.Mkdir(dst,0700);err!=nil{t.Fatal(err)}
 keep:=filepath.Join(dst,"keep-original")
 if err:=os.WriteFile(keep,[]byte("PRESERVE"),0600);err!=nil{t.Fatal(err)}
 if _,err:=RecoverAbandonedInactiveLabStage(context.Background(),src,dst,pub);err==nil{t.Fatal("ignored installed destination")}
 if b,err:=os.ReadFile(keep);err!=nil||string(b)!="PRESERVE"{t.Fatal("modified installed destination")}
 if err:=os.RemoveAll(dst);err!=nil{t.Fatal(err)} // test-owned temporary directory only
 wrong,_,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 if _,err:=RecoverAbandonedInactiveLabStage(context.Background(),src,dst,wrong);err==nil{t.Fatal("foreign signature accepted")}
 if _,err:=os.Stat(p);err!=nil{t.Fatal("removed pending with foreign key")}
}
func TestRejectPendingSymlinkWithoutRemoval(t *testing.T){
 src,dst,pub:=signedFixture(t);p:=dst+".pending"
 if err:=os.Mkdir(p,0700);err!=nil{t.Fatal(err)}
 link:=filepath.Join(p,"VOLVE_Full_Catalog.txt")
 if err:=os.Symlink(filepath.Join(src,"VOLVE_Full_Catalog.txt"),link);err!=nil{t.Skip("symlink privilege unavailable")}
 if _,err:=RecoverAbandonedInactiveLabStage(context.Background(),src,dst,pub);err==nil{t.Fatal("followed link")}
 if _,err:=os.Lstat(link);err!=nil{t.Fatal("deleted linked entry")}
}
func TestRecoveryCancelledOrLockedCannotDelete(t *testing.T){
 src,dst,pub:=signedFixture(t);p:=dst+".pending"
 if err:=os.Mkdir(p,0700);err!=nil{t.Fatal(err)}
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 if _,err:=RecoverAbandonedInactiveLabStage(ctx,src,dst,pub);!errors.Is(err,context.Canceled){t.Fatalf("cancel ignored %v",err)}
 if err:=os.WriteFile(p+".recovery-lock",[]byte("in progress"),0600);err!=nil{t.Fatal(err)}
 if _,err:=RecoverAbandonedInactiveLabStage(context.Background(),src,dst,pub);err==nil{t.Fatal("lock ignored")}
 if _,err:=os.Stat(p);err!=nil{t.Fatal("pending removed during lock")}
}
func TestRecoverPreservesAuthenticatedSource(t *testing.T){
 src,dst,pub:=signedFixture(t);p:=dst+".pending"
 if err:=os.Mkdir(p,0700);err!=nil{t.Fatal(err)}
 before,err:=unifiedbundle.Verify(src,pub);if err!=nil{t.Fatal(err)}
 if _,err:=RecoverAbandonedInactiveLabStage(context.Background(),src,dst,pub);err!=nil{t.Fatal(err)}
 after,err:=unifiedbundle.Verify(src,pub)
 if err!=nil||len(before.Components)!=len(after.Components){t.Fatal("source not preserved")}
}
