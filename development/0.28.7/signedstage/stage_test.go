package signedstage
import(
"context"
"crypto/ed25519"
"crypto/rand"
"crypto/sha256"
"encoding/hex"
"encoding/json"
"errors"
"os"
"path/filepath"
"sort"
"testing"
"volve.local/installer/unifiedbundle"
)
func signedFixture(t *testing.T)(string,string,ed25519.PublicKey){
 t.Helper()
 dir:=t.TempDir();src:=filepath.Join(dir,"VOLVE-CI-signed-input");dst:=filepath.Join(dir,PreparedPrefix+"0287")
 if err:=os.Mkdir(src,0700);err!=nil{t.Fatal(err)}
 pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 m:=unifiedbundle.Manifest{Schema:1,Release:"0.28.7",Platform:"windows-amd64"}
 files:=unifiedbundle.RequiredFiles();ids:=make([]string,0,len(files));for id:=range files{ids=append(ids,id)};sort.Strings(ids)
 for _,id:=range ids{
  b:=[]byte("SYNTHETIC CI ONLY NOT INSTALLABLE "+id)
  if err:=os.WriteFile(filepath.Join(src,files[id]),b,0600);err!=nil{t.Fatal(err)}
  sum:=sha256.Sum256(b)
  m.Components=append(m.Components,unifiedbundle.Component{ID:id,File:files[id],Size:int64(len(b)),SHA256:hex.EncodeToString(sum[:])})
 }
 raw,err:=json.Marshal(m);if err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(filepath.Join(src,"manifest.json"),raw,0600);err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(filepath.Join(src,"manifest.ed25519"),ed25519.Sign(priv,raw),0600);err!=nil{t.Fatal(err)}
 return src,dst,pub
}
func requireAbsent(t *testing.T,paths ...string){t.Helper();for _,p:=range paths{_,err:=os.Lstat(p);if !os.IsNotExist(err){t.Fatalf("unexpected file %s: %v",p,err)}}}
func TestSevenSignedPartsPreparedInactive(t *testing.T){
 src,dst,pub:=signedFixture(t);m,err:=PrepareInactiveLabVersion(context.Background(),src,dst,pub)
 if err!=nil{t.Fatal(err)}
 if len(m.Components)!=7{t.Fatalf("expected seven, got %d",len(m.Components))}
 if _,err:=unifiedbundle.Verify(dst,pub);err!=nil{t.Fatal(err)}
 if _,err:=unifiedbundle.Verify(src,pub);err!=nil{t.Fatal("source modified:",err)}
 requireAbsent(t,dst+".pending",filepath.Join(dst,"VOLVE_Uninstall.exe"))
}
func TestCopyInterruptionCleansOnlyNewPendingDir(t *testing.T){
 src,dst,pub:=signedFixture(t);n:=0
 _,err:=prepare(context.Background(),src,dst,pub,func(string)error{n++;if n==4{return errors.New("simulated disk interruption")};return nil})
 if err==nil{t.Fatal("interruption accepted")}
 requireAbsent(t,dst,dst+".pending")
 if _,err:=unifiedbundle.Verify(src,pub);err!=nil{t.Fatal("existing signed source damaged:",err)}
}
func TestTamperingMissingAssetsAndOwnerUninstallerRejected(t *testing.T){
 cases:=[]struct{name string;change func(string)error}{
  {"private-uninstaller",func(s string)error{return os.WriteFile(filepath.Join(s,"VOLVE_Uninstall.exe"),[]byte("owner-only forbidden"),0600)}},
  {"altered-dns",func(s string)error{return os.WriteFile(filepath.Join(s,"VOLVE_DNS_Motor_0_28_7.exe"),[]byte("tampered"),0600)}},
  {"missing-watchdog",func(s string)error{return os.Remove(filepath.Join(s,"VOLVE_Managed_Watchdog.exe"))}},
 }
 for _,tc:=range cases{t.Run(tc.name,func(t *testing.T){
  src,dst,pub:=signedFixture(t);if err:=tc.change(src);err!=nil{t.Fatal(err)}
  if _,err:=PrepareInactiveLabVersion(context.Background(),src,dst,pub);err==nil{t.Fatal("invalid bundle accepted")}
  requireAbsent(t,dst,dst+".pending")
 })}
}
func TestExistingInstallationNeverOverwritten(t *testing.T){
 src,dst,pub:=signedFixture(t)
 if err:=os.Mkdir(dst,0700);err!=nil{t.Fatal(err)}
 original:=filepath.Join(dst,"preserve-original")
 if err:=os.WriteFile(original,[]byte("PRESERVED"),0600);err!=nil{t.Fatal(err)}
 if _,err:=PrepareInactiveLabVersion(context.Background(),src,dst,pub);err==nil{t.Fatal("existing version overwritten")}
 b,err:=os.ReadFile(original);if err!=nil||string(b)!="PRESERVED"{t.Fatal("existing installation changed")}
}
func TestWrongPublisherCancellationAndPendingStateRejected(t *testing.T){
 src,dst,pub:=signedFixture(t);wrong,_,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 if _,err:=PrepareInactiveLabVersion(context.Background(),src,dst,wrong);err==nil{t.Fatal("wrong publisher key accepted")}
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 if _,err:=PrepareInactiveLabVersion(ctx,src,dst,pub);!errors.Is(err,context.Canceled){t.Fatal("cancel ignored")}
 if err:=os.Mkdir(dst+".pending",0700);err!=nil{t.Fatal(err)}
 if _,err:=PrepareInactiveLabVersion(context.Background(),src,dst,pub);err==nil{t.Fatal("stale candidate reused")}
 requireAbsent(t,dst)
}
func TestNonLabPathsAndLinkedParentRejected(t *testing.T){
 src,dst,pub:=signedFixture(t)
 if _,err:=PrepareInactiveLabVersion(context.Background(),src,filepath.Join(filepath.Dir(dst),"VOLVE-PRODUCTION"),pub);err==nil{t.Fatal("non-lab destination accepted")}
 link:=filepath.Join(t.TempDir(),"link")
 if err:=os.Symlink(filepath.Dir(src),link);err!=nil{t.Skip("symlink privileges unavailable")}
 if _,err:=PrepareInactiveLabVersion(context.Background(),filepath.Join(link,filepath.Base(src)),filepath.Join(link,filepath.Base(dst)),pub);err==nil{t.Fatal("linked parent accepted")}
 requireAbsent(t,dst)
}
