//go:build windows

package motorupdate

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "os"
 "path/filepath"
 "testing"
)

func writeFreshMotorFixture(t *testing.T,root,name string,body []byte) {
 t.Helper()
 if err:=os.WriteFile(filepath.Join(root,name),body,0600);err!=nil {t.Fatal(err)}
}

func TestWindowsFreshMotorFileInventoryAndSHA256(t *testing.T) {
 for _,tc:=range []struct {
  name string
  prepare func(*testing.T,string)
  legacy,versioned,inventory bool
  hashName string
 }{
  {"empty-root",func(*testing.T,string){},false,false,false,""},
  {"unrelated-center-only",func(t *testing.T,r string){writeFreshMotorFixture(t,r,"VOLVE_0_28_6_CENTRO.exe",[]byte("panel-only"))},false,false,false,""},
  {"legacy-binary",func(t *testing.T,r string){writeFreshMotorFixture(t,r,"VOLVE_DNS_Server_0270.exe",[]byte("legacy-motor"))},true,false,false,"VOLVE_DNS_Server_0270.exe"},
  {"versioned-executable",func(t *testing.T,r string){writeFreshMotorFixture(t,r,"VOLVE_DNS_Motor_0_28_7.exe",[]byte("versioned-motor"))},false,true,false,"VOLVE_DNS_Motor_0_28_7.exe"},
  {"empty-version-folder",func(t *testing.T,r string){if err:=os.Mkdir(filepath.Join(r,"motor-0.28.7"),0700);err!=nil{t.Fatal(err)}},false,true,false,""},
  {"empty-installed-inventory",func(t *testing.T,r string){if err:=os.Mkdir(filepath.Join(r,"installed-engines"),0700);err!=nil{t.Fatal(err)}},false,false,true,""},
 }{
  t.Run(tc.name,func(t *testing.T){
   root:=t.TempDir()
   tc.prepare(t,root)
   got,err:=InspectWindowsFreshMotorFilesReadOnly(context.Background(),root)
   if err!=nil{t.Fatal(err)}
   if got.LegacyExecutablePresent!=tc.legacy || got.VersionedMotorPresent!=tc.versioned ||
    got.InstalledEngineInventoryPresent!=tc.inventory {
    t.Fatalf("inaccurate motor presence classification: %+v",got)
   }
   if tc.hashName!=""{
    name:=filepath.Join(root,tc.hashName)
    data,err:=os.ReadFile(name);if err!=nil{t.Fatal(err)}
    digest:=sha256.Sum256(data)
    if len(got.MotorCandidates)!=1 || got.MotorSHA256[name]!=hex.EncodeToString(digest[:]){
     t.Fatalf("motor SHA256 was not computed from read-only bytes: %+v",got)
    }
   }
   // Other five inventory flags are synthetically true ONLY in this test.
   e:=freshCompleteObservation()
   e.LegacyExecutablePresent=got.LegacyExecutablePresent
   e.VersionedMotorPresent=got.VersionedMotorPresent
   e.InstalledEngineInventoryPresent=got.InstalledEngineInventoryPresent
   eligible:=CheckFreshMotorInstallReadiness(context.Background(),e)==nil
   if eligible!=(tc.name=="empty-root" || tc.name=="unrelated-center-only"){
    t.Fatalf("unsafe fresh classification: eligible=%t inventory=%+v",eligible,got)
   }
  })
 }
}

func TestWindowsFreshMotorFileInventoryRejectsUntrustedPaths(t *testing.T) {
 for _,name:=range []string{"VOLVE_DNS_Server_0270.exe","VOLVE_DNS_Motor_0_28_7.exe"}{
  t.Run(name+"-empty",func(t *testing.T){
   root:=t.TempDir()
   writeFreshMotorFixture(t,root,name,nil)
   if _,err:=InspectWindowsFreshMotorFilesReadOnly(context.Background(),root);err==nil{
    t.Fatal("empty motor-like executable was accepted")
   }
  })
  t.Run(name+"-directory",func(t *testing.T){
   root:=t.TempDir()
   if err:=os.Mkdir(filepath.Join(root,name),0700);err!=nil{t.Fatal(err)}
   if _,err:=InspectWindowsFreshMotorFilesReadOnly(context.Background(),root);err==nil{
    t.Fatal("directory with executable name was accepted")
   }
  })
 }
 for _,name:=range []string{"installed-engines","motor-0.28.7"}{
  t.Run(name+"-file",func(t *testing.T){
   root:=t.TempDir()
   writeFreshMotorFixture(t,root,name,[]byte("malformed-directory"))
   if _,err:=InspectWindowsFreshMotorFilesReadOnly(context.Background(),root);err==nil{
    t.Fatal("file masquerading as engine inventory directory was accepted")
   }
  })
 }
 root:=t.TempDir()
 if _,err:=InspectWindowsFreshMotorFilesReadOnly(context.Background(),filepath.Join(root,"missing"));err==nil{
  t.Fatal("missing installed root incorrectly proved motor absence")
 }
 if _,err:=InspectWindowsFreshMotorFilesReadOnly(context.Background(),"relative-root");err==nil {
  t.Fatal("relative root was accepted")
 }
 if _,err:=InspectWindowsFreshMotorFilesReadOnly(context.Background(),filepath.Join(root,".."));err==nil{
  t.Fatal("root whose parents have not been pinned was accepted")
 }
}

func TestWindowsFreshMotorFilesCancelledAndNoWrites(t *testing.T) {
 root:=t.TempDir()
 name:="VOLVE_DNS_Server_0270.exe"
 data:=[]byte("installed-bytes-never-modified")
 writeFreshMotorFixture(t,root,name,data)
 before,err:=os.Stat(filepath.Join(root,name));if err!=nil{t.Fatal(err)}
 got,err:=InspectWindowsFreshMotorFilesReadOnly(context.Background(),root)
 if err!=nil||!got.LegacyExecutablePresent{t.Fatalf("read-only file inventory failed: %v",err)}
 after,err:=os.Stat(filepath.Join(root,name));if err!=nil{t.Fatal(err)}
 current,err:=os.ReadFile(filepath.Join(root,name));if err!=nil{t.Fatal(err)}
 if string(current)!=string(data) || before.Size()!=after.Size() || !before.ModTime().Equal(after.ModTime()){
  t.Fatal("read-only inventory changed a motor")
 }
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 if _,err:=InspectWindowsFreshMotorFilesReadOnly(ctx,root);!errors.Is(err,context.Canceled){
  t.Fatalf("cancelled inventory should not read motor: %v",err)
 }
}
