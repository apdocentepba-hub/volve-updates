package unifiedbundle

import(
 "crypto/ed25519"
 "crypto/rand"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "os"
 "path/filepath"
 "testing"
)
func setup(t *testing.T)(string,ed25519.PublicKey,ed25519.PrivateKey,Manifest){
 t.Helper()
 dir:=t.TempDir()
 pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 m:=Manifest{Schema:schema,Release:release,Platform:target}
 for id,file:=range requiredComponents{
  data:=[]byte("synthetic test only: "+id)
  if err:=os.WriteFile(filepath.Join(dir,file),data,0600);err!=nil{t.Fatal(err)}
  sum:=sha256.Sum256(data)
  m.Components=append(m.Components,Component{ID:id,File:file,Size:int64(len(data)),SHA256:hex.EncodeToString(sum[:])})
 }
 sign(t,dir,priv,m)
 return dir,pub,priv,m
}
func sign(t *testing.T,dir string,priv ed25519.PrivateKey,m Manifest){
 t.Helper()
 raw,err:=json.Marshal(m);if err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(filepath.Join(dir,"manifest.json"),raw,0600);err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(filepath.Join(dir,"manifest.ed25519"),ed25519.Sign(priv,raw),0600);err!=nil{t.Fatal(err)}
}
func reject(t *testing.T,dir string,pub ed25519.PublicKey){
 t.Helper()
 if _,err:=Verify(dir,pub);err==nil{t.Fatal("unsafe bundle accepted")}
}
func TestSignedCompleteBundle(t *testing.T){
 dir,pub,_,_:=setup(t)
 m,err:=Verify(dir,pub);if err!=nil{t.Fatal(err)}
 if len(m.Components)!=8{t.Fatal("eight parts required")}
}
func TestMissingCriticalPartsFail(t *testing.T){
 for _,id:=range []string{"dns-motor","system-watchdog","uninstaller","browser-policies","full-catalog"}{
  t.Run(id,func(t *testing.T){
   dir,pub,_,_:=setup(t)
   if err:=os.Remove(filepath.Join(dir,requiredComponents[id]));err!=nil{t.Fatal(err)}
   reject(t,dir,pub)
  })
 }
}
func TestAlteredFileOrManifestFails(t *testing.T){
 dir,pub,_,_:=setup(t)
 if err:=os.WriteFile(filepath.Join(dir,requiredComponents["dns-motor"]),[]byte("tampered"),0600);err!=nil{t.Fatal(err)}
 reject(t,dir,pub)
 dir,pub,_,_=setup(t)
 if err:=os.WriteFile(filepath.Join(dir,"manifest.json"),[]byte("{}"),0600);err!=nil{t.Fatal(err)}
 reject(t,dir,pub)
}
func TestWrongPublisherAndSignatureFail(t *testing.T){
 dir,_,_,_:=setup(t)
 pub,_,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 reject(t,dir,pub)
 dir,pub,_,_=setup(t)
 if err:=os.WriteFile(filepath.Join(dir,"manifest.ed25519"),[]byte("fake"),0600);err!=nil{t.Fatal(err)}
 reject(t,dir,pub)
}
func TestEvenSignedIncorrectContentFails(t *testing.T){
 cases:=[]struct{name string;change func(*Manifest)}{
  {"old",func(m *Manifest){m.Release="0.28.6"}},
  {"architecture",func(m *Manifest){m.Platform="linux-amd64"}},
  {"incomplete",func(m *Manifest){m.Components=m.Components[:7]}},
  {"duplicate",func(m *Manifest){m.Components[0]=m.Components[1]}},
  {"traversal",func(m *Manifest){m.Components[0].File="../motor.exe"}},
  {"wrong-hash",func(m *Manifest){m.Components[0].SHA256="0000000000000000000000000000000000000000000000000000000000000000"}},
 }
 for _,tc:=range cases{t.Run(tc.name,func(t *testing.T){
  dir,pub,priv,m:=setup(t);tc.change(&m);sign(t,dir,priv,m);reject(t,dir,pub)
 })}
}
func TestExtraEntriesAndLinksFail(t *testing.T){
 dir,pub,_,_:=setup(t)
 if err:=os.WriteFile(filepath.Join(dir,"extra.exe"),[]byte("x"),0600);err!=nil{t.Fatal(err)}
 reject(t,dir,pub)
 dir,pub,_,_=setup(t)
 path:=filepath.Join(dir,requiredComponents["dns-motor"])
 target:=filepath.Join(t.TempDir(),"motor")
 bytes,err:=os.ReadFile(path);if err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(target,bytes,0600);err!=nil{t.Fatal(err)}
 if err:=os.Remove(path);err!=nil{t.Fatal(err)}
 if err:=os.Symlink(target,path);err!=nil{t.Skip("OS does not support test symlink: "+err.Error())}
 reject(t,dir,pub)
}
func TestNoImplicitTrust(t *testing.T){
 dir,pub,_,_:=setup(t)
 if _,err:=Verify(dir,nil);err==nil{t.Fatal("untrusted key accepted")}
 if _,err:=Verify("",pub);err==nil{t.Fatal("empty root accepted")}
}
