// Package unifiedbundle verifies complete signed input for a future
// single-file VOLVE installer. It does not install or activate components.
package unifiedbundle

import (
 "bytes"
 "crypto/ed25519"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "strings"
)

const (
 schema = 1
 release = "0.28.7"
 target = "windows-amd64"
 maxManifest int64 = 1 << 20
 maxComponent int64 = 1 << 30
)
var Required = map[string]string{
 "centro-updater":"VOLVE_Centro_Updater.exe",
 "dns-motor":"VOLVE_DNS_Motor_0_28_7.exe",
 "motor-manifest":"VOLVE_DNS_Motor_0_28_7.exe.json",
 "motor-signature":"VOLVE_DNS_Motor_0_28_7.exe.sig",
 "system-watchdog":"VOLVE_Managed_Watchdog.exe",
 "uninstaller":"VOLVE_Uninstall.exe",
 "browser-policies":"VOLVE_Browser_Policies.json",
 "full-catalog":"VOLVE_Full_Catalog.txt",
}
type Component struct {
 ID string `json:"id"`
 File string `json:"file"`
 Size int64 `json:"size"`
 SHA256 string `json:"sha256"`
}
type Manifest struct {
 Schema int `json:"schema"`
 Release string `json:"release"`
 Platform string `json:"platform"`
 Components []Component `json:"components"`
}

// Verify requires an external, pinned publisher public key, not a key supplied
// by the untrusted bundle. The exact signed manifest then pins all 8 inputs.
// Reverify after copying to protected installer staging; this is preflight only.
func Verify(dir string, trusted ed25519.PublicKey) (*Manifest,error) {
 if len(trusted)!=ed25519.PublicKeySize{return nil,errors.New("missing trusted publisher public key")}
 if dir==""{return nil,errors.New("empty bundle root")}
 info,err:=os.Lstat(dir)
 if err!=nil{return nil,err}
 if !info.IsDir()||info.Mode()&os.ModeSymlink!=0{return nil,errors.New("bundle root is not a real directory")}
 raw,err:=readFile(filepath.Join(dir,"manifest.json"),maxManifest)
 if err!=nil{return nil,fmt.Errorf("manifest: %w",err)}
 sig,err:=readFile(filepath.Join(dir,"manifest.ed25519"),ed25519.SignatureSize)
 if err!=nil{return nil,fmt.Errorf("signature: %w",err)}
 if len(sig)!=ed25519.SignatureSize||!ed25519.Verify(trusted,raw,sig){return nil,errors.New("invalid publisher manifest signature")}
 dec:=json.NewDecoder(bytes.NewReader(raw));dec.DisallowUnknownFields()
 var m Manifest
 if err:=dec.Decode(&m);err!=nil{return nil,fmt.Errorf("invalid manifest: %w",err)}
 var trailing any
 if dec.Decode(&trailing)!=io.EOF{return nil,errors.New("manifest contains trailing data")}
 if m.Schema!=schema||m.Release!=release||m.Platform!=target{return nil,errors.New("wrong schema, release or Windows architecture")}
 if len(m.Components)!=len(Required){return nil,errors.New("incomplete component set")}
 seen:=map[string]bool{}
 allowed:=map[string]bool{"manifest.json":true,"manifest.ed25519":true}
 for _,c:=range m.Components{
  expected,ok:=Required[c.ID]
  if !ok||seen[c.ID]||c.File!=expected{return nil,fmt.Errorf("wrong or repeated component %q",c.ID)}
  seen[c.ID]=true
  if c.Size<=0||c.Size>maxComponent{return nil,fmt.Errorf("component %s size rejected",c.ID)}
  if len(c.SHA256)!=64||strings.ToLower(c.SHA256)!=c.SHA256{return nil,fmt.Errorf("component %s hash format rejected",c.ID)}
  if _,err:=hex.DecodeString(c.SHA256);err!=nil{return nil,err}
  data,err:=readFile(filepath.Join(dir,expected),maxComponent)
  if err!=nil{return nil,fmt.Errorf("component %s: %w",c.ID,err)}
  digest:=sha256.Sum256(data)
  if c.Size!=int64(len(data))||hex.EncodeToString(digest[:])!=c.SHA256{return nil,fmt.Errorf("component %s modified",c.ID)}
  allowed[expected]=true
 }
 entries,err:=os.ReadDir(dir)
 if err!=nil{return nil,err}
 if len(entries)!=len(allowed){return nil,errors.New("missing or additional bundle entries")}
 for _,entry:=range entries{
  if !allowed[entry.Name()]||!entry.Type().IsRegular(){return nil,fmt.Errorf("unexpected or linked entry %q",entry.Name())}
 }
 return &m,nil
}
func readFile(path string,limit int64)([]byte,error){
 before,err:=os.Lstat(path)
 if err!=nil{return nil,err}
 if !before.Mode().IsRegular()||before.Size()>limit{return nil,errors.New("not a bounded regular file")}
 f,err:=os.Open(path);if err!=nil{return nil,err};defer f.Close()
 opened,err:=f.Stat()
 if err!=nil||!os.SameFile(before,opened){return nil,errors.New("file changed before read")}
 data,err:=io.ReadAll(io.LimitReader(f,limit+1));if err!=nil{return nil,err}
 after,err:=f.Stat()
 if err!=nil||!os.SameFile(before,after)||int64(len(data))!=after.Size()||int64(len(data))>limit{return nil,errors.New("file changed while reading")}
 return data,nil
}
