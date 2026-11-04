package mixedbundleci

import (
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "crypto/sha256"
 "debug/pe"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "sort"
 "strings"
 "volve.local/installer/signedstage"
 "volve.local/installer/unifiedbundle"
)

type Sources struct{
 Centro,Watchdog,Motor,MotorManifest,MotorSignature,AuditJSON,Root,Inactive string
}
type Result struct{
 AssetsFromRealSources int
 AssetsSynthetic int
 RealPEFiles int
 StagedComponents int
 ApprovedForRelease bool
}

func safeParents(path string)error{
 for {
  st,err:=os.Lstat(path);if err!=nil{return err}
  if !st.IsDir()||st.Mode()&os.ModeSymlink!=0{return errors.New("linked/non-directory ancestor refused")}
  next:=filepath.Dir(path);if next==path{return nil};path=next
 }
}
func regularBytes(path string,max int64)([]byte,error){
 st,err:=os.Lstat(path);if err!=nil{return nil,err}
 if !st.Mode().IsRegular()||st.Size()<=0||st.Size()>max{return nil,errors.New("missing/linked/unbounded real asset")}
 f,err:=os.Open(path);if err!=nil{return nil,err};defer f.Close()
 opened,err:=f.Stat();if err!=nil||!os.SameFile(st,opened){return nil,errors.New("source replaced")}
 data,err:=io.ReadAll(io.LimitReader(f,max+1));if err!=nil{return nil,err}
 after,err:=f.Stat()
 if err!=nil||!os.SameFile(st,after)||int64(len(data))!=st.Size()||int64(len(data))!=after.Size()||!st.ModTime().Equal(after.ModTime()){
  return nil,errors.New("source altered during read")
 }
 return data,nil
}
func readAudit(path string)(Audit,error){
 var a Audit
 data,err:=regularBytes(path,1<<20);if err!=nil{return a,err}
 d:=json.NewDecoder(strings.NewReader(string(data)));d.DisallowUnknownFields()
 if err:=d.Decode(&a);err!=nil{return a,err}
 if err:=ValidateAudit(a);err!=nil{return a,err}
 return a,nil
}
func assertWindowsPE64(path string)error{
 f,err:=pe.Open(path);if err!=nil{return fmt.Errorf("not a real Windows PE: %w",err)}
 defer f.Close()
 if f.FileHeader.Machine!=pe.IMAGE_FILE_MACHINE_AMD64{return errors.New("Windows AMD64 required")}
 if _,ok:=f.OptionalHeader.(*pe.OptionalHeader64);!ok{return errors.New("Windows PE32+ required")}
 return nil
}
// BuildMixedLab strictly cross-checks real Centro/watchdog/historic motor
// against the independent read-only materials audit, then fills ONLY the
// missing browser policies and catalog with explicit synthetic CI markers.
// A randomly generated private key is used for this ephemeral lab alone;
// no private key is stored or exported. An inactive second-stage is verified.
func BuildMixedLab(ctx context.Context,s Sources)(Result,error){
 var rejected Result
 if ctx==nil{return rejected,errors.New("context required")}
 if err:=ctx.Err();err!=nil{return rejected,err}
 if !filepath.IsAbs(s.Root)||!filepath.IsAbs(s.Inactive)||filepath.Clean(s.Root)!=s.Root||
  filepath.Clean(s.Inactive)!=s.Inactive||filepath.Dir(s.Root)!=filepath.Dir(s.Inactive)||
  filepath.Base(s.Root)!="VOLVE-CI-MIXED-REAL-5"||filepath.Base(s.Inactive)!="VOLVE-CI-VERSION-0287-MIXED"{
  return rejected,errors.New("only the fixed inactive CI paths are permitted")
 }
 if err:=safeParents(filepath.Dir(s.Root));err!=nil{return rejected,err}
 for _,path:=range []string{s.Root,s.Inactive,s.Inactive+".pending"}{
  if _,err:=os.Lstat(path);err==nil{return rejected,errors.New("existing lab source, output or pending directory refused")}else if !os.IsNotExist(err){return rejected,err}
 }
 audit,err:=readAudit(s.AuditJSON);if err!=nil{return rejected,fmt.Errorf("independent real material audit refused: %w",err)}
 proofs:=map[string]Material{};for _,m:=range audit.Materials{proofs[m.ID]=m}
 files:=unifiedbundle.RequiredFiles()
 if len(files)!=7{return rejected,errors.New("public contract is not seven roles")}
 origin:=map[string]string{
  "centro-updater":s.Centro,
  "system-watchdog":s.Watchdog,
  "dns-motor":s.Motor,
  "motor-manifest":s.MotorManifest,
  "motor-signature":s.MotorSignature,
 }
 // Read and pin everything BEFORE creating the output directory.
 content:=map[string][]byte{}
 for id,path:=range origin{
  if err:=ctx.Err();err!=nil{return rejected,err}
  if path==""||!filepath.IsAbs(path)||filepath.Clean(path)!=path||filepath.Base(path)!=files[id]&&id!="centro-updater"&&id!="system-watchdog" {
   return rejected,fmt.Errorf("ambiguous actual material path for %s",id)
  }
  if err:=safeParents(filepath.Dir(path));err!=nil{return rejected,err}
  raw,err:=regularBytes(path,128<<20);if err!=nil{return rejected,fmt.Errorf("real asset %s: %w",id,err)}
  digest:=SHA256(raw)
  if id=="dns-motor"{
   if int64(len(raw))!=ExpectedHistoricMotorBytes||digest!=ExpectedHistoricMotorSHA256{return rejected,errors.New("old signed motor candidate changed")}
  }
  if id=="centro-updater"||id=="system-watchdog"{
   m:=proofs[id]
   if int64(len(raw))!=m.Bytes||digest!=m.SHA256{return rejected,fmt.Errorf("CI-built PE %s mismatches independent auditor",id)}
   if err:=assertWindowsPE64(path);err!=nil{return rejected,fmt.Errorf("real PE %s: %w",id,err)}
  }
  content[id]=raw
 }
 // The historical editor signature is checked AGAIN at the assembly
 // boundary, not merely trusted from an earlier CI step or SHA-256 audit.
 if err:=VerifyHistoricMotorSidecars(
  content["motor-manifest"],content["motor-signature"],
  SHA256(content["dns-motor"]),int64(len(content["dns-motor"])),
 );err!=nil{return rejected,fmt.Errorf("historically signed motor sidecars refused: %w",err)}
 if SHA256(content["centro-updater"])==SHA256(content["system-watchdog"])||SHA256(content["centro-updater"])==ExpectedHistoricMotorSHA256||
  SHA256(content["system-watchdog"])==ExpectedHistoricMotorSHA256{return rejected,errors.New("distinct executable roles were reused")}
 content["browser-policies"]=[]byte("{\"ci_only\":true,\"synthetic_missing_product_policy\":true,\"never_install\":true}\n")
 content["full-catalog"]=[]byte("VOLVE-CI-ONLY-SYNTHETIC-CATALOG-NOT-PRODUCTION-NEVER-INSTALL\n")
 if err:=ctx.Err();err!=nil{return rejected,err}
 pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{return rejected,err}
 if err:=os.Mkdir(s.Root,0700);err!=nil{return rejected,err}
 ids:=make([]string,0,len(files));for id:=range files{ids=append(ids,id)};sort.Strings(ids)
 manifest:=unifiedbundle.Manifest{Schema:1,Release:"0.28.7",Platform:"windows-amd64"}
 for _,id:=range ids{
  if err:=ctx.Err();err!=nil{return rejected,err}
  raw:=content[id]
  target:=filepath.Join(s.Root,files[id])
  f,err:=os.OpenFile(target,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600);if err!=nil{return rejected,err}
  _,writeErr:=f.Write(raw);syncErr:=f.Sync();closeErr:=f.Close()
  if writeErr!=nil{return rejected,writeErr};if syncErr!=nil{return rejected,syncErr};if closeErr!=nil{return rejected,closeErr}
  hash:=sha256.Sum256(raw)
  manifest.Components=append(manifest.Components,unifiedbundle.Component{
   ID:id,File:files[id],Size:int64(len(raw)),SHA256:hex.EncodeToString(hash[:]),
  })
 }
 raw,err:=json.Marshal(manifest);if err!=nil{return rejected,err}
 if err:=os.WriteFile(filepath.Join(s.Root,"manifest.json"),raw,0600);err!=nil{return rejected,err}
 if err:=os.WriteFile(filepath.Join(s.Root,"manifest.ed25519"),ed25519.Sign(priv,raw),0600);err!=nil{return rejected,err}
 if _,err:=unifiedbundle.Verify(s.Root,pub);err!=nil{return rejected,fmt.Errorf("fresh signed lab manifest rejected: %w",err)}
 staged,err:=signedstage.PrepareInactiveLabVersion(ctx,s.Root,s.Inactive,pub)
 if err!=nil{return rejected,fmt.Errorf("inactive Windows stage refused: %w",err)}
 if len(staged.Components)!=7{return rejected,errors.New("invalid staged public count")}
 return Result{AssetsFromRealSources:5,AssetsSynthetic:2,RealPEFiles:3,StagedComponents:7,ApprovedForRelease:false},nil
}
