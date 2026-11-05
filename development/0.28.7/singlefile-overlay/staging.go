package singlefile

// StageInLab extracts authenticated assets to a disposable test-only folder.
// It must NOT be called from an installer; production requires NTFS ACL,
// exclusive SYSTEM lock and publisher Authenticode checks.
import (
 "archive/zip"
 "crypto/ed25519"
 "encoding/binary"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "strings"
 "volve.local/installer/unifiedbundle"
)

// StageInLab never executes binaries or alters DNS, tasks or registry.
// The destination must be a NEW absolute VOLVE-CI- laboratory directory.
func StageInLab(exe string, trusted ed25519.PublicKey, destination string) (_ *unifiedbundle.Manifest, err error) {
 if len(trusted)!=ed25519.PublicKeySize{return nil,errors.New("trusted publisher key required")}
 if destination=="" || !filepath.IsAbs(destination) || !strings.HasPrefix(filepath.Base(destination),"VOLVE-CI-"){
  return nil,errors.New("only an absolute VOLVE-CI- lab directory is allowed")
 }
 if err:=requireRealParents(filepath.Dir(destination));err!=nil{return nil,err}
 if _,err:=InspectExecutable(exe,trusted);err!=nil{return nil,fmt.Errorf("signed embedded payload refused: %w",err)}
 f,err:=os.Open(exe);if err!=nil{return nil,err};defer f.Close()
 st,err:=f.Stat();if err!=nil{return nil,err}
 hdr:=make([]byte,4096)
 n,err:=f.ReadAt(hdr,0);if err!=nil && err!=io.EOF{return nil,err}
 hdr=hdr[:n]
 if !isPE(hdr){return nil,errors.New("not Windows PE")}
 end,err:=payloadLogicalEnd(f,hdr,st.Size());if err!=nil{return nil,err}
 if end<footerSize{return nil,errors.New("no embedded payload")}
 footer:=make([]byte,footerSize)
 if _,err:=f.ReadAt(footer,end-footerSize);err!=nil{return nil,err}
 if string(footer[:16])!=magic{return nil,errors.New("missing signed footer")}
 length:=binary.LittleEndian.Uint64(footer[16:24])
 if length==0||length>uint64(maxPayload)||int64(length)>end-footerSize{return nil,errors.New("invalid embedded length")}
 offset:=end-footerSize-int64(length)
 if offset<=0||offset>maxPE{return nil,errors.New("invalid offset")}
 zr,err:=zip.NewReader(io.NewSectionReader(f,offset,int64(length)),int64(length))
 if err!=nil{return nil,err}
 if _,err:=verifyZip(zr,trusted);err!=nil{return nil,err}
 if err:=os.Mkdir(destination,0700);err!=nil{return nil,fmt.Errorf("fresh lab directory required: %w",err)}
 complete:=false
 defer func(){if !complete {os.RemoveAll(destination)}}()
 allowed:=map[string]bool{"manifest.json":true,"manifest.ed25519":true}
 for _,v:=range unifiedbundle.RequiredFiles(){allowed[v]=true}
 for _,entry:=range zr.File{
  if !allowed[entry.Name] || !fileIsCanonicalBase(entry.Name)||!entry.Mode().IsRegular()||entry.UncompressedSize64>uint64(maxPart){
   return nil,fmt.Errorf("unsafe archive member: %q",entry.Name)
  }
  source,err:=entry.Open();if err!=nil{return nil,err}
  dest,err:=os.OpenFile(filepath.Join(destination,entry.Name),os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
  if err!=nil{source.Close();return nil,err}
  _,copyErr:=io.Copy(dest,io.LimitReader(source,int64(entry.UncompressedSize64)+1))
  closeErr:=dest.Close();readCloseErr:=source.Close()
  if copyErr!=nil{return nil,copyErr}
  if closeErr!=nil{return nil,closeErr}
  if readCloseErr!=nil{return nil,readCloseErr}
 }
 m,err:=unifiedbundle.Verify(destination,trusted)
 if err!=nil{return nil,fmt.Errorf("staged output failed second signature/hash verification: %w",err)}
 complete=true
 return m,nil
}

func requireRealParents(path string) error {
 for {
  info,err:=os.Lstat(path)
  if err!=nil{return fmt.Errorf("lab parent missing: %w",err)}
  if !info.IsDir()||info.Mode()&os.ModeSymlink!=0{return errors.New("lab parent is not a real directory")}
  next:=filepath.Dir(path)
  if next==path{return nil}
  path=next
 }
}
