// Package signedstage prepares an INACTIVE signed bundle in isolated CI.
// It does not install, update, activate, uninstall, or change DNS/tasks.
package signedstage

import (
 "context"
 "crypto/ed25519"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "sort"
 "strings"
 "volve.local/installer/unifiedbundle"
)
const PreparedPrefix = "VOLVE-CI-VERSION-"

// PrepareInactiveLabVersion creates a NEW inactive version from a signed
// seven-component bundle. It never overwrites running or installed versions.
func PrepareInactiveLabVersion(ctx context.Context, source, destination string, key ed25519.PublicKey) (*unifiedbundle.Manifest,error) {
 return prepare(ctx,source,destination,key,nil)
}
// The optional callback is unexported and used exclusively for failure tests.
func prepare(ctx context.Context,source,destination string,key ed25519.PublicKey,onCopy func(string)error)(_ *unifiedbundle.Manifest,err error){
 if ctx==nil||len(key)!=ed25519.PublicKeySize{return nil,errors.New("context and pinned publisher key required")}
 if err:=ctx.Err();err!=nil{return nil,err}
 if !canonical(source)||!canonical(destination)||!strings.HasPrefix(filepath.Base(destination),PreparedPrefix){return nil,errors.New("canonical absolute CI-only paths required")}
 if strings.EqualFold(source,destination)||filepath.Dir(source)!=filepath.Dir(destination){return nil,errors.New("source and inactive destination must be distinct siblings")}
 if err:=realParents(filepath.Dir(source));err!=nil{return nil,err}
 // Lock before inspecting/creating pending state: recovery cannot race a writer.
 unlock,lockErr:=acquireStageLock(destination)
 if lockErr!=nil{return nil,fmt.Errorf("exclusive inactive staging lock unavailable: %w",lockErr)}
 defer unlock()
 pending:=destination+".pending"
 for _,p:=range []string{destination,pending} {
  if _,e:=os.Lstat(p);e==nil{return nil,fmt.Errorf("existing version or pending state: %s",p)}else if !os.IsNotExist(e){return nil,e}
 }
 if _,err:=unifiedbundle.Verify(source,key);err!=nil{return nil,fmt.Errorf("signed source rejected: %w",err)}
 if err:=ctx.Err();err!=nil{return nil,err}
 if err:=os.Mkdir(pending,0700);err!=nil{return nil,err}
 committed:=false
 defer func(){if !committed{cleanupPending(pending)}}()
 names:=[]string{"manifest.json","manifest.ed25519"}
 for _,name:=range unifiedbundle.RequiredFiles(){names=append(names,name)}
 sort.Strings(names)
 if len(names)!=9{return nil,errors.New("public seven-component contract changed")}
 for _,name:=range names{
  if err:=ctx.Err();err!=nil{return nil,err}
  if onCopy!=nil{if err:=onCopy(name);err!=nil{return nil,err}}
  if err:=copyRegularSync(filepath.Join(source,name),filepath.Join(pending,name));err!=nil{return nil,fmt.Errorf("copy %s: %w",name,err)}
 }
 if _,err:=unifiedbundle.Verify(source,key);err!=nil{return nil,fmt.Errorf("source changed during copy: %w",err)}
 m,err:=unifiedbundle.Verify(pending,key)
 if err!=nil{return nil,fmt.Errorf("staged bytes failed second signature/hash check: %w",err)}
 if err:=ctx.Err();err!=nil{return nil,err}
 if _,err:=os.Lstat(destination);err==nil{return nil,errors.New("destination appeared during preparation")}else if !os.IsNotExist(err){return nil,err}
 // This promotes only a NEW, INACTIVE lab directory on the same volume.
 if err:=os.Rename(pending,destination);err!=nil{return nil,err}
 committed=true
 if _,err:=unifiedbundle.Verify(destination,key);err!=nil{return nil,fmt.Errorf("inactive version preserved for inspection; post-rename verification failed: %w",err)}
 return m,nil
}
func canonical(p string)bool{return p!=""&&filepath.IsAbs(p)&&filepath.Clean(p)==p&&filepath.Base(p)!="."&&filepath.Base(p)!=string(filepath.Separator)}
func realParents(p string)error{
 for{
  info,err:=os.Lstat(p);if err!=nil{return err}
  if !info.IsDir()||info.Mode()&os.ModeSymlink!=0{return errors.New("linked or non-directory ancestor refused")}
  next:=filepath.Dir(p);if next==p{return nil};p=next
 }
}
func copyRegularSync(src,dst string)error{
 before,err:=os.Lstat(src);if err!=nil{return err}
 if !before.Mode().IsRegular()||before.Size()<=0||before.Size()>1<<30{return errors.New("unsafe source file type or size")}
 in,err:=os.Open(src);if err!=nil{return err};defer in.Close()
 opened,err:=in.Stat();if err!=nil||!os.SameFile(before,opened){return errors.New("source changed before copy")}
 out,err:=os.OpenFile(dst,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600);if err!=nil{return err}
 n,copyErr:=io.Copy(out,io.LimitReader(in,before.Size()+1))
 syncErr:=out.Sync();closeErr:=out.Close()
 if copyErr!=nil{return copyErr};if syncErr!=nil{return syncErr};if closeErr!=nil{return closeErr}
 after,err:=in.Stat()
 if err!=nil||!os.SameFile(before,after)||n!=before.Size()||after.Size()!=n||!before.ModTime().Equal(after.ModTime()){return errors.New("source changed during copy")}
 return nil
}
func cleanupPending(p string){
 info,err:=os.Lstat(p);if err!=nil||!info.IsDir()||info.Mode()&os.ModeSymlink!=0{return}
 names:=[]string{"manifest.json","manifest.ed25519"}
 for _,name:=range unifiedbundle.RequiredFiles(){names=append(names,name)}
 for _,name:=range names{_ = os.Remove(filepath.Join(p,name))}
 _ = os.Remove(p) // Unknown files remain untouched.
}
