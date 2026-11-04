package signedstage

// Recovery of an INTERRUPTED CI-only inactive staging attempt. This code
// neither activates VOLVE nor removes an installed version, DNS or tasks.
import (
 "bytes"
 "context"
 "crypto/ed25519"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "strings"
 "volve.local/installer/unifiedbundle"
)

// RecoveryOutcome is a result, not permission to alter any Windows protection.
type RecoveryOutcome string
const (
 RecoveryAlreadyClean RecoveryOutcome = "NO_PENDING_CI_STAGE"
 RecoveryRemovedPending RecoveryOutcome = "VERIFIED_INCOMPLETE_CI_STAGE_CLEANED"
)

// RecoverAbandonedInactiveLabStage removes only known files inside an
// abandoned CI pending stage. Every byte must be an exact prefix of the
// authenticated original, allowing recovery from an interrupted file write.
// Foreign files, changed bytes, links and installed destinations are vetoes.
func RecoverAbandonedInactiveLabStage(ctx context.Context, source,destination string,key ed25519.PublicKey)(RecoveryOutcome,error){
 if ctx==nil||len(key)!=ed25519.PublicKeySize{return "",errors.New("context and independently trusted publisher key required")}
 if err:=ctx.Err();err!=nil{return "",err}
 if !recoveryPath(source)||!recoveryPath(destination)||!strings.HasPrefix(filepath.Base(destination),PreparedPrefix)||strings.EqualFold(source,destination)||filepath.Dir(source)!=filepath.Dir(destination){
  return "",errors.New("canonical CI-only sibling locations required")
 }
 if err:=recoveryParents(filepath.Dir(source));err!=nil{return "",err}
 if _,err:=unifiedbundle.Verify(source,key);err!=nil{return "",fmt.Errorf("untrusted signed source: %w",err)}
 pending:=destination+".pending"
 if _,err:=os.Lstat(destination);err==nil{return "",errors.New("already prepared/installed destination: preserve files")}else if !os.IsNotExist(err){return "",err}
 info,err:=os.Lstat(pending)
 if os.IsNotExist(err){return RecoveryAlreadyClean,nil}
 if err!=nil{return "",err}
 if !info.IsDir()||info.Mode()&os.ModeSymlink!=0{return "",errors.New("pending is not an ordinary directory")}
 // An existing lock (including post-crash residue) fails closed.
 lockPath:=pending+".recovery-lock"
 lock,err:=os.OpenFile(lockPath,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
 if err!=nil{return "",fmt.Errorf("recovery lock already present: %w",err)}
 if err:=lock.Close();err!=nil{return "",err}
 defer os.Remove(lockPath)
 if err:=ctx.Err();err!=nil{return "",err}
 if _,err:=os.Lstat(destination);err==nil{return "",errors.New("destination appeared during recovery lock")}else if !os.IsNotExist(err){return "",err}
 allowed:=map[string]bool{"manifest.json":true,"manifest.ed25519":true}
 for _,name:=range unifiedbundle.RequiredFiles(){allowed[name]=true}
 entries,err:=os.ReadDir(pending);if err!=nil{return "",err}
 // Inspect EVERY entry before any deletion; no RemoveAll.
 for _,entry:=range entries{
  if err:=ctx.Err();err!=nil{return "",err}
  if !allowed[entry.Name()]||!entry.Type().IsRegular(){return "",fmt.Errorf("foreign or linked entry %q; no deletion",entry.Name())}
  if err:=signedPrefix(ctx,filepath.Join(source,entry.Name()),filepath.Join(pending,entry.Name()));err!=nil{return "",fmt.Errorf("untrusted pending %q: %w",entry.Name(),err)}
 }
 if err:=ctx.Err();err!=nil{return "",err}
 if _,err:=unifiedbundle.Verify(source,key);err!=nil{return "",fmt.Errorf("signed source changed during review: %w",err)}
 if _,err:=os.Lstat(destination);err==nil{return "",errors.New("destination appeared during review")}else if !os.IsNotExist(err){return "",err}
 for _,entry:=range entries{
  if err:=ctx.Err();err!=nil{return "",err}
  if err:=os.Remove(filepath.Join(pending,entry.Name()));err!=nil{return "",err}
 }
 if err:=os.Remove(pending);err!=nil{return "",fmt.Errorf("pending contains foreign files or is busy: %w",err)}
 return RecoveryRemovedPending,nil
}
func recoveryPath(p string)bool{return p!=""&&filepath.IsAbs(p)&&filepath.Clean(p)==p&&filepath.Base(p)!="."&&filepath.Base(p)!=string(filepath.Separator)}
func recoveryParents(p string)error{
 for{
  st,err:=os.Lstat(p);if err!=nil{return err}
  if !st.IsDir()||st.Mode()&os.ModeSymlink!=0{return errors.New("linked or invalid parent directory")}
  next:=filepath.Dir(p);if next==p{return nil};p=next
 }
}
// An interrupted copy may leave a zero-byte or truncated final file.
// It can be removed only if all bytes match the trusted original prefix.
func signedPrefix(ctx context.Context,original,pendingPath string)error{
 a,err:=os.Lstat(original);if err!=nil{return err}
 b,err:=os.Lstat(pendingPath);if err!=nil{return err}
 if !a.Mode().IsRegular()||!b.Mode().IsRegular()||b.Size()>a.Size()||b.Size()>1<<30{return errors.New("unsafe file type or size")}
 in,err:=os.Open(original);if err!=nil{return err};defer in.Close()
 out,err:=os.Open(pendingPath);if err!=nil{return err};defer out.Close()
 aa,err:=in.Stat();if err!=nil||!os.SameFile(a,aa){return errors.New("source replaced")}
 bb,err:=out.Stat();if err!=nil||!os.SameFile(b,bb){return errors.New("pending replaced")}
 left,right:=make([]byte,64*1024),make([]byte,64*1024)
 remain:=b.Size()
 for remain>0{
  if err:=ctx.Err();err!=nil{return err}
  n:=int64(len(left));if n>remain{n=remain}
  if _,err:=io.ReadFull(in,left[:int(n)]);err!=nil{return err}
  if _,err:=io.ReadFull(out,right[:int(n)]);err!=nil{return err}
  if !bytes.Equal(left[:int(n)],right[:int(n)]){return errors.New("pending bytes differ from authenticated source prefix")}
  remain-=n
 }
 now,err:=out.Stat()
 if err!=nil||!os.SameFile(b,now)||b.Size()!=now.Size()||!b.ModTime().Equal(now.ModTime()){return errors.New("pending changed during inspection")}
 return nil
}
