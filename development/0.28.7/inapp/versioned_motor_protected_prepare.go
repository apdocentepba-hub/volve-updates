package motorupdate

// Prepared-only bridge from an authenticated downloaded DNS motor to a
// create-only protected versioned installation directory. NO task/SYSTEM/DNS
// changes, no installed receipt, no activation or release authorization.
// The future privileged Windows transaction must hold the protected kernel
// mutex and ensure a publisher-bound independent watchdog BEFORE switching.
import (
 "context"
 "crypto/ed25519"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "strings"
)

const preparedMotorMaxBytes int64 = 80 << 20
const preparedMotorSidecarMaxBytes int64 = 8192

// ProtectedTargetFileOps must be bound by an elevated native installer to
// native NTFS DACL seal and verification. It is NOT a publisher permission;
// passing callbacks do not authorize activation.
type ProtectedTargetFileOps struct {
 SealNew func(string) error
 VerifyProtected func(string) error
}

// PrepareProtectedVersionedMotor copies the exact already signed bundle to a
// NEW motor-<version> directory under an existing trusted root. It fails
// closed if the target already exists, including failed previous attempts.
// It never removes partial files automatically: an interrupted operation must
// be reviewed under the pending recovery journal before retry.
func PrepareProtectedVersionedMotor(
 ctx context.Context, source, targetRoot string, publisher ed25519.PublicKey,
 acl ProtectedTargetFileOps,
) (string,error) {
 if err:=ctx.Err();err!=nil{return "",err}
 if acl.SealNew==nil||acl.VerifyProtected==nil{
  return "",errors.New("protected target requires native seal and ACL verification")
 }
 if !filepath.IsAbs(source)||filepath.Clean(source)!=source||
  !filepath.IsAbs(targetRoot)||filepath.Clean(targetRoot)!=targetRoot{
  return "",errors.New("source and destination must be canonical absolute paths")
 }
 if err:=safeInventoryDirectory(targetRoot);err!=nil{
  return "",fmt.Errorf("installed engine parent unsafe: %w",err)
 }
 if err:=acl.VerifyProtected(targetRoot);err!=nil{
  return "",fmt.Errorf("installed engine parent is not ACL-protected: %w",err)
 }
 if err:=safeInventoryDirectory(filepath.Dir(source));err!=nil{
  return "",fmt.Errorf("downloaded motor parent is redirected or unsafe: %w",err)
 }
 // A symlink in the staged EXE/manifest/signature must fail before the
 // create-only destination directory is created, not after partial writes.
 for _,sidecar:=range []string{"",".json",".sig"}{
  stat,err:=os.Lstat(source+sidecar)
  if err!=nil{return "",err}
  if !stat.Mode().IsRegular()||stat.Mode()&os.ModeSymlink!=0||stat.Size()<1{
   return "",errors.New("publisher bundle contains a link or nonregular file")
  }
 }
 manifest,err:=VerifyStaged(source,publisher)
 if err!=nil{return "",fmt.Errorf("publisher-signed candidate refused: %w",err)}
 if manifest.Component!="dns-engine"||manifest.Version==""{
  return "",errors.New("signed payload is not an independently versioned DNS engine")
 }
 dir:=filepath.Join(targetRoot,"motor-"+manifest.Version)
 dest:=filepath.Join(dir,stagedFilename(manifest))
 if strings.EqualFold(filepath.Clean(source),filepath.Clean(dest)){
  return "",errors.New("download path aliases installed engine destination")
 }
 if _,err:=os.Lstat(dir);err==nil{
  return "",errors.New("destination already exists; never overwrite a managed engine or interrupted preparation")
 }else if !errors.Is(err,os.ErrNotExist){return "",err}
 if err:=ctx.Err();err!=nil{return "",err}
 if err:=os.Mkdir(dir,0700);err!=nil{return "",fmt.Errorf("create-only versioned motor directory: %w",err)}
 if err:=acl.SealNew(dir);err!=nil{return "",fmt.Errorf("cannot seal fresh version directory: %w",err)}
 if err:=acl.VerifyProtected(dir);err!=nil{return "",fmt.Errorf("version directory ACL rejected: %w",err)}
 for _,sidecar:=range []struct{suffix string;max int64}{
  {"",preparedMotorMaxBytes},{".json",preparedMotorSidecarMaxBytes},{".sig",preparedMotorSidecarMaxBytes},
 }{
  if err:=ctx.Err();err!=nil{return "",err}
  if err:=copyCreateOnlyProtectedMotorFile(source+sidecar.suffix,dest+sidecar.suffix,sidecar.max,acl);err!=nil{
   return "",fmt.Errorf("protected motor bundle %s failed: %w",sidecar.suffix,err)
  }
 }
 // Strong TOCTOU fences: the installed payload and the external signed
 // original must BOTH still authenticate to exactly the same manifest.
 verified,err:=VerifyStaged(dest,publisher)
 if err!=nil||verified!=manifest{
  return "",fmt.Errorf("installed protected copy does not match publisher signature and SHA256: %v",err)
 }
 sourceAgain,err:=VerifyStaged(source,publisher)
 if err!=nil||sourceAgain!=manifest{
  return "",errors.New("staged publisher candidate changed during create-only copy")
 }
 if err:=acl.VerifyProtected(targetRoot);err!=nil{return "",err}
 if err:=acl.VerifyProtected(dir);err!=nil{return "",err}
 for _,suffix:=range []string{"",".json",".sig"}{
  if err:=acl.VerifyProtected(dest+suffix);err!=nil{return "",err}
 }
 if err:=ctx.Err();err!=nil{return "",err}
 return dest,nil
}

func copyCreateOnlyProtectedMotorFile(source,dest string,max int64,acl ProtectedTargetFileOps) error {
 if filepath.Dir(source)==filepath.Dir(dest) {return errors.New("refusing in-place signed candidate copy")}
 stat,err:=os.Lstat(source)
 if err!=nil{return err}
 if !stat.Mode().IsRegular()||stat.Mode()&os.ModeSymlink!=0||
  stat.Size()<1||stat.Size()>max {
  return errors.New("candidate file is a link, special file or outside strict byte bounds")
 }
 input,err:=os.Open(source);if err!=nil{return err}
 defer input.Close()
 output,err:=os.OpenFile(dest,os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600)
 if err!=nil{return err}
 size,copyErr:=io.CopyN(output,input,stat.Size()+1)
 if copyErr==io.EOF{copyErr=nil}
 if copyErr==nil&&size!=stat.Size(){copyErr=errors.New("source size changed during copy")}
 if copyErr==nil{copyErr=output.Sync()}
 closeErr:=output.Close()
 if copyErr!=nil{return copyErr}
 if closeErr!=nil{return closeErr}
 if err:=acl.SealNew(dest);err!=nil{return err}
 if err:=acl.VerifyProtected(dest);err!=nil{return err}
 after,err:=os.Lstat(source)
 if err!=nil{return err}
 if !after.Mode().IsRegular()||after.Size()!=stat.Size()||!after.ModTime().Equal(stat.ModTime()){
  return errors.New("signed source changed while copying")
 }
 return nil
}
