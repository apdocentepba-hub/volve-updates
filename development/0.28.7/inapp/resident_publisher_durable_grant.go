package motorupdate

// Durable, create-only publisher authorization for an already ARMED DNS
// recovery journal. The signed grant is stored in a separate sealed sibling
// directory, never as extra data inside the two-file recovery journal.
// Neither this code nor its caller is permitted to change the active motor,
// Windows Task Scheduler, DNS adapters or host network policy.
import (
 "bytes"
 "context"
 "crypto/ed25519"
 "errors"
 "fmt"
 "os"
 "path/filepath"
)

const residentGrantFolder="publisher-authorization"
const residentGrantPermitFile="migration-permit.json"
const residentGrantSignatureFile="migration-permit.sig"

type ResidentDurablePublisherGrant struct{
 JournalDir string
 BackupDir string
 Permit []byte
 Signature []byte
}

// residentGrantPaths checks fixed sibling placement. No arbitrary paths from
// signed material or an untrusted journal can affect where we write.
func residentGrantPaths(root string)(parent,grant,journal,backup string,err error){
 if !filepath.IsAbs(root)||filepath.Clean(root)!=root{
  err=errors.New("recovery installation root must be absolute and canonical")
  return
 }
 parent=filepath.Join(root,"legacy-engine-recovery")
 grant=filepath.Join(parent,residentGrantFolder)
 journal=filepath.Join(parent,"motor-recovery-transaction")
 backup=filepath.Join(parent,"original-before-upgrade")
 if filepath.Dir(parent)!=root{
  err=errors.New("invalid recovery installation root")
 }
 return
}
func checkResidentGrantNode(path string, directory bool)error{
 info,err:=os.Lstat(path)
 if err!=nil{return err}
 if info.Mode()&os.ModeSymlink!=0{
  return errors.New("resident publisher grant contains link or redirection")
 }
 if directory && !info.IsDir(){return errors.New("resident publisher grant directory not regular")}
 if !directory && !info.Mode().IsRegular(){return errors.New("resident publisher grant file not regular")}
 return nil
}

// LoadResidentDurablePublisherGrant works in an entirely NEW process after a
// reboot. Protect must verify non-inherited SYSTEM/Admin owner + DACL on each
// object (including the parent), not merely their basic file permissions.
// The caller supplies the public key compiled into its signed watchdog.
func LoadResidentDurablePublisherGrant(ctx context.Context,root string,
 key ed25519.PublicKey, protect func(string)error,
 protectJournal,protectBackup func(string)error,
)(ResidentDurablePublisherGrant,error){
 var empty ResidentDurablePublisherGrant
 if err:=ctx.Err();err!=nil{return empty,err}
 if protect==nil||protectJournal==nil||protectBackup==nil||len(key)!=ed25519.PublicKeySize{
  return empty,errors.New("recovery publisher grant missing trusted ACL/key services")
 }
 parent,dir,journal,backup,err:=residentGrantPaths(root)
 if err!=nil{return empty,err}
 for _,p:=range []string{root,parent,dir}{
  if err:=checkResidentGrantNode(p,true);err!=nil{return empty,err}
  if err:=protect(p);err!=nil{return empty,fmt.Errorf("untrusted signed grant directory: %w",err)}
 }
 entries,err:=os.ReadDir(dir);if err!=nil{return empty,err}
 if len(entries)!=2{return empty,errors.New("incomplete or extra publisher grant files")}
 seen:=map[string]bool{}
 for _,entry:=range entries{
  if entry.IsDir(){return empty,errors.New("nested publisher grant forbidden")}
  seen[entry.Name()]=true
 }
 if !seen[residentGrantPermitFile]||!seen[residentGrantSignatureFile]{
  return empty,errors.New("publisher grant file set not allowlisted")
 }
 paths:=[]string{filepath.Join(dir,residentGrantPermitFile),filepath.Join(dir,residentGrantSignatureFile)}
 read:=func(path string,limit int)([]byte,error){
  if err:=checkResidentGrantNode(path,false);err!=nil{return nil,err}
  if err:=protect(path);err!=nil{return nil,err}
  st,err:=os.Lstat(path)
  if err!=nil{return nil,err}
  if st.Size()<=0||st.Size()>int64(limit){return nil,errors.New("publisher grant size not allowed")}
  raw,err:=os.ReadFile(path)
  if err!=nil{return nil,err}
  if len(raw)==0||len(raw)>limit||int64(len(raw))!=st.Size(){
   return nil,errors.New("publisher grant changed length during read")
  }
  if err:=protect(path);err!=nil{return nil,err}
  return raw,nil
 }
 raw,err:=read(paths[0],maxMigrationPermitBytes)
 if err!=nil{return empty,fmt.Errorf("signed grant permit unsafe: %w",err)}
 sig,err:=read(paths[1],256)
 if err!=nil{return empty,fmt.Errorf("signed grant signature unsafe: %w",err)}
 if _,err:=VerifyResidentPublisherRecoveryBinding(ctx,journal,backup,raw,sig,key,
  protectJournal,protectBackup);err!=nil{
  return empty,fmt.Errorf("persisted grant not bound to pending protected recovery: %w",err)
 }
 // Verify the same bytes again from the fixed on-disk paths. An attacker
 // changing a file between read and cryptographic check cannot turn the
 // result into a trusted grant.
 againRaw,err:=read(paths[0],maxMigrationPermitBytes)
 if err!=nil||!bytes.Equal(raw,againRaw){
  return empty,errors.New("publisher grant permit changed during verification")
 }
 againSig,err:=read(paths[1],256)
 if err!=nil||!bytes.Equal(sig,againSig){
  return empty,errors.New("publisher grant signature changed during verification")
 }
 if err:=ctx.Err();err!=nil{return empty,err}
 return ResidentDurablePublisherGrant{
  JournalDir:journal,BackupDir:backup,
  Permit:append([]byte(nil),raw...),Signature:append([]byte(nil),sig...),
 },nil
}

// PersistResidentDurablePublisherGrant performs an EXCLUSIVE, irreversible
// create-only write. The caller MUST hold the privileged transition mutex,
// have an already armed immutable journal, and have sealed the backup. Sealer
// may set ACL only on NEWLY CREATED nodes; no existing ACL is repaired.
// A crash between writes leaves a fail-closed incomplete directory. Recovery
// may be retried only after administrative investigation, never auto-overwrite.
func PersistResidentDurablePublisherGrant(ctx context.Context,root string,
 permit,signature []byte,key ed25519.PublicKey,
 sealNew,protect,protectJournal,protectBackup func(string)error,
)error{
 if err:=ctx.Err();err!=nil{return err}
 if sealNew==nil||protect==nil||protectJournal==nil||protectBackup==nil{
  return errors.New("publisher grant requires trusted Windows ACL services")
 }
 if len(key)!=ed25519.PublicKeySize{return errors.New("missing pinned publisher public key")}
 parent,dir,journal,backup,err:=residentGrantPaths(root)
 if err!=nil{return err}
 // Persisting an EXPIRED authorization is forbidden; the exception is only
 // for a watchdog reading an authorization that was safely stored earlier.
 if _,err:=parseSignedMigrationPermit(permit,signature,key);err!=nil{
  return fmt.Errorf("cannot arm publisher grant for a new transaction: %w",err)
 }
 for _,p:=range []string{root,parent}{
  if err:=checkResidentGrantNode(p,true);err!=nil{return err}
  if err:=protect(p);err!=nil{return err}
 }
 if _,err:=VerifyResidentPublisherRecoveryBinding(ctx,journal,backup,permit,signature,key,
   protectJournal,protectBackup);err!=nil{
  return fmt.Errorf("unsigned or mismatched pending recovery cannot be persisted: %w",err)
 }
 if err:=ctx.Err();err!=nil{return err}
 if err:=os.Mkdir(dir,0700);err!=nil{return fmt.Errorf("publisher grant already present or cannot create: %w",err)}
 if err:=sealNew(dir);err!=nil{return fmt.Errorf("fresh grant dir not sealed: %w",err)}
 if err:=protect(dir);err!=nil{return fmt.Errorf("fresh grant dir not trusted: %w",err)}
 write:=func(name string,payload []byte)error{
  path:=filepath.Join(dir,name)
  file,err:=os.OpenFile(path,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
  if err!=nil{return err}
  n,writeErr:=file.Write(payload)
  if writeErr==nil&&n!=len(payload){writeErr=errors.New("partial publisher grant write")}
  if writeErr==nil{writeErr=file.Sync()}
  closeErr:=file.Close()
  if writeErr!=nil{return writeErr}
  if closeErr!=nil{return closeErr}
  if err:=sealNew(path);err!=nil{return err}
  return protect(path)
 }
 if err:=write(residentGrantPermitFile,permit);err!=nil{return err}
 if err:=write(residentGrantSignatureFile,signature);err!=nil{return err}
 if err:=ctx.Err();err!=nil{return err}
 loaded,err:=LoadResidentDurablePublisherGrant(ctx,root,key,protect,protectJournal,protectBackup)
 if err!=nil{return fmt.Errorf("publisher grant saved but cannot be audited: %w",err)}
 if !bytes.Equal(loaded.Permit,permit)||!bytes.Equal(loaded.Signature,signature){
  return errors.New("durable publisher grant differs from signed authorization")
 }
 return nil
}
