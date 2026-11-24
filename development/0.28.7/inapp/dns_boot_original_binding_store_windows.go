//go:build windows

package motorupdate

// Create-only NTFS persistence for the publisher-signed original-DNS binding.
// This is evidence staging, NOT permission to change DNS, install a task, or
// declare successful recovery. No signing key is created or stored here.
// Only the immutable public key pinned by the future SYSTEM watchdog may
// verify the binding on an independently restarted process.
import (
 "bytes"
 "context"
 "crypto/ed25519"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "reflect"
 "strings"
)

const (
 dnsBootOriginalBindingJSONFile="dns-original-binding.json"
 dnsBootOriginalBindingSignatureFile="dns-original-binding.sig"
)

// All operations on this store must run with the same exclusive OS-wide
// kernel mutex as migration and independent recovery.
func dnsOriginalBindingEvidencePaths(root string)(string,string,string,error){
 if !filepath.IsAbs(root)||filepath.Clean(root)!=root||
  strings.HasPrefix(root,string(filepath.Separator)+string(filepath.Separator)){
  return "","","",errors.New("signed original DNS evidence requires canonical local installation root")
 }
 parent:=filepath.Join(root,"legacy-engine-recovery")
 return parent,filepath.Join(parent,dnsBootOriginalBindingJSONFile),
  filepath.Join(parent,dnsBootOriginalBindingSignatureFile),nil
}

// Persist... never overwrites an existing binding. An incomplete first write
// consumes the slot: a later signed and audited recovery/cleanup transaction
// must address it; no automatic retry that could race with a watchdog.
func PersistSignedOriginalDNSEvidenceNativeWindows(
 ctx context.Context,root string,key ed25519.PublicKey,
 signedJSON,signedSignature []byte,
)error{
 if ctx==nil{return errors.New("signed DNS evidence staging requires context")}
 if err:=ctx.Err();err!=nil{return err}
 if err:=residentCurrentIsPrivileged();err!=nil{return err}
 if len(key)!=ed25519.PublicKeySize{return errors.New("publisher identity not pinned")}
 parent,dataPath,sigPath,err:=dnsOriginalBindingEvidencePaths(root)
 if err!=nil{return err}
 release,err:=AcquireProtectedResidentTransitionLease(ctx)
 if err!=nil{return err}
 if release==nil{return errors.New("native signed DNS evidence missing protected mutex")}
 defer release()
 grant,err:=LoadResidentDurablePublisherGrant(ctx,root,key,
  func(p string)error{return nativeDNSOriginalBackupACL(ctx,p)},
  func(p string)error{return nativeDNSOriginalBackupACL(ctx,p)},
  func(p string)error{return nativeDNSOriginalBackupACL(ctx,p)})
 if err!=nil{return fmt.Errorf("untrusted pending publisher grant: %w",err)}
 pending,err:=InspectResidentRecoveryJournal(ctx,grant.JournalDir,
  func(p string)error{return nativeDNSOriginalBackupACL(ctx,p)})
 if err!=nil||pending.Status!="recovery-required"{
  return errors.New("no protected pending DNS recovery transaction")
 }
 if err:=VerifyExplicitResidentRecoveryScope(ctx,grant.Permit,grant.Signature,key,ResidentRecoveryScopeMotorAndDNS,pending.Intent.Nonce);err!=nil{return nil,nil,err}
 binding,err:=VerifySignedDNSOriginalBinding(
  ctx,signedJSON,signedSignature,key,pending.Intent,grant.Permit)
 if err!=nil{return err}
 records,err:=ReadDNSOriginalBackupNativeWindows(
  ctx,parent,binding.OriginalDNSJournalSHA256)
 if err!=nil||len(records)<2{
  return errors.New("signed original DNS snapshot not durably verified")
 }
 if err:=nativeDNSOriginalBackupACL(ctx,parent);err!=nil{return err}
 for _,name:=range []string{dataPath,sigPath}{
  _,e:=os.Lstat(name)
  if e==nil{return errors.New("signed original DNS evidence already staged; never overwrite")}
  if !errors.Is(e,os.ErrNotExist){return e}
 }
 for _,pair:=range []struct{path string;raw []byte}{
  {dataPath,signedJSON},{sigPath,signedSignature},
 }{
  if err:=ctx.Err();err!=nil{return err}
  file,err:=os.OpenFile(pair.path,os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600)
  if err!=nil{return fmt.Errorf("create-only signed DNS evidence refused: %w",err)}
  n,writeErr:=file.Write(pair.raw)
  if writeErr==nil&&n!=len(pair.raw){writeErr=io.ErrShortWrite}
  if writeErr==nil{writeErr=file.Sync()}
  closeErr:=file.Close()
  if writeErr!=nil||closeErr!=nil{
   return errors.Join(errors.New("signed original DNS binding not fully durable; existing files must never be reused"),writeErr,closeErr)
  }
  if err:=nativeSealNewDNSOriginalNode(ctx,parent,pair.path);err!=nil{
   return fmt.Errorf("signed original DNS binding NTFS seal failed; evidence stays nonreusable: %w",err)
  }
 }
 againJSON,againSig,err:=loadSignedOriginalDNSEvidenceUnderLeaseWindows(
  ctx,root,key)
 if err!=nil{return err}
 if !bytes.Equal(againJSON,signedJSON)||!bytes.Equal(againSig,signedSignature){
  return errors.New("sealed signed original DNS evidence changed during independent readback")
 }
 return nil
}

// Caller must already hold the protected Windows kernel mutex. This performs
// fresh on-disk ACL, publisher-grant, pending-journal, signature, and original
// DNS snapshot verification; raw file bytes are never trusted in isolation.
func loadSignedOriginalDNSEvidenceUnderLeaseWindows(
 ctx context.Context,root string,key ed25519.PublicKey,
)([]byte,[]byte,error){
 if ctx==nil||len(key)!=ed25519.PublicKeySize{
  return nil,nil,errors.New("missing protected boot signer or context")
 }
 if err:=ctx.Err();err!=nil{return nil,nil,err}
 parent,dataPath,sigPath,err:=dnsOriginalBindingEvidencePaths(root)
 if err!=nil{return nil,nil,err}
 for _,path:=range []string{root,parent,dataPath,sigPath}{
  stat,err:=os.Lstat(path)
  if err!=nil{return nil,nil,err}
  if stat.Mode()&os.ModeSymlink!=0{return nil,nil,errors.New("signed DNS evidence contains link")}
  if err:=nativeDNSOriginalBackupACL(ctx,path);err!=nil{return nil,nil,err}
 }
 read:=func(path string,limit int)([]byte,error){
  stat,err:=os.Lstat(path)
  if err!=nil{return nil,err}
  if !stat.Mode().IsRegular()||stat.Size()<=0||stat.Size()>int64(limit){
   return nil,errors.New("non-regular or excessive signed original DNS evidence")
  }
  bytes,err:=os.ReadFile(path)
  if err!=nil{return nil,err}
  if len(bytes)==0||len(bytes)>limit||int64(len(bytes))!=stat.Size(){
   return nil,errors.New("signed DNS evidence changed while reopening")
  }
  return bytes,nil
 }
 raw,err:=read(dataPath,signedDNSReceiptMaxBytes)
 if err!=nil{return nil,nil,err}
 sig,err:=read(sigPath,256)
 if err!=nil{return nil,nil,err}
 grant,err:=LoadResidentDurablePublisherGrant(ctx,root,key,
  func(p string)error{return nativeDNSOriginalBackupACL(ctx,p)},
  func(p string)error{return nativeDNSOriginalBackupACL(ctx,p)},
  func(p string)error{return nativeDNSOriginalBackupACL(ctx,p)})
 if err!=nil{return nil,nil,err}
 pending,err:=InspectResidentRecoveryJournal(ctx,grant.JournalDir,
  func(p string)error{return nativeDNSOriginalBackupACL(ctx,p)})
 if err!=nil||pending.Status!="recovery-required"{
  return nil,nil,errors.New("signed DNS evidence no longer matches pending recovery")
 }
 binding,err:=VerifySignedDNSOriginalBinding(
  ctx,raw,sig,key,pending.Intent,grant.Permit)
 if err!=nil{return nil,nil,err}
 before,err:=ReadDNSOriginalBackupNativeWindows(ctx,parent,binding.OriginalDNSJournalSHA256)
 if err!=nil||len(before)<2{return nil,nil,errors.New("signed original DNS backup missing")}
 after,err:=ReadDNSOriginalBackupNativeWindows(ctx,parent,binding.OriginalDNSJournalSHA256)
 if err!=nil||!reflect.DeepEqual(before,after){
  return nil,nil,errors.New("original DNS backup changed during signed evidence reopen")
 }
 if err:=nativeDNSOriginalBackupACL(ctx,dataPath);err!=nil{return nil,nil,err}
 if err:=nativeDNSOriginalBackupACL(ctx,sigPath);err!=nil{return nil,nil,err}
 return raw,sig,nil
}
