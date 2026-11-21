//go:build windows

package motorupdate

// A durable, create-once Windows NTFS admission marker for a publisher-signed
// DNS activation intent. This is a SECURITY PRIMITIVE, not an installer:
// it does not activate DNS, create a task, edit HOSTS or start the motor.
//
// The caller must supply the signed publisher key pinned by trusted product
// code, the current journal/motor/watchdog evidence independently authenticated
// under a pending SYSTEM recovery transaction, and an existing SYSTEM/Admin-
// only NTFS parent. A local administrator able to delete protected recovery
// files remains outside this primitive's tamper-resistance threat model;
// watchdog + protected transaction journal must ALSO detect rollback/replay.
import (
 "bytes"
 "context"
 "crypto/ed25519"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "time"
)

const dnsActivationOnceReceiptComponent="volve-dns-publisher-activation-once-v1"
const dnsActivationOnceFilePrefix="dns-activation-used-"
const dnsActivationOnceReceiptLimit=2048


const dnsActivationOnceNativeSealAcknowledgment="VOLVE_NATIVE_SIGNED_ACTIVATION_ONCE_SEALED"

// sealNewDNSActivationOnceNativeFile applies the same non-inherited Windows
// SID ACL model as the original DNS backup. Merely creating a new file under
// an NTFS parent is NOT enough: it may be owned by the current user and inherit
// ACEs that fail the required SYSTEM/Administrators-only ACL attestation.
func sealNewDNSActivationOnceNativeFile(ctx context.Context,parent,path,nonce string)error{
 if err:=ctx.Err();err!=nil{return err}
 if err:=verifyDNSActivationEvidencePins(DNSActivationExternallyPinnedEvidence{
  IntentNonce:nonce,
  OriginalDNSJournalSHA256:strings.Repeat("0",64),
  TargetMotorSHA256:strings.Repeat("0",64),
  WatchdogTaskXMLSHA256:strings.Repeat("0",64),
 });err!=nil{return err}
 if filepath.Base(parent)!="legacy-engine-recovery"||
  filepath.Clean(parent)!=parent||
  filepath.Join(parent,dnsActivationOnceFilePrefix+nonce+".json")!=path{
  return errors.New("activation nonce seal outside exact protected recovery child")
 }
 if err:=nativeDNSOriginalBackupACL(ctx,parent);err!=nil{return err}
 stat,err:=os.Lstat(path)
 if err!=nil{return err}
 if !stat.Mode().IsRegular()||stat.Mode()&os.ModeSymlink!=0{
  return errors.New("activation nonce seal refused linked or special file")
 }
 root:=os.Getenv("SystemRoot")
 if !filepath.IsAbs(root)||strings.HasPrefix(root,\`\\\`){
  return errors.New("trusted Windows SystemRoot unavailable for activation nonce seal")
 }
 ps:=filepath.Join(root,"System32","WindowsPowerShell","v1.0","powershell.exe")
 binary,err:=os.Lstat(ps)
 if err!=nil{return err}
 if !binary.Mode().IsRegular()||binary.Mode()&os.ModeSymlink!=0{
  return errors.New("activation nonce sealer requires trusted WindowsPowerShell")
 }
 quoted:="'"+strings.ReplaceAll(path,"'","''")+"'"
 script:="$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';"+
  "$p="+quoted+";"+
  "$attr=[IO.File]::GetAttributes($p);"+
  "if(($attr -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Reparse point'};"+
  "$sys=[Security.Principal.SecurityIdentifier]::new('S-1-5-18');"+
  "$adm=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544');"+
  "$full=[Security.AccessControl.FileSystemRights]::FullControl;"+
  "$allow=[Security.AccessControl.AccessControlType]::Allow;"+
  "$acl=New-Object Security.AccessControl.FileSecurity;"+
  "foreach($sid in @($sys,$adm)){"+
  "$rule=[Security.AccessControl.FileSystemAccessRule]::new($sid,$full,$allow);"+
  "$acl.AddAccessRule($rule)};"+
  "$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner($adm);"+
  "[IO.File]::SetAccessControl($p,$acl);"+
  "Write-Output '"+dnsActivationOnceNativeSealAcknowledgment+"'"
 output,err:=exec.CommandContext(ctx,ps,
  "-NoLogo","-NoProfile","-NonInteractive","-Command",script).Output()
 if err!=nil{return fmt.Errorf("activation nonce NTFS ACL seal refused: %w",err)}
 if strings.TrimSpace(string(output))!=dnsActivationOnceNativeSealAcknowledgment{
  return errors.New("activation nonce ACL seal returned untrusted acknowledgment")
 }
 return nativeDNSOriginalBackupACL(ctx,path)
}

type DNSActivationOnceReceipt struct{
 Schema int `json:"schema"`
 Component string `json:"component"`
 IntentNonce string `json:"intent_nonce"`
 SignedGrantSHA256 string `json:"signed_grant_sha256"`
 OriginalDNSJournalSHA256 string `json:"original_dns_journal_sha256"`
 TargetMotorSHA256 string `json:"target_motor_sha256"`
 WatchdogTaskXMLSHA256 string `json:"watchdog_task_xml_sha256"`
 ReservedAtUnix int64 `json:"reserved_at_unix"`
}

// ReserveSignedDNSActivationOnceNativeWindows consumes one short-lived
// publisher grant atomically on an existing, ACL-sealed, local recovery tree.
// A failed post-write ACL/readback leaves the reserved marker in place and
// MUST NOT be interpreted as success or silently recycled.
func ReserveSignedDNSActivationOnceNativeWindows(
 ctx context.Context,recoveryParent string,grantJSON,signature []byte,
 pinnedPublisherKey ed25519.PublicKey,
 independentlyPinned DNSActivationExternallyPinnedEvidence,
 now time.Time,
)(DNSActivationOnceReceipt,error){
 var refused DNSActivationOnceReceipt
 if ctx==nil{return refused,errors.New("one-use activation requires context")}
 if err:=ctx.Err();err!=nil{return refused,err}
 if !filepath.IsAbs(recoveryParent)||filepath.Clean(recoveryParent)!=recoveryParent||
  filepath.Base(recoveryParent)!="legacy-engine-recovery"||
  strings.HasPrefix(recoveryParent,`\\`){
  return refused,errors.New("one-use activation requires exact trusted local recovery parent")
 }
 grant,err:=VerifyPublisherSignedDNSActivationGrant(
  ctx,grantJSON,signature,pinnedPublisherKey,independentlyPinned,now)
 if err!=nil{return refused,fmt.Errorf("one-use activation grant invalid: %w",err)}
 // THIS lease is held for every step. It is the identical protected kernel
 // mutex shared by future SYSTEM activation and independent boot recovery.
 release,err:=AcquireProtectedResidentTransitionLease(ctx)
 if err!=nil{return refused,fmt.Errorf("protected activation reservation mutex denied: %w",err)}
 if release==nil{return refused,errors.New("protected activation reservation missing release")}
 defer release()
 if err:=nativeDNSOriginalBackupACL(ctx,recoveryParent);err!=nil{
  return refused,fmt.Errorf("one-use activation parent has untrusted NTFS ACL: %w",err)
 }
 parent,err:=os.Lstat(recoveryParent)
 if err!=nil{return refused,err}
 if !parent.IsDir()||parent.Mode()&os.ModeSymlink!=0{
  return refused,errors.New("one-use activation recovery parent is a link or non-directory")
 }
 grantDigest:=sha256.Sum256(grantJSON)
 receipt:=DNSActivationOnceReceipt{
  Schema:1,Component:dnsActivationOnceReceiptComponent,
  IntentNonce:grant.IntentNonce,
  SignedGrantSHA256:hex.EncodeToString(grantDigest[:]),
  OriginalDNSJournalSHA256:grant.OriginalDNSJournalSHA256,
  TargetMotorSHA256:grant.TargetMotorSHA256,
  WatchdogTaskXMLSHA256:grant.WatchdogTaskXMLSHA256,
  ReservedAtUnix:now.Unix(),
 }
 raw,err:=json.Marshal(receipt)
 if err!=nil||len(raw)==0||len(raw)>dnsActivationOnceReceiptLimit{
  return refused,errors.New("one-use activation receipt not serializable")
 }
 destination:=filepath.Join(recoveryParent,dnsActivationOnceFilePrefix+grant.IntentNonce+".json")
 // O_EXCL is the actual NTFS cross-process one-use arbiter. NEVER treat an
 // existing file (even a broken receipt) as a reusable publisher grant.
 file,err:=os.OpenFile(destination,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
 if err!=nil{
  if errors.Is(err,os.ErrExist){return refused,errors.New("DNS activation nonce already reserved; signed grant cannot be replayed")}
  return refused,fmt.Errorf("cannot atomically reserve DNS activation nonce: %w",err)
 }
 written,writeErr:=file.Write(raw)
 if writeErr==nil&&written!=len(raw){writeErr=io.ErrShortWrite}
 if writeErr==nil{writeErr=file.Sync()}
 closeErr:=file.Close()
 if writeErr!=nil||closeErr!=nil{
  return refused,errors.Join(errors.New("one-use activation receipt could not be durably committed"),writeErr,closeErr)
 }
 if err:=ctx.Err();err!=nil{return refused,err}
 // Seal the BRAND-NEW marker under exact SYSTEM/Admin owner and DACL before
 // any success receipt is exposed. Failure keeps the nonce consumed.
 if err:=sealNewDNSActivationOnceNativeFile(ctx,recoveryParent,destination,grant.IntentNonce);err!=nil{
  return refused,fmt.Errorf("activation nonce created but native ACL sealing failed; grant remains spent: %w",err)
 }
 stat,err:=os.Lstat(destination)
 if err!=nil{return refused,err}
 if !stat.Mode().IsRegular()||stat.Mode()&os.ModeSymlink!=0||stat.Size()!=int64(len(raw)){
  return refused,errors.New("one-use activation receipt type or length changed after write")
 }
 if err:=nativeDNSOriginalBackupACL(ctx,destination);err!=nil{
  return refused,fmt.Errorf("one-use activation marker was not SYSTEM/Admin-only: %w",err)
 }
 reread,err:=os.ReadFile(destination)
 if err!=nil||!bytes.Equal(raw,reread){
  return refused,errors.New("one-use activation receipt changed during independent readback")
 }
 if err:=nativeDNSOriginalBackupACL(ctx,recoveryParent);err!=nil{
  return refused,errors.New("one-use activation parent changed protection during reservation")
 }
 if err:=ctx.Err();err!=nil{return refused,err}
 // Caller must now prove the separate watchdog is ARMED, system identity is
 // LocalSystem, replay is durably journaled and activation is publisher-
 // authorized under the protected transaction. This receipt alone permits
 // no DNS changes.
 return receipt,nil
}
