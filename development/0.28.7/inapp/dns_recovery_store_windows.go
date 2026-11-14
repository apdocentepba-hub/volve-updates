//go:build windows

package motorupdate

// Create-only staging of the ORIGINAL DNS configuration on NTFS.
// This function does not install VOLVE, change DNS, arm the watchdog,
// publish a restore permit, or sign a publisher authorization.
//
// A hash pin is NOT a signature. The caller must keep the already-trusted
// SHA-256 outside this backup and independently authenticate its origin.
// The parent must be an existing NTFS recovery directory whose ACL is
// verified BEFORE even a transient original DNS payload is created.
import (
 "bytes"
 "context"
 "crypto/sha256"
 "crypto/subtle"
 "encoding/hex"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "strings"
)

const DNSOriginalBackupDirectoryName="dns-original-backup-v1"
const DNSOriginalBackupFileName="original-dns.json"

type DNSOriginalBackupStage struct {
 Schema int `json:"schema"`
 Component string `json:"component"`
 FileVerified bool `json:"file_verified"`
 NTFSACLVerified bool `json:"ntfs_acl_verified"`
 CreateOnly bool `json:"create_only"`
 PerformedDNSWrites bool `json:"performed_dns_writes"`
 InstallAuthorized bool `json:"install_authorized"`
 RestoreAuthorized bool `json:"restore_authorized"`
}

// StoreDNSOriginalBackupUnarmed creates a sealed, read-back-verified file
// under a protected parent. The file cannot be silently replaced or reused.
// All paths used for ACL callbacks are exact allowlisted nodes, with no
// direct caller-supplied file path. No cleanup occurs on a failed seal:
// a partial recovery staging tree remains REFUSED for a future attempt.
func StoreDNSOriginalBackupUnarmed(
 ctx context.Context,protectedRecoveryParent string,raw []byte,
 independentlyPinnedSHA256 string,
 sealNewNode func(string)error,
 verifyACL func(string)error,
)(DNSOriginalBackupStage,error){
 var denied DNSOriginalBackupStage
 if ctx==nil{return denied,errors.New("missing staging context")}
 if err:=ctx.Err();err!=nil{return denied,err}
 if sealNewNode==nil||verifyACL==nil{return denied,errors.New("trusted NTFS seal and verify callbacks required")}
 if !filepath.IsAbs(protectedRecoveryParent)||
  filepath.Clean(protectedRecoveryParent)!=protectedRecoveryParent||
  filepath.Base(protectedRecoveryParent)!="legacy-engine-recovery"||
  strings.HasPrefix(protectedRecoveryParent,`\\`){
  return denied,errors.New("recovery parent not an approved absolute local NTFS path")
 }
 parentStat,err:=os.Lstat(protectedRecoveryParent)
 if err!=nil{return denied,err}
 if !parentStat.IsDir()||parentStat.Mode()&os.ModeSymlink!=0{
  return denied,errors.New("recovery parent redirected or not a directory")
 }
 if err:=verifyACL(protectedRecoveryParent);err!=nil{
  return denied,fmt.Errorf("recovery parent ACL not protected: %w",err)
 }
 if _,err:=VerifyDNSOriginalJournal(ctx,raw,independentlyPinnedSHA256);err!=nil{
  return denied,fmt.Errorf("original DNS journal was not independently verified: %w",err)
 }
 dir:=filepath.Join(protectedRecoveryParent,DNSOriginalBackupDirectoryName)
 file:=filepath.Join(dir,DNSOriginalBackupFileName)
 // A pre-existing stage, valid or not, must NEVER be overwritten.
 if err:=os.Mkdir(dir,0700);err!=nil{return denied,fmt.Errorf("DNS original recovery stage must be new: %w",err)}
 if err:=sealNewNode(dir);err!=nil{return denied,fmt.Errorf("staged backup directory could not be sealed: %w",err)}
 if err:=verifyACL(dir);err!=nil{return denied,fmt.Errorf("staged backup directory ACL invalid: %w",err)}
 if err:=ctx.Err();err!=nil{return denied,err}
 // The directory must already exclude untrusted access before the private
 // GUIDs and DNS server IPs can reach the filesystem.
 f,err:=os.OpenFile(file,os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600)
 if err!=nil{return denied,fmt.Errorf("cannot create original DNS snapshot exclusively: %w",err)}
 n,writeErr:=f.Write(raw)
 if writeErr==nil&&n!=len(raw){writeErr=io.ErrShortWrite}
 if writeErr==nil{writeErr=f.Sync()}
 closeErr:=f.Close()
 if writeErr!=nil{return denied,fmt.Errorf("original DNS recovery data not durable: %w",writeErr)}
 if closeErr!=nil{return denied,fmt.Errorf("original DNS recovery file close failed: %w",closeErr)}
 if err:=sealNewNode(file);err!=nil{return denied,fmt.Errorf("original DNS snapshot ACL not sealed: %w",err)}
 if err:=verifyACL(file);err!=nil{return denied,fmt.Errorf("original DNS snapshot ACL not protected: %w",err)}
 if err:=verifyACL(dir);err!=nil{return denied,fmt.Errorf("recovery directory ACL changed: %w",err)}
 if err:=verifyACL(protectedRecoveryParent);err!=nil{return denied,fmt.Errorf("recovery parent ACL changed: %w",err)}
 if err:=ctx.Err();err!=nil{return denied,err}
 verified,err:=ReadStagedDNSOriginalBackupUnarmed(ctx,protectedRecoveryParent,independentlyPinnedSHA256,verifyACL)
 if err!=nil{return denied,fmt.Errorf("durable original DNS read-back failed: %w",err)}
 if len(verified)==0{return denied,errors.New("staged original DNS backup empty")}
 return DNSOriginalBackupStage{
  Schema:1,Component:"volve-original-dns-ntfs-backup-lab",
  FileVerified:true,NTFSACLVerified:true,CreateOnly:true,
  PerformedDNSWrites:false,InstallAuthorized:false,RestoreAuthorized:false,
 },nil
}

// ReadStagedDNSOriginalBackupUnarmed rechecks owner/DACL, file identity,
// exact bytes, externally pinned hash and complete IPv4/IPv6 provenance.
// It deliberately cannot return a signed permit or authorize adapter writes.
func ReadStagedDNSOriginalBackupUnarmed(
 ctx context.Context,protectedRecoveryParent,independentlyPinnedSHA256 string,
 verifyACL func(string)error,
)([]DNSRestoreRecord,error){
 if ctx==nil||verifyACL==nil{return nil,errors.New("trusted ACL verifier and context required")}
 if err:=ctx.Err();err!=nil{return nil,err}
 if !filepath.IsAbs(protectedRecoveryParent)||
  filepath.Clean(protectedRecoveryParent)!=protectedRecoveryParent||
  filepath.Base(protectedRecoveryParent)!="legacy-engine-recovery"||
  strings.HasPrefix(protectedRecoveryParent,`\\`){
  return nil,errors.New("untrusted recovery parent")
 }
 dir:=filepath.Join(protectedRecoveryParent,DNSOriginalBackupDirectoryName)
 file:=filepath.Join(dir,DNSOriginalBackupFileName)
 for _,path:=range []string{protectedRecoveryParent,dir,file}{
  stat,err:=os.Lstat(path)
  if err!=nil{return nil,err}
  if stat.Mode()&os.ModeSymlink!=0||(!stat.IsDir()&&!stat.Mode().IsRegular()){
   return nil,errors.New("protected DNS recovery contains a link or special file")
  }
  if err:=verifyACL(path);err!=nil{return nil,fmt.Errorf("protected DNS recovery ACL refused: %w",err)}
 }
 before,err:=os.Lstat(file)
 if err!=nil{return nil,err}
 if !before.Mode().IsRegular()||before.Size()<2||before.Size()>dnsRecoveryJournalMaxBytes{
  return nil,errors.New("protected DNS recovery file invalid size or type")
 }
 f,err:=os.Open(file)
 if err!=nil{return nil,err}
 opened,err:=f.Stat()
 if err!=nil{f.Close();return nil,err}
 if !os.SameFile(before,opened){f.Close();return nil,errors.New("DNS original backup identity changed before read")}
 raw,readErr:=io.ReadAll(io.LimitReader(f,dnsRecoveryJournalMaxBytes+1))
 endHandle,statErr:=f.Stat()
 closeErr:=f.Close()
 if readErr!=nil||statErr!=nil||closeErr!=nil{
  return nil,errors.New("staged DNS recovery file could not be read consistently")
 }
 after,err:=os.Lstat(file)
 if err!=nil{return nil,err}
 if len(raw)>dnsRecoveryJournalMaxBytes||
  !os.SameFile(before,after)||!os.SameFile(opened,endHandle)||
  before.Size()!=after.Size()||before.Size()!=endHandle.Size()||
  before.Size()!=int64(len(raw))||
  !before.ModTime().Equal(after.ModTime())||
  !before.ModTime().Equal(endHandle.ModTime()){
  return nil,errors.New("staged DNS recovery file changed or was replaced")
 }
 // Re-check paths after reading, before treating records as validated.
 for _,path:=range []string{protectedRecoveryParent,dir,file}{
  if err:=verifyACL(path);err!=nil{return nil,fmt.Errorf("recovery ACL weakened during read: %w",err)}
 }
 expected,err:=hex.DecodeString(independentlyPinnedSHA256)
 if err!=nil||len(expected)!=sha256.Size{return nil,errors.New("trusted external DNS snapshot hash required")}
 sum:=sha256.Sum256(raw)
 if subtle.ConstantTimeCompare(expected,sum[:])!=1{
  return nil,errors.New("staged DNS original snapshot differs from protected digest")
 }
 records,err:=VerifyDNSOriginalJournal(ctx,raw,independentlyPinnedSHA256)
 if err!=nil{return nil,err}
 // Refuse ambiguity from unexpected extra files in this sealed stage.
 nodes,err:=os.ReadDir(dir)
 if err!=nil{return nil,err}
 if len(nodes)!=1||nodes[0].Name()!=DNSOriginalBackupFileName{
  return nil,errors.New("unexpected node in original DNS recovery staging directory")
 }
 if err:=ctx.Err();err!=nil{return nil,err}
 return records,nil
}

// compile-time reference to bytes: avoid accidental inclusion of noncanonical
// payloads (already checked by VerifyDNSOriginalJournal).
var _ = bytes.Equal
