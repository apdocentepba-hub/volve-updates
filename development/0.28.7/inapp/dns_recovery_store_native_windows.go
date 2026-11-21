//go:build windows

package motorupdate

// Native Windows NTFS-only adapter for the original-DNS recovery backup.
// This creates or seals only brand-new backup nodes under an existing
// trusted recovery parent. It does NOT modify DNS, tasks or services,
// establish publisher authorization or arm a SYSTEM boot watchdog.
import (
 "context"
 "errors"
 "fmt"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
)

const dnsOriginalNativeSealToken="VOLVE_NATIVE_DNS_ORIGINAL_NODE_SEALED"

func nativeDNSOriginalBackupACL(ctx context.Context,path string)error{
 if err:=ctx.Err();err!=nil{return err}
 token,err:=DefaultWindowsDNSProtectedACLInspect(ctx,path)
 if err!=nil{return fmt.Errorf("untrusted Windows DNS original backup owner/DACL: %w",err)}
 if token!=windowsDNSProtectedACLToken{
  return errors.New("Windows original backup owner/DACL verification ambiguous")
 }
 return nil
}

// nativeSealNewDNSOriginalNode is allowlisted to the directory and its one
// backup file. An existing backup cannot be resealed through the staging
// operation: StoreDNSOriginalBackupUnarmed must have created it exclusively.
// Its PowerShell body uses only SID-based owner/ACL setting on that node.
func nativeSealNewDNSOriginalNode(
 ctx context.Context,recoveryParent,path string,
)error{
 if err:=ctx.Err();err!=nil{return err}
 if !filepath.IsAbs(recoveryParent)||
  filepath.Clean(recoveryParent)!=recoveryParent||
  filepath.Base(recoveryParent)!="legacy-engine-recovery"||
  strings.HasPrefix(recoveryParent,`\\`){
  return errors.New("native DNS original backup parent not a trusted local absolute path")
 }
 allowedDir:=filepath.Join(recoveryParent,DNSOriginalBackupDirectoryName)
 allowedFile:=filepath.Join(allowedDir,DNSOriginalBackupFileName)
 if path!=allowedDir&&path!=allowedFile{
  return errors.New("native DNS original seal refused unrelated file or folder")
 }
 stat,err:=os.Lstat(path)
 if err!=nil{return err}
 if stat.Mode()&os.ModeSymlink!=0||(!stat.IsDir()&&!stat.Mode().IsRegular()){
  return errors.New("native DNS original seal refused special or linked path")
 }
 root:=os.Getenv("SystemRoot")
 if !filepath.IsAbs(root)||strings.HasPrefix(root,`\\`){
  return errors.New("trusted Windows SystemRoot unavailable")
 }
 ps:=filepath.Join(root,"System32","WindowsPowerShell","v1.0","powershell.exe")
 binary,err:=os.Lstat(ps)
 if err!=nil{return err}
 if !binary.Mode().IsRegular()||binary.Mode()&os.ModeSymlink!=0{
  return errors.New("WindowsPowerShell is not a regular local executable")
 }
 quoted:="'"+strings.ReplaceAll(path,"'","''")+"'"
 script:=`$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';`+
  `$p=`+quoted+`;`+
  `$attr=[IO.File]::GetAttributes($p);`+
  `if(($attr -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Reparse point'};`+
  `$system=[Security.Principal.SecurityIdentifier]::new('S-1-5-18');`+
  `$admins=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544');`+
  `$full=[Security.AccessControl.FileSystemRights]::FullControl;`+
  `$allow=[Security.AccessControl.AccessControlType]::Allow;`+
  `if([IO.Directory]::Exists($p)){`+
  `$acl=New-Object Security.AccessControl.DirectorySecurity;`+
  `$flags=[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit;`+
  `foreach($sid in @($system,$admins)){`+
  `$rule=[Security.AccessControl.FileSystemAccessRule]::new($sid,$full,$flags,[Security.AccessControl.PropagationFlags]::None,$allow);`+
  `$acl.AddAccessRule($rule)};`+
  `$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner($admins);`+
  `[IO.Directory]::SetAccessControl($p,$acl);`+
  `}elseif([IO.File]::Exists($p)){`+
  `$acl=New-Object Security.AccessControl.FileSecurity;`+
  `foreach($sid in @($system,$admins)){`+
  `$rule=[Security.AccessControl.FileSystemAccessRule]::new($sid,$full,$allow);`+
  `$acl.AddAccessRule($rule)};`+
  `$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner($admins);`+
  `[IO.File]::SetAccessControl($p,$acl);`+
  `}else{throw 'Backup node missing'};`+
  `Write-Output '`+dnsOriginalNativeSealToken+`'`
 output,err:=exec.CommandContext(ctx,ps,
  "-NoLogo","-NoProfile","-NonInteractive","-Command",script).Output()
 if err!=nil{return fmt.Errorf("native original DNS ACL sealing refused: %w",err)}
 if strings.TrimSpace(string(output))!=dnsOriginalNativeSealToken{
  return errors.New("native original DNS seal did not produce the exact acknowledgement")
 }
 return nativeDNSOriginalBackupACL(ctx,path)
}

// StoreDNSOriginalBackupNativeWindows is the real Windows adapter: no fake
// sealer or ACL verifier is injectable through this API. The external pin
// MUST already be authenticated by a separate signed transaction receipt.
// Administrator rights suffice only for staging protected original metadata;
// they do NOT authorize a DNS switch, rollback or boot recovery.
func StoreDNSOriginalBackupNativeWindows(
 ctx context.Context,recoveryParent string,originalJSON []byte,
 independentlyTrustedSHA256 string,
)(DNSOriginalBackupStage,error){
 var denied DNSOriginalBackupStage
 if ctx==nil{return denied,errors.New("native DNS backup context required")}
 if err:=ctx.Err();err!=nil{return denied,err}
 if err:=residentCurrentIsPrivileged();err!=nil{return denied,err}
 seal:=func(path string)error{return nativeSealNewDNSOriginalNode(ctx,recoveryParent,path)}
 check:=func(path string)error{return nativeDNSOriginalBackupACL(ctx,path)}
 return StoreDNSOriginalBackupUnarmed(ctx,recoveryParent,originalJSON,independentlyTrustedSHA256,seal,check)
}

// ReadDNSOriginalBackupNativeWindows is independently usable by a future
// watchdog after a restart, but always needs the externally trusted hash.
func ReadDNSOriginalBackupNativeWindows(
 ctx context.Context,recoveryParent,independentlyTrustedSHA256 string,
)([]DNSRestoreRecord,error){
 if ctx==nil{return nil,errors.New("native DNS backup context required")}
 if err:=ctx.Err();err!=nil{return nil,err}
 if err:=residentCurrentIsPrivileged();err!=nil{return nil,err}
 return ReadStagedDNSOriginalBackupUnarmed(ctx,recoveryParent,independentlyTrustedSHA256,
  func(path string)error{return nativeDNSOriginalBackupACL(ctx,path)})
}
