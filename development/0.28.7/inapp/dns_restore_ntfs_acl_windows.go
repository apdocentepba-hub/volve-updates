//go:build windows

package motorupdate

// Read-only Windows NTFS security descriptor gate for a future privileged
// recovery controller. This is NOT a SYSTEM token or publisher-key verifier.
// It never grants permission to mutate DNS by itself.
import (
 "context"
 "errors"
 "fmt"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
)

const windowsDNSProtectedACLToken="VOLVE_DNS_RECOVERY_NTFS_ACL_VALID"

type WindowsDNSProtectedACLInspect func(context.Context,string)(string,error)

// NewWindowsDNSProtectedACLVerifier restricts the callback to the exact
// journal and DNS snapshot paths belonging to one resident transaction.
// Each check re-reads the current OWNER and DACL, not Go's POSIX-like bits.
// The caller must independently bind the protected parent to a trusted
// installation root and pin open handles across critical OS operations.
func NewWindowsDNSProtectedACLVerifier(
 ctx context.Context,journalDir,snapshotPath string,
 inspect WindowsDNSProtectedACLInspect,
)(func(string)error,error){
 if inspect==nil{return nil,errors.New("Windows DACL inspector missing")}
 if err:=ctx.Err();err!=nil{return nil,err}
 if !filepath.IsAbs(journalDir)||filepath.Base(journalDir)!="motor-recovery-transaction"||
  filepath.Base(filepath.Dir(journalDir))!="legacy-engine-recovery"{
  return nil,errors.New("NTFS verification is restricted to resident journal path")
 }
 parent:=filepath.Dir(journalDir)
 if snapshotPath!=filepath.Join(parent,WindowsDNSRecoverySnapshotName){
  return nil,errors.New("NTFS verification snapshot outside resident recovery parent")
 }
 allow:=map[string]bool{
  parent:true,
  journalDir:true,
  filepath.Join(journalDir,ResidentIntentFile):true,
  filepath.Join(journalDir,ResidentResultFile):true,
  snapshotPath:true,
 }
 return func(path string)error{
  if err:=ctx.Err();err!=nil{return err}
  if !allow[path]||!filepath.IsAbs(path)||filepath.Clean(path)!=path {
   return errors.New("untrusted Windows DNS recovery ACL path")
  }
  info,err:=os.Lstat(path)
  if err!=nil{return err}
  if info.Mode()&os.ModeSymlink!=0||(!info.IsDir()&&!info.Mode().IsRegular()){
   return errors.New("recovery security descriptor path is a link or special file")
  }
  result,err:=inspect(ctx,path)
  if err!=nil{return fmt.Errorf("Windows recovery NTFS ACL rejected: %w",err)}
  if strings.TrimSpace(result)!=windowsDNSProtectedACLToken{
   return errors.New("Windows recovery ACL result ambiguous or not allowed")
  }
  return nil
 },nil
}

// DefaultWindowsDNSProtectedACLInspect inspects real Windows security
// descriptors with SID-based checks, which do not depend on OS language.
// The script is fixed and the path is PowerShell single-quoted with every
// quote escaped. An exact full path to the OS executable avoids PATH lookup.
func DefaultWindowsDNSProtectedACLInspect(ctx context.Context,path string)(string,error){
 if err:=ctx.Err();err!=nil{return "",err}
 if !filepath.IsAbs(path){return "",errors.New("absolute NTFS recovery ACL path required")}
 root:=os.Getenv("SystemRoot")
 if root==""||!filepath.IsAbs(root)||strings.HasPrefix(root,`\\`) {
  return "",errors.New("trusted Windows SystemRoot unavailable")
 }
 ps:=filepath.Join(root,"System32","WindowsPowerShell","v1.0","powershell.exe")
 stat,err:=os.Lstat(ps)
 if err!=nil{return "",err}
 if !stat.Mode().IsRegular()||stat.Mode()&os.ModeSymlink!=0{
  return "",errors.New("WindowsPowerShell binary redirected")
 }
 quoted:="'"+strings.ReplaceAll(path,"'","''")+"'"
 script:=`$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';`+
  `$p=`+quoted+`;`+
  `$a=[IO.File]::GetAttributes($p);`+
  `if(($a -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Reparse point'};`+
  `if([IO.Directory]::Exists($p)){$acl=[IO.Directory]::GetAccessControl($p)}else{$acl=[IO.File]::GetAccessControl($p)};`+
  `$allowed=@('S-1-5-18','S-1-5-32-544');`+
  `$owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value;`+
  `if($owner -notin $allowed){throw 'Untrusted owner'};`+
  `if(-not $acl.AreAccessRulesProtected){throw 'Inherited recovery DACL'};`+
  `$all=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]));`+
  `if($all.Count -lt 2){throw 'Missing protected trustees'};`+
  `foreach($rule in $all){`+
  `if($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or $rule.IdentityReference.Value -notin $allowed){throw 'Foreign or deny ACL entry'}`+
  `};`+
  `$full=[int][Security.AccessControl.FileSystemRights]::FullControl;`+
  `foreach($sid in $allowed){`+
  `$has=$false;foreach($rule in $all){`+
  `if($rule.IdentityReference.Value -eq $sid -and (([int]$rule.FileSystemRights -band $full) -eq $full)){$has=$true}`+
  `};if(-not $has){throw 'Missing SYSTEM/Administrators FullControl'}`+
  `};Write-Output '`+windowsDNSProtectedACLToken+`'`
 out,err:=exec.CommandContext(ctx,ps,"-NoLogo","-NoProfile","-NonInteractive",
  "-ExecutionPolicy","Bypass","-Command",script).CombinedOutput()
 if err!=nil{return "",fmt.Errorf("Windows NTFS DACL inspection failed: %w",err)}
 return strings.TrimSpace(string(out)),nil
}
