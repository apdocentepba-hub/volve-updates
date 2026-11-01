//go:build windows

package motorupdate

// Read-only inventory of the REAL, protected legacy recovery paths. A
// non-empty OR merely existing recovery parent excludes the "fresh install"
// path, even if its journal reports committed/restored. Existing protection
// must be handled by a separate publisher-signed migration driver.
import (
 "context"
 "errors"
 "fmt"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
)

const freshRecoveryParentName = "legacy-engine-recovery"
const freshRecoverySnapshotName = "original-before-upgrade"
const freshRecoveryJournalName = "motor-recovery-transaction"

type WindowsFreshRecoveryACLInspect func(context.Context,string) error

// The PATH is passed through an OS environment variable, never interpolated
// into the fixed privileged PowerShell program. It is read-only. This is an
// independent DACL/owner check, not a repair or a signature attestation.
const WindowsFreshRecoveryACLQuery = `$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';
$p=$env:VOLVE_RECOVERY_READ_PATH;
if([string]::IsNullOrWhiteSpace($p)){throw 'Missing recovery path'};
$attr=[IO.File]::GetAttributes($p);
if(($attr -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Recovery reparse path'};
if([IO.Directory]::Exists($p)){$acl=[IO.Directory]::GetAccessControl($p)}
else{$acl=[IO.File]::GetAccessControl($p)};
$allow=@('S-1-5-18','S-1-5-32-544');
$owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value;
if($owner -notin $allow){throw 'Untrusted recovery owner'};
if(-not $acl.AreAccessRulesProtected){throw 'Inherited recovery ACL'};
$full=[int][Security.AccessControl.FileSystemRights]::FullControl;
$rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]));
foreach($rule in $rules){
 if($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
    $rule.IdentityReference.Value -notin $allow){throw 'Untrusted recovery ACE'}
};
foreach($sid in $allow){
 $found=$false;
 foreach($rule in $rules){
  if($rule.IdentityReference.Value -eq $sid -and
     (([int]$rule.FileSystemRights -band $full) -eq $full)){$found=$true}
 };
 if(-not $found){throw 'Required recovery ACL missing'}
};
Write-Output 'VOLVE_RECOVERY_ACL_READ_ONLY_OK'`

func DefaultWindowsFreshRecoveryACLInspect(ctx context.Context,path string) error {
 if err:=ctx.Err();err!=nil{return err}
 if !filepath.IsAbs(path){return errors.New("nonabsolute recovery ACL check path")}
 root:=os.Getenv("SystemRoot")
 if !filepath.IsAbs(root){return errors.New("Windows system root unavailable")}
 ps:=filepath.Join(root,"System32","WindowsPowerShell","v1.0","powershell.exe")
 cmd:=exec.CommandContext(ctx,ps,"-NoLogo","-NoProfile","-NonInteractive","-Command",WindowsFreshRecoveryACLQuery)
 cmd.Env=append(os.Environ(),"VOLVE_RECOVERY_READ_PATH="+path)
 out,err:=cmd.Output()
 if err!=nil{return fmt.Errorf("Windows recovery ACL cannot be verified: %w",err)}
 if strings.TrimSpace(string(out))!="VOLVE_RECOVERY_ACL_READ_ONLY_OK"{
  return errors.New("ambiguous Windows recovery ACL result")
 }
 return nil
}

type WindowsFreshRecoveryInventory struct {
 RecoveryArtifactsPresent bool
 RecoveryJournalPresent bool
 PendingRollbackPresent bool
 JournalStatus string
 SnapshotPresent bool
}

// InspectWindowsFreshRecoveryReadOnly inspects exactly the current product's
// allowlisted parent, snapshot and journal paths. The existing install root
// must be resolved from trusted installed state. It NEVER creates, repairs or
// removes any journal, ACL, backup or scheduled task. An absent parent is
// valid ONLY if Lstat says ENOENT under the verified root. A present parent
// is ALWAYS evidence against a new installation, including an empty parent.
func InspectWindowsFreshRecoveryReadOnly(ctx context.Context,root string,
 protect WindowsFreshRecoveryACLInspect)(WindowsFreshRecoveryInventory,error){
 var zero WindowsFreshRecoveryInventory
 if err:=ctx.Err();err!=nil{return zero,err}
 if protect==nil{return zero,errors.New("independent protected-recovery ACL verifier required")}
 if err:=lstatAllExistingParents(root);err!=nil{return zero,err}
 parent:=filepath.Join(root,freshRecoveryParentName)
 info,err:=os.Lstat(parent)
 if errors.Is(err,os.ErrNotExist){
  return WindowsFreshRecoveryInventory{},nil
 }
 if err!=nil{return zero,err}
 if !info.IsDir()||info.Mode()&os.ModeSymlink!=0{
  return zero,errors.New("existing recovery parent is redirected or not a directory")
 }
 if err:=protect(ctx,parent);err!=nil{return zero,fmt.Errorf("untrusted legacy recovery parent: %w",err)}
 entries,err:=os.ReadDir(parent)
 if err!=nil{return zero,err}
 if len(entries)>8{return zero,errors.New("recovery parent has too many objects")}
 result:=WindowsFreshRecoveryInventory{RecoveryArtifactsPresent:true,JournalStatus:"not-present"}
 seen:=map[string]bool{}
 for _,e:=range entries {
  if err:=ctx.Err();err!=nil{return zero,err}
  name:=e.Name()
  lower:=strings.ToLower(name)
  if seen[lower]{return zero,errors.New("case-ambiguous recovery entry")}
  seen[lower]=true
  path:=filepath.Join(parent,name)
  stat,err:=os.Lstat(path)
  if err!=nil{return zero,err}
  if !stat.IsDir()||stat.Mode()&os.ModeSymlink!=0{
   return zero,errors.New("recovery artifact is linked, incomplete or not directory")
  }
  if name!=freshRecoverySnapshotName && name!=freshRecoveryJournalName{
   return zero,errors.New("unrecognized recovery entry or abandoned staging directory")
  }
  if err:=protect(ctx,path);err!=nil{return zero,fmt.Errorf("recovery artifact ACL untrusted: %w",err)}
  if name==freshRecoverySnapshotName {
   // The snapshot verifier validates receipt and SHA256; independently
   // verify each CHILD file's DACL too. Checking only the parent directory
   // would miss a separately writable recovery EXE, XML or JSON receipt.
   children,readErr:=os.ReadDir(path)
   if readErr!=nil{return zero,readErr}
   if len(children)!=3{return zero,errors.New("incomplete or unexpected recovery snapshot content")}
   expected:=map[string]bool{
    legacyBackupExe:true,legacyBackupXML:true,legacyBackupReceipt:true,
   }
   for _,child:=range children {
    if !expected[child.Name()] {return zero,errors.New("unknown legacy backup entry")}
    childPath:=filepath.Join(path,child.Name())
    childInfo,statErr:=os.Lstat(childPath)
    if statErr!=nil{return zero,statErr}
    if !childInfo.Mode().IsRegular()||childInfo.Mode()&os.ModeSymlink!=0{
     return zero,errors.New("legacy recovery backup is linked or nonregular")
    }
    if aclErr:=protect(ctx,childPath);aclErr!=nil{
     return zero,fmt.Errorf("untrusted legacy backup file ACL: %w",aclErr)
    }
   }
   record,err:=VerifyUnversionedLegacyRecovery(path,func(p string)error{return protect(ctx,p)})
   if err!=nil{return zero,fmt.Errorf("legacy recovery snapshot incomplete: %w",err)}
   if record.ExeSHA256==""||record.XMLSHA256==""{
    return zero,errors.New("legacy snapshot hashes absent")
   }
   result.SnapshotPresent=true
  }else{
   state,err:=InspectResidentRecoveryJournal(ctx,path,func(p string)error{return protect(ctx,p)})
   if err!=nil{return zero,fmt.Errorf("resident recovery journal not independently verified: %w",err)}
   result.RecoveryJournalPresent=true
   result.JournalStatus=state.Status
   result.PendingRollbackPresent=state.Status=="recovery-required"
  }
 }
 if err:=ctx.Err();err!=nil{return zero,err}
 return result,nil
}
