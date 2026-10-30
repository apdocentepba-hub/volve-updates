//go:build windows

package main

// Independent resident recovery-journal auditor. Read-only: cannot schedule,
// restore or switch VOLVE-DNS-SERVER-0270. The journal is NOT a publisher
// signature and never grants authority for a production migration.
import (
 "context"
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "strings"

 "volve-browser-protection/motorupdate"
)

const residentJournalDirName="motor-recovery-transaction"

func residentJournalPathAllowed(dir string) bool {
 return filepath.IsAbs(dir) && filepath.Base(dir)==residentJournalDirName &&
  filepath.Base(filepath.Dir(dir))==residentRecoveryParent
}

// A recovery decision controls SYSTEM behavior. Every path must be owned
// by SYSTEM or BUILTIN\Administrators, with a protected DACL and no foreign
// ACEs, even if its JSON hashes appear valid. No ACLs are repaired here.
func checkResidentJournalNTFS(ctx context.Context,path string)error{
 if err:=ctx.Err();err!=nil{return err}
 if !filepath.IsAbs(path){return errors.New("journal ACL path not absolute")}
 info,err:=os.Lstat(path);if err!=nil{return err}
 if info.Mode()&os.ModeSymlink!=0 || (!info.IsDir() && !info.Mode().IsRegular()){
  return errors.New("journal path is linked or special")
 }
 script:=`$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';`+
  `$p=`+q(path)+`;`+
  `$allowed=@('S-1-5-18','S-1-5-32-544');`+
  `$attr=[IO.File]::GetAttributes($p);`+
  `if(($attr -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Journal reparse point'};`+
  `if([IO.Directory]::Exists($p)){$acl=[IO.Directory]::GetAccessControl($p)}else{$acl=[IO.File]::GetAccessControl($p)};`+
  `$owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value;`+
  `if($owner -notin $allowed){throw 'Untrusted journal owner'};`+
  `if(-not $acl.AreAccessRulesProtected){throw 'Inherited journal DACL'};`+
  `$rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]));`+
  `foreach($r in $rules){`+
  `if($r.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or $r.IdentityReference.Value -notin $allowed){throw 'Foreign journal ACL entry'};`+
  `};$full=[int][Security.AccessControl.FileSystemRights]::FullControl;`+
  `foreach($sid in $allowed){`+
  `$hasFull=$false;foreach($r in $rules){`+
  `if($r.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and `+
  `$r.IdentityReference.Value -eq $sid -and `+
  `(([int]$r.FileSystemRights -band $full) -eq $full)){$hasFull=$true}`+
  `};if(-not $hasFull){throw ('Missing SYSTEM/Admin FullControl: '+$sid)}`+
  `};`+
  `Write-Output 'VOLVE_RESIDENT_JOURNAL_ACL_OK'`
 out,err:=ps(ctx,script)
 if err!=nil{return fmt.Errorf("journal ACL rejected: %w",err)}
 if strings.TrimSpace(out)!="VOLVE_RESIDENT_JOURNAL_ACL_OK"{
  return fmt.Errorf("journal ACL ambiguous: %q",out)
 }
 return nil
}

// auditResidentJournal verifies parent + recovery transaction directory,
// each present journal file and the create-only nonce/hash chain. Only an
// exact, valid terminal receipt may suppress the 'recovery-required' state.
func auditResidentJournal(ctx context.Context,dir string)(motorupdate.ResidentRecoveryJournalState,error){
 var empty motorupdate.ResidentRecoveryJournalState
 if !residentJournalPathAllowed(dir){
  return empty,errors.New("resident journal outside authorized recovery parent")
 }
 if err:=checkResidentJournalNTFS(ctx,filepath.Dir(dir));err!=nil{return empty,err}
 return motorupdate.InspectResidentRecoveryJournal(ctx,dir,
  func(path string)error{return checkResidentJournalNTFS(ctx,path)})
}
