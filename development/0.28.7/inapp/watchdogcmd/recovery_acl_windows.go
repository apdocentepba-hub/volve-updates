//go:build windows

package main

import (
 "context"
 "errors"
 "fmt"
 "os"
 "path/filepath"
)

// verifyRecoveryACL is read-only. A live motor transition must reject
// snapshots and journals unless the directory and all files are controlled
// by SYSTEM or BUILTIN\Administrators. Windows DACLs, not Unix 0600 bits,
// decide which accounts may change a recovery transaction.
func verifyRecoveryACL(ctx context.Context, journalPath, snapshotPath string) error {
 if err:=guardedSnapshotPath(journalPath,snapshotPath);err!=nil{return err}
 dir:=filepath.Clean(filepath.Dir(journalPath))
 for _,p:=range []string{dir,journalPath,snapshotPath}{
   if !filepath.IsAbs(p){return errors.New("recovery ACL path is not absolute")}
   if _,err:=os.Lstat(p);err!=nil{return err}
 }
 // Query the effective Windows file security descriptors. Account names are
 // localized; always translate each principal and owner to a stable SID.
 // Fail closed if any trustee cannot be translated or the descriptor is
 // inherited from an untrusted parent. Do not use icacls textual output.
 script:=`$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';`+
  `$allowed=@('S-1-5-18','S-1-5-32-544');`+
  `$critical=[int][Security.AccessControl.FileSystemRights]::Write -bor `+
    `[int][Security.AccessControl.FileSystemRights]::Delete -bor `+
    `[int][Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor `+
    `[int][Security.AccessControl.FileSystemRights]::ChangePermissions -bor `+
    `[int][Security.AccessControl.FileSystemRights]::TakeOwnership;`+
  `$paths=@(`+q(dir)+`,`+q(journalPath)+`,`+q(snapshotPath)+`);`+
  `foreach($path in $paths){`+
  `$attributes=[IO.File]::GetAttributes($path);`+
  `if(($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Recovery path is a reparse point'};`+
  `if([IO.Directory]::Exists($path)){$acl=[IO.Directory]::GetAccessControl($path)}else{$acl=[IO.File]::GetAccessControl($path)};`+
  `$owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value;`+
  `if($owner -notin $allowed){throw 'Untrusted recovery ACL owner: '+$owner};`+
  `if($path -eq $paths[0] -and -not $acl.AreAccessRulesProtected){throw 'Recovery directory inherits untrusted DACL'};`+
  `foreach($ace in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){`+
    `$sid=$ace.IdentityReference.Value;`+
    `if($ace.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and `+
       `$sid -notin $allowed -and (([int]$ace.FileSystemRights -band $critical) -ne 0)){`+
      `throw 'Untrusted writer on recovery ACL: '+$sid`+
    `}`+
  `}`+
  `};Write-Output 'VOLVE_RECOVERY_ACL_OK'`
 output,err:=ps(ctx,script)
 if err!=nil{return fmt.Errorf("untrusted recovery ACL: %w",err)}
 if output!="VOLVE_RECOVERY_ACL_OK" {return fmt.Errorf("unrecognized ACL verification result: %q",output)}
 return nil
}
