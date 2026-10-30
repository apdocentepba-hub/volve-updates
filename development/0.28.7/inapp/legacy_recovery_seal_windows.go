//go:build windows

package main

// Only seals ownership/ACL of new recovery files; never switches a DNS task.
import (
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "strings"
)

var legacySealableFiles=map[string]bool{
    "VOLVE_DNS_Legacy_Recovery.exe":true,
    "VOLVE_DNS_Legacy_Task.xml":true,
    "VOLVE_DNS_Legacy_Recovery.json":true,
}

func isNewLegacyRecoveryNode(path string) bool {
    if !filepath.IsAbs(path) {return false}
    name:=filepath.Base(path)
    parent:=filepath.Base(filepath.Dir(path))
    if name==localRecoveryFolder {return true}
    if parent==localRecoveryFolder && strings.HasPrefix(name,".legacy-recovery-") && len(name)>len(".legacy-recovery-") {
        return true
    }
    if legacySealableFiles[name] && strings.HasPrefix(parent,".legacy-recovery-") &&
       filepath.Base(filepath.Dir(filepath.Dir(path)))==localRecoveryFolder {
        return true
    }
    return false
}

// Accept ONLY objects just created by our privileged snapshot workflow;
// never operate on an existing backup directory or resident motor.
func sealNewLegacyRecoveryNode(path string) error {
    if !isAdmin() {return errors.New("privileged recovery sealing requires administrator")}
    if !isNewLegacyRecoveryNode(path) {return errors.New("refusing to seal unrelated or already published path")}
    info,err:=os.Lstat(path);if err!=nil{return err}
    if info.Mode()&os.ModeSymlink!=0 || (!info.IsDir() && !info.Mode().IsRegular()) {
        return errors.New("recovery node is a link or special file")
    }
    script:=`$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';`+
        `$p=`+psQuote(path)+`;`+
        `$attr=[IO.File]::GetAttributes($p);`+
        `if(($attr -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Recovery node reparse point'};`+
        `$admins=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544');`+
        `$system=[Security.Principal.SecurityIdentifier]::new('S-1-5-18');`+
        `$full=[Security.AccessControl.FileSystemRights]::FullControl;`+
        `$allow=[Security.AccessControl.AccessControlType]::Allow;`
    if info.IsDir() {
        script+=`$acl=New-Object Security.AccessControl.DirectorySecurity;`+
            `$flags=[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit;`+
            `foreach($sid in @($system,$admins)){`+
            `$rule=[Security.AccessControl.FileSystemAccessRule]::new($sid,$full,$flags,`+
            `[Security.AccessControl.PropagationFlags]::None,$allow);$acl.AddAccessRule($rule)};`+
            `$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner($admins);`+
            `[IO.Directory]::SetAccessControl($p,$acl);`
    }else{
        script+=`$acl=New-Object Security.AccessControl.FileSecurity;`+
            `foreach($sid in @($system,$admins)){`+
            `$rule=[Security.AccessControl.FileSystemAccessRule]::new($sid,$full,$allow);$acl.AddAccessRule($rule)};`+
            `$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner($admins);`+
            `[IO.File]::SetAccessControl($p,$acl);`
    }
    script+=`Write-Output 'VOLVE_RECOVERY_NODE_SEALED'`
    out,err:=runPS(script)
    if err!=nil || !hasStandaloneRollbackToken(out,"VOLVE_RECOVERY_NODE_SEALED") {
        return fmt.Errorf("recovery owner/DACL could not be sealed: %v (%s)",err,out)
    }
    return nil
}

// Stronger Windows verifier matching the independent watchdog policy.
// It additionally checks owners, denies, inheritance and FullControl.
func checkSealedLegacyRecoveryACL(dir string) error {
    if !filepath.IsAbs(dir) {return errors.New("sealed recovery path must be absolute")}
    name:=filepath.Base(dir)
    if name!=localRecoveryFolder && name!=localRecoverySnapshot &&
       !strings.HasPrefix(name,".legacy-recovery-") {
        return errors.New("not an approved rollback directory")
    }
    if err:=checkLegacyRecoveryACL(dir);err!=nil{return err}
    entries,err:=os.ReadDir(dir);if err!=nil{return err}
    if len(entries)>8{return errors.New("too many items in sealed recovery directory")}
    paths:=[]string{dir}
    for _,e:=range entries{paths=append(paths,filepath.Join(dir,e.Name()))}
    quoted:=make([]string,0,len(paths))
    for _,p:=range paths {
        inf,e:=os.Lstat(p);if e!=nil{return e}
        if inf.Mode()&os.ModeSymlink!=0 || (!inf.IsDir() && !inf.Mode().IsRegular()) {
            return errors.New("sealed recovery has special file or link")
        }
        quoted=append(quoted,psQuote(p))
    }
    script:=`$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';`+
        `$allowed=@('S-1-5-18','S-1-5-32-544');`+
        `$paths=@(`+strings.Join(quoted,",")+`);`+
        `$full=[int][Security.AccessControl.FileSystemRights]::FullControl;`+
        `foreach($p in $paths){`+
        `$attr=[IO.File]::GetAttributes($p);`+
        `if(($attr -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Recovery path reparse point'};`+
        `if([IO.Directory]::Exists($p)){$acl=[IO.Directory]::GetAccessControl($p)}`+
        `else{$acl=[IO.File]::GetAccessControl($p)};`+
        `$owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value;`+
        `if($owner -notin $allowed){throw ('Untrusted owner: '+$owner)};`+
        `if(-not $acl.AreAccessRulesProtected){throw 'Inherited recovery DACL'};`+
        `$rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]));`+
        `foreach($r in $rules){`+
        `if($r.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or `+
        `$r.IdentityReference.Value -notin $allowed){throw 'Untrusted recovery DACL entry'}`+
        `};`+
        `foreach($sid in $allowed){`+
        `$found=$false;foreach($r in $rules){`+
        `if($r.IdentityReference.Value -eq $sid -and `+
        `(([int]$r.FileSystemRights -band $full) -eq $full)){$found=$true}`+
        `};if(-not $found){throw ('Recovery FullControl missing: '+$sid)}`+
        `}`+
        `};Write-Output 'VOLVE_SEALED_RECOVERY_ACL_OK'`
    out,e:=runPS(script)
    if e!=nil{return fmt.Errorf("sealed recovery ACL rejected: %w",e)}
    if !hasStandaloneRollbackToken(out,"VOLVE_SEALED_RECOVERY_ACL_OK"){
        return fmt.Errorf("sealed recovery ACL ambiguous: %q",out)
    }
    return nil
}
