//go:build windows

package main

import (
 "fmt"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

// secureCIPilotRecovery gives only SYSTEM/Administrators full access to a
// DISPOSABLE lab transaction. It never changes anything under production
// ProgramData or an existing VOLVE-DNS task.
func secureCIPilotRecovery(t *testing.T, journalPath, snapshotPath string) {
 t.Helper()
 if !filepath.IsAbs(journalPath) || !filepath.IsAbs(snapshotPath) {t.Fatal("lab paths not absolute")}
 root:=filepath.Clean(filepath.Dir(journalPath))
 relative,err:=filepath.Rel(root,filepath.Clean(snapshotPath))
 if err!=nil || relative==".." || strings.HasPrefix(relative,".."+string(os.PathSeparator)) {t.Fatal("snapshot escapes lab transaction")}
 paths:=[]string{root}
 cursor:=root
 segments:=strings.Split(relative,string(os.PathSeparator))
 for i,component:=range segments {
  if component=="" || component=="." || component==".." {t.Fatal("invalid lab snapshot component")}
  cursor=filepath.Join(cursor,component)
  if i<len(segments)-1 {paths=append(paths,cursor)}
 }
 paths=append(paths,journalPath,snapshotPath)
 for _,p:=range paths {
  info,err:=os.Lstat(p)
  if err!=nil {t.Fatal(err)}
  if info.Mode()&os.ModeSymlink!=0 {t.Fatalf("cannot harden linked lab path %q",p)}
  // Construct a completely new protected ACL, never preserve an explicit
  // runner-user ACE that might be inherited from a temporary directory.
  script:=`$ErrorActionPreference='Stop';$p=`+labQuote(p)+`;`+
    `$system=[Security.Principal.SecurityIdentifier]'S-1-5-18';`+
    `$admins=[Security.Principal.SecurityIdentifier]'S-1-5-32-544';`+
    `if([IO.Directory]::Exists($p)){`+
      `$acl=New-Object Security.AccessControl.DirectorySecurity;`+
      `foreach($sid in @($system,$admins)){`+
       `$rule=[Security.AccessControl.FileSystemAccessRule]::new($sid,[Security.AccessControl.FileSystemRights]::FullControl,`+
        `[Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',`+
        `[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow);`+
       `$acl.AddAccessRule($rule)};`+
      `$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner($admins);`+
      `[IO.Directory]::SetAccessControl($p,$acl)`+
    `}else{`+
      `$acl=New-Object Security.AccessControl.FileSecurity;`+
      `foreach($sid in @($system,$admins)){`+
       `$rule=[Security.AccessControl.FileSystemAccessRule]::new($sid,[Security.AccessControl.FileSystemRights]::FullControl,`+
        `[Security.AccessControl.AccessControlType]::Allow);`+
       `$acl.AddAccessRule($rule)};`+
      `$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner($admins);`+
      `[IO.File]::SetAccessControl($p,$acl)`+
    `};Write-Output 'OK'`
  out,err:=labPS(script)
  if err!=nil || strings.TrimSpace(out)!="OK" {
   t.Fatalf("cannot harden disposable recovery path %q: %v %q",p,err,out)
  }
 }
 if len(paths)<3 {t.Fatal(fmt.Errorf("unanticipated test recovery structure"))}
}
