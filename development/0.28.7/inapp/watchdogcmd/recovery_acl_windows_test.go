//go:build windows

package main

import (
 "context"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "testing"
)

func hardenedTestACL(t *testing.T, journalPath, snapshotPath string) {
 t.Helper()
 dir:=filepath.Dir(journalPath)
 for _,p:=range []string{dir,journalPath,snapshotPath} {
  // Start with an empty *protected* DACL rather than layering two allow
  // entries over the runner's existing explicit user ACE. The latter could
  // still let that user falsify a committed transaction.
  script:=`$ErrorActionPreference='Stop';`+
    `$p=`+q(p)+`;$system=[Security.Principal.SecurityIdentifier]'S-1-5-18';`+
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
  output,err:=ps(context.Background(),script)
  if err!=nil || output!="OK" {t.Fatalf("failed to set protected test ACL: %v %q",err,output)}
 }
}
func TestRecoveryACLRejectsOrdinaryTempDirectory(t *testing.T){
 jpath,j:=fixtureJournal(t,"pending")
 err:=verifyRecoveryACL(context.Background(),jpath,j.SnapshotFile)
 if err==nil {t.Fatal("inherited and user-owned recovery transaction trusted")}
}
func TestRecoveryACLSecuredSYSTEMAdministratorsOnly(t *testing.T){
 jpath,j:=fixtureJournal(t,"pending")
 hardenedTestACL(t,jpath,j.SnapshotFile)
 if err:=verifyRecoveryACL(context.Background(),jpath,j.SnapshotFile);err!=nil{
  t.Fatalf("SYSTEM/Admin-only recovery transaction rejected: %v",err)
 }
}
func TestRecoveryACLRejectsUnauthorizedWriteGrant(t *testing.T){
 jpath,j:=fixtureJournal(t,"pending")
 hardenedTestACL(t,jpath,j.SnapshotFile)
 out,err:=exec.Command("icacls.exe",jpath,"/grant","*S-1-1-0:W").CombinedOutput()
 if err!=nil{t.Fatalf("unable to simulate unsafe ACL: %v %s",err,string(out))}
 err=verifyRecoveryACL(context.Background(),jpath,j.SnapshotFile)
 if err==nil || !strings.Contains(err.Error(),"ACL"){
  t.Fatalf("world-writable recovery journal accepted: %v",err)
 }
}
func TestRecoveryACLRejectsUnknownOrLinkedSnapshot(t *testing.T){
 jpath,j:=fixtureJournal(t,"pending")
 hardenedTestACL(t,jpath,j.SnapshotFile)
 other:=filepath.Join(t.TempDir(),"outside.xml")
 if err:=os.WriteFile(other,[]byte("faux"),0600);err!=nil{t.Fatal(err)}
 if err:=verifyRecoveryACL(context.Background(),jpath,other);err==nil{
  t.Fatal("snapshot outside recovery transaction trusted")
 }
}
