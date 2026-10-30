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
 for _,p:=range []string{dir,journalPath,snapshotPath}{
  grant:=[]string{"*S-1-5-18:F","*S-1-5-32-544:F"}
  if p==dir {grant=[]string{"*S-1-5-18:(OI)(CI)F","*S-1-5-32-544:(OI)(CI)F"}}
  args:=append([]string{p,"/inheritance:r","/grant:r"},grant...)
  out,err:=exec.Command("icacls.exe",args...).CombinedOutput()
  if err!=nil {t.Fatalf("failed to set disposable ACL: %v %s",err,string(out))}
  // Windows ownership is independent of the DACL: the file owner has the
  // ability to rewrite its permissions. Use Administrators as owner.
  script:=`$ErrorActionPreference='Stop';`+
   `$p=`+q(p)+`;$acl=Get-Acl -LiteralPath $p;`+
   `$acl.SetOwner([Security.Principal.SecurityIdentifier]'S-1-5-32-544');`+
   `Set-Acl -LiteralPath $p -AclObject $acl -ErrorAction Stop;`+
   `Write-Output 'OK'`
  outText,err:=ps(context.Background(),script)
  if err!=nil || outText!="OK" {t.Fatalf("failed setting disposable ACL owner: %v %q",err,outText)}
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
