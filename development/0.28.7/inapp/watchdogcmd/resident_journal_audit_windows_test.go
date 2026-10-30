//go:build windows

package main

// All fixtures are disposable under t.TempDir(). No real DNS task, adapter,
// system ProgramData or installed VOLVE binary is modified.
import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "testing"

 "volve-browser-protection/motorupdate"
)

func journalAuditFixture(t *testing.T)(string,func(string)error,func(string)error){
 t.Helper()
 root:=t.TempDir()
 parent:=filepath.Join(root,residentRecoveryParent)
 dir:=filepath.Join(parent,residentJournalDirName)
 if err:=os.MkdirAll(dir,0700);err!=nil{t.Fatal(err)}
 guard:=filepath.Join(parent,"CI-only-ACL-guard")
 if err:=os.WriteFile(guard,[]byte("test"),0600);err!=nil{t.Fatal(err)}
 hardenedTestACL(t,guard,dir)
 if err:=os.Remove(guard);err!=nil{t.Fatal(err)}
 seal:=func(path string)error{
  // Test-only helper operates on the freshly-created disposable path.
  hardenedTestACL(t,path,path)
  return nil
 }
 protect:=func(path string)error{return checkResidentJournalNTFS(context.Background(),path)}
 return dir,seal,protect
}
func journalAuditIdentity()motorupdate.ResidentRecoveryIntent{
 digest:=func(x string)string{sum:=sha256.Sum256([]byte(x));return hex.EncodeToString(sum[:])}
 return motorupdate.ResidentRecoveryIntent{
  Schema:1,Component:"dns-engine-recovery-intent",Task:"VOLVE-DNS-SERVER-0270",
  LegacySHA256:digest("original bytes"),TaskXMLSHA256:digest("SYSTEM XML"),
  TargetSHA256:digest("signed candidate"),TargetVersion:"0.28.7",
 }
}
func TestWindowsResidentJournalAuditIsReadOnlyAndConservative(t *testing.T){
 // Elevated Windows CI is required by hardenedTestACL; no application helper dependency.
 dir,seal,protect:=journalAuditFixture(t)
 original,err:=motorupdate.ArmResidentRecoveryIntent(context.Background(),dir,
  journalAuditIdentity(),seal,protect)
 if err!=nil{t.Fatal(err)}
 state,err:=auditResidentJournal(context.Background(),dir)
 if err!=nil||state.Status!="recovery-required"||state.Intent!=original{
  t.Fatalf("standalone watchdog audit lost interrupted state: %+v %v",state,err)
 }
 if err:=motorupdate.FinishResidentRecoveryIntent(context.Background(),dir,"committed",seal,protect);err!=nil{
  t.Fatal(err)
 }
 state,err=auditResidentJournal(context.Background(),dir)
 if err!=nil||state.Status!="committed"{t.Fatalf("verified terminal receipt lost: %+v %v",state,err)}
 // Hash-valid JSON alone is not enough if an ordinary user gets NTFS WRITE.
 terminal:=filepath.Join(dir,motorupdate.ResidentResultFile)
 out,err:=exec.Command("icacls.exe",terminal,"/grant","*S-1-1-0:W").CombinedOutput()
 if err!=nil{t.Fatalf("cannot weaken disposable result ACL: %v %s",err,out)}
 if _,err:=auditResidentJournal(context.Background(),dir);err==nil{
  t.Fatal("unsafe terminal ACL was accepted as committed")
 }
}

func TestWindowsResidentJournalAuditRejectsUnprotectedPathsAndTornWrites(t *testing.T){
 // Elevated Windows CI is required by hardenedTestACL; no application helper dependency.
 root:=t.TempDir()
 if _,err:=auditResidentJournal(context.Background(),root);err==nil{
  t.Fatal("unrecognized journal path accepted")
 }
 dir,seal,protect:=journalAuditFixture(t)
 if _,err:=auditResidentJournal(context.Background(),dir);err!=nil{
  t.Fatalf("secure but empty journal unexpectedly unsafe: %v",err)
 }
 if _,err:=motorupdate.ArmResidentRecoveryIntent(context.Background(),dir,
  journalAuditIdentity(),seal,protect);err!=nil{t.Fatal(err)}
 resultPath:=filepath.Join(dir,motorupdate.ResidentResultFile)
 if err:=os.WriteFile(resultPath,[]byte("{"),0600);err!=nil{t.Fatal(err)}
 if err:=seal(resultPath);err!=nil{t.Fatal(err)}
 if state,err:=auditResidentJournal(context.Background(),dir);err==nil{
  t.Fatalf("torn terminal journal treated as a valid result: %+v",state)
 }
 if err:=motorupdate.FinishResidentRecoveryIntent(context.Background(),dir,"committed",seal,protect);err==nil{
  t.Fatal("cannot overwrite torn receipt even with privileges")
 }
 if _,err:=os.Stat(filepath.Join(dir,motorupdate.ResidentIntentFile));err!=nil{
  t.Fatalf("pending recovery intent was destroyed: %v",err)
 }
}

func TestWindowsResidentJournalPathRestricted(t *testing.T){
 root:=filepath.Join(os.Getenv("WINDIR"),"VOLVE-CI")
 permitted:=filepath.Join(root,residentRecoveryParent,residentJournalDirName)
 for _,p:=range []string{
  root,filepath.Join(root,"other",residentJournalDirName),
  filepath.Join(root,residentRecoveryParent,"another"),
  "relative/"+residentJournalDirName,
 }{
  if residentJournalPathAllowed(p){t.Fatalf("arbitrary journal path accepted: %s",p)}
 }
 if !residentJournalPathAllowed(permitted) || !strings.HasSuffix(permitted,residentJournalDirName){
  t.Fatal("correctly scoped journal path refused")
 }
}
