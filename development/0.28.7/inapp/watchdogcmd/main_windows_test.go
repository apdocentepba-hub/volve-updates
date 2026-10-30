//go:build windows

package main

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func fixtureJournal(t *testing.T,phase string)(string,journal){
 t.Helper()
 root:=t.TempDir()
 snapshot:=filepath.Join(root,"task.xml")
 data:=[]byte("<Task>trusted pilot snapshot fixture</Task>")
 if err:=os.WriteFile(snapshot,data,0600);err!=nil{t.Fatal(err)}
 digest:=sha256.Sum256(data)
 j:=journal{
 Schema:1,Phase:phase,TaskName:"VOLVE-CI-ManagedMotor-1793321319528439500",
 OriginalExe:filepath.Join(os.Getenv("WINDIR"),"System32","cmd.exe"),
 OriginalArgs:"/C exit 0",SnapshotFile:snapshot,SnapshotSHA256:hex.EncodeToString(digest[:]),
 }
 path:=filepath.Join(root,"journal.json")
 raw,err:=json.Marshal(j);if err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(path,raw,0600);err!=nil{t.Fatal(err)}
 return path,j
}
func TestReadJournalStrictSchemaAndTaskAllowlist(t *testing.T){
 path,original:=fixtureJournal(t,"pending")
 if got,err:=readJournal(path);err!=nil || got.TaskName!=original.TaskName{t.Fatalf("valid journal rejected: %#v %v",got,err)}
 for _,phase:=range []string{"", "switching", "rollback", "COMPLETE"} {
  if err:=safeConfig(journal{Schema:1,Phase:phase,TaskName:original.TaskName,OriginalExe:original.OriginalExe,OriginalArgs:original.OriginalArgs,SnapshotFile:original.SnapshotFile,SnapshotSHA256:original.SnapshotSHA256});err==nil{t.Fatalf("invalid phase %q accepted",phase)}
 }
 changed:=original
 changed.TaskName="VOLVE-DNS-SERVER-0270"
 if err:=safeConfig(changed);err==nil{t.Fatal("production task allowed")}
 changed=original
 changed.OriginalExe="C:\\Windows\\System32\\powershell.exe"
 if err:=safeConfig(changed);err==nil{t.Fatal("arbitrary restoration executable allowed")}
}
func TestReadJournalRejectsUnknownFieldsAndTrailingData(t *testing.T){
 path,_:=fixtureJournal(t,"pending")
 raw,err:=os.ReadFile(path);if err!=nil{t.Fatal(err)}
 for _,payload:=range [][]byte{
  append(append([]byte{},raw...),[]byte(" {}")...),
  []byte(strings.Replace(string(raw),"\"schema\":1","\"schema\":1,\"hack\":true",1)),
 }{
  if err:=os.WriteFile(path,payload,0600);err!=nil{t.Fatal(err)}
  if _,err:=readJournal(path);err==nil{t.Fatal("malformed journal accepted")}
 }
}
func secureFixtureJournal(t *testing.T,phase string)(string,journal){
 t.Helper()
 path,j:=fixtureJournal(t,phase)
 hardenedTestACL(t,path,j.SnapshotFile)
 return path,j
}
func TestWatchdogRequiresTrustedACLBeforeAnyPhase(t *testing.T){
 for _,phase:=range []string{"pending","committed","restored"}{
  path,_:=fixtureJournal(t,phase)
  if err:=run(context.Background(),path);err==nil {
   t.Fatalf("insecure transaction accepted in phase %s",phase)
  }
 }
}
func TestCommittedJournalNeverRestoresOrTouchesTask(t *testing.T){
 path,_:=secureFixtureJournal(t,"committed")
 if err:=run(context.Background(),path);err!=nil{t.Fatalf("committed journal: %v",err)}
 path,_=secureFixtureJournal(t,"restored")
 if err:=run(context.Background(),path);err!=nil{t.Fatalf("already restored journal: %v",err)}
}
func TestIndependentRecoveryRejectsWrongSnapshotHash(t *testing.T){
 path,j:=secureFixtureJournal(t,"pending")
 if err:=os.WriteFile(j.SnapshotFile,[]byte("tampered"),0600);err!=nil{t.Fatal(err)}
 err:=run(context.Background(),path)
 if err==nil || !strings.Contains(err.Error(),"SHA256") {
  t.Fatalf("tampered snapshot accepted: %v",err)
 }
 after,err:=readJournal(path)
 if err!=nil||after.Phase!="pending"{t.Fatalf("journal wrongly committed after failed restore: %v %#v",err,after)}
}
func TestSymlinkedJournalRejected(t *testing.T){
 path,_:=fixtureJournal(t,"pending")
 symlink:=filepath.Join(filepath.Dir(path),"alias.json")
 if err:=os.Symlink(path,symlink);err!=nil{t.Skipf("Windows symlink requires developer privileges: %v",err)}
 if _,err:=readJournal(symlink);err==nil{t.Fatal("symlink journal accepted")}
}

func TestIndependentWatchdogRejectsExternalSnapshotPath(t *testing.T){
    journalPath,j:=fixtureJournal(t,"pending")
    outside:=t.TempDir()
    other:=filepath.Join(outside,"external-task.xml")
    if err:=os.WriteFile(other,[]byte("<Task>external</Task>"),0600);err!=nil{t.Fatal(err)}
    j.SnapshotFile=other
    raw,err:=json.Marshal(j);if err!=nil{t.Fatal(err)}
    if err:=os.WriteFile(journalPath,raw,0600);err!=nil{t.Fatal(err)}
    if _,err:=readJournal(journalPath);err==nil{t.Fatal("external recovery snapshot accepted")}
}
func TestIndependentWatchdogRejectsLinkedSnapshotParent(t *testing.T){
    journalPath,j:=fixtureJournal(t,"pending")
    elsewhere:=t.TempDir()
    outsideFile:=filepath.Join(elsewhere,"linked-task.xml")
    if err:=os.WriteFile(outsideFile,[]byte("<Task>test</Task>"),0600);err!=nil{t.Fatal(err)}
    linkDir:=filepath.Join(filepath.Dir(journalPath),"linked-parent")
    if err:=os.Symlink(elsewhere,linkDir);err!=nil{t.Skipf("Windows symlink permission unavailable: %v",err)}
    j.SnapshotFile=filepath.Join(linkDir,"linked-task.xml")
    raw,err:=json.Marshal(j);if err!=nil{t.Fatal(err)}
    if err:=os.WriteFile(journalPath,raw,0600);err!=nil{t.Fatal(err)}
    if _,err:=readJournal(journalPath);err==nil{t.Fatal("symlinked snapshot parent accepted")}
}
