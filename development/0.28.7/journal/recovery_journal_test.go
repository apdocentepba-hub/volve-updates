package motorupdate
import("os";"path/filepath";"strings";"testing";"time")
func journalFixture(t *testing.T) RecoveryJournal{
 t.Helper()
 j,e:=NewRecoveryJournal("0.29.0",[]byte("MZ_old"),[]byte("MZ_new"),[]byte("<Task/>"),time.Date(2026,10,29,20,0,0,0,time.UTC))
 if e!=nil{t.Fatal(e)}
 return j
}
func TestJournalSurvivesRestartAndRequiresRollback(t *testing.T){
 path:=filepath.Join(t.TempDir(),"recovery.json")
 j:=journalFixture(t)
 if e:=WriteRecoveryJournalDurable(path,j);e!=nil{t.Fatal(e)}
 got,e:=ReadRecoveryJournal(path)
 if e!=nil||got!=j||got.NeedsRollback(){t.Fatalf("prepared snapshot: %+v %v",got,e)}
 j,_=j.Next(PhaseSwitching);if e=WriteRecoveryJournalDurable(path,j);e!=nil{t.Fatal(e)}
 got,e=ReadRecoveryJournal(path)
 if e!=nil||!got.NeedsRollback(){t.Fatalf("interrupted switchover must rollback: %+v %v",got,e)}
 j,_=got.Next(PhaseRestoring);if e=WriteRecoveryJournalDurable(path,j);e!=nil{t.Fatal(e)}
 got,e=ReadRecoveryJournal(path)
 if e!=nil||!got.NeedsRollback(){t.Fatal("restart during rollback must retry")}
 j,_=got.Next(PhaseRestored);if e=WriteRecoveryJournalDurable(path,j);e!=nil{t.Fatal(e)}
 got,e=ReadRecoveryJournal(path);if e!=nil||got.NeedsRollback(){t.Fatal("restored state should be terminal")}
}
func TestJournalCommitOnlyAfterProving(t *testing.T){
 j:=journalFixture(t)
 if _,e:=j.Next(PhaseCommitted);e==nil{t.Fatal("commit before switch")}
 j,_=j.Next(PhaseSwitching)
 if _,e:=j.Next(PhaseCommitted);e==nil{t.Fatal("commit before probe")}
 j,_=j.Next(PhaseProving)
 j,e:=j.Next(PhaseCommitted)
 if e!=nil||j.NeedsRollback(){t.Fatalf("commit failed %v",e)}
 if _,e=j.Next(PhaseSwitching);e==nil{t.Fatal("replayed completed transaction")}
}
func TestJournalRejectsTamperedAndUnsafeData(t *testing.T){
 root:=t.TempDir();file:=filepath.Join(root,"recovery.json");j:=journalFixture(t)
 if e:=WriteRecoveryJournalDurable(file,j);e!=nil{t.Fatal(e)}
 altered:=j;altered.PreviousEngineSHA=strings.Repeat("0",64)
 if e:=WriteRecoveryJournalDurable(file,altered);e==nil{t.Fatal("accepted changed previous engine hash")}
 raw,_:=os.ReadFile(file);if e:=os.WriteFile(file,append(raw,[]byte("{}")...),0600);e!=nil{t.Fatal(e)}
 if _,e:=ReadRecoveryJournal(file);e==nil{t.Fatal("accepted extra object")}
 if e:=os.Remove(file);e!=nil{t.Fatal(e)}
 if e:=os.Symlink(filepath.Join(root,"outside.json"),file);e==nil{
  if _,e:=ReadRecoveryJournal(file);e==nil{t.Fatal("accepted symlink journal")}
  if e:=WriteRecoveryJournalDurable(file,j);e==nil{t.Fatal("accepted symlink journal overwrite")}
 }
}
func TestJournalDoesNotCarryExecutableOrTaskCommand(t *testing.T){
 j:=journalFixture(t);file:=filepath.Join(t.TempDir(),"recovery.json")
 if e:=WriteRecoveryJournalDurable(file,j);e!=nil{t.Fatal(e)}
 raw,_:=os.ReadFile(file)
 for _,bad:=range []string{"task_command","powershell","C:\\","/bin/sh"}{
  if strings.Contains(string(raw),bad){t.Fatalf("unexpected task path or command %s",bad)}
 }
}
