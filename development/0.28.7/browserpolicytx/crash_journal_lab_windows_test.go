//go:build windows

package browserpolicytx

// This test spawns the real Windows Go test EXE as a separate process.
// The child writes 317 Registry values after a synced on-disk intent, then
// deliberately exits with code 73 WITHOUT rollback. Parent replays on disk.
import (
    "context"
    "errors"
    "os"
    "os/exec"
    "path/filepath"
    "testing"
)
func hostedLab(t *testing.T){
    t.Helper()
    if os.Getenv("GITHUB_ACTIONS")!="true"||
       os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{
        t.Skip("hosted disposable Windows CI required")
    }
}
func TestLabCrashChild(t *testing.T){
    if os.Getenv("VOLVE_CI_CRASH_CHILD")!="yes" {return}
    if _,err:=labRootFromEnvironment();err!=nil{t.Fatal(err)}
    // The journal must be independently re-read in the child before writes.
    store:=&WindowsRegistryLab{root:`SOFTWARE\VOLVE-CI-BrowserPolicies-`+
        os.Getenv("GITHUB_RUN_ID")+"-"+os.Getenv("GITHUB_RUN_ATTEMPT")}
    path:=os.Getenv("VOLVE_CI_CRASH_JOURNAL")
    intent,err:=readLabIntent(path,store)
    if err!=nil{t.Fatal(err)}
    for i:=0;i<317;i++{
        if err:=store.CreateOnly(context.Background(),intent.Policy.RegistryValues[i]);err!=nil{t.Fatal(err)}
    }
    os.Exit(73)
}
func TestRealWindowsCrossProcessAbruptCrashRecovery317Of772(t *testing.T){
    hostedLab(t)
    store,err:=NewWindowsRegistryLab()
    if err!=nil{t.Fatal(err)}
    t.Cleanup(func(){if err:=store.Cleanup();err!=nil{t.Errorf("lab hive cleanup: %v",err)}})
    journal:=filepath.Join(t.TempDir(),"pending.json")
    plan:=fixturePlan()
    if err:=createLabIntentDurable(journal,store,plan);err!=nil{t.Fatal(err)}
    cmd:=exec.Command(os.Args[0],"-test.run=^TestLabCrashChild$")
    cmd.Env=append(os.Environ(),"VOLVE_CI_CRASH_CHILD=yes","VOLVE_CI_CRASH_JOURNAL="+journal)
    err=cmd.Run()
    var exit *exec.ExitError
    if !errors.As(err,&exit)||exit.ExitCode()!=73{
        t.Fatalf("child did not demonstrably die without rollback: %v",err)
    }
    for i:=0;i<317;i++{
        present,err:=store.Exists(context.Background(),plan.RegistryValues[i])
        if err!=nil||!present{t.Fatalf("crashed child lost value %d: %v",i,err)}
    }
    result,err:=ReplayLabIntent(context.Background(),journal,store)
    if err!=nil{t.Fatal(err)}
    if result.Checked!=772||result.Reverted!=317||result.Status!="LAB_RECOVERED_NO_INSTALL"||
        result.InstallAuthorized{
        t.Fatalf("cross-process Windows crash recovery failed: %+v",result)
    }
    again,err:=ReplayLabIntent(context.Background(),journal,store)
    if err!=nil||again.Reverted!=0||again.Status!="LAB_RECOVERED_NO_INSTALL"{
        t.Fatalf("replaying recovered intent was not idempotent: %+v, %v",again,err)
    }
    t.Log("PASS VOLVE_CI_CROSS_PROCESS_CRASH_EXIT73_RECOVER_317_OF_772_NATIVE_WINDOWS_HKCU NO_INSTALL")
}
func TestRealWindowsRecoveryRejectsTamperedJournalAndForeignValue(t *testing.T){
    hostedLab(t)
    store,err:=NewWindowsRegistryLab();if err!=nil{t.Fatal(err)}
    t.Cleanup(func(){if err:=store.Cleanup();err!=nil{t.Errorf("lab hive cleanup: %v",err)}})
    journal:=filepath.Join(t.TempDir(),"pending.json")
    p:=fixturePlan()
    if err:=createLabIntentDurable(journal,store,p);err!=nil{t.Fatal(err)}
    if err:=store.CreateOnly(context.Background(),p.RegistryValues[0]);err!=nil{t.Fatal(err)}
    data,err:=os.ReadFile(journal);if err!=nil{t.Fatal(err)}
    corrupted:=filepath.Join(t.TempDir(),"corrupt.json")
    if err:=os.WriteFile(corrupted,append(data,[]byte("unexpected")...),0600);err!=nil{t.Fatal(err)}
    if _,err:=ReplayLabIntent(context.Background(),corrupted,store);err==nil{
        t.Fatal("tampered journal unexpectedly accepted")
    }
    found,err:=store.Exists(context.Background(),p.RegistryValues[0]);if err!=nil||!found{
        t.Fatal("journal tampering affected registry")
    }
    foreign:=p.RegistryValues[0]
    foreign.Value="different.example"
    if err:=store.DeleteOnlyIfEqual(context.Background(),p.RegistryValues[0]);err!=nil{t.Fatal(err)}
    if err:=store.CreateOnly(context.Background(),foreign);err!=nil{t.Fatal(err)}
    if _,err:=ReplayLabIntent(context.Background(),journal,store);err==nil{
        t.Fatal("recovery deleted or accepted changed foreign value")
    }
    found,err=store.Exists(context.Background(),foreign);if err!=nil||!found{
        t.Fatal("foreign policy value was deleted")
    }
    if err:=store.DeleteOnlyIfEqual(context.Background(),foreign);err!=nil{t.Fatal(err)}
}
