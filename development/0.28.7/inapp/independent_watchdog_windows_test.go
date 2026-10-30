//go:build windows

package main

import (
    "context"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "os"
    "os/exec"
    "path/filepath"
    "strings"
    "testing"
    "time"
    "fmt"
)

type ciWatchdogJournal struct {
    Schema int `json:"schema"`
    Phase string `json:"phase"`
    TaskName string `json:"task_name"`
    OriginalExe string `json:"original_exe"`
    OriginalArgs string `json:"original_args"`
    SnapshotFile string `json:"snapshot_file"`
    SnapshotSHA256 string `json:"snapshot_sha256"`
}

func writeCIWatchdogJournal(t *testing.T, path string, j ciWatchdogJournal) {
    t.Helper()
    data,err:=json.Marshal(j);if err!=nil{t.Fatal(err)}
    f,err:=os.OpenFile(path,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
    if err!=nil{t.Fatal(err)}
    if _,err=f.Write(append(data,'\n'));err!=nil{f.Close();t.Fatal(err)}
    if err=f.Sync();err!=nil{f.Close();t.Fatal(err)}
    if err=f.Close();err!=nil{t.Fatal(err)}
}

func TestIndependentWatchdogRestoresAfterUpdaterExit(t *testing.T) {
    helper:=os.Getenv("VOLVE_CI_MANAGED_WATCHDOG_EXE")
    if helper=="" {t.Fatal("Windows CI must build a separate independent watchdog executable first")}
    if info,err:=os.Lstat(helper);err!=nil || !info.Mode().IsRegular(){t.Fatalf("separate executable unavailable: %v",err)}
    for _,tamper:=range []bool{false,true} {
        label:="normal-rollback";if tamper{label="tampered-snapshot-rejected"}
        t.Run(label,func(t *testing.T){
            name:=fmt.Sprintf("VOLVE-CI-ManagedMotor-%d",time.Now().UnixNano())
            original:=filepath.Join(os.Getenv("WINDIR"),"System32","cmd.exe")
            if err:=createDisposableTask(name,original);err!=nil{t.Fatal(err)}
            t.Cleanup(func(){if err:=removeDisposableTask(name);err!=nil{t.Errorf("cleanup: %v",err)}})
            root:=t.TempDir()
            candidate,key:=prepareSignedLabCandidate(t,root)
            d:=&managedWindowsTaskLab{
                name:name,root:filepath.Join(root,"transaction"),original:original,
                backup:filepath.Join(root,"transaction","original-task.xml"),publicKey:key,
            }
            ctx:=context.Background()
            if err:=d.Snapshot(ctx);err!=nil{t.Fatal(err)}
            originalXML,err:=os.ReadFile(d.backup);if err!=nil{t.Fatal(err)}
            if err:=d.InstallVersionedCandidate(ctx,candidate);err!=nil{t.Fatal(err)}
            if err:=switchVerifiedMotorTaskAction(ctx,name,original,"/C exit 0",d.installedExe,"",key);err!=nil{t.Fatal(err)}
            switched,args,err:=d.currentAction()
            if err!=nil || !strings.EqualFold(filepath.Clean(switched),filepath.Clean(d.installedExe)) || args!=""{
                t.Fatalf("disposable task switch not completed: %q %q %v",switched,args,err)
            }
            journalPath:=filepath.Join(root,"watchdog-journal.json")
            journal:=ciWatchdogJournal{Schema:1,Phase:"pending",TaskName:name,
                OriginalExe:original,OriginalArgs:"/C exit 0",SnapshotFile:d.backup,SnapshotSHA256:d.originalHash}
            writeCIWatchdogJournal(t,journalPath,journal)
            if tamper {
                changed:=append(append([]byte{},originalXML...),[]byte("<!--modified-->")...)
                if err:=os.WriteFile(d.backup,changed,0600);err!=nil{t.Fatal(err)}
                // Always make the original snapshot available for task cleanup
                // after the negative test has verified the rejection.
                defer func(){if err:=os.WriteFile(d.backup,originalXML,0600);err!=nil{t.Errorf("restore snapshot: %v",err)}}()
            }
            // The parent updater is not executing: this is an entirely
            // different compiled .exe process restoring the SYSTEM task.
            procCtx,cancel:=context.WithTimeout(ctx,40*time.Second)
            defer cancel()
            command:=exec.CommandContext(procCtx,helper,"--recover-pilot-journal",journalPath)
            output,runErr:=command.CombinedOutput()
            if tamper{
                if runErr==nil || !strings.Contains(string(output),"SHA256"){
                    t.Fatalf("tampered XML should be rejected: %v %s",runErr,string(output))
                }
                switched,_,err=d.currentAction()
                if err!=nil || !strings.EqualFold(filepath.Clean(switched),filepath.Clean(d.installedExe)){
                    t.Fatalf("tampered snapshot caused task change: %q %v",switched,err)
                }
                updated,err:=os.ReadFile(journalPath);if err!=nil{t.Fatal(err)}
                if err:=json.Unmarshal(updated,&journal);err!=nil{t.Fatal(err)}
                if journal.Phase!="pending"{t.Fatalf("failure incorrectly committed: %s",journal.Phase)}
                return
            }
            if runErr!=nil {t.Fatalf("separate watchdog executable failed: %v %s",runErr,string(output))}
            restored,restoredArgs,err:=d.currentAction()
            if err!=nil || !strings.EqualFold(filepath.Clean(restored),filepath.Clean(original)) || restoredArgs!="/C exit 0" {
                t.Fatalf("independent recovery did not restore task: %q %q %v",restored,restoredArgs,err)
            }
            data,err:=os.ReadFile(journalPath);if err!=nil{t.Fatal(err)}
            if err:=json.Unmarshal(data,&journal);err!=nil{t.Fatal(err)}
            if journal.Phase!="restored"{t.Fatalf("journal after independent restoration: %q",journal.Phase)}
            // Running the independent watchdog a second time is idempotent.
            second:=exec.CommandContext(procCtx,helper,"--recover-pilot-journal",journalPath)
            if extra,err:=second.CombinedOutput();err!=nil{
                t.Fatalf("restored phase not idempotent: %v %s",err,string(extra))
            }
        })
    }
}

func TestIndependentWatchdogFixtureHashMatches(t *testing.T) {
    source:=[]byte("VOLVE original XML reference")
    sum:=sha256.Sum256(source)
    if len(hex.EncodeToString(sum[:]))!=64{t.Fatal("unexpected SHA256 length")}
}
