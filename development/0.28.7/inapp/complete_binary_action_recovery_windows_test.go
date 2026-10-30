//go:build windows

package main

// VOLVE 0.28.7 CI ONLY: verifies a freshly compiled REAL VOLVE application
// executable can be signed as the isolated candidate, staged and selected in
// a disposable SYSTEM task, then restored by a separate SYSTEM watchdog.
// The test NEVER RUNS the candidate, does not use port 53, does not change
// DNS, and does not touch VOLVE-DNS-SERVER-0270 or a user's installation.
import (
    "context"
    "crypto/ed25519"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "strings"
    "testing"
    "time"

    "volve-browser-protection/motorupdate"
)

func signedCompleteApplicationCandidate(t *testing.T,root,compiledExe string) (string,ed25519.PublicKey,string) {
    t.Helper()
    if !filepath.IsAbs(compiledExe) {t.Fatal("compiled real Windows binary path is not absolute")}
    info,err:=os.Lstat(compiledExe)
    if err!=nil || !info.Mode().IsRegular() || info.Size()<=1024*1024 || info.Size()>80<<20 {
        t.Fatalf("real built VOLVE executable is missing or unexpected size: %v",err)
    }
    src,err:=os.Open(compiledExe);if err!=nil{t.Fatal(err)}
    defer src.Close()
    candidate:=filepath.Join(root,"VOLVE_DNS_Motor_0_28_7.exe")
    out,err:=os.OpenFile(candidate,os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600)
    if err!=nil{t.Fatal(err)}
    hash:=sha256.New()
    n,copyErr:=io.Copy(io.MultiWriter(out,hash),src)
    if copyErr==nil{copyErr=out.Sync()}
    closeErr:=out.Close()
    if copyErr!=nil{t.Fatal(copyErr)}
    if closeErr!=nil{t.Fatal(closeErr)}
    if n!=info.Size(){t.Fatal("incomplete real motor image fixture copy")}
    sha:=hex.EncodeToString(hash.Sum(nil))
    m:=motorupdate.Manifest{
        Schema:1,Component:"dns-engine",Version:"0.28.7",MinPanelVersion:"0.28.7",
        URL:"https://github.com/apdocentepba-hub/volve-updates/releases/download/v0.28.7/VOLVE_DNS_Motor_0_28_7.exe",
        SHA256:sha,Size:n,
        Notes:"CI proof only; complete VOLVE build; binary is never started as DNS",
    }
    manifest,err:=json.Marshal(m);if err!=nil{t.Fatal(err)}
    public,private,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
    if err:=os.WriteFile(candidate+".json",manifest,0600);err!=nil{t.Fatal(err)}
    if err:=os.WriteFile(candidate+".sig",
        []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(private,manifest))),0600);err!=nil{t.Fatal(err)}
    if _,err:=motorupdate.VerifyStaged(candidate,public);err!=nil {
        t.Fatalf("full compiled VOLVE candidate failed signed package proof: %v",err)
    }
    return candidate,public,sha
}

func TestCompleteApplicationCandidateSystemTaskRecovery(t *testing.T) {
    compiledExe:=os.Getenv("VOLVE_CI_REAL_CENTRO_EXE")
    watchdog:=os.Getenv("VOLVE_CI_MANAGED_WATCHDOG_EXE")
    if compiledExe=="" || watchdog=="" {
        t.Fatal("Windows CI must provide compiled full VOLVE exe and independent recovery exe")
    }
    name:=fmt.Sprintf("VOLVE-CI-ManagedMotor-%d",time.Now().UnixNano())
    original:=filepath.Join(os.Getenv("WINDIR"),"System32","cmd.exe")
    if err:=createDisposableTask(name,original);err!=nil{t.Fatal(err)}
    t.Cleanup(func(){if err:=removeDisposableTask(name);err!=nil{t.Errorf("original task cleanup: %v",err)}})

    root:=t.TempDir()
    candidate,key,wantSHA:=signedCompleteApplicationCandidate(t,root,compiledExe)
    d:=&managedWindowsTaskLab{
        name:name,root:filepath.Join(root,"transaction"),original:original,
        backup:filepath.Join(root,"transaction","original-task.xml"),publicKey:key,
    }
    if err:=d.Snapshot(context.Background());err!=nil{t.Fatal(err)}
    journalPath:=filepath.Join(root,"transaction.json")
    writeCIWatchdogJournal(t,journalPath,ciWatchdogJournal{
        Schema:1,Phase:"pending",TaskName:name,
        OriginalExe:original,OriginalArgs:"/C exit 0",
        SnapshotFile:d.backup,SnapshotSHA256:d.originalHash,
    })
    // The SYSTEM watchdog is prepared BEFORE the task switch, with a trusted
    // ACL-protected journal and original XML. Neither the new exe nor the
    // old task is executed during this dry-run.
    secureCIPilotRecovery(t,journalPath,d.backup)
    watcherName:=fmt.Sprintf("VOLVE-CI-ManagedWatchdog-%d",time.Now().UnixNano())
    if err:=createSYSTEMWatchdogLabTask(watcherName,watchdog,journalPath);err!=nil{t.Fatal(err)}
    t.Cleanup(func(){if err:=removeSYSTEMWatchdogLabTask(watcherName);err!=nil{t.Errorf("watchdog cleanup: %v",err)}})
    if err:=d.InstallVersionedCandidate(context.Background(),candidate);err!=nil{t.Fatal(err)}
    verified,err:=motorupdate.VerifyStaged(d.installedExe,key)
    if err!=nil || verified.SHA256!=wantSHA {
        t.Fatalf("installed, full-size signed VOLVE image differs: %v",err)
    }
    if err:=switchVerifiedMotorTaskAction(context.Background(),name,original,
        "/C exit 0",d.installedExe,"",key);err!=nil{t.Fatal(err)}
    switched,args,err:=d.currentAction()
    if err!=nil || !strings.EqualFold(filepath.Clean(switched),filepath.Clean(d.installedExe)) || args!="" {
        t.Fatalf("full application candidate not selected by CI task: %q %q %v",switched,args,err)
    }
    // Run ONLY the independent watchdog task as SYSTEM, NOT the candidate.
    if err:=startSYSTEMWatchdogLabTask(watcherName);err!=nil{t.Fatal(err)}
    deadline:=time.Now().Add(40*time.Second)
    for time.Now().Before(deadline){
        raw,err:=os.ReadFile(journalPath)
        if err==nil {
            var j ciWatchdogJournal
            if json.Unmarshal(raw,&j)==nil && j.Phase=="restored" {
                current,currentArgs,actionErr:=d.currentAction()
                if actionErr!=nil || !strings.EqualFold(filepath.Clean(current),filepath.Clean(original)) || currentArgs!="/C exit 0" {
                    t.Fatalf("SYSTEM watchdog did not restore CI-only original action: %q %q %v",current,currentArgs,actionErr)
                }
                if _,err:=motorupdate.VerifyStaged(d.installedExe,key);err!=nil {
                    t.Fatalf("signed motor bytes damaged during recovery: %v",err)
                }
                return
            }
        }
        time.Sleep(400*time.Millisecond)
    }
    t.Fatal("separate SYSTEM watchdog did not restore a task after selecting full compiled VOLVE executable")
}
