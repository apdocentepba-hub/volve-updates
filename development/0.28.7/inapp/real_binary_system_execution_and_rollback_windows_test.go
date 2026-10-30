//go:build windows

package main

// This test closes the gap between "the candidate was selected by a SYSTEM
// task" and "the candidate actually ran its DNS engine under SYSTEM".
//
// It ONLY uses the disposable task names VOLVE-CI-ManagedMotor-* and
// VOLVE-CI-ManagedWatchdog-*. The signed, full compiled Windows VOLVE EXE
// runs its harmless --motor-dns-isolated-loopback CLI: five real UDP queries
// on dynamically allocated localhost ports, NEVER the production port 53.
// The independent SYSTEM watchdog is armed BEFORE the task switch; then a
// failed/unfinished candidate can be reverted independently.
import (
    "context"
    "encoding/json"
    "fmt"
    "os"
    "path/filepath"
    "strings"
    "testing"
    "time"

    "volve-browser-protection/motorupdate"
)

func TestSignedRealVOLVECandidateRunsDNSAsSYSTEMThenRecovers(t *testing.T) {
    compiled:=os.Getenv("VOLVE_CI_REAL_CENTRO_EXE")
    watchdog:=os.Getenv("VOLVE_CI_MANAGED_WATCHDOG_EXE")
    if compiled=="" || watchdog=="" {t.Fatal("full compiled VOLVE and independent watchdog paths required")}
    if os.Getenv("GITHUB_ACTIONS")!="true" || os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted" {
        t.Fatal("refusing SYSTEM engine execution outside a disposable GitHub-hosted runner")
    }
    if !filepath.IsAbs(compiled) || !filepath.IsAbs(watchdog) {t.Fatal("absolute executable paths required")}
    name:=fmt.Sprintf("VOLVE-CI-ManagedMotor-%d",time.Now().UnixNano())
    oldExe:=filepath.Join(os.Getenv("WINDIR"),"System32","cmd.exe")
    if err:=createDisposableTask(name,oldExe);err!=nil{t.Fatal(err)}
    t.Cleanup(func(){if err:=removeDisposableTask(name);err!=nil{t.Errorf("engine cleanup: %v",err)}})
    root:=t.TempDir()
    candidate,key,expectedHash:=signedCompleteApplicationCandidate(t,root,compiled)
    d:=&managedWindowsTaskLab{
        name:name,root:filepath.Join(root,"transaction"),original:oldExe,
        backup:filepath.Join(root,"transaction","original-task.xml"),publicKey:key,
    }
    if err:=d.Snapshot(context.Background());err!=nil{t.Fatal(err)}
    jpath:=filepath.Join(root,"recovery.json")
    writeCIWatchdogJournal(t,jpath,ciWatchdogJournal{
        Schema:1,Phase:"pending",TaskName:name,
        OriginalExe:oldExe,OriginalArgs:"/C exit 0",
        SnapshotFile:d.backup,SnapshotSHA256:d.originalHash,
    })
    secureCIPilotRecovery(t,jpath,d.backup)
    watchName:=fmt.Sprintf("VOLVE-CI-ManagedWatchdog-%d",time.Now().UnixNano())
    if err:=createSYSTEMWatchdogLabTask(watchName,watchdog,jpath);err!=nil{t.Fatal(err)}
    t.Cleanup(func(){
        // If the test failed after switching, make a best-effort recovery
        // before unregistering either disposable task.
        switched,_,err:=d.currentAction()
        if err==nil && !strings.EqualFold(filepath.Clean(switched),filepath.Clean(oldExe)){
            if e:=startSYSTEMWatchdogLabTask(watchName);e!=nil{t.Errorf("emergency watchdog start: %v",e)}
        }
        if err:=removeSYSTEMWatchdogLabTask(watchName);err!=nil{t.Errorf("watchdog cleanup: %v",err)}
    })

    // Once the rollback task and ACL-protected journal are durable, install
    // the signed and hashed candidate. Do not trust an unsigned file.
    if err:=d.InstallVersionedCandidate(context.Background(),candidate);err!=nil{t.Fatal(err)}
    actual,err:=motorupdate.VerifyStaged(d.installedExe,key)
    if err!=nil || actual.SHA256!=expectedHash {t.Fatalf("signed installed candidate mismatch: %v",err)}
    const cli="--motor-dns-isolated-loopback"
    if err:=switchVerifiedMotorTaskAction(context.Background(),name,oldExe,
        "/C exit 0",d.installedExe,cli,key);err!=nil{t.Fatal(err)}
    exe,args,err:=d.currentAction()
    if err!=nil || !strings.EqualFold(filepath.Clean(exe),filepath.Clean(d.installedExe)) || args!=cli {
        t.Fatalf("SYSTEM task did not point to signed real DNS self-test: %q %q %v",exe,args,err)
    }

    // Start the actual compiled EXE under the real Windows SYSTEM token.
    // LastTaskResult=0 only after the DNS self-test has exited successfully;
    // Get-ScheduledTaskInfo supplies the elapsed run timestamp as evidence.
    start:=time.Now().Add(-3*time.Second)
    command:=`$ErrorActionPreference='Stop';Start-ScheduledTask -TaskName `+labQuote(name)+` -ErrorAction Stop`
    if _,err:=labPS(command);err!=nil{t.Fatal(err)}
    deadline:=time.Now().Add(30*time.Second)
    passed:=false
    for time.Now().Before(deadline) {
        query:=`$ErrorActionPreference='Stop';$t=Get-ScheduledTask -TaskName `+labQuote(name)+` -ErrorAction Stop;`+
          `$i=Get-ScheduledTaskInfo -TaskName `+labQuote(name)+` -ErrorAction Stop;`+
          `Write-Output ($t.State.ToString()+'|'+$i.LastTaskResult+'|'+$i.LastRunTime.ToUniversalTime().ToString('o')+'|'+$t.Principal.UserId)`
        reply,err:=labPS(query)
        if err!=nil{t.Fatal(err)}
        fields:=strings.Split(strings.TrimSpace(reply),"|")
        if len(fields)!=4{t.Fatalf("ambiguous Task Scheduler result: %q",reply)}
        last,err:=time.Parse(time.RFC3339Nano,fields[2]);if err!=nil{t.Fatalf("task timestamp invalid %q: %v",fields[2],err)}
        if fields[3]!="SYSTEM" && fields[3]!="S-1-5-18" {t.Fatalf("candidate was not scheduled as SYSTEM: %q",fields[3])}
        if last.After(start) && fields[0]!="Running" && fields[1]=="0" {
            passed=true
            break
        }
        if last.After(start) && fields[0]!="Running" && fields[1]!="0" {
            t.Fatalf("signed VOLVE DNS engine failed under SYSTEM: Task Scheduler result %q",fields[1])
        }
        time.Sleep(500*time.Millisecond)
    }
    if !passed{t.Fatal("signed real VOLVE candidate did not complete its isolated DNS UDP proof as SYSTEM")}

    // Fail the upgrade deliberately: let the independent watchdog restore
    // the old SYSTEM task. No update is committed or published.
    if err:=startSYSTEMWatchdogLabTask(watchName);err!=nil{t.Fatal(err)}
    until:=time.Now().Add(35*time.Second)
    for time.Now().Before(until){
        b,readErr:=os.ReadFile(jpath)
        if readErr==nil{
            var j ciWatchdogJournal
            if json.Unmarshal(b,&j)==nil && j.Phase=="restored"{
                restored,restoredArgs,err:=d.currentAction()
                if err!=nil || !strings.EqualFold(filepath.Clean(restored),filepath.Clean(oldExe)) ||
                    restoredArgs!="/C exit 0"{
                    t.Fatalf("independent SYSTEM watchdog did not restore original task: %q %q %v",restored,restoredArgs,err)
                }
                if _,err:=motorupdate.VerifyStaged(d.installedExe,key);err!=nil{
                    t.Fatalf("recovery damaged installed signed candidate: %v",err)
                }
                t.Log("PASS: full signed VOLVE EXE actually ran real isolated DNS UDP selftest as SYSTEM; separate SYSTEM watchdog restored original task")
                return
            }
        }
        time.Sleep(350*time.Millisecond)
    }
    t.Fatal("independent SYSTEM rollback did not restore original task after real candidate execution")
}
