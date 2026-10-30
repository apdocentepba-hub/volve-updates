//go:build windows

package main

// This is a WINDOWS CI-ONLY signed legacy migration trial. It switches only a
// disposable VOLVE-CI-ManagedMotor-* task, never the production DNS task,
// adapter, hosts file or installed VOLVE. Successful probes validate the
// Scheduled Task action, NOT real DNS/Internet service health.
import (
    "context"
    "crypto/ed25519"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "strings"
    "testing"
    "time"

    "volve-browser-protection/motorupdate"
)

// The lab adapter requires the independent SYSTEM watchdog task to exist
// BEFORE the migration transaction. Its journal and original task XML have
// protected NTFS ACLs. No production SignedLegacySwitchDriver exists.
type signedLegacyWindowsTaskLab struct {
    *managedWindowsTaskLab
    watcherName, watchdogExe, watchdogJournal string
}

func (d *signedLegacyWindowsTaskLab) IndependentRecoveryReady(ctx context.Context, proof motorupdate.VerifiedLegacyMigrationProof) error {
    if err:=ctx.Err();err!=nil{return err}
    if !managedLabName.MatchString(d.name) || !watchdogLabName.MatchString(d.watcherName) {
        return errors.New("signed migration driver must use disposable CI tasks")
    }
    if proof.CandidateVersion!="0.28.7" || len(proof.LegacySHA256)!=64 {
        return errors.New("signed legacy evidence incomplete")
    }
    if !filepath.IsAbs(d.watchdogJournal) || !filepath.IsAbs(d.watchdogExe){
        return errors.New("independent recovery paths must be absolute")
    }
    raw,err:=os.ReadFile(d.watchdogJournal)
    if err!=nil{return err}
    var state ciWatchdogJournal
    if err:=json.Unmarshal(raw,&state);err!=nil{return err}
    if state.Phase!="pending" || state.TaskName!=d.name || state.SnapshotFile!=d.backup ||
        state.SnapshotSHA256!=d.originalHash {
        return errors.New("independent recovery journal is not pending or does not match snapshot")
    }
    xml,err:=os.ReadFile(d.backup)
    if err!=nil{return err}
    sum:=sha256.Sum256(xml)
    if hex.EncodeToString(sum[:])!=state.SnapshotSHA256 {
        return errors.New("independent watchdog XML changed")
    }
    // Read actual Windows Task Scheduler metadata, not just an in-memory flag.
    // The boot trigger and SYSTEM identity are mandatory. This is a lab-only
    // proof; a production driver must additionally secure the entire path and
    // establish a persistent recovery journal under protected ProgramData.
    script:="$t=Get-ScheduledTask -TaskName "+labQuote(d.watcherName)+" -ErrorAction Stop;"+
        "if($t.TaskPath -ne '\\' -or $t.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or @($t.Actions).Count -ne 1){throw 'Bad SYSTEM watchdog task'};"+
        "$boot=@($t.Triggers|Where-Object{$_.CimClass.CimClassName -eq 'MSFT_TaskBootTrigger'});"+
        "if($boot.Count -ne 1){throw 'Watchdog missing boot trigger'};"+
        "if($t.Actions[0].Execute -ine "+labQuote(d.watchdogExe)+"){throw 'Wrong recovery executable'};"+
        "Write-Output 'SIGNED_LEGACY_CI_WATCHDOG_READY'"
    out,err:=labPS(script)
    if err!=nil || !strings.Contains(out,"SIGNED_LEGACY_CI_WATCHDOG_READY") {
        return fmt.Errorf("independent recovery SYSTEM task not ready: %v %s",err,out)
    }
    return nil
}

// VerifyPreparedTarget is a separate check of the VERSIONED INSTALLED COPY.
// It rejects a bad or substituted candidate even if its earlier staged
// download and the signed migration authorization were valid.
func (d *signedLegacyWindowsTaskLab) VerifyPreparedTarget(ctx context.Context, manifest motorupdate.Manifest) error {
    if err:=ctx.Err();err!=nil{return err}
    if d.installedExe=="" || !filepath.IsAbs(d.installedExe) {
        return errors.New("versioned motor was not installed in CI lab")
    }
    rel,err:=filepath.Rel(d.root,d.installedExe)
    if err!=nil || rel=="." || rel==".." || filepath.IsAbs(rel) ||
        strings.HasPrefix(rel,".."+string(os.PathSeparator)) {
        return errors.New("prepared engine escaped disposable versioned directory")
    }
    verified,err:=motorupdate.VerifyStaged(d.installedExe,d.publicKey)
    if err!=nil{return fmt.Errorf("signed installed candidate failed: %w",err)}
    if verified!=manifest {return errors.New("installed motor version, hash or size differs from publisher manifest")}
    return nil
}

// Snapshot was durably written and its recovery task armed BEFORE calling the
// signed transaction. Fail closed if that precondition changed.
func (d *signedLegacyWindowsTaskLab) Snapshot(ctx context.Context) error {
    if err:=ctx.Err();err!=nil{return err}
    if d.originalHash==""{return errors.New("independent recovery snapshot not prepared")}
    return nil
}

// Only the separately compiled watcher, executed by a disposable SYSTEM task,
// performs rollback. No direct task restoration is allowed in this adapter.
func (d *signedLegacyWindowsTaskLab) Restore(ctx context.Context) error {
    if err:=startSYSTEMWatchdogLabTask(d.watcherName);err!=nil{return err}
    tick:=time.NewTicker(300*time.Millisecond)
    defer tick.Stop()
    for {
        if err:=ctx.Err();err!=nil{return err}
        raw,err:=os.ReadFile(d.watchdogJournal)
        if err==nil {
            var j ciWatchdogJournal
            if json.Unmarshal(raw,&j)==nil && j.Phase=="restored" {
                d.restored=true
                return nil
            }
        }
        select {
        case <-ctx.Done(): return ctx.Err()
        case <-tick.C:
        }
    }
}

func (d *signedLegacyWindowsTaskLab) Commit(ctx context.Context,m motorupdate.Manifest) error {
    // The existing disposable task driver verifies a signed engine inventory.
    // Journal finalization is a separate lab operation, not a production API.
    if err:=d.managedWindowsTaskLab.Commit(ctx,m);err!=nil{return err}
    data,err:=os.ReadFile(d.watchdogJournal)
    if err!=nil{return err}
    var j ciWatchdogJournal
    if err:=json.Unmarshal(data,&j);err!=nil{return err}
    if j.Phase!="pending"{return errors.New("watchdog journal not pending at commit")}
    j.Phase="committed"
    next,err:=json.Marshal(j)
    if err!=nil{return err}
    f,err:=os.OpenFile(d.watchdogJournal,os.O_WRONLY|os.O_TRUNC,0600)
    if err!=nil{return err}
    if _,err=f.Write(append(next,'\n'));err!=nil{f.Close();return err}
    if err=f.Sync();err!=nil{f.Close();return err}
    return f.Close()
}

func TestWindowsSignedPreparedCopyTamperingIsRejected(t *testing.T){
    root:=t.TempDir()
    candidate,key:=prepareSignedLabCandidate(t,root)
    manifest,err:=motorupdate.VerifyStaged(candidate,key)
    if err!=nil{t.Fatal(err)}
    d:=&signedLegacyWindowsTaskLab{managedWindowsTaskLab:&managedWindowsTaskLab{
        root:filepath.Join(root,"ci-transaction"),publicKey:key,
    }}
    if err:=d.InstallVersionedCandidate(context.Background(),candidate);err!=nil{t.Fatal(err)}
    if err:=d.VerifyPreparedTarget(context.Background(),manifest);err!=nil{
        t.Fatalf("signed installed copy unexpectedly invalid: %v",err)
    }
    if err:=os.WriteFile(d.installedExe,[]byte("MZ_TAMPERED_INSTALLED_COPY"),0600);err!=nil{t.Fatal(err)}
    if err:=d.VerifyPreparedTarget(context.Background(),manifest);err==nil{
        t.Fatal("staged signature incorrectly accepted an altered installed executable")
    }
}

func TestWindowsSignedUnversionedMigrationWithActualSYSTEMRecovery(t *testing.T){
    helper:=os.Getenv("VOLVE_CI_MANAGED_WATCHDOG_EXE")
    if helper=="" {t.Fatal("independent CI watchdog binary missing")}
    if !isAdmin(){t.Skip("CI elevated Windows runner required")}
    for _,networkFails:=range []bool{false,true}{
        label:="signed-commit"
        if networkFails{label="SYSTEM-watchdog-rollback-on-connectivity-failure"}
        t.Run(label,func(t *testing.T){
            name:=fmt.Sprintf("VOLVE-CI-ManagedMotor-%d",time.Now().UnixNano())
            original:=filepath.Join(os.Getenv("WINDIR"),"System32","cmd.exe")
            if err:=createDisposableTask(name,original);err!=nil{t.Fatal(err)}
            t.Cleanup(func(){if err:=removeDisposableTask(name);err!=nil{t.Errorf("cleanup CI motor task: %v",err)}})
            root:=t.TempDir()
            legacyExe:=filepath.Join(root,dnsServiceFile)
            old:=[]byte("MZ_CI_LEGACY_UNVERSIONED_MOTOR_NOT_EXECUTED")
            if err:=os.WriteFile(legacyExe,old,0600);err!=nil{t.Fatal(err)}
            parent,err:=ensureSecureLegacyRecoveryParent(root)
            if err!=nil{t.Fatal(err)}
            legacyBackup:=filepath.Join(parent,localRecoverySnapshot)
            // This XML is the CI signed-identity fixture; the separate real
            // Task Scheduler task snapshot below is used by SYSTEM rollback.
            fixtureXML:=[]byte(strings.Repeat("<Task><Principal>SYSTEM</Principal><Command>VOLVE_DNS_Server_0270.exe</Command></Task>",2))
            record,err:=motorupdate.PrepareUnversionedLegacyRecovery(context.Background(),legacyExe,fixtureXML,legacyBackup,checkLegacyRecoveryACL)
            if err!=nil{t.Fatal(err)}
            pub,priv,err:=ed25519.GenerateKey(rand.Reader)
            if err!=nil{t.Fatal(err)}
            candidate:=filepath.Join(root,"VOLVE_DNS_Motor_0_28_7.exe")
            next,err:=os.ReadFile(filepath.Join(os.Getenv("WINDIR"),"System32","notepad.exe"))
            if err!=nil{t.Fatal(err)}
            if err:=os.WriteFile(candidate,next,0600);err!=nil{t.Fatal(err)}
            digest:=sha256.Sum256(next)
            manifest:=motorupdate.Manifest{Schema:1,Component:"dns-engine",Version:"0.28.7",MinPanelVersion:"0.28.7",
                URL:"https://github.com/apdocentepba-hub/volve-updates/releases/download/v0.28.7/VOLVE_DNS_Motor_0_28_7.exe",
                SHA256:hex.EncodeToString(digest[:]),Size:int64(len(next)),Notes:"CI-only signed disposable task"}
            rawManifest,err:=json.Marshal(manifest);if err!=nil{t.Fatal(err)}
            if err:=os.WriteFile(candidate+".json",rawManifest,0600);err!=nil{t.Fatal(err)}
            if err:=os.WriteFile(candidate+".sig",[]byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv,rawManifest))),0600);err!=nil{t.Fatal(err)}
            now:=time.Now().UTC()
            permit:=motorupdate.LegacyMigrationPermit{
                Schema:1,Component:"dns-engine-legacy-migration",FromTask:dnsServiceTask,FromArgs:"--dns-service",
                FromExecutable:dnsServiceFile,FromSHA256:record.ExeSHA256,FromSize:record.ExeSize,
                FromTaskXMLSHA256:record.XMLSHA256,ToVersion:manifest.Version,ToSHA256:manifest.SHA256,
                ToSize:manifest.Size,MinPanelVersion:manifest.MinPanelVersion,
                IssuedUTC:now.Add(-time.Minute).Format(time.RFC3339),ExpiresUTC:now.Add(time.Hour).Format(time.RFC3339),
            }
            rawPermit,err:=json.Marshal(permit);if err!=nil{t.Fatal(err)}
            permitSig:=[]byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv,rawPermit)))

            core:=&managedWindowsTaskLab{name:name,root:filepath.Join(root,"ci-transaction"),
                backup:filepath.Join(root,"ci-transaction","original-task.xml"),
                original:original,publicKey:pub,failConnectivityOnce:networkFails}
            if err:=core.Snapshot(context.Background());err!=nil{t.Fatal(err)}
            journal:=filepath.Join(core.root,"recovery.json")
            writeCIWatchdogJournal(t,journal,ciWatchdogJournal{Schema:1,Phase:"pending",TaskName:name,
                OriginalExe:original,OriginalArgs:"/C exit 0",SnapshotFile:core.backup,SnapshotSHA256:core.originalHash})
            secureCIPilotRecovery(t,journal,core.backup)
            watcher:=fmt.Sprintf("VOLVE-CI-ManagedWatchdog-%d",time.Now().UnixNano())
            if err:=createSYSTEMWatchdogLabTask(watcher,helper,journal);err!=nil{t.Fatal(err)}
            t.Cleanup(func(){if err:=removeSYSTEMWatchdogLabTask(watcher);err!=nil{t.Errorf("watchdog CI cleanup: %v",err)}})
            driver:=&signedLegacyWindowsTaskLab{managedWindowsTaskLab:core,watcherName:watcher,
                watchdogExe:helper,watchdogJournal:journal}
            preflight:=func()error{
                exe,args,err:=core.currentAction()
                if err!=nil{return err}
                if !strings.EqualFold(filepath.Clean(exe),filepath.Clean(original)) || args!="/C exit 0"{
                    return errors.New("disposable old SYSTEM task changed before signed migration")
                }
                return nil
            }
            err=motorupdate.ApplySignedLegacyWithRollback(context.Background(),legacyExe,legacyBackup,candidate,
                "0.28.7",rawPermit,permitSig,pub,checkLegacyRecoveryACL,preflight,driver)
            exe,args,actionErr:=core.currentAction()
            if actionErr!=nil{t.Fatal(actionErr)}
            if networkFails{
                if err==nil || !strings.Contains(err.Error(),"revertida") || !driver.restored || core.committed{
                    t.Fatalf("SYSTEM recovery did not run after connectivity rejection: %v restored=%v committed=%v",err,driver.restored,core.committed)
                }
                if !strings.EqualFold(filepath.Clean(exe),filepath.Clean(original)) || args!="/C exit 0"{
                    t.Fatalf("signed migration did not restore original task: %s %s",exe,args)
                }
            }else{
                if err!=nil || !core.committed || driver.restored {
                    t.Fatalf("signed migration CI commit failed: %v committed=%v restored=%v",err,core.committed,driver.restored)
                }
                if !strings.EqualFold(filepath.Clean(exe),filepath.Clean(core.installedExe)) || args!=""{
                    t.Fatalf("signed target not selected for CI task: %s %s",exe,args)
                }
                if got,checkErr:=motorupdate.InspectInstalledEngine(core.root,pub);checkErr!=nil || got!="0.28.7"{
                    t.Fatalf("signed installed engine receipt invalid: %q %v",got,checkErr)
                }
            }
            rawJournal,readErr:=os.ReadFile(journal);if readErr!=nil{t.Fatal(readErr)}
            var final ciWatchdogJournal
            if err:=json.Unmarshal(rawJournal,&final);err!=nil{t.Fatal(err)}
            expected:="committed";if networkFails{expected="restored"}
            if final.Phase!=expected{t.Fatalf("SYSTEM journal phase %s, expected %s",final.Phase,expected)}
            t.Logf("CI ONLY: signed legacy grant, actual disposable SYSTEM task and independent watchdog; final=%s",expected)
        })
    }
}
