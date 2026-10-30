//go:build windows
//
// This CI-only integration test creates a disposable harmless SYSTEM task.
// It NEVER executes the staged candidate, changes DNS, modifies VOLVE tasks,
// changes adapters, or installs a real engine on a user computer.
package main

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
    "io"
    "os"
    "os/exec"
    "path/filepath"
    "regexp"
    "strings"
    "testing"
    "time"

    "volve-browser-protection/motorupdate"
)

var managedLabName = regexp.MustCompile("^VOLVE-CI-ManagedMotor-[0-9]{12,20}$")

func labQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func labPS(script string) (string, error) {
    c := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference='Stop';"+script)
    data, err := c.CombinedOutput()
    if err != nil { return "",fmt.Errorf("disposable task script failed: %w; output: %s",err,string(data)) }
    return strings.TrimSpace(string(data)),nil
}

func createDisposableTask(name, oldExe string) error {
    if !managedLabName.MatchString(name) { return errors.New("refusing unsafe disposable task name") }
    script := "$name="+labQuote(name)+";"+
        "$action=New-ScheduledTaskAction -Execute "+labQuote(oldExe)+" -Argument '/C exit 0';"+
        "$trigger=New-ScheduledTaskTrigger -Once -At ((Get-Date).AddYears(1));"+
        "Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -User 'SYSTEM' -RunLevel Highest -ErrorAction Stop | Out-Null;"
    _,e:=labPS(script);return e
}

func removeDisposableTask(name string) error {
    if !managedLabName.MatchString(name) { return errors.New("refusing unexpected cleanup target") }
    script := "$t=Get-ScheduledTask -TaskName "+labQuote(name)+" -ErrorAction SilentlyContinue;"+
        "if($null -ne $t) {"+
        "if($t.TaskPath -ne '\\' -or $t.Principal.UserId -notin @('SYSTEM','S-1-5-18')) { throw 'Refusing unowned task cleanup' };"+
        "Unregister-ScheduledTask -TaskName "+labQuote(name)+" -Confirm:$false -ErrorAction Stop }"
    _,e:=labPS(script);return e
}

type managedWindowsTaskLab struct {
    name, root, original, backup, stagedExe, installedExe string
    originalHash string
    failConnectivityOnce bool
    restored bool
    committed bool
    publicKey ed25519.PublicKey
}

func (d *managedWindowsTaskLab) currentAction() (string, string, error) {
    if !managedLabName.MatchString(d.name) { return "","",errors.New("unsafe name") }
    script:="$t=Get-ScheduledTask -TaskName "+labQuote(d.name)+" -ErrorAction Stop;"+
        "if($t.TaskPath -ne '\\' -or $t.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or @($t.Actions).Count -ne 1) {throw 'Unknown SYSTEM task ownership or action'};"+
        "Write-Output ($t.Actions[0].Execute + '|' + $t.Actions[0].Arguments)"
    txt,err:=labPS(script)
    if err != nil { return "","",err }
    parts:=strings.SplitN(txt,"|",2)
    if len(parts)!=2{return "","",errors.New("ambiguous Windows task action")}
    return strings.TrimSpace(parts[0]),strings.TrimSpace(parts[1]),nil
}

func (d *managedWindowsTaskLab) Preflight(ctx context.Context, m motorupdate.Manifest) error {
    if err:=ctx.Err();err!=nil{return err}
    if m.Component!="dns-engine" || !managedLabName.MatchString(d.name){return errors.New("unexpected pilot identity")}
    exe,args,err:=d.currentAction()
    if err!=nil{return err}
    if !strings.EqualFold(filepath.Clean(exe), filepath.Clean(d.original)) || args!="/C exit 0" {
        return fmt.Errorf("unrecognized original disposable action: %q %q",exe,args)
    }
    return nil
}

func (d *managedWindowsTaskLab) Snapshot(ctx context.Context) error {
    if err:=ctx.Err();err!=nil{return err}
    if err:=os.MkdirAll(d.root,0700);err!=nil{return err}
    script := "$snapshot=Export-ScheduledTask -TaskName "+labQuote(d.name)+" -ErrorAction Stop;"+
        "[IO.File]::WriteAllText("+labQuote(d.backup)+",$snapshot,[Text.UTF8Encoding]::new($false))"
    if _,err:=labPS(script);err!=nil{return err}
    data,err:=os.ReadFile(d.backup);if err!=nil{return err}
    if len(data)==0 || len(data)>1<<20 {return errors.New("invalid task snapshot length")}
    h:=sha256.Sum256(data);d.originalHash=hex.EncodeToString(h[:])
    f,err:=os.OpenFile(d.backup,os.O_RDWR,0600);if err!=nil{return err}
    err=f.Sync();f.Close();return err
}

func (d *managedWindowsTaskLab) InstallVersionedCandidate(ctx context.Context, candidate string) error {
    if err:=ctx.Err();err!=nil{return err}
    targetDir:=filepath.Join(d.root,"motor-0.28.7")
    if err:=os.Mkdir(targetDir,0700);err!=nil{return err}
    d.installedExe=filepath.Join(targetDir,"VOLVE_DNS_Motor_0_28_7.exe")
    // Copy the signed package as three immutable/versioned files, not just EXE:
    // the installed-version inventory re-verifies the manifest and signature.
    for _,suffix:=range []string{"",".json",".sig"} {
        src,err:=os.Open(candidate+suffix);if err!=nil{return err}
        dest,err:=os.OpenFile(d.installedExe+suffix,os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600)
        if err!=nil{src.Close();return err}
        _,err=io.Copy(dest,src)
        if err==nil{err=dest.Sync()}
        closeErr:=dest.Close()
        src.Close()
        if err!=nil{return err}
        if closeErr!=nil{return closeErr}
    }
    return nil
}

func (d *managedWindowsTaskLab) Switch(ctx context.Context) error {
    if d.installedExe=="" {return errors.New("signed candidate not installed")}
    return switchVerifiedMotorTaskAction(ctx,d.name,d.original,"/C exit 0",d.installedExe,"",d.publicKey)
}

func (d *managedWindowsTaskLab) Probe(ctx context.Context) error {
    if err:=ctx.Err();err!=nil{return err}
    exe,args,err:=d.currentAction();if err!=nil{return err}
    if d.restored {
        if !strings.EqualFold(filepath.Clean(exe),filepath.Clean(d.original)) || args!="/C exit 0" {return errors.New("previous task action not restored")}
    } else if !strings.EqualFold(filepath.Clean(exe),filepath.Clean(d.installedExe)) || args!="" {
        return errors.New("candidate action not registered")
    }
    // This verifies ONLY the scheduled-task action, NOT a live DNS probe.
    return nil
}

func (d *managedWindowsTaskLab) ProbeConnectivity(ctx context.Context) error {
    if err:=ctx.Err();err!=nil{return err}
    if d.failConnectivityOnce {
        d.failConnectivityOnce=false
        return errors.New("simulated Internet outage during candidate validation")
    }
    // No external network is probed in this harmless CI laboratory.
    return nil
}

func (d *managedWindowsTaskLab) Commit(ctx context.Context, m motorupdate.Manifest) error {
    if err:=ctx.Err();err!=nil{return err}
    if d.restored{return errors.New("cannot commit reverted pilot")}
    if m.Version!="0.28.7"{return errors.New("unexpected lab version")}
    if err:=motorupdate.RecordVerifiedEngine(d.root,d.installedExe,d.publicKey);err!=nil{return err}
    d.committed=true
    return nil
}

func (d *managedWindowsTaskLab) Restore(ctx context.Context) error {
    if err:=restoreVerifiedMotorTaskXML(ctx,d.name,d.backup,d.originalHash,d.original,"/C exit 0");err!=nil{return err}
    d.restored=true
    return nil
}

func prepareSignedLabCandidate(t *testing.T, dir string) (string,ed25519.PublicKey) {
    t.Helper()
    originalExe:=filepath.Join(os.Getenv("WINDIR"),"System32","notepad.exe")
    data,err:=os.ReadFile(originalExe)
    if err!=nil || len(data)==0 || len(data)>80<<20 {t.Fatalf("notepad fixture unreadable: %v",err)}
    candidate:=filepath.Join(dir,"VOLVE_DNS_Motor_0_28_7.exe")
    if err:=os.WriteFile(candidate,data,0600);err!=nil{t.Fatal(err)}
    h:=sha256.Sum256(data)
    m:=motorupdate.Manifest{
        Schema:1,Component:"dns-engine",Version:"0.28.7",MinPanelVersion:"0.28.7",
        URL:"https://github.com/apdocentepba-hub/volve-updates/releases/download/v0.28.7/VOLVE_DNS_Motor_0_28_7.exe",
        SHA256:hex.EncodeToString(h[:]),Size:int64(len(data)),Notes:"Windows CI disposable task fixture",
    }
    raw,err:=json.Marshal(m);if err!=nil{t.Fatal(err)}
    pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
    if err:=os.WriteFile(candidate+".json",raw,0600);err!=nil{t.Fatal(err)}
    if err:=os.WriteFile(candidate+".sig",[]byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv,raw))),0600);err!=nil{t.Fatal(err)}
    return candidate,pub
}

func TestManagedWindowsDisposableTaskIntegration(t *testing.T) {
    for _,failNetwork:=range []bool{false,true} {
        label:="success";if failNetwork {label="rollback-after-failed-connectivity"}
        t.Run(label,func(t *testing.T) {
            name:=fmt.Sprintf("VOLVE-CI-ManagedMotor-%d",time.Now().UnixNano())
            root:=t.TempDir()
            original:=filepath.Join(os.Getenv("WINDIR"),"System32","cmd.exe")
            if err:=createDisposableTask(name,original);err!=nil{t.Fatal(err)}
            t.Cleanup(func(){if err:=removeDisposableTask(name);err!=nil{t.Errorf("cleanup failed: %v",err)}})
            candidate,key:=prepareSignedLabCandidate(t,root)
            d:=&managedWindowsTaskLab{
                name:name,root:filepath.Join(root,"transaction"),original:original,
                backup:filepath.Join(root,"transaction","original-task.xml"),
                stagedExe:candidate,failConnectivityOnce:failNetwork,publicKey:key,
            }
            err:=motorupdate.ApplyManagedWithRollback(context.Background(),candidate,key,"0.27.0","0.28.7",d)
            if failNetwork {
                if err==nil || !d.restored || d.committed {t.Fatalf("expected safe restoration with no commit: %v; %+v",err,d)}
                if err=d.Probe(context.Background());err!=nil{t.Fatalf("original task not restored: %v",err)}
                if _,err:=motorupdate.InspectInstalledEngine(d.root,key);!errors.Is(err,motorupdate.ErrUnregisteredEngine) {
                    t.Fatalf("failed update incorrectly marked installed: %v",err)
                }
            }else{
                if err!=nil || !d.committed || d.restored {t.Fatalf("expected confirmed disposable test task: %v; %+v",err,d)}
                got,verifyErr:=motorupdate.InspectInstalledEngine(d.root,key)
                if verifyErr!=nil || got!="0.28.7" {t.Fatalf("verified installed receipt missing: %q %v",got,verifyErr)}
            }
        })
    }
}

func TestNativeMotorTaskRejectsUnsignedMutationAndWrongOwner(t *testing.T) {
    name:=fmt.Sprintf("VOLVE-CI-ManagedMotor-%d",time.Now().UnixNano())
    original:=filepath.Join(os.Getenv("WINDIR"),"System32","cmd.exe")
    if err:=createDisposableTask(name,original);err!=nil{t.Fatal(err)}
    t.Cleanup(func(){if err:=removeDisposableTask(name);err!=nil{t.Errorf("cleanup: %v",err)}})
    root:=t.TempDir()
    candidate,key:=prepareSignedLabCandidate(t,root)
    if err:=os.WriteFile(candidate,[]byte("MZ_UNTRUSTED"),0600);err!=nil{t.Fatal(err)}
    err:=switchVerifiedMotorTaskAction(context.Background(),name,original,"/C exit 0",candidate,"",key)
    if err==nil{t.Fatal("unverified motor was allowed to change SYSTEM task")}
    exe,args,checkErr:=(&managedWindowsTaskLab{name:name}).currentAction()
    if checkErr!=nil || !strings.EqualFold(filepath.Clean(exe),filepath.Clean(original)) || args!="/C exit 0" {
        t.Fatalf("task mutated after rejected signature: %s %s %v",exe,args,checkErr)
    }
    if err:=switchVerifiedMotorTaskAction(context.Background(),"UnknownSYSTEMTask",original,"/C exit 0",candidate,"",key);err==nil{
        t.Fatal("arbitrary SYSTEM task allowed")
    }
}

func TestNativeMotorTaskRestoreRejectsTamperedBackup(t *testing.T) {
    name:=fmt.Sprintf("VOLVE-CI-ManagedMotor-%d",time.Now().UnixNano())
    original:=filepath.Join(os.Getenv("WINDIR"),"System32","cmd.exe")
    if err:=createDisposableTask(name,original);err!=nil{t.Fatal(err)}
    t.Cleanup(func(){if err:=removeDisposableTask(name);err!=nil{t.Errorf("cleanup: %v",err)}})
    root:=t.TempDir()
    d:=&managedWindowsTaskLab{name:name,root:root,backup:filepath.Join(root,"original-task.xml")}
    if err:=d.Snapshot(context.Background());err!=nil{t.Fatal(err)}
    data,err:=os.ReadFile(d.backup);if err!=nil{t.Fatal(err)}
    if err:=os.WriteFile(d.backup,append(data,[]byte("<!--tamp-->" )...),0600);err!=nil{t.Fatal(err)}
    if err:=restoreVerifiedMotorTaskXML(context.Background(),name,d.backup,d.originalHash,original,"/C exit 0");err==nil{
        t.Fatal("altered rollback XML was accepted")
    }
    exe,args,err:=d.currentAction()
    if err!=nil || !strings.EqualFold(filepath.Clean(exe),filepath.Clean(original)) || args!="/C exit 0"{
        t.Fatalf("tampered snapshot changed the SYSTEM task: %q %q %v",exe,args,err)
    }
}

func TestNativeMotorTaskProductionSwitchBlockedWithoutWatchdog(t *testing.T) {
    // This intentionally does not query or modify the resident Windows task.
    // It enforces that no future panel caller can accidentally activate a
    // signed candidate before independent motor recovery has been proved.
    err:=switchVerifiedMotorTaskAction(
        context.Background(),dnsServiceTask,
        filepath.Join(os.Getenv("WINDIR"),"System32","not-a-motor.exe"),
        "--dns-service","C:\\invalid\\untrusted.exe","--dns-service",nil,
    )
    if err==nil || !strings.Contains(err.Error(),"watchdog") {
        t.Fatalf("production switch should be mechanically disabled: %v",err)
    }
}
