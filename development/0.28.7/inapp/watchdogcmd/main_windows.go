//go:build windows

// VOLVE 0.28.7 -- independent recovery helper, CI TEST TASKS ONLY.
// This binary is deliberately separate from the updater and cannot affect
// production VOLVE-DNS-SERVER-0270 or any network/DNS setting.
package main

import (
    "bytes"
    "context"
    "crypto/sha256"
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
    "syscall"
    "time"
    "unicode/utf16"
    "encoding/base64"
)

const maxJournal = 8192
const maxXML = 1 << 20
var pilotTaskPattern = regexp.MustCompile(`^VOLVE-CI-ManagedMotor-[0-9]{12,20}$`)
var validSHA = regexp.MustCompile(`^[a-f0-9]{64}$`)

type journal struct {
    Schema int `json:"schema"`
    Phase string `json:"phase"`
    TaskName string `json:"task_name"`
    OriginalExe string `json:"original_exe"`
    OriginalArgs string `json:"original_args"`
    SnapshotFile string `json:"snapshot_file"`
    SnapshotSHA256 string `json:"snapshot_sha256"`
}

func exactJSON(raw []byte, output any) error {
    d:=json.NewDecoder(bytes.NewReader(raw))
    d.DisallowUnknownFields()
    if err:=d.Decode(output);err!=nil{return err}
    var extra any
    if err:=d.Decode(&extra);err!=io.EOF{return errors.New("journal with trailing JSON")}
    return nil
}
func normalFile(path string,max int64) error {
    info,err:=os.Lstat(path);if err!=nil{return err}
    if !info.Mode().IsRegular() || info.Size()<=0 || info.Size()>max {
        return errors.New("expected bounded regular file (no symlink)")
    }
    return nil
}
func safeConfig(j journal) error {
    if j.Schema!=1 || (j.Phase!="pending" && j.Phase!="committed" && j.Phase!="restored"){
        return errors.New("unrecognized recovery phase/schema")
    }
    if !pilotTaskPattern.MatchString(j.TaskName) {
        return errors.New("production or unknown task forbidden")
    }
    winDir:=os.Getenv("WINDIR")
    if winDir=="" || !filepath.IsAbs(winDir) {return errors.New("Windows directory unknown")}
    original:=filepath.Join(winDir,"System32","cmd.exe")
    if !strings.EqualFold(filepath.Clean(j.OriginalExe),filepath.Clean(original)) ||
        j.OriginalArgs!="/C exit 0" {
        return errors.New("original recovery program not allowlisted")
    }
    if !filepath.IsAbs(j.SnapshotFile) || !validSHA.MatchString(j.SnapshotSHA256) {
        return errors.New("invalid original task snapshot reference")
    }
    return nil
}
// Recovery may read only a snapshot inside the directory containing this
// transaction journal. This rejects arbitrary external task XML paths and
// symlinked ancestor directories without confusing valid DOS 8.3 paths
// with junctions (EvalSymlinks can change short-name spelling on Windows).
func guardedSnapshotPath(journalPath,snapshotPath string) error {
 if !filepath.IsAbs(journalPath) || !filepath.IsAbs(snapshotPath) {
  return errors.New("journal/snapshot paths must be absolute")
 }
 root:=filepath.Clean(filepath.Dir(journalPath))
 rel,err:=filepath.Rel(root,filepath.Clean(snapshotPath))
 if err!=nil || rel=="." || rel==".." || filepath.IsAbs(rel) ||
    strings.HasPrefix(rel,".."+string(os.PathSeparator)) {
    return errors.New("snapshot escapes transaction journal directory")
 }
 current:=root
 parts:=strings.Split(rel,string(os.PathSeparator))
 for i,part:=range parts {
   if part=="" || part=="." || part==".." {return errors.New("snapshot path component invalid")}
   current=filepath.Join(current,part)
   info,err:=os.Lstat(current)
   if err!=nil{return err}
   if info.Mode()&os.ModeSymlink!=0 {return errors.New("snapshot path contains link/reparse point")}
   if i<len(parts)-1 && !info.IsDir() {return errors.New("snapshot parent is not a directory")}
   if i==len(parts)-1 && !info.Mode().IsRegular(){return errors.New("snapshot is not a regular file")}
 }
 return nil
}

func readJournal(path string) (journal,error) {
    var j journal
    if !filepath.IsAbs(path) {return j,errors.New("journal path must be absolute")}
    if err:=normalFile(path,maxJournal);err!=nil{return j,err}
    raw,err:=os.ReadFile(path);if err!=nil{return j,err}
    if err:=exactJSON(raw,&j);err!=nil{return journal{},err}
    if err:=safeConfig(j);err!=nil{return journal{},err}
    if err:=guardedSnapshotPath(path,j.SnapshotFile);err!=nil{return journal{},err}
    return j,nil
}
func q(s string) string {return "'"+strings.ReplaceAll(s,"'","''")+"'"}

func ps(ctx context.Context, script string) (string,error) {
    units:=utf16.Encode([]rune(script))
    buf:=make([]byte,2*len(units))
    for i,u:=range units {buf[2*i]=byte(u);buf[2*i+1]=byte(u>>8)}
    arg:=base64.StdEncoding.EncodeToString(buf)
    cmd:=exec.CommandContext(ctx,"powershell.exe","-NoProfile","-NonInteractive","-EncodedCommand",arg)
    cmd.SysProcAttr=&syscall.SysProcAttr{HideWindow:true}
    // PowerShell writes harmless progress XML to STDERR while importing
    // ScheduledTasks. CombinedOutput would corrupt the strict success token
    // and falsely report failure after a successful rollback.
    var stderr bytes.Buffer
    cmd.Stderr=&stderr
    out,err:=cmd.Output()
    if len(out)>8192 {out=out[:8192]}
    if err!=nil {
        reason:=stderr.String()
        if len(reason)>4096{reason=reason[:4096]}
        return strings.TrimSpace(string(out)),fmt.Errorf("PowerShell: %w: %s",err,reason)
    }
    return strings.TrimSpace(string(out)),nil
}
func restore(ctx context.Context,j journal) error {
    if err:=normalFile(j.SnapshotFile,maxXML);err!=nil{return fmt.Errorf("snapshot invalid: %w",err)}
    snapshot,err:=os.ReadFile(j.SnapshotFile);if err!=nil{return err}
    got:=sha256.Sum256(snapshot)
    if hex.EncodeToString(got[:])!=j.SnapshotSHA256 {
        return errors.New("snapshot SHA256 mismatch: refusing to restore")
    }
    // Verify both the backed-up task and the live task are SYSTEM-owned,
    // single-action pilot tasks before changing the Task Scheduler. Never
    // unregister or touch any other task.
    script:=`$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';`+
      `$n=`+q(j.TaskName)+`;$snap=`+q(j.SnapshotFile)+`;`+
      `$expected=`+q(j.OriginalExe)+`;$args=`+q(j.OriginalArgs)+`;`+
      `$expectedHash=`+q(j.SnapshotSHA256)+`;`+
      `$snapshotBytes=[IO.File]::ReadAllBytes($snap);`+
      `$hasher=[Security.Cryptography.SHA256]::Create();`+
      `try{$actualHash=[BitConverter]::ToString($hasher.ComputeHash($snapshotBytes)).Replace('-','').ToLowerInvariant()}finally{$hasher.Dispose()};`+
      `if($actualHash -cne $expectedHash){throw 'Snapshot changed since Go verification'};`+
      `$saved=[Text.UTF8Encoding]::new($false,$true).GetString($snapshotBytes);`+
      `$parsed=[xml]$saved;`+
      `$owner=[string]$parsed.Task.Principals.Principal.UserId;`+
      `$execs=@($parsed.Task.Actions.Exec);`+
      `if($owner -notin @('SYSTEM','S-1-5-18') -or $execs.Count -ne 1 -or `+
        `[string]$execs[0].Command -ine $expected -or [string]$execs[0].Arguments -ne $args){throw 'Backup task identity mismatch'};`+
      `$current=Get-ScheduledTask -TaskName $n -ErrorAction Stop;`+
      `if($current.TaskPath -ne '\' -or $current.Principal.UserId -notin @('SYSTEM','S-1-5-18') `+
        `-or @($current.Actions).Count -ne 1){throw 'Live task identity mismatch'};`+
      `Register-ScheduledTask -TaskName $n -Xml $saved -Force -ErrorAction Stop | Out-Null;`+
      `$restored=Get-ScheduledTask -TaskName $n -ErrorAction Stop;`+
      `if($restored.TaskPath -ne '\' -or $restored.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or `+
        `@($restored.Actions).Count -ne 1 -or $restored.Actions[0].Execute -ine $expected `+
        `-or $restored.Actions[0].Arguments -ne $args){throw 'Task not restored after import'};`+
      `Write-Output 'RECOVERED'`
    output,err:=ps(ctx,script)
    if err!=nil{return fmt.Errorf("independent task recovery error: %s: %w",output,err)}
    if output!="RECOVERED" {return fmt.Errorf("ambiguous recovery result: %q",output)}
    return nil
}

func savePhase(path string,j journal) error {
    raw,err:=json.Marshal(j);if err!=nil{return err}
    dir:=filepath.Dir(path)
    f,err:=os.CreateTemp(dir,".volve-ci-recovery-*")
    if err!=nil{return err}
    defer os.Remove(f.Name())
    if err=f.Chmod(0600);err!=nil{f.Close();return err}
    if _,err=f.Write(append(raw,'\n'));err!=nil{f.Close();return err}
    if err=f.Sync();err!=nil{f.Close();return err}
    if err=f.Close();err!=nil{return err}
    return os.Rename(f.Name(),path)
}
func run(ctx context.Context,path string) error {
    j,err:=readJournal(path);if err!=nil{return err}
    // Recovery is privileged, so even "committed" and "restored" markers
    // cannot be trusted if the journal can be changed by an ordinary user.
    // Fail before any Task Scheduler access or journal modification.
    if err:=verifyRecoveryACL(ctx,path,j.SnapshotFile);err!=nil{
        return fmt.Errorf("recovery transaction ACL not trusted: %w",err)
    }
    switch j.Phase {
    case "committed","restored":return nil
    case "pending":
        if err:=restore(ctx,j);err!=nil{return err}
        j.Phase="restored"
        return savePhase(path,j)
    default:return errors.New("invalid phase")
    }
}
func main(){
    if len(os.Args)!=3 || os.Args[1]!="--recover-pilot-journal"{
        fmt.Fprintln(os.Stderr,"usage: volve-managed-watchdog --recover-pilot-journal <ABSOLUTE-JOURNAL>; no production tasks allowed")
        os.Exit(2)
    }
    ctx,cancel:=context.WithTimeout(context.Background(),90*time.Second);defer cancel()
    if err:=run(ctx,os.Args[2]);err!=nil{
        fmt.Fprintln(os.Stderr,"VOLVE CI MOTOR RECOVERY FAILED:",err)
        os.Exit(1)
    }
    fmt.Println("RECOVERY CHECK COMPLETE")
}
