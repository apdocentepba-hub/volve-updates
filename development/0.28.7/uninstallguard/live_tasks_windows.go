//go:build windows

package uninstallguard

// Real Windows Task Scheduler read-only ownership audit. This runs in the
// auditing process and has no task registration/deletion, DNS or file writes.
import (
    "bytes"
    "context"
    "crypto/ed25519"
    "encoding/base64"
    "encoding/binary"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "os"
    "os/exec"
    "path/filepath"
    "time"
    "unicode/utf16"
)

type windowsTaskSnapshot struct {
    Schema int `json:"schema"`
    Tasks []ObservedTask `json:"tasks"`
}

func liveWindowsVolveTasks(ctx context.Context)([]ObservedTask,error){
    if ctx==nil{return nil,errors.New("task audit context required")}
    if err:=ctx.Err();err!=nil{return nil,err}
    systemRoot:=os.Getenv("SystemRoot")
    if !filepath.IsAbs(systemRoot) || filepath.Clean(systemRoot)!=systemRoot {
        return nil,errors.New("Windows system root unavailable")
    }
    powershell:=filepath.Join(systemRoot,"System32","WindowsPowerShell","v1.0","powershell.exe")
    modules:=filepath.Join(systemRoot,"System32","WindowsPowerShell","v1.0","Modules")
    if st,err:=os.Stat(modules);err!=nil||!st.IsDir(){
        return nil,errors.New("canonical Windows PowerShell modules unavailable")
    }
    // No caller-supplied PowerShell expressions. Query ALL VOLVE tasks so
    // unlisted legacy/additional entries make exact ownership fail closed.
    const script = `$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';`+
        `$found=@(Get-ScheduledTask -ErrorAction Stop | Where-Object {$_.TaskName -match '^(?i:VOLVE[-_])'});`+
        `$entries=@();foreach($task in $found){`+
        `$actions=@($task.Actions);if($actions.Count -ne 1){throw 'multi-action VOLVE task refused'};`+
        `$xml=Export-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop;`+
        `$act=[ordered]@{execute=[string]$actions[0].Execute;arguments=[string]$actions[0].Arguments;working_directory=[string]$actions[0].WorkingDirectory};`+
        `$entries+=([ordered]@{name=[string]$task.TaskName;task_path=[string]$task.TaskPath;principal=[string]$task.Principal.UserId;xml=[string]$xml;action=$act})`+
        `};ConvertTo-Json -InputObject ([ordered]@{schema=1;tasks=@($entries)}) -Depth 8 -Compress`
    chars:=utf16.Encode([]rune(script))
    encoded:=make([]byte,len(chars)*2)
    for i,v:=range chars{binary.LittleEndian.PutUint16(encoded[2*i:],v)}
    limited,cancel:=context.WithTimeout(ctx,45*time.Second)
    defer cancel()
    cmd:=exec.CommandContext(limited,powershell,"-NoProfile","-NonInteractive","-EncodedCommand",base64.StdEncoding.EncodeToString(encoded))
    cmd.Env=append(os.Environ(),"PSModulePath="+modules)
    out,err:=cmd.CombinedOutput()
    if err!=nil{return nil,fmt.Errorf("Windows scheduled-task audit unavailable: %w",err)}
    if len(out)==0 || len(out)>8<<20 {return nil,errors.New("Windows task inventory output invalid size")}
    dec:=json.NewDecoder(bytes.NewReader(out))
    dec.DisallowUnknownFields()
    var snapshot windowsTaskSnapshot
    if err:=dec.Decode(&snapshot);err!=nil{return nil,fmt.Errorf("Windows task inventory ambiguous: %w",err)}
    var extra any
    if dec.Decode(&extra)!=io.EOF{return nil,errors.New("Windows task inventory contains extra output")}
    if snapshot.Schema!=1 || snapshot.Tasks==nil{return nil,errors.New("Windows task snapshot incomplete")}
    if len(snapshot.Tasks)>64{return nil,errors.New("excessive VOLVE task inventory, manual audit required")}
    return snapshot.Tasks,nil
}

// AuditSignedInstalledTasksReadOnly requires an authentic installed-receipt
// signature before querying Task Scheduler. Even if all task hashes match,
// it CANNOT authorize any task removal or process, DNS or browser change.
func AuditSignedInstalledTasksReadOnly(ctx context.Context,raw,signature []byte,trusted ed25519.PublicKey)(InstalledTasksAudit,error) {
    var rejected InstalledTasksAudit
    receipt,err:=VerifySignedInstalledReceipt(raw,signature,trusted)
    if err!=nil{return rejected,err}
    observed,err:=liveWindowsVolveTasks(ctx)
    if err!=nil{return rejected,err}
    return auditReceiptTasksAgainstObservation(ctx,receipt,observed)
}
