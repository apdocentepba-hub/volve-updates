//go:build windows

package uninstallguard

import (
    "bytes"
    "context"
    "encoding/base64"
    "encoding/binary"
    "encoding/json"
    "errors"
    "fmt"
    "os"
    "os/exec"
    "path/filepath"
    "strings"
    "time"
    "unicode/utf16"
)

// InspectWindowsReadOnly queries actual Task Scheduler, services, DNS and
// browser policy registry state. It makes no changes to the host whatsoever.
// Do not treat its output as a signed ownership or uninstall permission.
func InspectWindowsReadOnly(ctx context.Context) (Evidence,error) {
    var zero Evidence
    if ctx==nil {return zero,errors.New("non-nil context required")}
    if err:=ctx.Err();err!=nil{return zero,err}
    systemRoot:=os.Getenv("SystemRoot")
    if !filepath.IsAbs(systemRoot) || filepath.Clean(systemRoot)!=systemRoot {
        return zero,errors.New("trusted Windows system root missing")
    }
    powershell:=filepath.Join(systemRoot,"System32","WindowsPowerShell","v1.0","powershell.exe")
    modules:=filepath.Join(systemRoot,"System32","WindowsPowerShell","v1.0","Modules")
    if fi,err:=os.Stat(modules);err!=nil||!fi.IsDir(){return zero,errors.New("canonical Windows PowerShell modules unavailable")}

    // Fixed command only: no caller-supplied task names, paths, or executable
    // arguments. Read-only ScheduledTasks, CIM, NetTCPIP and registry queries.
    const script = `$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';` +
        `$t=@(Get-ScheduledTask -ErrorAction Stop | Where-Object {$_.TaskName -match '(?i)^VOLVE[-_]' });` +
        `$legacy=@('VOLVE-CATALOGO-0230','VOLVE-DNS-RESCUE-0270','VOLVE-DNS-SERVER-0270');` +
        `$l=@($t | Where-Object {$_.TaskName -in $legacy});` +
        `$s=@(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object {$_.Name -match '(?i)^VOLVE[-_]'});` +
        `$udp=@(Get-NetUDPEndpoint -ErrorAction Stop | Where-Object {$_.LocalPort -eq 53});` +
        `$tcp=@(Get-NetTCPConnection -ErrorAction Stop | Where-Object {$_.LocalPort -eq 53 -and $_.State -eq 'Listen'});` +
        `$d=@(Get-DnsClientServerAddress -ErrorAction Stop);` +
        `$loop=$false;foreach($x in $d){foreach($ip in @($x.ServerAddresses)){if($ip -eq '127.0.0.1' -or $ip -eq '::1'){$loop=$true}}};` +
        `$roots=@(Join-Path $env:ProgramData 'VOLVE-Browser-Filter',Join-Path $env:ProgramData 'VOLVE-DNS-Recovery');` +
        `$dataCount=@($roots | Where-Object {Test-Path -LiteralPath $_}).Count;` +
        `$rec=Test-Path -LiteralPath (Join-Path $env:ProgramData 'VOLVE-DNS-Recovery');` +
        `$proot=Test-Path -LiteralPath (Join-Path $env:ProgramFiles 'VOLVE');` +
        `$policyPaths=@('HKLM:\\SOFTWARE\\Policies\\Google\\Chrome\\URLBlocklist','HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge\\URLBlocklist','HKLM:\\SOFTWARE\\Policies\\Mozilla\\Firefox');` +
        `$policyCount=@($policyPaths | Where-Object {Test-Path -LiteralPath $_}).Count;` +
        `$pr=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent());` +
        `$admin=$pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);` +
        `$out=[ordered]@{schema=1;complete=$true;elevated=$admin;legacy_tasks=$l.Count;other_volve_tasks=($t.Count-$l.Count);volve_services=$s.Count;udp53_listeners=$udp.Count;tcp53_listeners=$tcp.Count;dns_loopback=$loop;programfiles_root=$proot;programdata_residues=$dataCount;browser_policy_stores=$policyCount;recovery_journal_present=$rec};` +
        `ConvertTo-Json -InputObject $out -Compress -Depth 4`
    units:=utf16.Encode([]rune(script))
    command:=make([]byte,2*len(units))
    for i,v:=range units{binary.LittleEndian.PutUint16(command[2*i:],v)}
    sub,cancel:=context.WithTimeout(ctx,40*time.Second)
    defer cancel()
    cmd:=exec.CommandContext(sub,powershell,"-NoProfile","-NonInteractive","-EncodedCommand",base64.StdEncoding.EncodeToString(command))
    cmd.Env=append(os.Environ(),"PSModulePath="+modules)
    out,err:=cmd.CombinedOutput()
    if err!=nil{return zero,fmt.Errorf("Windows read-only uninstall inventory failed: %w",err)}
    if len(out)>8192 || len(bytes.TrimSpace(out))==0 {return zero,errors.New("invalid native Windows census output length")}
    dec:=json.NewDecoder(bytes.NewReader(out));dec.DisallowUnknownFields()
    var e Evidence
    if err:=dec.Decode(&e);err!=nil{return zero,fmt.Errorf("Windows census JSON refused: %w",err)}
    // Native script emits all known fields; no user-controlled input or flags
    // are accepted as a source of install receipts or publisher permissions.
    if !e.Complete || e.Schema!=1 {return zero,errors.New("native Windows census incomplete")}
    // Also ensure a later command never treats the command's first JSON object
    // as valid if warnings or attacker-controlled text follows it.
    if strings.Count(string(out),"{")!=1 || strings.Count(string(out),"}")!=1 {
        return zero,errors.New("ambiguous native Windows census output")
    }
    return e,nil
}
