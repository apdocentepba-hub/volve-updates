# VOLVE 0.28.7 - OFFLINE LAB ONLY. Never deploy on a personal or production PC.
# Prepares and verifies a disposable Windows Scheduled Task recovery across REAL VM reboot.
# This script DOES NOT reboot a machine, change DNS, touch VOLVE production tasks,
# alter browser policies, or run any actual DNS engine.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('Probe','Prepare','Verify','Cleanup')]
    [string]$Mode,
    [ValidatePattern('^[0-9]{14,18}$')]
    [string]$RunId,
    [string]$LabScript,
    [string]$JournalExe
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-DisposableVM {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $admin = ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $description = ($cs.Manufacturer + ' ' + $cs.Model)
    $vmMarkers = @('Virtual Machine','VMware','VirtualBox','KVM','QEMU','Xen','HVM domU','Parallels','Hyper-V')
    $isVM = $false
    foreach($marker in $vmMarkers) {
        if($description.IndexOf($marker,[StringComparison]::OrdinalIgnoreCase) -ge 0) {$isVM=$true;break}
    }
    if(-not $isVM) {throw 'REFUSED: the computer is not positively identified as a VM. Never run this on a personal PC.'}
    if(-not $admin) {throw 'REFUSED: this isolated VM trial requires an elevated PowerShell.'}
    Write-Host ('VM identified: '+$description)
}
function BootTimeUTC {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    # DMTF/CIM usually provides a DateTime expressed in the VM local time zone.
    return ([datetime]$os.LastBootUpTime).ToUniversalTime()
}
function Get-KitPath([string]$id) {
    if($id -cnotmatch '^[0-9]{14,18}$') {throw 'Unsafe trial identifier'}
    return (Join-Path $env:ProgramData ('VOLVE-VM-RebootLab-'+$id))
}
function Assert-ProtectedDir([string]$dir) {
    $acl = Get-Acl -LiteralPath $dir
    $allowed = @('S-1-5-18','S-1-5-32-544')
    foreach ($ace in $acl.Access) {
        $sid = $null
        try { $sid = $ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value }
        catch { throw 'Unresolved identity in laboratory ACL' }
        if($ace.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and $sid -notin $allowed) {
            throw ('Unsafe lab directory ACL allows '+$sid)
        }
    }
}
function Protect-Kit([string]$dir) {
    & icacls.exe $dir '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if($LASTEXITCODE -ne 0){throw 'Cannot protect the VM trial folder; refusing to proceed'}
    Assert-ProtectedDir $dir
}
function Read-Metadata([string]$dir) {
    $path = Join-Path $dir 'vm-trial.json'
    if(-not (Test-Path -LiteralPath $path -PathType Leaf)) {throw 'No prepared VM trial metadata'}
    $data = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    if($data.schema -ne 1 -or $data.runId -ne $RunId -or $data.computer -ne $env:COMPUTERNAME) {throw 'VM trial metadata mismatch'}
    foreach($member in @('bootBeforeUtc','labSha256','journalSha256')) {
        if(-not ($data.$member -is [string]) -or [string]::IsNullOrWhiteSpace($data.$member)){throw ('Missing '+$member)}
    }
    return $data
}
function Assert-LabIdentity([string]$dir,[object]$meta) {
    Assert-ProtectedDir $dir
    $lab=Join-Path $dir 'boot_recovery_lab.ps1'
    $helper=Join-Path $dir 'volve-journal-lab.exe'
    if(-not (Test-Path -LiteralPath $lab -PathType Leaf) -or -not (Test-Path -LiteralPath $helper -PathType Leaf)) {throw 'Missing protected VM test tools'}
    if((Get-FileHash -Algorithm SHA256 -LiteralPath $lab).Hash -ne $meta.labSha256) {throw 'VM lab script was changed'}
    if((Get-FileHash -Algorithm SHA256 -LiteralPath $helper).Hash -ne $meta.journalSha256) {throw 'VM journal tool was changed'}
}
function Assert-LabTask([string]$name,[string]$expectedPath) {
    $task=Get-ScheduledTask -TaskName $name -ErrorAction Stop
    if($task.TaskPath -ne '\' -or $task.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or @($task.Actions).Count -ne 1) {throw 'Unexpected ownership or task path'}
    if(@($task.Actions)[0].Execute -ne $expectedPath) {throw 'Unexpected task action executable'}
    return $task
}

Assert-DisposableVM
if($Mode -eq 'Probe') {
    Write-Host 'PASS: isolated VM detected, elevated PowerShell available. No changes made.'
    return
}
if([string]::IsNullOrWhiteSpace($RunId)) {
    if($Mode -ne 'Prepare') {throw '-RunId is mandatory for Verify and Cleanup'}
    $RunId=(Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss') + (Get-Random -Minimum 100 -Maximum 999).ToString()
}
$kit=Get-KitPath $RunId
$labTask='VOLVE-CI-StartupMotor-'+$RunId
$bootTask='VOLVE-CI-BootRecovery-'+$RunId
$root=Join-Path $kit ('VOLVE-CI-BOOT-'+$RunId)
$cmd=Join-Path $env:WINDIR 'System32\cmd.exe'

if($Mode -eq 'Prepare') {
    if(-not (Test-Path -LiteralPath $LabScript -PathType Leaf) -or -not (Test-Path -LiteralPath $JournalExe -PathType Leaf)) {throw 'Pass valid -LabScript and -JournalExe development paths'}
    if(Test-Path -LiteralPath $kit) {throw 'Trial already exists. Refusing to overwrite a staged recovery.'}
    if(Get-ScheduledTask -TaskName $labTask -ErrorAction SilentlyContinue){throw 'Disposable motor task name already in use'}
    if(Get-ScheduledTask -TaskName $bootTask -ErrorAction SilentlyContinue){throw 'Disposable watchdog task name already in use'}
    New-Item -ItemType Directory -Path $kit -ErrorAction Stop | Out-Null
    Protect-Kit $kit
    $copiedLab=Join-Path $kit 'boot_recovery_lab.ps1'
    $copiedJournal=Join-Path $kit 'volve-journal-lab.exe'
    Copy-Item -LiteralPath $LabScript -Destination $copiedLab -ErrorAction Stop
    Copy-Item -LiteralPath $JournalExe -Destination $copiedJournal -ErrorAction Stop
    $before=BootTimeUTC
    $metadata=[ordered]@{
        schema=1;runId=$RunId;computer=$env:COMPUTERNAME;
        bootBeforeUtc=$before.ToString('o');
        labSha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $copiedLab).Hash;
        journalSha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $copiedJournal).Hash;
    }
    $metadata | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $kit 'vm-trial.json') -Encoding UTF8
    & $copiedLab -Mode stage -TaskName $labTask -WatchdogName $bootTask -Workspace $root -JournalExe $copiedJournal
    if($LASTEXITCODE -ne 0){throw 'Failed to stage isolated VM recovery trial'}
    $watch=Get-ScheduledTask -TaskName $bootTask
    if(@($watch.Triggers).Count -ne 1 -or $watch.Triggers[0].CimClass.CimClassName -ne 'MSFT_TaskBootTrigger'){throw 'Recovery task has no boot trigger'}
    Assert-ProtectedDir $kit
    Write-Host ''
    Write-Host ('PREPARED: VM-only trial id = '+$RunId)
    Write-Host 'NEXT: take a VM snapshot, restart THIS TEST VM manually, then invoke -Mode Verify -RunId <id>.'
    Write-Host 'There is no reboot command in this script. Do not use on a personal computer.'
    return
}

if(-not (Test-Path -LiteralPath $kit -PathType Container)){throw 'Trial folder not found'}
$meta=Read-Metadata $kit
Assert-LabIdentity $kit $meta

if($Mode -eq 'Verify') {
    $before=[DateTime]::Parse($meta.bootBeforeUtc,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind)
    $now=BootTimeUTC
    if($now -le $before.AddSeconds(5)) {throw 'NOT VERIFIED: VM has not undergone a new boot since the trial was prepared'}
    $watch=Get-ScheduledTask -TaskName $bootTask -ErrorAction Stop
    if($watch.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or @($watch.Triggers).Count -ne 1 -or $watch.Triggers[0].CimClass.CimClassName -ne 'MSFT_TaskBootTrigger') {throw 'Unexpected watchdog task identity/trigger'}
    $taskInfo=Get-ScheduledTaskInfo -TaskName $bootTask -ErrorAction Stop
    if($taskInfo.LastTaskResult -ne 0 -or $taskInfo.LastRunTime.ToUniversalTime() -lt $now.AddSeconds(-3)) {throw 'No successful watchdog execution associated with this boot'}
    $task=Assert-LabTask $labTask $cmd
    if($task.Actions[0].Arguments -ne '/C exit 0') {throw 'Original harmless task arguments not recovered'}
    $mark=Join-Path $root 'boot-recovery-success.marker'
    if(-not (Test-Path -LiteralPath $mark -PathType Leaf) -or [IO.File]::ReadAllText($mark) -ne 'RESTORED_BY_SYSTEM_STARTUP_TASK'){throw 'No verified SYSTEM recovery marker'}
    if(Test-Path -LiteralPath (Join-Path $root 'boot-recovery-failed.marker')){throw 'Watchdog reported recovery failure'}
    $helper=Join-Path $kit 'volve-journal-lab.exe'
    $journal=Join-Path $root 'recovery.json'
    $status=& $helper status $journal
    if($LASTEXITCODE -ne 0 -or $status -ne 'NO_ROLLBACK:restored') {throw 'Recovery journal is not in restored state'}
    [IO.File]::WriteAllText((Join-Path $kit 'vm-proof-success.txt'),('Verified UTC: '+[DateTime]::UtcNow.ToString('o')+'; boot UTC: '+$now.ToString('o')))
    Write-Host 'PASS: actual VM reboot detected and SYSTEM startup watchdog restored the disposable original task.'
    Write-Host ('Evidence stored in '+$kit)
    return
}

if($Mode -eq 'Cleanup') {
    $watch=Get-ScheduledTask -TaskName $bootTask -ErrorAction SilentlyContinue
    if($watch){
        if($watch.TaskPath -ne '\' -or $watch.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or @($watch.Actions).Count -ne 1){throw 'Refusing to delete unexpected recovery task'}
        $a=$watch.Actions[0]
        $expectedPS=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
        if($a.Execute -ne $expectedPS -or $a.Arguments.IndexOf($kit,[StringComparison]::OrdinalIgnoreCase) -lt 0){
            throw 'Unexpected recovery task command; refusing deletion'
        }
        Unregister-ScheduledTask -TaskName $bootTask -Confirm:$false
    }
    $motor=Get-ScheduledTask -TaskName $labTask -ErrorAction SilentlyContinue
    if($motor){
        $a=@($motor.Actions)[0]
        $allow=@($cmd,(Join-Path $env:WINDIR 'System32\notepad.exe'))
        if($motor.TaskPath -ne '\' -or $motor.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or @($motor.Actions).Count -ne 1 -or $a.Execute -notin $allow){throw 'Refusing to delete unexpected motor task'}
        Unregister-ScheduledTask -TaskName $labTask -Confirm:$false
    }
    Write-Host ('CLEAN: only disposable VM lab tasks unregistered. Evidence remains at '+$kit)
}
