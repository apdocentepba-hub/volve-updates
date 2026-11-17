# VOLVE 0.28.7 - OFFLINE LAB ONLY. Never deploy on a personal or production PC.
# Prepares and verifies a disposable Windows Scheduled Task recovery across REAL VM reboot.
# This script DOES NOT reboot a machine, change DNS, touch VOLVE production tasks,
# alter browser policies, or run any actual DNS engine.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('Probe','Prepare','AuditPrepared','Verify','Cleanup')]
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
    if(-not [IO.Directory]::Exists($dir)){throw 'Protected VM trial directory is missing'}
    $attributes=[IO.File]::GetAttributes($dir)
    if(($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){
        throw 'Protected VM trial directory is a Windows reparse point'
    }
    $acl=Get-Acl -LiteralPath $dir -ErrorAction Stop
    $allowed=@('S-1-5-18','S-1-5-32-544')
    $owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if($owner -notin $allowed){throw ('Untrusted VM trial directory owner: '+$owner)}
    if(-not $acl.AreAccessRulesProtected){throw 'VM trial directory DACL inherits untrusted parent permissions'}
    $full=[int][Security.AccessControl.FileSystemRights]::FullControl
    $confirmed=@{}
    foreach($ace in @($acl.Access)){
        $sid=$null
        try{$sid=$ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value}
        catch{throw 'Unresolved identity in VM trial directory ACL'}
        if($ace.IsInherited -or
           $ace.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
           $sid -notin $allowed){
            throw ('Foreign, inherited or DENY VM trial DACL entry: '+$sid)
        }
        if((([int]$ace.FileSystemRights -band $full) -eq $full)){
            $confirmed[$sid]=$true
        }
    }
    foreach($sid in $allowed){
        if(-not $confirmed.ContainsKey($sid)){
            throw ('Missing explicit SYSTEM/Administrators FullControl for '+$sid)
        }
    }
}
# Read-only trust check for every file used to attest a real reboot.
# Files may inherit the ALREADY VERIFIED protected parent DACL; however an
# explicit file-level foreign ACE, untrusted owner, or reparse point is fatal.
function Assert-ProtectedEvidenceFile([string]$path) {
    if(-not [IO.File]::Exists($path)){throw ('Missing protected VM evidence file: '+$path)}
    $attributes=[IO.File]::GetAttributes($path)
    if(($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){
        throw 'VM evidence file is a reparse point'
    }
    $acl=Get-Acl -LiteralPath $path -ErrorAction Stop
    $allowed=@('S-1-5-18','S-1-5-32-544')
    $owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if($owner -notin $allowed){throw ('Untrusted VM evidence file owner: '+$owner)}
    $full=[int][Security.AccessControl.FileSystemRights]::FullControl
    $confirmed=@{}
    foreach($ace in @($acl.Access)){
        $sid=$null
        try{$sid=$ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value}
        catch{throw 'Unresolved VM evidence file trustee'}
        if($ace.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
           $sid -notin $allowed){
            throw ('Foreign or DENY VM evidence file DACL entry: '+$sid)
        }
        if((([int]$ace.FileSystemRights -band $full) -eq $full)){
            $confirmed[$sid]=$true
        }
    }
    foreach($sid in $allowed){
        if(-not $confirmed.ContainsKey($sid)){
            throw ('Missing SYSTEM/Administrators full access to VM evidence file: '+$sid)
        }
    }
}
function Protect-Kit([string]$dir) {
    # icacls numerical SID operands require a leading * (Microsoft syntax).
    & icacls.exe $dir '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if($LASTEXITCODE -ne 0){throw 'Cannot protect the VM trial folder DACL; refusing to proceed'}
    & icacls.exe $dir '/setowner' '*S-1-5-32-544' | Out-Null
    if($LASTEXITCODE -ne 0){throw 'Cannot set protected VM trial owner; refusing to proceed'}
    Assert-ProtectedDir $dir
}
function Read-Metadata([string]$dir) {
    $path = Join-Path $dir 'vm-trial.json'
    Assert-ProtectedDir $dir
    Assert-ProtectedEvidenceFile $path
    $data = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    if($data.schema -ne 1 -or $data.runId -ne $RunId -or $data.computer -ne $env:COMPUTERNAME) {throw 'VM trial metadata mismatch'}
    foreach($member in @('bootBeforeUtc','labSha256','journalSha256','evidenceLibSha256','taskSnapshotSha256','originalFixtureSha256','watchdogTaskSnapshotSha256','cleanupContractSha256')) {
        if($null -eq $data.$member -or [string]::IsNullOrWhiteSpace([string]$data.$member)){throw ('Missing '+$member)}
    }
    return $data
}
function Assert-LabIdentity([string]$dir,[object]$meta) {
    Assert-ProtectedDir $dir
    $lab=Join-Path $dir 'boot_recovery_lab.ps1'
    $helper=Join-Path $dir 'volve-journal-lab.exe'
    Assert-ProtectedEvidenceFile $lab
    Assert-ProtectedEvidenceFile $helper
    if((Get-FileHash -Algorithm SHA256 -LiteralPath $lab).Hash -ne $meta.labSha256) {throw 'VM lab script was changed'}
    if((Get-FileHash -Algorithm SHA256 -LiteralPath $helper).Hash -ne $meta.journalSha256) {throw 'VM journal tool was changed'}
    $cleanupContract=Join-Path $dir 'vm_cleanup_state_contract.ps1'
    Assert-ProtectedEvidenceFile $cleanupContract
    if((Get-FileHash -Algorithm SHA256 -LiteralPath $cleanupContract).Hash -cne [string]$meta.cleanupContractSha256){
        throw 'VM cleanup contract was changed after preparing the VM trial'
    }
    $evidenceLib=Join-Path $dir 'reboot_event_chain.ps1'
    Assert-ProtectedEvidenceFile $evidenceLib
    if((Get-FileHash -Algorithm SHA256 -LiteralPath $evidenceLib).Hash -ne $meta.evidenceLibSha256){
        throw 'Boot-event verification helper was changed after preparing the VM trial'
    }
    # Pin the exact original fixture bytes independently of the rollback
    # journal. Otherwise a modified XML/engine could be silently accepted
    # when the verifier first runs after the VM restarts.
    $taskSnapshot=Join-Path $dir ('VOLVE-CI-BOOT-'+$RunId)
    $originalXML=Join-Path $taskSnapshot 'old-task.xml'
    $oldFixture=Join-Path $taskSnapshot 'old-test-engine.bin'
    $codeSeal=Join-Path $taskSnapshot 'recovery-code-seal.json'
    $watchdogXML=Join-Path $dir 'watchdog-task.xml'
    Assert-ProtectedEvidenceFile $watchdogXML
    if((Get-FileHash -Algorithm SHA256 -LiteralPath $watchdogXML).Hash -cne [string]$meta.watchdogTaskSnapshotSha256){
        throw 'Protected startup watchdog XML snapshot hash mismatch'
    }
    Assert-ProtectedEvidenceFile $codeSeal
    $seal=Get-Content -LiteralPath $codeSeal -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if($seal.schema -ne 1 -or $seal.taskName -cne ('VOLVE-CI-StartupMotor-'+$RunId) -or
       $seal.watchdogName -cne ('VOLVE-CI-BootRecovery-'+$RunId) -or
       $seal.workspace -cne $taskSnapshot -or
       [string]$seal.labScriptSha256 -cne [string]$meta.labSha256 -or
       [string]$seal.journalHelperSha256 -cne [string]$meta.journalSha256 -or
       [string]$seal.verificationLibSha256 -cne [string]$meta.evidenceLibSha256 -or
       [string]$seal.originalTaskXMLSha256 -cne [string]$meta.taskSnapshotSha256 -or
       [string]$seal.previousFixtureSha256 -cne [string]$meta.originalFixtureSha256){
        throw 'Protected recovery code seal does not match independent VM trial metadata'
    }
    Assert-ProtectedEvidenceFile $originalXML
    Assert-ProtectedEvidenceFile $oldFixture
    if((Get-FileHash -Algorithm SHA256 -LiteralPath $originalXML).Hash -cne [string]$meta.taskSnapshotSha256){
        throw 'Original XML snapshot hash mismatch since VM Prepare'
    }
    if((Get-FileHash -Algorithm SHA256 -LiteralPath $oldFixture).Hash -cne [string]$meta.originalFixtureSha256){
        throw 'Original motor fixture hash mismatch since VM Prepare'
    }
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
    if($Mode -ne 'Prepare') {throw '-RunId is mandatory for AuditPrepared, Verify and Cleanup'}
    $RunId=(Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss') + (Get-Random -Minimum 100 -Maximum 999).ToString()
}
$kit=Get-KitPath $RunId
$labTask='VOLVE-CI-StartupMotor-'+$RunId
$bootTask='VOLVE-CI-BootRecovery-'+$RunId
$root=Join-Path $kit ('VOLVE-CI-BOOT-'+$RunId)
$cmd=Join-Path $env:WINDIR 'System32\cmd.exe'

if($Mode -eq 'Prepare') {
    # VM-only readiness: without prior Task Scheduler history, an actual
    # startup trigger cannot be distinguished from a manual Start-ScheduledTask.
    $taskLog=Get-WinEvent -ListLog 'Microsoft-Windows-TaskScheduler/Operational' -ErrorAction Stop
    if(-not $taskLog.IsEnabled) {throw 'REFUSED: enable Task Scheduler Operational history in the isolated VM before Prepare'}
    if(-not (Test-Path -LiteralPath $LabScript -PathType Leaf) -or -not (Test-Path -LiteralPath $JournalExe -PathType Leaf)) {throw 'Pass valid -LabScript and -JournalExe development paths'}
    $sourceEvidenceLib=Join-Path $PSScriptRoot 'reboot_event_chain.ps1'
    if(-not (Test-Path -LiteralPath $sourceEvidenceLib -PathType Leaf)){throw 'Missing boot-event correlation library; fail before staging'}

    if(Test-Path -LiteralPath $kit) {throw 'Trial already exists. Refusing to overwrite a staged recovery.'}
    if(Get-ScheduledTask -TaskName $labTask -ErrorAction SilentlyContinue){throw 'Disposable motor task name already in use'}
    if(Get-ScheduledTask -TaskName $bootTask -ErrorAction SilentlyContinue){throw 'Disposable watchdog task name already in use'}
    New-Item -ItemType Directory -Path $kit -ErrorAction Stop | Out-Null
    Protect-Kit $kit
    $copiedLab=Join-Path $kit 'boot_recovery_lab.ps1'
    $copiedJournal=Join-Path $kit 'volve-journal-lab.exe'
    Copy-Item -LiteralPath $LabScript -Destination $copiedLab -ErrorAction Stop
    Copy-Item -LiteralPath $JournalExe -Destination $copiedJournal -ErrorAction Stop
    $copiedEvidenceLib=Join-Path $kit 'reboot_event_chain.ps1'
    Copy-Item -LiteralPath $sourceEvidenceLib -Destination $copiedEvidenceLib -ErrorAction Stop
    $copiedCleanupContract=Join-Path $kit 'vm_cleanup_state_contract.ps1'
    $sourceCleanupContract=Join-Path $PSScriptRoot 'vm_cleanup_state_contract.ps1'
    if(-not (Test-Path -LiteralPath $sourceCleanupContract -PathType Leaf)){
        throw 'Missing VM cleanup contract before staging; refusing trial'
    }
    Copy-Item -LiteralPath $sourceCleanupContract -Destination $copiedCleanupContract -ErrorAction Stop
    $before=BootTimeUTC
    & $copiedLab -Mode stage -TaskName $labTask -WatchdogName $bootTask -Workspace $root -JournalExe $copiedJournal
    if($LASTEXITCODE -ne 0){throw 'Failed to stage isolated VM recovery trial'}
    # Only record a ready-to-verify metadata receipt AFTER the protected
    # snapshot has actually been staged and the boot watchdog armed.
    $originalXML=Join-Path $root 'old-task.xml'
    $oldFixture=Join-Path $root 'old-test-engine.bin'
    # The watchdog itself is a privileged execution surface. Snapshot ALL
    # its settings, including executable/arguments, not merely SYSTEM+boot.
    $startupXML=Export-ScheduledTask -TaskName $bootTask -TaskPath '\' -ErrorAction Stop
    $startupXMLPath=Join-Path $kit 'watchdog-task.xml'
    [IO.File]::WriteAllText($startupXMLPath,[string]$startupXML,[Text.UTF8Encoding]::new($false))
    Assert-ProtectedEvidenceFile $startupXMLPath
    Assert-ProtectedEvidenceFile $originalXML
    Assert-ProtectedEvidenceFile $oldFixture
    $metadata=[ordered]@{
        schema=1;runId=$RunId;computer=$env:COMPUTERNAME;
        bootBeforeUtc=$before.ToString('o');
        labSha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $copiedLab).Hash;
        journalSha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $copiedJournal).Hash;
        evidenceLibSha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $copiedEvidenceLib).Hash;
        taskSnapshotSha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $originalXML).Hash;
        originalFixtureSha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $oldFixture).Hash;
        watchdogTaskSnapshotSha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $startupXMLPath).Hash;
        cleanupContractSha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $copiedCleanupContract).Hash;
    }
    $metadata | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $kit 'vm-trial.json') -Encoding UTF8
    $watch=Get-ScheduledTask -TaskName $bootTask
    if(@($watch.Triggers).Count -ne 1 -or $watch.Triggers[0].CimClass.CimClassName -ne 'MSFT_TaskBootTrigger'){throw 'Recovery task has no boot trigger'}
    # The VM must be completely recovery-ready BEFORE the operator reboots.
    # A failed metadata ACL, wrong task action or missing pending journal
    # must stop here, not leave a potentially unrecoverable reboot rehearsal.
    $preparedMeta=Read-Metadata $kit
    Assert-LabIdentity $kit $preparedMeta
    . $copiedEvidenceLib
    if(-not (Assert-VolvRestoredTaskXML -SavedXML ([IO.File]::ReadAllText($startupXMLPath)) -RestoredXML (Export-ScheduledTask -TaskName $bootTask -TaskPath '\' -ErrorAction Stop))){
        throw 'Protected startup watchdog definition diverged during VM preparation'
    }
    Assert-ProtectedEvidenceFile (Join-Path $root 'old-task.xml')
    Assert-ProtectedEvidenceFile (Join-Path $root 'recovery.json')
    $journalState=& $copiedJournal status (Join-Path $root 'recovery.json')
    if($LASTEXITCODE -ne 0 -or $journalState -ne 'ROLLBACK_REQUIRED'){
        throw 'VM trial journal was not armed before reboot'
    }
    $candidate=Join-Path $env:WINDIR 'System32\notepad.exe'
    $motor=Assert-LabTask $labTask $candidate
    if([string]$motor.Actions[0].Arguments -ne ''){
        throw 'Disposable motor candidate action unexpectedly has arguments'
    }
    Write-Host 'PASS: pre-reboot VM kit, evidence-file DACLs, signed lab helper, pending journal and switched disposable task verified.'
    Write-Host ''
    Write-Host ('PREPARED: VM-only trial id = '+$RunId)
    Write-Host 'NEXT: take a VM snapshot, restart THIS TEST VM manually, then invoke -Mode Verify -RunId <id>.'
    Write-Host 'There is no reboot command in this script. Do not use on a personal computer.'
    return
}

if(-not (Test-Path -LiteralPath $kit -PathType Container)){throw 'Trial folder not found'}
$meta=Read-Metadata $kit
Assert-LabIdentity $kit $meta

if($Mode -eq 'AuditPrepared') {
    # Pure read-only pre-boot evidence gate. This must never be confused with
    # the real reboot proof, which requires a fresh OS boot and Scheduler
    # instance correlation. Useful for VM operator preflight and CI tampering.
    . (Join-Path $kit 'reboot_event_chain.ps1')
    $watch=Get-ScheduledTask -TaskName $bootTask -TaskPath '\' -ErrorAction Stop
    if($watch.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or
       @($watch.Triggers).Count -ne 1 -or
       $watch.Triggers[0].CimClass.CimClassName -ne 'MSFT_TaskBootTrigger'){
        throw 'NOT VERIFIED: startup watchdog identity or trigger changed'
    }
    if(-not (Assert-VolvRestoredTaskXML -SavedXML ([IO.File]::ReadAllText((Join-Path $kit 'watchdog-task.xml'))) -RestoredXML (Export-ScheduledTask -TaskName $bootTask -TaskPath '\' -ErrorAction Stop))){
        throw 'NOT VERIFIED: startup watchdog definition changed'
    }
    $current=Assert-LabTask $labTask (Join-Path $env:WINDIR 'System32\notepad.exe')
    if([string]$current.Actions[0].Arguments -ne ''){
        throw 'NOT VERIFIED: disposable candidate arguments changed'
    }
    Assert-ProtectedEvidenceFile (Join-Path $root 'recovery.json')
    $journalState=& (Join-Path $kit 'volve-journal-lab.exe') status (Join-Path $root 'recovery.json')
    if($LASTEXITCODE -ne 0 -or $journalState -ne 'ROLLBACK_REQUIRED'){
        throw 'NOT VERIFIED: pre-boot rollback journal no longer pending'
    }
    Write-Host 'PASS: protected VM pre-boot snapshots, original watchdog XML, candidate and pending journal; NO REBOOT PROOF'
    return
}

if($Mode -eq 'Verify') {
    $before=$meta.bootBeforeUtc
    if($before -isnot [datetime]) {
        $before=[DateTime]::Parse([string]$before,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind)
    }
    $before=$before.ToUniversalTime()
    $now=BootTimeUTC
    if($now -le $before.AddSeconds(5)) {throw 'NOT VERIFIED: VM has not undergone a new boot since the trial was prepared'}
    # A boot timestamp plus a success marker could be forged or produced by a
    # manually invoked recovery. Match the same task *instance* across actual
    # startup trigger 118, task start 100, zero-exit action 201 and completion
    # 102. The library is hash-pinned in VM metadata before the initial boot.
    $taskLog=Get-WinEvent -ListLog 'Microsoft-Windows-TaskScheduler/Operational' -ErrorAction Stop
    if(-not $taskLog.IsEnabled){throw 'NOT VERIFIED: Task Scheduler Operational history is disabled'}
    . (Join-Path $kit 'reboot_event_chain.ps1')
    $bootChain=Get-VolvRealBootChain -TaskName ('\'+$bootTask) -BootUTC $now
    $watch=Get-ScheduledTask -TaskName $bootTask -ErrorAction Stop
    if($watch.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or @($watch.Triggers).Count -ne 1 -or $watch.Triggers[0].CimClass.CimClassName -ne 'MSFT_TaskBootTrigger') {throw 'Unexpected watchdog task identity/trigger'}
    $savedWatchdogXML=[IO.File]::ReadAllText((Join-Path $kit 'watchdog-task.xml'))
    $currentWatchdogXML=Export-ScheduledTask -TaskName $bootTask -TaskPath '\' -ErrorAction Stop
    if(-not (Assert-VolvRestoredTaskXML -SavedXML $savedWatchdogXML -RestoredXML $currentWatchdogXML)){
        throw 'NOT VERIFIED: startup watchdog definition changed since VM Prepare'
    }
    $taskInfo=Get-ScheduledTaskInfo -TaskName $bootTask -ErrorAction Stop
    if($taskInfo.LastTaskResult -ne 0 -or $taskInfo.LastRunTime.ToUniversalTime() -lt $now.AddSeconds(-3)) {throw 'No successful watchdog execution associated with this boot'}
    $task=Assert-LabTask $labTask $cmd
    if($task.Actions[0].Arguments -ne '/C exit 0') {throw 'Original harmless task arguments not recovered'}
    # The visible action alone does not prove that principal, triggers,
    # settings or additional actions match the protected original XML.
    # This library was hash-pinned BEFORE reboot and parses XML without DTDs.
    $savedTaskXml=[IO.File]::ReadAllText((Join-Path $root 'old-task.xml'))
    $restoredTaskXml=Export-ScheduledTask -TaskName $labTask -ErrorAction Stop
    if(-not (Assert-VolvRestoredTaskXML -SavedXML $savedTaskXml -RestoredXML $restoredTaskXml)){
        throw 'NOT VERIFIED: complete original Task Scheduler XML was not recovered'
    }
    $mark=Join-Path $root 'boot-recovery-success.marker'
    Assert-ProtectedEvidenceFile $mark
    Assert-ProtectedEvidenceFile (Join-Path $root 'old-task.xml')
    Assert-ProtectedEvidenceFile (Join-Path $root 'recovery.json')
    if([IO.File]::ReadAllText($mark) -ne 'RESTORED_BY_SYSTEM_STARTUP_TASK'){throw 'No verified SYSTEM recovery marker'}
    if(Test-Path -LiteralPath (Join-Path $root 'boot-recovery-failed.marker')){throw 'Watchdog reported recovery failure'}
    $helper=Join-Path $kit 'volve-journal-lab.exe'
    $journal=Join-Path $root 'recovery.json'
    $status=& $helper status $journal
    if($LASTEXITCODE -ne 0 -or $status -ne 'NO_ROLLBACK:restored') {throw 'Recovery journal is not in restored state'}
    # An auditable, machine-readable result. The JSON is evidence from a
    # real VM run ONLY; the GitHub unit tests cannot generate it successfully.
    $proof=[ordered]@{
        schema=2;test='VOLVE-VM-REAL-REBOOT';runId=$RunId;computer=$env:COMPUTERNAME;
        bootBeforeUtc=$before.ToString('o');bootAfterUtc=$now.ToString('o');
        verifiedUtc=[DateTime]::UtcNow.ToString('o');
        watchdogTask=$bootTask;motorTask=$labTask;
        taskInstanceId=$bootChain.InstanceId;
        schedulerEventIds=$bootChain.EventIds;
        schedulerEventRecordIds=$bootChain.RecordIds;
        watchdogLastTaskResult=[int]$taskInfo.LastTaskResult;
        recoveryJournalState=$status;
        restoredAction=$cmd;restoredArguments='/C exit 0';
        restoredTaskXMLMatchesProtectedSnapshot=$true;
        startupWatchdogXMLMatchesProtectedSnapshot=$true;
        startupWatchdogXMLSnapshotSha256=$meta.watchdogTaskSnapshotSha256;
        originalTaskSnapshotSha256=(Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $root 'old-task.xml')).Hash;
        originalFixtureSha256=(Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $root 'old-test-engine.bin')).Hash;
        bootChainVerificationSha256=$meta.evidenceLibSha256;
    }
    $proofPath=Join-Path $kit 'vm-proof-evidence.json'
    if(Test-Path -LiteralPath $proofPath){throw 'Previous boot proof already exists; refusing silent overwrite'}
    $proof | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $proofPath -Encoding UTF8
    [IO.File]::WriteAllText((Join-Path $kit 'vm-proof-success.txt'),('Verified UTC: '+$proof.verifiedUtc+'; boot UTC: '+$proof.bootAfterUtc+'; correlated scheduler events: '+$bootChain.EventIds+'; records: '+$bootChain.RecordIds))
    Write-Host 'PASS: actual VM reboot detected and SYSTEM startup watchdog restored the disposable original task.'
    Write-Host ('Evidence stored in '+$kit)
    return
}

if($Mode -eq 'Cleanup') {
    # Fail closed: never retire the watchdog while a test is still pending,
    # failed, or unverified. A crafted success marker alone is insufficient.
    # No mutations happen before BOTH disposable task definitions are checked.
    $proofPath=Join-Path $kit 'vm-proof-evidence.json'
    if(-not (Test-Path -LiteralPath $proofPath -PathType Leaf)){
        throw 'REFUSED: Cleanup requires verified real reboot proof; pending or failed trials must preserve watchdog and evidence'
    }
    Assert-ProtectedEvidenceFile $proofPath
    $proof=Get-Content -LiteralPath $proofPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if($proof.schema -ne 2 -or
       [string]$proof.test -cne 'VOLVE-VM-REAL-REBOOT' -or
       [string]$proof.runId -cne $RunId -or
       [string]$proof.computer -cne $env:COMPUTERNAME -or
       [string]$proof.watchdogTask -cne $bootTask -or
       [string]$proof.motorTask -cne $labTask -or
       [string]$proof.bootBeforeUtc -cne [string]$meta.bootBeforeUtc -or
       [string]$proof.startupWatchdogXMLSnapshotSha256 -cne [string]$meta.watchdogTaskSnapshotSha256 -or
       [string]$proof.originalTaskSnapshotSha256 -cne [string]$meta.taskSnapshotSha256 -or
       [string]$proof.originalFixtureSha256 -cne [string]$meta.originalFixtureSha256 -or
       $proof.startupWatchdogXMLMatchesProtectedSnapshot -ne $true -or
       $proof.restoredTaskXMLMatchesProtectedSnapshot -ne $true -or
       [string]$proof.recoveryJournalState -cne 'NO_ROLLBACK:restored'){
        throw 'REFUSED: Cleanup proof does not match protected VM recovery receipt'
    }
    $before=[DateTime]::Parse([string]$proof.bootBeforeUtc,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
    $after=[DateTime]::Parse([string]$proof.bootAfterUtc,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
    $currentBoot=BootTimeUTC
    if($after -le $before.AddSeconds(5) -or $currentBoot -ne $after){
        throw 'REFUSED: Cleanup cannot confirm the previously verified Windows VM boot'
    }
    . (Join-Path $kit 'reboot_event_chain.ps1')
    $bootChain=Get-VolvRealBootChain -TaskName ('\'+$bootTask) -BootUTC $currentBoot
    if([string]$bootChain.InstanceId -cne [string]$proof.taskInstanceId -or
       (($bootChain.EventIds -join ',') -cne ($proof.schedulerEventIds -join ',')) -or
       (($bootChain.RecordIds -join ',') -cne ($proof.schedulerEventRecordIds -join ','))){
        throw 'REFUSED: Cleanup proof does not match real Task Scheduler boot instance events'
    }
    $mark=Join-Path $root 'boot-recovery-success.marker'
    Assert-ProtectedEvidenceFile $mark
    Assert-ProtectedEvidenceFile (Join-Path $root 'recovery.json')
    if([IO.File]::ReadAllText($mark) -cne 'RESTORED_BY_SYSTEM_STARTUP_TASK' -or
       (Test-Path -LiteralPath (Join-Path $root 'boot-recovery-failed.marker'))){
        throw 'REFUSED: Cleanup requires an unambiguous recovery-success marker'
    }
    $status=& (Join-Path $kit 'volve-journal-lab.exe') status (Join-Path $root 'recovery.json')
    if($LASTEXITCODE -ne 0 -or $status -cne 'NO_ROLLBACK:restored'){
        throw 'REFUSED: Cleanup cannot remove watchdog with unfinished recovery journal'
    }
    # Recovery of an interrupted cleanup is deliberately separate from
    # recovery of a migration. Both require real reboot proof, preserved
    # journals and the complete original task definitions.
    . (Join-Path $kit 'vm_cleanup_state_contract.ps1')
    $intentPath=Join-Path $kit 'vm-cleanup-intent.json'
    $receiptPath=Join-Path $kit 'vm-cleanup-evidence.json'
    $proofSHA=(Get-FileHash -Algorithm SHA256 -LiteralPath $proofPath).Hash
    $verifiedIntent=$false
    if(Test-Path -LiteralPath $intentPath -PathType Leaf){
        Assert-ProtectedEvidenceFile $intentPath
        $intent=Get-Content -LiteralPath $intentPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        if($intent.schema -ne 1 -or
           [string]$intent.kind -cne 'VOLVE_VM_CLEANUP_INTENT' -or
           [string]$intent.runId -cne $RunId -or
           [string]$intent.computer -cne $env:COMPUTERNAME -or
           [string]$intent.bootTask -cne $bootTask -or
           [string]$intent.motorTask -cne $labTask -or
           [string]$intent.bootAfterUtc -cne [string]$proof.bootAfterUtc -or
           [string]$intent.proofSha256 -cne $proofSHA -or
           [string]$intent.watchdogXMLSha256 -cne [string]$meta.watchdogTaskSnapshotSha256 -or
           [string]$intent.motorXMLSha256 -cne [string]$meta.taskSnapshotSha256){
            throw 'REFUSED: existing VM cleanup intent does not match protected recovery evidence'
        }
        $verifiedIntent=$true
    }
    # An existing completion receipt must be validated BEFORE even the first
    # destructive Task Scheduler action. A forged or stale completion record
    # is a hard rejection, not a late post-deletion error.
    $preExistingReceipt=$false
    if(Test-Path -LiteralPath $receiptPath -PathType Leaf){
        Assert-ProtectedEvidenceFile $receiptPath
        $receipt=Get-Content -LiteralPath $receiptPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $null=Assert-VolvVMCleanupReceipt -Receipt $receipt -RunId $RunId -Computer $env:COMPUTERNAME -ProofSha256 $proofSHA -BootAfterUtc ([string]$proof.bootAfterUtc)
        $preExistingReceipt=$true
    }
    # Get-ScheduledTask cannot use a missing task as proof of completed
    # cleanup. It is acceptable only with the protected intent just checked.
    $watch=Get-ScheduledTask -TaskName $bootTask -TaskPath '\' -ErrorAction SilentlyContinue
    $motor=Get-ScheduledTask -TaskName $labTask -TaskPath '\' -ErrorAction SilentlyContinue
    $phase=Resolve-VolvVMCleanupPhase -HasWatchdog ($null -ne $watch) -HasMotor ($null -ne $motor) -HasVerifiedIntent $verifiedIntent
    $null=Assert-VolvVMCleanupReceiptPhase -Phase $phase -HasExistingReceipt $preExistingReceipt

    # During a new cleanup or recovery of a crash after watchdog removal,
    # the motor task must still be the *complete* original harmless fixture.
    if($phase -in @('READY','RESUME_MOTOR')){
        if($motor.TaskPath -ne '\' -or $motor.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or
           @($motor.Actions).Count -ne 1 -or $motor.Actions[0].Execute -ne $cmd -or
           [string]$motor.Actions[0].Arguments -cne '/C exit 0'){
            throw 'REFUSED: disposable motor not completely restored; no tasks removed'
        }
        if(-not (Assert-VolvRestoredTaskXML -SavedXML ([IO.File]::ReadAllText((Join-Path $root 'old-task.xml'))) -RestoredXML (Export-ScheduledTask -TaskName $labTask -TaskPath '\' -ErrorAction Stop))){
            throw 'REFUSED: motor XML diverged; no tasks removed'
        }
    }
    if($phase -eq 'READY'){
        if($watch.TaskPath -ne '\' -or $watch.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or
           @($watch.Actions).Count -ne 1 -or @($watch.Triggers).Count -ne 1 -or
           $watch.Triggers[0].CimClass.CimClassName -cne 'MSFT_TaskBootTrigger'){
            throw 'REFUSED: unexpected SYSTEM watchdog; no tasks removed'
        }
        $action=$watch.Actions[0]
        $expectedPowerShell=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
        if($action.Execute -ne $expectedPowerShell -or
           [string]::IsNullOrWhiteSpace([string]$action.Arguments) -or
           $action.Arguments.IndexOf($kit,[StringComparison]::OrdinalIgnoreCase) -lt 0){
            throw 'REFUSED: unexpected watchdog command; no tasks removed'
        }
        if(-not (Assert-VolvRestoredTaskXML -SavedXML ([IO.File]::ReadAllText((Join-Path $kit 'watchdog-task.xml'))) -RestoredXML (Export-ScheduledTask -TaskName $bootTask -TaskPath '\' -ErrorAction Stop))){
            throw 'REFUSED: watchdog XML diverged; no tasks removed'
        }
        if(-not $verifiedIntent){
            # Intent is written to the ACL-protected evidence directory only
            # after BOTH full task XMLs and the independent boot proof passed.
            # It makes a crash BETWEEN the two deletions safely resumable.
            $newIntent=[ordered]@{
                schema=1;kind='VOLVE_VM_CLEANUP_INTENT';runId=$RunId;
                computer=$env:COMPUTERNAME;bootTask=$bootTask;motorTask=$labTask;
                bootAfterUtc=[string]$proof.bootAfterUtc;
                proofSha256=$proofSHA;
                watchdogXMLSha256=[string]$meta.watchdogTaskSnapshotSha256;
                motorXMLSha256=[string]$meta.taskSnapshotSha256;
                recordedUtc=[DateTime]::UtcNow.ToString('o');
            }
            $newIntent|ConvertTo-Json -Depth 4|Set-Content -LiteralPath $intentPath -Encoding UTF8 -ErrorAction Stop
            Assert-ProtectedEvidenceFile $intentPath
            $verifiedIntent=$true
        }
        # The watchdog is disarmed first; never leave a boot-time recovery
        # command after the successfully attested migration has been closed.
        Unregister-ScheduledTask -TaskName $bootTask -TaskPath '\' -Confirm:$false -ErrorAction Stop
    }
    if($phase -in @('READY','RESUME_MOTOR')){
        # If interrupted just after deleting the watchdog, reentry detects
        # the protected intent and removes ONLY the still-validated motor.
        Unregister-ScheduledTask -TaskName $labTask -TaskPath '\' -Confirm:$false -ErrorAction Stop
    }
    if($null -ne (Get-ScheduledTask -TaskName $bootTask -TaskPath '\' -ErrorAction SilentlyContinue) -or
       $null -ne (Get-ScheduledTask -TaskName $labTask -TaskPath '\' -ErrorAction SilentlyContinue)){
        throw 'REFUSED: cleanup incomplete; preserve protected intent and reboot evidence'
    }
    if(-not $preExistingReceipt){
        $receipt=[ordered]@{
            schema=1;kind='VOLVE_VM_CLEANUP_VERIFIED';runId=$RunId;
            computer=$env:COMPUTERNAME;bootAfterUtc=[string]$proof.bootAfterUtc;
            proofSha256=$proofSHA;watchdogRemoved=$true;motorRemoved=$true;
            completedUtc=[DateTime]::UtcNow.ToString('o');
        }
        $receipt|ConvertTo-Json -Depth 4|Set-Content -LiteralPath $receiptPath -Encoding UTF8 -ErrorAction Stop
        Assert-ProtectedEvidenceFile $receiptPath
    }
    Write-Host ('CLEAN: both verified disposable VM tasks absent; restart-safe intent and evidence remain at '+$kit)
}
