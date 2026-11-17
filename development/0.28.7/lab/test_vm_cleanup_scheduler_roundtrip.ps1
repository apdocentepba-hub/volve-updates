# VOLVE 0.28.7 - REAL Windows Task Scheduler CI integration, NO REAL REBOOT.
# Tests transitions of isolated one-time disposable SYSTEM tasks only.
# This does NOT bypass the production proof gate in vm_reboot_proof.ps1.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted'){
    throw 'REFUSED: only GitHub-hosted disposable Windows CI may run the Scheduler cleanup rehearsal'
}
if($env:OS -cne 'Windows_NT'){
    throw 'REFUSED: Windows Task Scheduler is required'
}
$principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    throw 'REFUSED: elevated ephemeral Windows CI runner required'
}
$id=([string]$env:GITHUB_RUN_ID)+'777'
if($id -cnotmatch '^[0-9]{14,18}$'){throw 'Invalid CI-only task identifier'}
$watchName='VOLVE-CI-BootRecovery-'+$id
$motorName='VOLVE-CI-StartupMotor-'+$id
foreach($name in @($watchName,$motorName)){
    if($name -cnotmatch '^VOLVE-CI-(BootRecovery|StartupMotor)-[0-9]{14,18}$'){
        throw 'REFUSED: CI-only task name outside allowlist'
    }
    if($null -ne (Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction SilentlyContinue)){
        throw ('REFUSED: temporary CI task name already exists: '+$name)
    }
}
. (Join-Path $PSScriptRoot 'vm_cleanup_state_contract.ps1')
. (Join-Path $PSScriptRoot 'reboot_event_chain.ps1')
$cmd=Join-Path $env:WINDIR 'System32\cmd.exe'
$notepad=Join-Path $env:WINDIR 'System32\notepad.exe'
$trigger=New-ScheduledTaskTrigger -Once -At ((Get-Date).AddYears(1))
$action=New-ScheduledTaskAction -Execute $cmd -Argument '/C exit 0'
function Get-CleanupPhase([bool]$verifiedIntent){
    $watch=Get-ScheduledTask -TaskName $watchName -TaskPath '\' -ErrorAction SilentlyContinue
    $motor=Get-ScheduledTask -TaskName $motorName -TaskPath '\' -ErrorAction SilentlyContinue
    return Resolve-VolvVMCleanupPhase -HasWatchdog ($null -ne $watch) -HasMotor ($null -ne $motor) -HasVerifiedIntent $verifiedIntent
}
function Assert-RejectedCleanupPhase([string]$case,[bool]$intent){
    $denied=$false
    try {
        $null=Get-CleanupPhase $intent
    } catch {
        if($_.Exception.Message -like 'REFUSED: inconsistent VM task cleanup state*'){$denied=$true}else{throw}
    }
    if(-not $denied){throw ('UNSAFE: inconsistent cleanup phase accepted: '+$case)}
}
try {
    # Two SYSTEM tasks exist in the same hosted Windows runner; neither is a
    # real VOLVE task nor has a boot trigger. They can never run by themselves.
    Register-ScheduledTask -TaskName $watchName -TaskPath '\' -Action $action -Trigger $trigger -User SYSTEM -RunLevel Highest -ErrorAction Stop | Out-Null
    Register-ScheduledTask -TaskName $motorName -TaskPath '\' -Action $action -Trigger $trigger -User SYSTEM -RunLevel Highest -ErrorAction Stop | Out-Null
    $watch=Get-ScheduledTask -TaskName $watchName -TaskPath '\' -ErrorAction Stop
    $motor=Get-ScheduledTask -TaskName $motorName -TaskPath '\' -ErrorAction Stop
    foreach($task in @($watch,$motor)){
        if($task.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or
           $task.TaskPath -cne '\' -or
           @($task.Actions).Count -ne 1 -or
           $task.Actions[0].Execute -cne $cmd -or
           [string]$task.Actions[0].Arguments -cne '/C exit 0'){
            throw 'Disposable task definition or principal unexpected'
        }
    }
    $watchXML=Export-ScheduledTask -TaskName $watchName -TaskPath '\' -ErrorAction Stop
    $motorXML=Export-ScheduledTask -TaskName $motorName -TaskPath '\' -ErrorAction Stop
    if((Get-CleanupPhase $false) -cne 'READY'){throw 'Missing READY phase with both tasks intact'}
    if(-not (Assert-VolvRestoredTaskXML -SavedXML $watchXML -RestoredXML (Export-ScheduledTask -TaskName $watchName -TaskPath '\' -ErrorAction Stop)) -or
       -not (Assert-VolvRestoredTaskXML -SavedXML $motorXML -RestoredXML (Export-ScheduledTask -TaskName $motorName -TaskPath '\' -ErrorAction Stop))){
        throw 'Initial Task Scheduler XML snapshot mismatch'
    }
    # Simulate a crash strictly BETWEEN the two task removals. An unproven
    # cleanup intent cannot authorize deleting the remaining motor.
    Unregister-ScheduledTask -TaskName $watchName -TaskPath '\' -Confirm:$false -ErrorAction Stop
    Assert-RejectedCleanupPhase 'watchdog missing without verified intent' $false
    if((Get-CleanupPhase $true) -cne 'RESUME_MOTOR'){
        throw 'Verified intent did not permit safe resume after interrupted cleanup'
    }
    # A restored-looking but altered motor must not be accepted as an exact
    # rollback, even if the cleanup contract recognizes RESUME_MOTOR.
    Set-ScheduledTask -TaskName $motorName -TaskPath '\' -Action (
        New-ScheduledTaskAction -Execute $notepad
    ) -ErrorAction Stop | Out-Null
    $tamperRejected=$false
    try {
        $null=Assert-VolvRestoredTaskXML -SavedXML $motorXML -RestoredXML (Export-ScheduledTask -TaskName $motorName -TaskPath '\' -ErrorAction Stop)
    } catch {
        if($_.Exception.Message -like 'NOT VERIFIED: restored Task Scheduler XML differs from original protected snapshot*'){$tamperRejected=$true}else{throw}
    }
    if(-not $tamperRejected){throw 'UNSAFE: changed motor accepted during simulated cleanup recovery'}
    if((Get-CleanupPhase $true) -cne 'RESUME_MOTOR'){throw 'Unexpected cleanup state after changed motor'}
    Register-ScheduledTask -TaskName $motorName -TaskPath '\' -Xml $motorXML -Force -ErrorAction Stop | Out-Null
    if(-not (Assert-VolvRestoredTaskXML -SavedXML $motorXML -RestoredXML (Export-ScheduledTask -TaskName $motorName -TaskPath '\' -ErrorAction Stop))){
        throw 'Original motor definition was not restored in disposable Scheduler'
    }
    Unregister-ScheduledTask -TaskName $motorName -TaskPath '\' -Confirm:$false -ErrorAction Stop
    if((Get-CleanupPhase $true) -cne 'COMPLETE'){throw 'Idempotent COMPLETE phase not reached'}
    if((Get-CleanupPhase $true) -cne 'COMPLETE'){throw 'Idempotent cleanup reentry failed'}
    Assert-RejectedCleanupPhase 'both tasks absent without verified intent' $false
    foreach($name in @($watchName,$motorName)){
        if($null -ne (Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction SilentlyContinue)){
            throw ('Disposable CI Task Scheduler task still registered: '+$name)
        }
    }
    Write-Host 'PASS: actual Windows Task Scheduler disposable SYSTEM tasks completed READY -> interrupted -> RESUME_MOTOR -> COMPLETE'
    Write-Host 'PASS: absent cleanup intent and altered motor XML each refused; reentry idempotent; both temporary tasks removed'
    Write-Host 'NO REAL REBOOT; CI simulates verified intent in the pure state contract, not a successful vm_reboot_proof Cleanup'
} finally {
    # Safety cleanup belongs ONLY to these generated names and this hosted runner.
    foreach($name in @($watchName,$motorName)){
        $remaining=Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction SilentlyContinue
        if($null -eq $remaining){continue}
        if($remaining.TaskPath -cne '\' -or $remaining.Principal.UserId -notin @('SYSTEM','S-1-5-18')){
            throw ('REFUSED: unexpected Task Scheduler identity during CI fixture cleanup: '+$name)
        }
        Unregister-ScheduledTask -TaskName $name -TaskPath '\' -Confirm:$false -ErrorAction Stop
    }
}
