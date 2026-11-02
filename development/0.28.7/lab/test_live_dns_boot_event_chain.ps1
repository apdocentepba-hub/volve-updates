# VOLVE 0.28.7 — deterministic, nonprivileged negative tests. No reboot.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'live_dns_boot_event_chain.ps1')
$boot=([datetime]'2026-11-01T12:00:00Z').ToUniversalTime()
$observed=$boot.AddMinutes(5)
$task='\VOLVE-CI-FreshMotor-41306065399'
$guid='9aeae1a7-abf7-4dd6-8618-ea2a92db5a33'
function NewRecord([int]$id,[long]$record,[string]$instance=$guid,[string]$taskName=$task,[int]$seconds=0){
    return [pscustomobject]@{
        Id=$id;RecordId=$record;TaskName=$taskName;InstanceId=$instance;
        TimeCreated=$boot.AddSeconds($seconds)
    }
}
$good=@((NewRecord 118 101 -seconds 1),(NewRecord 100 102 -seconds 2),(NewRecord 200 103 -seconds 3))
$x=Assert-VolvLiveDNSBootChain -Events $good -TaskName $task -BootUTC $boot -ObservationUTC $observed
if($x.EventIds -ne '118,100,200' -or $x.RecordIds -ne '101,102,103' -or
   $x.InstanceId -ne $guid){throw 'Valid distinct SYSTEM boot motor instance rejected'}
$script:rejected=0
function MustReject([string]$label,[object[]]$events,[string]$taskName=$task,
  [datetime]$when=$observed,[datetime]$started=$boot){
    try{
        $null=Assert-VolvLiveDNSBootChain -Events $events -TaskName $taskName -BootUTC $started -ObservationUTC $when
        throw ('UNSAFE: '+$label+' accepted')
    }catch{
        if($_.Exception.Message -notmatch '^NOT VERIFIED:'){throw}
        $script:rejected++
    }
}
MustReject 'no scheduler events captured after actual boot' @()
MustReject 'manual task start without event 118' @((NewRecord 100 102 -seconds 2),(NewRecord 200 103 -seconds 3))
MustReject 'missing task start' @((NewRecord 118 101 -seconds 1),(NewRecord 200 103 -seconds 3))
MustReject 'missing process/action start' @((NewRecord 118 101 -seconds 1),(NewRecord 100 102 -seconds 2))
MustReject 'completed action before observation' @($good+(NewRecord 201 104 -seconds 4))
MustReject 'completed task before observation' @($good+(NewRecord 102 104 -seconds 4))
MustReject 'mixed task instance' @((NewRecord 118 101 -instance $guid -seconds 1),
  (NewRecord 100 102 -instance 'f78f60b7-2c63-4470-a7c4-258840a0483a' -seconds 2),
  (NewRecord 200 103 -instance $guid -seconds 3))
MustReject 'unknown task name' $good -taskName '\VOLVE-DNS-SERVER-0270'
MustReject 'wrong lab task' $good -taskName '\VOLVE-CI-FreshMotor-999999'
MustReject 'bad GUID' @((NewRecord 118 101 -instance 'fake' -seconds 1),(NewRecord 100 102 -instance 'fake' -seconds 2),(NewRecord 200 103 -instance 'fake' -seconds 3))
MustReject 'record order reversed' @((NewRecord 118 103 -seconds 1),(NewRecord 100 102 -seconds 2),(NewRecord 200 101 -seconds 3))
MustReject 'wall clock reversal' @((NewRecord 118 101 -seconds 3),(NewRecord 100 102 -seconds 2),(NewRecord 200 103 -seconds 4))
MustReject 'before current boot' @((NewRecord 118 101 -seconds -20),(NewRecord 100 102 -seconds -19),(NewRecord 200 103 -seconds -18))
MustReject 'late startup trigger' @((NewRecord 118 101 -seconds 1000),(NewRecord 100 102 -seconds 1001),(NewRecord 200 103 -seconds 1002)) -when ($boot.AddMinutes(20))
MustReject 'observation 31 min after boot' $good -when ($boot.AddMinutes(31))
MustReject 'boot after observation' $good -started ($observed.AddMinutes(1))
MustReject 'finished prior instance and manual restart' @($good+(NewRecord 201 104 -seconds 4)+
  (NewRecord 100 105 -instance '0b1d7e73-ff66-4e8e-984f-bd51218c0003' -seconds 9)+
  (NewRecord 200 106 -instance '0b1d7e73-ff66-4e8e-984f-bd51218c0003' -seconds 10))
MustReject 'zero event record ID' @((NewRecord 118 0 -seconds 1),(NewRecord 100 1 -seconds 2),(NewRecord 200 2 -seconds 3))
if($script:rejected -ne 18){throw ('Expected 18 negative cases, got '+$script:rejected)}
Write-Host ('PASS: live SYSTEM DNS boot instance correlation, 18 negative cases, no host changes')
