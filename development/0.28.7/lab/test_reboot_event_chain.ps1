# VOLVE VM proof contract tests: pure synthetic Task Scheduler event records.
# Does NOT require elevated privileges, scheduled tasks, restarts or DNS.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'reboot_event_chain.ps1')

$boot=([datetime]'2026-10-30T10:00:00Z').ToUniversalTime()
$task='\VOLVE-CI-BootRecovery-20261030102030001'
$guid='26c4d13f-22a0-4239-9cff-b100a5f19223'
function Record([int]$id,[long]$num,[string]$instance=$guid,[string]$name=$task,[string]$result='0',[int]$seconds=0){
    return [pscustomobject]@{
        Id=$id;RecordId=$num;TimeCreated=$boot.AddSeconds($seconds);
        InstanceId=$instance;TaskName=$name;ResultCode=$result;
    }
}
$good=@(
    (Record 118 1001 -seconds 1),
    (Record 100 1002 -seconds 2),
    (Record 201 1003 -seconds 3),
    (Record 102 1004 -seconds 4)
)
$answer=Assert-VolvBootEventChain -Events $good -TaskName $task -BootUTC $boot
if($answer.InstanceId -ne $guid -or $answer.EventIds -ne '118,100,201,102' -or $answer.RecordIds -ne '1001,1002,1003,1004') {
    throw 'Correlated real startup event contract failed'
}
$script:rejections=0
function MustReject([string]$name,[object[]]$sample,[string]$taskName=$task,[datetime]$bootTime=$boot) {
    try {
        $null=Assert-VolvBootEventChain -Events $sample -TaskName $taskName -BootUTC $bootTime
        throw ('UNSAFE: '+$name+' was incorrectly accepted')
    } catch {
        if($_.Exception.Message -notmatch '^NOT VERIFIED:') {throw}
        $script:rejections++
        Write-Host ('REJECTED: '+$name)
    }
}
MustReject 'missing boot trigger (manual recovery)' @($good | Where-Object Id -ne 118)
MustReject 'missing task start' @($good | Where-Object Id -ne 100)
MustReject 'missing action success' @($good | Where-Object Id -ne 201)
MustReject 'missing completion' @($good | Where-Object Id -ne 102)
MustReject 'failed action' @(
    (Record 118 1001 -seconds 1),(Record 100 1002 -seconds 2),
    (Record 201 1003 -result '1' -seconds 3),(Record 102 1004 -seconds 4)
)
MustReject 'wrong boot instance ID' @(
    (Record 118 1001 -instance 'd53d6225-f60d-4e90-b7e8-a0a2c957cbe4' -seconds 1),
    $good[1],$good[2],$good[3]
)
MustReject 'wrong task name' @($good) -taskName '\VOLVE-CI-BootRecovery-20261030102030002'
MustReject 'non-lab task name' @($good) -taskName '\VOLVE-DNS-SERVER-0270'
MustReject 'reordered completion events' @(
    (Record 118 1001 -seconds 1),(Record 100 1002 -seconds 2),
    (Record 201 1004 -seconds 3),(Record 102 1003 -seconds 4)
)
MustReject 'events from previous boot' @(
    (Record 118 1001 -seconds -12),(Record 100 1002 -seconds -11),
    (Record 201 1003 -seconds -10),(Record 102 1004 -seconds -9)
)
MustReject 'invalid boot task GUID' @(
    (Record 118 1001 -instance 'not-a-guid' -seconds 1),
    (Record 100 1002 -instance 'not-a-guid' -seconds 2),
    (Record 201 1003 -instance 'not-a-guid' -seconds 3),
    (Record 102 1004 -instance 'not-a-guid' -seconds 4)
)
$manualAfterBoot=@(
    (Record 110 995 -seconds 1),
    (Record 100 1002 -seconds 2),
    (Record 201 1003 -seconds 3),
    (Record 102 1004 -seconds 4)
)
MustReject 'manually started recovery after a boot' $manualAfterBoot
if($script:rejections -ne 12){throw ('Expected 12 rejection cases, got '+$script:rejections)}
Write-Host ('PASS: correlated 118/100/201/102 proof and '+$script:rejections+' false-positive/altered-evidence cases')
