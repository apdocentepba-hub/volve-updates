# VOLVE VM-only pure receipt and task-phase validation. No disk/task mutations.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'vm_cleanup_state_contract.ps1')
$runId='20261117000000123'
$computer='VOLVE-CI-VM'
$sha='ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789'
$boot='2026-11-17T10:45:00.0000000Z'
$good=[ordered]@{
    schema=1
    kind='VOLVE_VM_CLEANUP_VERIFIED'
    runId=$runId
    computer=$computer
    proofSha256=$sha
    bootAfterUtc=$boot
    watchdogRemoved=$true
    motorRemoved=$true
    completedUtc='2026-11-17T10:46:00.0000000Z'
}
$serialized=$good|ConvertTo-Json -Depth 4
$valid=$serialized|ConvertFrom-Json
if(-not (Assert-VolvVMCleanupReceipt -Receipt $valid -RunId $runId -Computer $computer -ProofSha256 $sha -BootAfterUtc $boot)){
    throw 'A complete matching receipt must validate'
}
$cases=@(
    @{field='schema';value=2},
    @{field='kind';value='FORGED'},
    @{field='runId';value='other-run'},
    @{field='computer';value='OTHER-VM'},
    @{field='proofSha256';value='bad-sha'},
    @{field='bootAfterUtc';value='2026-11-16T10:45:00Z'},
    @{field='watchdogRemoved';value=$false},
    @{field='motorRemoved';value=$false},
    @{field='watchdogRemoved';value='true'},
    @{field='motorRemoved';value='true'},
    @{field='completedUtc';value='not-a-date'},
    @{field='runId';remove=$true},
    @{field='watchdogRemoved';remove=$true}
)
foreach($case in $cases){
    $bad=$serialized|ConvertFrom-Json
    if($case.ContainsKey('remove') -and $case.remove){
        $bad.PSObject.Properties.Remove($case.field)
    } else {
        $bad.PSObject.Properties[$case.field].Value=$case.value
    }
    $refused=$false
    try {
        $null=Assert-VolvVMCleanupReceipt -Receipt $bad -RunId $runId -Computer $computer -ProofSha256 $sha -BootAfterUtc $boot
    } catch {
        if($_.Exception.Message -like 'REFUSED: existing cleanup receipt*'){$refused=$true}else{throw}
    }
    if(-not $refused){throw ('INVALID receipt was accepted: '+$case.field)}
}
$phases=@(
    @{phase='READY';existing=$false;expected='PASS'},
    @{phase='READY';existing=$true;expected='REJECT'},
    @{phase='RESUME_MOTOR';existing=$false;expected='PASS'},
    @{phase='RESUME_MOTOR';existing=$true;expected='REJECT'},
    @{phase='COMPLETE';existing=$false;expected='PASS'},
    @{phase='COMPLETE';existing=$true;expected='PASS'}
)
foreach($case in $phases){
    $result='PASS'
    try {
        $null=Assert-VolvVMCleanupReceiptPhase -Phase $case.phase -HasExistingReceipt $case.existing
    } catch {
        if($_.Exception.Message -like 'REFUSED: existing cleanup receipt claims completion*'){$result='REJECT'}else{throw}
    }
    if($result -cne $case.expected){
        throw ('Receipt/task state mismatch '+$case.phase+' exists='+$case.existing)
    }
}
Write-Host ('PASS: real receipt, '+$cases.Count+' malformed/forged receipt rejections and '+$phases.Count+' receipt/task-state cases')
