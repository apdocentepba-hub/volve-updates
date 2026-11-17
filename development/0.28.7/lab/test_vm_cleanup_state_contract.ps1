# Pure synthetic truth-table tests; NO Task Scheduler or filesystem changes.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'vm_cleanup_state_contract.ps1')
$cases=@(
    @{watch=$true;motor=$true;intent=$false;expected='READY'},
    @{watch=$true;motor=$true;intent=$true;expected='READY'},
    @{watch=$false;motor=$true;intent=$true;expected='RESUME_MOTOR'},
    @{watch=$false;motor=$false;intent=$true;expected='COMPLETE'},
    @{watch=$false;motor=$true;intent=$false;expected='REJECT'},
    @{watch=$false;motor=$false;intent=$false;expected='REJECT'},
    @{watch=$true;motor=$false;intent=$false;expected='REJECT'},
    @{watch=$true;motor=$false;intent=$true;expected='REJECT'}
)
foreach($case in $cases){
    $actual='REJECT'
    try {
        $actual=Resolve-VolvVMCleanupPhase -HasWatchdog $case.watch -HasMotor $case.motor -HasVerifiedIntent $case.intent
    } catch {
        if($_.Exception.Message -notlike 'REFUSED: inconsistent VM task cleanup state*'){throw}
    }
    if($actual -cne $case.expected){
        throw ('VM cleanup phase mismatch: watchdog='+$case.watch+' motor='+$case.motor+' verifiedIntent='+$case.intent+' expected='+$case.expected+' actual='+$actual)
    }
}
Write-Host 'PASS: eight VM cleanup phases, including interrupted/resumed/complete and all disallowed orphan states'
