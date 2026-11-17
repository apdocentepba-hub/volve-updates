# VOLVE 0.28.7 VM-only cleanup state contract.
# Pure decision helper: NEVER reads or changes Task Scheduler, DNS or files.
Set-StrictMode -Version Latest
function Resolve-VolvVMCleanupPhase {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][bool]$HasWatchdog,
        [Parameter(Mandatory=$true)][bool]$HasMotor,
        [Parameter(Mandatory=$true)][bool]$HasVerifiedIntent
    )
    # A new cleanup can only begin when both complete task definitions still
    # exist. A verified, protected intent permits resuming interrupted cleanup
    # after the watchdog was removed, not initiating unsafe partial cleanup.
    if($HasWatchdog -and $HasMotor){return 'READY'}
    if(-not $HasWatchdog -and $HasMotor -and $HasVerifiedIntent){return 'RESUME_MOTOR'}
    if(-not $HasWatchdog -and -not $HasMotor -and $HasVerifiedIntent){return 'COMPLETE'}
    throw 'REFUSED: inconsistent VM task cleanup state; preserve evidence and inspect manually'
}

function Assert-VolvVMCleanupReceipt {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][object]$Receipt,
        [Parameter(Mandatory=$true)][string]$RunId,
        [Parameter(Mandatory=$true)][string]$Computer,
        [Parameter(Mandatory=$true)][string]$ProofSha256,
        [Parameter(Mandatory=$true)][string]$BootAfterUtc
    )
    # A previous COMPLETE receipt is NOT permission to unregister anything.
    # Its integrity is a precondition for all destructive cleanup actions.
    $fields=@('schema','kind','runId','computer','proofSha256','bootAfterUtc',
              'watchdogRemoved','motorRemoved','completedUtc')
    foreach($field in $fields){
        if($Receipt.PSObject.Properties.Name -cnotcontains $field){
            throw 'REFUSED: existing cleanup receipt lacks required protected fields'
        }
    }
    $finished=[datetimeoffset]::MinValue
    if(-not [datetimeoffset]::TryParse([string]$Receipt.completedUtc,[ref]$finished) -or
       $Receipt.schema -ne 1 -or
       [string]$Receipt.kind -cne 'VOLVE_VM_CLEANUP_VERIFIED' -or
       [string]$Receipt.runId -cne $RunId -or
       [string]$Receipt.computer -cne $Computer -or
       [string]$Receipt.proofSha256 -cne $ProofSha256 -or
       [string]$Receipt.bootAfterUtc -cne $BootAfterUtc -or
       $Receipt.watchdogRemoved -isnot [bool] -or
       $Receipt.motorRemoved -isnot [bool] -or
       $Receipt.watchdogRemoved -ne $true -or
       $Receipt.motorRemoved -ne $true){
        throw 'REFUSED: existing cleanup receipt does not match the protected real reboot'
    }
    return $true
}
