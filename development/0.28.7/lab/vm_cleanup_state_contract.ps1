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
