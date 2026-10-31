# VOLVÉ 0.28.7 — read-only REAL Windows Scheduler event negative control.
# Run ONLY after a pre-existing disposable task was MANUALLY executed.
# Never creates tasks, writes DNS, restarts Windows or changes event settings.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidatePattern('^\\VOLVE-CI-BootRecovery-[0-9]{14,18}$')]
    [string]$TaskName,
    [Parameter(Mandatory=$true)]
    [datetime]$ManualStartUTC
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'reboot_event_chain.ps1')
if($env:GITHUB_ACTIONS -cne 'true'){
    throw 'CI-only real manual-start negative proof requires disposable GitHub Windows runner'
}
$os=Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
$bootUTC=([datetime]$os.LastBootUpTime).ToUniversalTime()
$from=$ManualStartUTC.ToUniversalTime().AddSeconds(-3)
if($from -le $bootUTC -or $from -gt [DateTime]::UtcNow.AddSeconds(3)){
    throw 'Manual start does not belong to the current non-reboot CI session'
}
$log='Microsoft-Windows-TaskScheduler/Operational'
$info=Get-WinEvent -ListLog $log -ErrorAction Stop
if(-not $info.IsEnabled){throw 'TaskScheduler Operational events not enabled for real negative control'}

# Windows delivers events asynchronously. Require a REAL, matching, same-PID
# Scheduler instance with 100/start, 201/action-success, and 102/completion,
# rather than passing on an empty log, a synthetic event or another task.
$matched=$null
$deadline=[DateTime]::UtcNow.AddSeconds(28)
do {
    $raw=@(Get-WinEvent -FilterHashtable @{
        LogName=$log
        Id=@(100,201,102,118)
        StartTime=$from
    } -ErrorAction SilentlyContinue)
    $all=@($raw | ForEach-Object { ConvertTo-VolvSchedulerEvent $_ } |
        Where-Object { $_.TaskName -ceq $TaskName })
    foreach($group in @($all | Group-Object InstanceId)){
        $guid=[guid]::Empty
        if(-not [guid]::TryParse([string]$group.Name,[ref]$guid) -or
           $guid -eq [guid]::Empty){continue}
        $sequence=@(100,201,102)
        $previousId=[long]0
        $previousUTC=$from
        $proof=@()
        foreach($code in $sequence){
            $next=@($group.Group | Where-Object {
                $_.Id -eq $code -and
                [long]$_.RecordId -gt $previousId -and
                $_.TimeCreated.ToUniversalTime() -ge $previousUTC
            } | Sort-Object RecordId)
            if($next.Count -eq 0){break}
            $event=$next[0]
            if($code -eq 201 -and
               ([string]$event.ResultCode -notin @('0','0x0','0x00000000'))){
                break
            }
            $proof+=,$event
            $previousId=[long]$event.RecordId
            $previousUTC=$event.TimeCreated.ToUniversalTime()
        }
        if($proof.Count -eq 3){$matched=$proof;break}
    }
    if($null -eq $matched){Start-Sleep -Milliseconds 500}
}while($null -eq $matched -and [DateTime]::UtcNow -lt $deadline)
if($null -eq $matched){
    throw 'No real 100/201(exit 0)/102 same-instance Scheduler event chain from manual SYSTEM execution'
}

# A task can have an AtStartup trigger yet be manually launched. Its presence,
# a successful exit code and an up-to-date timestamp are NOT reboot evidence.
$rejected=$false
try {
    $wrong=Get-VolvRealBootChain -TaskName $TaskName -BootUTC $bootUTC
} catch {
    if($_.Exception.Message -match '^NOT VERIFIED: no single boot-triggered Task Scheduler instance'){
        $rejected=$true
    }else{throw}
}
if(-not $rejected){
    throw 'SECURITY REGRESSION: manual SYSTEM execution falsely counted as real boot trigger'
}
Write-Host ('PASS: real manual SYSTEM task emitted 100/201(exit0)/102 instance '+$matched[0].InstanceId+
    ' (event records '+(($matched | ForEach-Object RecordId) -join ',')+
    '); genuine boot 118/100/201/102 verifier rejected this manual execution')
