# VOLVE 0.28.7 - pure verification of a REAL Task Scheduler boot execution.
# Development/VM-only helper. No filesystem, Task Scheduler or DNS mutations.
# An event 118 by itself is INSUFFICIENT: require one correlated instance
# through boot trigger (118), task start (100), action completed (201, exit 0),
# and task completion (102), with monotonic record IDs after THIS OS boot.
Set-StrictMode -Version Latest

function ConvertTo-VolvSchedulerEvent {
    param([Parameter(Mandatory=$true)][object]$Event)
    $xml=[xml]$Event.ToXml()
    $fields=@{}
    $dataNodes=$xml.SelectNodes("//*[local-name()='EventData']/*[local-name()='Data']")
    foreach($node in $dataNodes){
        $key=[string]$node.GetAttribute('Name')
        if(-not [string]::IsNullOrWhiteSpace($key)){
            $fields[$key]=[string]$node.InnerText
        }
    }
    $id=[int]$Event.Id
    $instance=''
    foreach($key in @('InstanceId','TaskInstanceId')){
        if($fields.ContainsKey($key) -and -not [string]::IsNullOrWhiteSpace($fields[$key])){
            $instance=$fields[$key];break
        }
    }
    return [pscustomobject]@{
        Id=$id
        RecordId=[long]$Event.RecordId
        TimeCreated=([datetime]$Event.TimeCreated).ToUniversalTime()
        TaskName=[string]$fields['TaskName']
        InstanceId=$instance
        ResultCode=[string]$fields['ResultCode']
    }
}

function Assert-VolvBootEventChain {
    param(
        [Parameter(Mandatory=$true)][object[]]$Events,
        [Parameter(Mandatory=$true)][string]$TaskName,
        [Parameter(Mandatory=$true)][datetime]$BootUTC
    )
    if($TaskName -cnotmatch '^\\VOLVE-CI-BootRecovery-[0-9]{14,18}$'){
        throw 'NOT VERIFIED: boot recovery task name is outside VM-only allowlist'
    }
    $bootStart=$BootUTC.ToUniversalTime()
    $lower=$bootStart.AddSeconds(-3)
    $now=[DateTime]::UtcNow
    if($bootStart -gt $now.AddSeconds(3)){
        throw 'NOT VERIFIED: OS boot timestamp is in the future'
    }
    # A real at-startup trigger must occur near this boot, not hours later
    # during a manually resumed task. Permit a 15-minute startup delay.
    $latestStartup=$bootStart.AddMinutes(15)
    $filtered=@($Events | Where-Object {
        $_.TaskName -ceq $TaskName -and
        $_.TimeCreated.ToUniversalTime() -ge $lower -and
        $_.TimeCreated.ToUniversalTime() -le $now.AddSeconds(3) -and
        $_.Id -in @(118,100,201,102)
    } | Sort-Object RecordId)
    if($filtered.Count -gt 1000){throw 'NOT VERIFIED: excessive task event history'}
    $bootCandidates=@($filtered | Where-Object {
        $_.Id -eq 118 -and $_.TimeCreated.ToUniversalTime() -le $latestStartup
    })
    foreach($b in $bootCandidates){
        $guid=[guid]::Empty
        if(-not [guid]::TryParse([string]$b.InstanceId,[ref]$guid) -or $guid -eq [guid]::Empty){continue}
        $related=@($filtered | Where-Object {
            $other=[guid]::Empty
            [guid]::TryParse([string]$_.InstanceId,[ref]$other) -and $other -eq $guid
        })
        $sequence=@(118,100,201,102)
        $chain=@()
        $previous=[long]0
        $previousUTC=$lower
        $ok=$true
        foreach($code in $sequence){
            # Pick the first event that is BOTH later in the journal and
            # not earlier in wall-clock time. A forged mixed timeline must
            # never certify a genuine startup recovery.
            $matches=@($related | Where-Object {
                $_.Id -eq $code -and
                [long]$_.RecordId -gt $previous -and
                $_.TimeCreated.ToUniversalTime() -ge $previousUTC
            })
            if($matches.Count -eq 0){$ok=$false;break}
            $entry=$matches[0]
            if($code -eq 201 -and ([string]$entry.ResultCode -notin @('0','0x0','0x00000000'))){
                $ok=$false;break
            }
            # Task completion (102) may not include ResultCode in actual
            # Windows EventData. If it DOES carry one, nonzero is fatal.
            if($code -eq 102 -and
               -not [string]::IsNullOrWhiteSpace([string]$entry.ResultCode) -and
               ([string]$entry.ResultCode -notin @('0','0x0','0x00000000'))){
                $ok=$false;break
            }
            $chain+=,$entry
            $previous=[long]$entry.RecordId
            $previousUTC=$entry.TimeCreated.ToUniversalTime()
        }
        if($ok){
            return [pscustomobject]@{
                Task=$TaskName
                InstanceId=$guid.ToString('D')
                EventIds=($sequence -join ',')
                RecordIds=(($chain | ForEach-Object {$_.RecordId}) -join ',')
                TriggerRecordId=[long]$chain[0].RecordId
                CompletedRecordId=[long]$chain[3].RecordId
                CompletedUTC=$chain[3].TimeCreated.ToUniversalTime().ToString('o')
            }
        }
    }
    throw 'NOT VERIFIED: no single boot-triggered Task Scheduler instance has correlated 118/100/201(exit 0)/102 events after OS startup'
}

function Get-VolvRealBootChain {
    param(
        [Parameter(Mandatory=$true)][string]$TaskName,
        [Parameter(Mandatory=$true)][datetime]$BootUTC
    )
    $events=@(Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-TaskScheduler/Operational'
        Id=@(118,100,201,102)
        StartTime=$BootUTC.ToUniversalTime().AddSeconds(-3)
    } -ErrorAction SilentlyContinue)
    $normalized=@($events | ForEach-Object {ConvertTo-VolvSchedulerEvent $_})
    return Assert-VolvBootEventChain -Events $normalized -TaskName $TaskName -BootUTC $BootUTC
}
