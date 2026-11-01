# VOLVE 0.28.7 - PURE verification for a long-running DNS motor after a REAL VM boot.
# 118=startup trigger; 100=task started; 200=action started. For a resident
# process, 201 and 102 should NOT have completed the very same instance.
# No OS changes. Never infer a reboot solely from a successful DNS response.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

function Assert-VolvLiveDNSBootChain {
    param(
        [Parameter(Mandatory=$true)][object[]]$Events,
        [Parameter(Mandatory=$true)][string]$TaskName,
        [Parameter(Mandatory=$true)][datetime]$BootUTC,
        [datetime]$ObservationUTC=[datetime]::UtcNow
    )
    if($TaskName -cnotmatch '^\\VOLVE-CI-FreshMotor-[0-9]{6,20}$'){
        throw 'NOT VERIFIED: unsupported non-disposable DNS task name'
    }
    $boot=$BootUTC.ToUniversalTime()
    $now=$ObservationUTC.ToUniversalTime()
    if($boot -gt $now -or $now -gt $boot.AddMinutes(30)){
        throw 'NOT VERIFIED: DNS VM observation outside the allowed post-boot interval'
    }
    $start=$boot.AddSeconds(-3)
    $candidate=@($Events | Where-Object {
        $_.TaskName -ceq $TaskName -and
        $_.TimeCreated.ToUniversalTime() -ge $start -and
        $_.TimeCreated.ToUniversalTime() -le $now -and
        $_.Id -in @(118,100,200,201,102)
    } | Sort-Object RecordId)
    if($candidate.Count -gt 1000){throw 'NOT VERIFIED: excessive event history'}
    foreach($trigger in @($candidate | Where-Object {
        $_.Id -eq 118 -and $_.TimeCreated.ToUniversalTime() -le $boot.AddMinutes(15)
    })){
        $id=[guid]::Empty
        if(-not [guid]::TryParse([string]$trigger.InstanceId,[ref]$id) -or $id -eq [guid]::Empty){continue}
        $related=@($candidate | Where-Object {
            $other=[guid]::Empty
            [guid]::TryParse([string]$_.InstanceId,[ref]$other) -and $other -eq $id
        })
        $chain=@($trigger)
        $prior=[long]$trigger.RecordId
        $at=$trigger.TimeCreated.ToUniversalTime()
        $valid=($prior -gt 0)
        foreach($expected in @(100,200)){
            $next=@($related | Where-Object {
                $_.Id -eq $expected -and [long]$_.RecordId -gt $prior -and
                $_.TimeCreated.ToUniversalTime() -ge $at -and
                $_.TimeCreated.ToUniversalTime() -le $boot.AddMinutes(15)
            } | Sort-Object RecordId)
            if($next.Count -eq 0){$valid=$false;break}
            $event=$next[0]
            $chain+=,$event
            $prior=[long]$event.RecordId
            $at=$event.TimeCreated.ToUniversalTime()
        }
        if(-not $valid){continue}
        # A completed task could be followed by a manually started task
        # listening on DNS/53. That is NOT evidence of boot persistence.
        $terminated=@($related | Where-Object {
            $_.Id -in @(201,102) -and [long]$_.RecordId -gt $prior
        })
        if($terminated.Count -gt 0){continue}
        return [pscustomobject]@{
            Task=$TaskName
            InstanceId=$id.ToString('D')
            EventIds='118,100,200'
            RecordIds=(($chain | ForEach-Object {$_.RecordId}) -join ',')
            BootUTC=$boot.ToString('o')
        }
    }
    throw 'NOT VERIFIED: no live same-instance 118/100/200 boot-trigger chain; stopped or manually started tasks never count'
}
