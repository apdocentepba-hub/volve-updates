# VOLVE 0.28.7 - VM ONLY read-only environmental integrity baseline.
# Takes no locks, edits no DNS/HOSTS and does not register/modify tasks.
Set-StrictMode -Version Latest

# Exact allowlist: exclude ONLY the two owned fixtures of THIS trial,
# never another trial's tasks or any identically named task in a subfolder.
function Test-VolvVMBaselineExcludedTask {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][ValidatePattern('^[0-9]{14,18}$')][string]$RunId,
        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$TaskPath,
        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$TaskName
    )
    return ($TaskPath -ceq '\' -and $TaskName -cin @(
        ('VOLVE-CI-StartupMotor-'+$RunId),
        ('VOLVE-CI-BootRecovery-'+$RunId)
    ))
}

function Get-VolvVMBaselineState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][ValidatePattern('^[0-9]{14,18}$')][string]$RunId
    )
    $hosts=Join-Path $env:WINDIR 'System32\drivers\etc\hosts'
    if(-not (Test-Path -LiteralPath $hosts -PathType Leaf)){
        throw 'NOT VERIFIED: Windows HOSTS file missing; cannot establish VM baseline'
    }
    $hostsSHA=(Get-FileHash -Algorithm SHA256 -LiteralPath $hosts -ErrorAction Stop).Hash

    # Preserve the full DNS server list and both address families per
    # interface. Interface index changes across reboot are a failure,
    # rather than silently comparing settings on a different adapter.
    $dns=@(Get-DnsClientServerAddress -ErrorAction Stop | ForEach-Object {
        $adapter=$_
        $servers=@($adapter.ServerAddresses | ForEach-Object {[string]$_})
        '{0}|{1}|{2}' -f ([int]$adapter.InterfaceIndex),([string]$adapter.AddressFamily),([string]::Join(',',[string[]]$servers))
    } | Sort-Object -CaseSensitive)
    if($dns.Count -eq 0){throw 'NOT VERIFIED: no DNS adapter configuration returned by VM'}

    # Read EVERY Scheduler folder, not just the root. Include full TaskPath
    # so identical task names in different subfolders cannot cancel each other.
    # Fail closed if even a single task cannot be exported or canonicalized.
    # Exclude only the two exact root task names owned by this RunId.
    $allTasks=@(Get-ScheduledTask -ErrorAction Stop)
    $taskRecords=@($allTasks | Where-Object {
        -not (Test-VolvVMBaselineExcludedTask -RunId $RunId -TaskPath ([string]$_.TaskPath) -TaskName ([string]$_.TaskName))
    } | ForEach-Object {
        $task=$_
        if([string]::IsNullOrWhiteSpace([string]$task.TaskName) -or
           [string]::IsNullOrWhiteSpace([string]$task.TaskPath)){
            throw 'NOT VERIFIED: Scheduler returned a task without a full path or name'
        }
        $xml=Export-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop
        $canonical=ConvertTo-VolvTaskXMLFingerprint -XMLText ([string]$xml)
        $sha=[Security.Cryptography.SHA256]::Create()
        try {
            $digest=[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($canonical))).Replace('-','')
        } finally {
            $sha.Dispose()
        }
        [string]$task.TaskPath+[string]$task.TaskName+'|'+$digest
    } | Sort-Object -CaseSensitive)
    if($taskRecords.Count -gt 20000){throw 'NOT VERIFIED: excessive Scheduler task inventory'}
    if(@($taskRecords | Select-Object -Unique).Count -ne $taskRecords.Count){
        throw 'NOT VERIFIED: duplicate Scheduler task entries in VM inventory'
    }

    return [pscustomobject][ordered]@{
        schema=1
        kind='VOLVE_VM_READ_ONLY_ENVIRONMENT'
        hostsSha256=$hostsSHA
        dnsRecords=[string[]]$dns
        taskRecords=[string[]]$taskRecords
    }
}

function Assert-VolvVMBaselineState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][object]$Expected,
        [Parameter(Mandatory=$true)][object]$Actual
    )
    foreach($record in @($Expected,$Actual)){
        foreach($name in @('schema','kind','hostsSha256','dnsRecords','taskRecords')){
            if($record.PSObject.Properties.Name -cnotcontains $name){
                throw ('NOT VERIFIED: VM environment baseline missing '+$name)
            }
        }
        if($record.schema -ne 1 -or
           [string]$record.kind -cne 'VOLVE_VM_READ_ONLY_ENVIRONMENT' -or
           [string]$record.hostsSha256 -cnotmatch '^[A-F0-9]{64}$'){
            throw 'NOT VERIFIED: malformed VM environment baseline'
        }
    }
    if([string]$Expected.hostsSha256 -cne [string]$Actual.hostsSha256){
        throw 'NOT VERIFIED: Windows HOSTS contents changed since VM Prepare'
    }
    foreach($field in @('dnsRecords','taskRecords')){
        $before=@($Expected.$field)
        $after=@($Actual.$field)
        if($before.Count -ne $after.Count){
            throw ('NOT VERIFIED: VM '+$field+' count changed since Prepare')
        }
        for($i=0;$i -lt $before.Count;$i++){
            if([string]$before[$i] -cne [string]$after[$i]){
                throw ('NOT VERIFIED: VM '+$field+' changed since Prepare')
            }
        }
    }
    return $true
}
