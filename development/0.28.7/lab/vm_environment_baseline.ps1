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

# Read-only section fingerprints. Store digests ONLY inside the VM-protected
# baseline, never raw XML or task command lines in a public CI log.
function Get-VolvVMBaselineSha {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][AllowEmptyString()][string]$Value)
    $sha=[Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value))).Replace('-','')
    } finally {$sha.Dispose()}
}

function Get-VolvVMBaselineTaskRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$TaskPath,
        [Parameter(Mandatory=$true)][string]$TaskName,
        [Parameter(Mandatory=$true)][string]$XMLText
    )
    if($TaskPath.Contains('|') -or $TaskName.Contains('|')){
        throw 'NOT VERIFIED: task identity cannot be encoded safely'
    }
    # Uses the existing strict XML root/DTD/size/whitespace verifier.
    $canonical=ConvertTo-VolvTaskXMLFingerprint -XMLText $XMLText
    $document=[System.Xml.XmlDocument]::new()
    $document.XmlResolver=$null
    $document.PreserveWhitespace=$true
    $document.LoadXml($canonical)
    $sections=@('RegistrationInfo','Triggers','Principals','Settings','Actions')
    $sectionHashes=@()
    foreach($section in $sections){
        $matches=@($document.DocumentElement.ChildNodes | Where-Object {
            $_.NodeType -eq [System.Xml.XmlNodeType]::Element -and
            $_.LocalName -ceq $section -and
            $_.NamespaceURI -ceq 'http://schemas.microsoft.com/windows/2004/02/mit/task'
        })
        if($matches.Count -gt 1){throw 'NOT VERIFIED: duplicate Task Scheduler XML section'}
        $value='<absent>'
        if($matches.Count -eq 1){$value=[string]$matches[0].OuterXml}
        $sectionHashes+=Get-VolvVMBaselineSha -Value $value
    }
    return ($TaskPath+$TaskName+'|'+(Get-VolvVMBaselineSha -Value $canonical)+'|'+($sectionHashes -join '|'))
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
        Get-VolvVMBaselineTaskRecord -TaskPath ([string]$task.TaskPath) -TaskName ([string]$task.TaskName) -XMLText ([string]$xml)
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

# CI-only diagnostics: compare task identity without exposing raw task names,
# task XML, or definition hashes. The integrity gate below remains fail-closed.
function Get-VolvVMBaselineTaskDriftHint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$ExpectedRecord,
        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$ActualRecord
    )
    $before=@($ExpectedRecord.Split('|'))
    $after=@($ActualRecord.Split('|'))
    if($before.Count -lt 2 -or $after.Count -lt 2 -or
       [string]::IsNullOrWhiteSpace($before[0]) -or [string]::IsNullOrWhiteSpace($after[0])){
        return ' (first difference: malformed task record)'
    }
    $oldIdentity=[string]$before[0]
    $newIdentity=[string]$after[0]
    if($oldIdentity -cne $newIdentity){
        return ' (first difference: task identity changed)'
    }
    $scope='other-folder'
    if($oldIdentity.StartsWith('\Microsoft\Windows\',[StringComparison]::OrdinalIgnoreCase)){
        $scope='microsoft-windows-folder'
    }
    $identityId=(Get-VolvVMBaselineSha -Value $oldIdentity).Substring(0,16)
    $changed='unavailable'
    # Six SHA256 values: full XML followed by five fixed, coarse sections.
    # Never log task names, complete XML, raw command arguments or full SHA256s.
    if($before.Count -eq 7 -and $after.Count -eq 7){
        $names=@('RegistrationInfo','Triggers','Principals','Settings','Actions')
        $diff=@()
        for($i=0;$i -lt $names.Count;$i++){
            if($before[$i+2] -cne $after[$i+2]){$diff+=($names[$i])}
        }
        if($diff.Count -gt 0){$changed=$diff -join ','}
        elseif($before[1] -cne $after[1]){$changed='TaskRootOrUnclassified'}
        else {$changed='UnclassifiedRecordChange'}
    }
    return (' (first difference: definition changed for the same task; scope='+$scope+
        '; identityId='+$identityId+'; changedSections='+$changed+')')
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
                $detail=''
                if($field -ceq 'taskRecords' -and $env:GITHUB_ACTIONS -ceq 'true'){
                    # Read-only CI hint; still throw on every mismatch.
                    $detail=Get-VolvVMBaselineTaskDriftHint -ExpectedRecord ([string]$before[$i]) -ActualRecord ([string]$after[$i])
                }
                throw ('NOT VERIFIED: VM '+$field+' changed since Prepare'+$detail)
            }
        }
    }
    return $true
}
