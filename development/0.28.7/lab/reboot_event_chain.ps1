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
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][object[]]$Events,
        [Parameter(Mandatory=$true)][string]$TaskName,
        [Parameter(Mandatory=$true)][datetime]$BootUTC
    )
    if($Events.Count -eq 0){throw 'NOT VERIFIED: no matching Task Scheduler records available after VM reboot'}
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
    # Read raw Operational history; the provider's StartTime UTC filter can
    # return zero results even when the true boot event chain is present.
    # Restrict by UTC and IDs after retrieving, then require one exact GUID.
    $events=@()
    try {
        $events=@(Get-WinEvent -LogName 'Microsoft-Windows-TaskScheduler/Operational' -MaxEvents 4096 -ErrorAction Stop)
    } catch {
        if($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound'){
            throw ('NOT VERIFIED: cannot read Windows Task Scheduler event journal: '+$_.Exception.Message)
        }
    }
    $lower=$BootUTC.ToUniversalTime().AddSeconds(-3)
    $normalized=@($events | Where-Object {
        $_.Id -in @(118,100,201,102) -and
        ([datetime]$_.TimeCreated).ToUniversalTime() -ge $lower
    } | ForEach-Object {ConvertTo-VolvSchedulerEvent $_})
    return Assert-VolvBootEventChain -Events $normalized -TaskName $TaskName -BootUTC $BootUTC
}


# Indentation is ignorable only between XML child ELEMENTS. In particular,
# an <Arguments> element containing whitespace is not the same as an empty
# <Arguments> element: that leaf text must remain part of the comparison.
function Remove-VolvTaskXMLIndentation {
    param([Parameter(Mandatory=$true)][System.Xml.XmlNode]$Node)
    foreach($child in @($Node.ChildNodes)){
        if($child.NodeType -eq [System.Xml.XmlNodeType]::Element){
            Remove-VolvTaskXMLIndentation -Node $child
        }
    }
    $hasChildElements=$false
    foreach($child in @($Node.ChildNodes)){
        if($child.NodeType -eq [System.Xml.XmlNodeType]::Element){
            $hasChildElements=$true
            break
        }
    }
    if($hasChildElements){
        foreach($child in @($Node.ChildNodes)){
            if($child.NodeType -eq [System.Xml.XmlNodeType]::Whitespace){
                $null=$Node.RemoveChild($child)
            }
        }
    }
}

# Strict read-only comparison of the entire restored Task Scheduler definition.
# This is stronger than checking only the executable/arguments of the first
# action. Whitespace-only formatting between XML elements is ignored, but
# all element names, namespaces, attributes, text values and ordering remain
# relevant. Any unsupported or malformed XML fails closed.
function ConvertTo-VolvTaskXMLFingerprint {
    param([Parameter(Mandatory=$true)][string]$XMLText)
    if($XMLText.Length -gt 1048576){throw 'NOT VERIFIED: Task Scheduler XML exceeds the lab limit'}
    $settings=[System.Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing=[System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver=$null
    $settings.MaxCharactersInDocument=1048576
    $readerText=[System.IO.StringReader]::new($XMLText)
    $reader=$null
    try {
        $reader=[System.Xml.XmlReader]::Create($readerText,$settings)
        $xml=[System.Xml.XmlDocument]::new()
        $xml.XmlResolver=$null
        $xml.PreserveWhitespace=$true
        $xml.Load($reader)
        # Preserve all leaf text, even whitespace-only command arguments;
        # discard only harmless indentation between nested elements.
        Remove-VolvTaskXMLIndentation -Node $xml.DocumentElement
        if($null -eq $xml.DocumentElement -or
           $xml.DocumentElement.LocalName -cne 'Task' -or
           $xml.DocumentElement.NamespaceURI -cne 'http://schemas.microsoft.com/windows/2004/02/mit/task'){
            throw 'NOT VERIFIED: unexpected Task Scheduler XML root or namespace'
        }
        return $xml.OuterXml
    } catch {
        if($_.Exception.Message -like 'NOT VERIFIED:*'){throw}
        throw ('NOT VERIFIED: malformed or unsupported Task Scheduler XML: '+$_.Exception.Message)
    } finally {
        if($null -ne $reader){$reader.Dispose()}
        $readerText.Dispose()
    }
}
function Assert-VolvRestoredTaskXML {
    param(
        [Parameter(Mandatory=$true)][string]$SavedXML,
        [Parameter(Mandatory=$true)][string]$RestoredXML
    )
    $original=ConvertTo-VolvTaskXMLFingerprint -XMLText $SavedXML
    $restored=ConvertTo-VolvTaskXMLFingerprint -XMLText $RestoredXML
    if($original -cne $restored){
        throw 'NOT VERIFIED: restored Task Scheduler XML differs from original protected snapshot'
    }
    return $true
}
