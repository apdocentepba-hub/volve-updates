# VOLVE 0.28.7 - independent, READ-ONLY Windows CI post-failure diagnostics.
# Scheduler Event ID 140 indicates an updated task; NOT which XML field or
# which process caused it. An event correlation must NEVER override fail-closed.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Test','Investigate')][string]$Mode,
    [ValidatePattern('^[A-Fa-f0-9]{16}$')][string]$IdentityId='4023F1322DB1C44E',
    [ValidateRange(1,90)][int]$Minutes=45,
    [long]$AfterSecurityRecordId=0,
    [long]$AfterSchedulerRecordId=0
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

function Get-VolvCITaskPseudonym {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Identity)
    $sha=[Security.Cryptography.SHA256]::Create()
    try {
        $digest=$sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Identity))
        return [BitConverter]::ToString($digest).Replace('-','').Substring(0,16)
    } finally {$sha.Dispose()}
}

# Only the broad account category is exposed, never the EventData user value.
# Event 140 contains UserName on common Windows builds; missing data stays unknown.
# The actor account does not identify the process that made the change.
function Get-VolvCIEventActorClass {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][System.Xml.XmlDocument]$Document)
    $users=@($Document.SelectNodes("/*[local-name()='Event']/*[local-name()='EventData']/*[local-name()='Data']") |
        Where-Object {$_.GetAttribute('Name') -ceq 'UserName'})
    if($users.Count -ne 1){return 'unknown'}
    $user=[string]$users[0].InnerText
    if([string]::IsNullOrWhiteSpace($user)){return 'unknown'}
    $user=$user.Trim()
    if($user -in @('SYSTEM','NT AUTHORITY\SYSTEM','S-1-5-18')){return 'system'}
    if($user -in @('NETWORK SERVICE','NT AUTHORITY\NETWORK SERVICE','S-1-5-20')){return 'networkService'}
    if($user -in @('LOCAL SERVICE','NT AUTHORITY\LOCAL SERVICE','S-1-5-19')){return 'localService'}
    return 'other'
}

function Get-VolvCIEventSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$TaskIdentity,
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][string[]]$EventXML
    )
    $counts=[ordered]@{registration=0;updated=0;deleted=0;system=0;networkService=0;localService=0;other=0;unknown=0}
    foreach($raw in $EventXML){
        $doc=[System.Xml.XmlDocument]::new()
        $doc.XmlResolver=$null
        try {$doc.LoadXml($raw)}
        catch {throw 'NOT VERIFIED: invalid synthetic or Windows event XML'}
        $idNode=$doc.SelectSingleNode("/*[local-name()='Event']/*[local-name()='System']/*[local-name()='EventID']")
        if($null -eq $idNode){continue}
        $kind=switch([string]$idNode.InnerText){
            '106' {'registration';break}
            '140' {'updated';break}
            '141' {'deleted';break}
            default {$null}
        }
        if($null -eq $kind){continue}
        $taskNodes=@($doc.SelectNodes("/*[local-name()='Event']/*[local-name()='EventData']/*[local-name()='Data']") |
            Where-Object {$_.GetAttribute('Name') -ceq 'TaskName'})
        if($taskNodes.Count -ne 1){continue}
        if(-not [string]::Equals([string]$taskNodes[0].InnerText,$TaskIdentity,
               [StringComparison]::OrdinalIgnoreCase)){continue}
        $counts[$kind]++
        if($kind -ceq 'updated'){
            $class=Get-VolvCIEventActorClass -Document $doc
            $counts[$class]++
        }
    }
    return [pscustomobject]$counts
}


# Read-only Security 4702 correlation. Windows may provide ClientProcessId
# and ParentProcessId on newer event versions. A PID is NOT an executable
# identity or proof of causal attribution; the process can have exited/reused
# the PID. Never export task XML, usernames, PIDs or account identifiers.
function Test-VolvCIEventPositivePid {
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Value)
    if([string]::IsNullOrWhiteSpace($Value)){return $false}
    $valueText=$Value.Trim()
    $number=[int64]0
    if($valueText -cmatch '^0[xX][0-9a-fA-F]{1,8}$'){
        if(-not [int64]::TryParse($valueText.Substring(2),
            [Globalization.NumberStyles]::AllowHexSpecifier,
            [Globalization.CultureInfo]::InvariantCulture,[ref]$number)){return $false}
    } elseif($valueText -cmatch '^[0-9]{1,10}$'){
        if(-not [int64]::TryParse($valueText,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,[ref]$number)){return $false}
    } else {return $false}
    return ($number -gt 0 -and $number -le [int32]::MaxValue)
}

function Get-VolvCISecurity4702Summary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$TaskIdentity,
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][string[]]$EventXML
    )
    $counts=[ordered]@{matched4702=0;clientPidFieldPresent=0;parentPidFieldPresent=0;pidMissingOrInvalid=0}
    foreach($raw in $EventXML){
        $doc=[System.Xml.XmlDocument]::new()
        $doc.XmlResolver=$null
        try{$doc.LoadXml($raw)}catch{throw 'NOT VERIFIED: invalid Security 4702 XML'}
        $eid=$doc.SelectSingleNode("/*[local-name()='Event']/*[local-name()='System']/*[local-name()='EventID']")
        $provider=$doc.SelectSingleNode("/*[local-name()='Event']/*[local-name()='System']/*[local-name()='Provider']")
        if($null -eq $eid -or [string]$eid.InnerText -cne '4702' -or $null -eq $provider -or
           $provider.GetAttribute('Name') -cne 'Microsoft-Windows-Security-Auditing'){continue}
        $data=@($doc.SelectNodes("/*[local-name()='Event']/*[local-name()='EventData']/*[local-name()='Data']"))
        $task=@($data | Where-Object {$_.GetAttribute('Name') -ceq 'TaskName'})
        if($task.Count -ne 1 -or -not [string]::Equals([string]$task[0].InnerText,
              $TaskIdentity,[StringComparison]::OrdinalIgnoreCase)){continue}
        $counts.matched4702++
        $client=@($data | Where-Object {$_.GetAttribute('Name') -ceq 'ClientProcessId'})
        $parent=@($data | Where-Object {$_.GetAttribute('Name') -ceq 'ParentProcessId'})
        if($client.Count -eq 1 -and (Test-VolvCIEventPositivePid -Value ([string]$client[0].InnerText))){
            $counts.clientPidFieldPresent++
        } else {
            $counts.pidMissingOrInvalid++
        }
        if($parent.Count -eq 1 -and (Test-VolvCIEventPositivePid -Value ([string]$parent[0].InnerText))){
            $counts.parentPidFieldPresent++
        }
    }
    return [pscustomobject]$counts
}


# Optional Security 4688 (process creation) is correlated to Security 4702
# strictly for postmortem triage. PID reuse, incomplete log retention and
# missing process-start-key linkage forbid executable attribution or exemption.
# The only output is aggregate counts; process paths/PIDs remain in the VM.
function ConvertTo-VolvCIPidDecimal {
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Value)
    if(-not (Test-VolvCIEventPositivePid -Value $Value)){return $null}
    $clean=$Value.Trim()
    if($clean -match '^0[xX]'){
        return ([Convert]::ToInt64($clean.Substring(2),16)).ToString([Globalization.CultureInfo]::InvariantCulture)
    }
    return ([int64]::Parse($clean,[Globalization.CultureInfo]::InvariantCulture)).ToString([Globalization.CultureInfo]::InvariantCulture)
}

# Match only the exact standard Edge Update image path, never a basename,
# suffix or process-name guess. This remains a path lead, NOT attribution.
function Test-VolvCIStandardEdgeUpdateImage {
    param([string]$Image)
    if([string]::IsNullOrWhiteSpace($Image)){return $false}
    return [string]::Equals($Image,'C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe',[StringComparison]::OrdinalIgnoreCase)
}

# Current on-disk signer is a separate investigative observation, not proof
# that those bytes ran at the event time. Never emit paths or certificate data.
# Only called from the already-attested disposable CI investigation.
function Get-VolvCICurrentWindowsImageClass {
    param([string]$Image)
    try {
        if([string]::IsNullOrWhiteSpace($Image) -or $Image -cnotmatch '^[A-Za-z]:\\' -or [IO.Path]::GetExtension($Image) -ine '.exe'){return 'unknown'}
        $root=[IO.Path]::GetFullPath($env:WINDIR).TrimEnd('\')+'\'
        $full=[IO.Path]::GetFullPath($Image)
        $edge=Test-VolvCIStandardEdgeUpdateImage -Image $Image
        if(-not $full.StartsWith($root,[StringComparison]::OrdinalIgnoreCase) -and -not $edge){return 'outside_windows'}
        if(-not [string]::Equals($full,$Image,[StringComparison]::OrdinalIgnoreCase)){return 'unknown'}
        if($edge){$root=[IO.Path]::GetPathRoot($full)}
        $file=Get-Item -LiteralPath $full -ErrorAction Stop
        if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)){return 'unknown'}
        # Do not follow reparse points anywhere under the Windows directory.
        $parent=$file.Directory
        while($null -ne $parent){
            if($parent.Attributes -band [IO.FileAttributes]::ReparsePoint){return 'unknown'}
            if([string]::Equals($parent.FullName.TrimEnd('\'),$root.TrimEnd('\'),[StringComparison]::OrdinalIgnoreCase)){break}
            $parent=$parent.Parent
        }
        if($null -eq $parent){return 'unknown'}
        $signature=Get-AuthenticodeSignature -LiteralPath $full -ErrorAction Stop
        if($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate){
            if($edge){return 'edge_update_path_signature_unverified'}
            return 'windows_signature_unverified'
        }
        if($edge){
            if($signature.SignerCertificate.Subject -match '(?:^|,\s*)O=Microsoft Corporation(?:,|$)'){return 'edge_update_microsoft_signed_current_file'}
            return 'edge_update_other_signed_current_file'
        }
        if($signature.SignerCertificate.Subject -match '(?:^|,\s*)O=Microsoft Corporation(?:,|$)'){return 'windows_microsoft_signed_current_file'}
        return 'windows_other_signed_current_file'
    }catch{return 'unknown'}
}

function Get-VolvCIProcessCreationCorrelation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$TaskIdentity,
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][string[]]$UpdateEventXML,
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][string[]]$CreationEventXML,
        [switch]$InspectCurrentImage
    )
    function Read-CIEvent([string]$Raw) {
        $doc=[System.Xml.XmlDocument]::new()
        $doc.XmlResolver=$null
        try {$doc.LoadXml($Raw)}
        catch {throw 'NOT VERIFIED: malformed 4702/4688 event XML'}
        $provider=$doc.SelectSingleNode("/*[local-name()='Event']/*[local-name()='System']/*[local-name()='Provider']")
        $eventId=$doc.SelectSingleNode("/*[local-name()='Event']/*[local-name()='System']/*[local-name()='EventID']")
        $when=$doc.SelectSingleNode("/*[local-name()='Event']/*[local-name()='System']/*[local-name()='TimeCreated']")
        $date=$null
        if($null -ne $when){
            try {$date=[DateTimeOffset]::Parse([string]$when.GetAttribute('SystemTime'),
              [Globalization.CultureInfo]::InvariantCulture)}
            catch {$date=$null}
        }
        $fields=@($doc.SelectNodes("/*[local-name()='Event']/*[local-name()='EventData']/*[local-name()='Data']"))
        return [pscustomobject]@{
            event=if($null -eq $eventId){''}else{[string]$eventId.InnerText}
            provider=if($null -eq $provider){''}else{[string]$provider.GetAttribute('Name')}
            when=$date
            data=$fields
        }
    }
    function Read-OnlyField([object]$E,[string]$Field) {
        $nodes=@($E.data | Where-Object {$_.GetAttribute('Name') -ceq $Field})
        if($nodes.Count -ne 1){return $null}
        return [string]$nodes[0].InnerText
    }
    $births=@()
    foreach($raw in $CreationEventXML){
        $event=Read-CIEvent $raw
        if($event.event -cne '4688' -or
           $event.provider -cne 'Microsoft-Windows-Security-Auditing' -or
           $null -eq $event.when){continue}
        $clientProcessNumber=ConvertTo-VolvCIPidDecimal (Read-OnlyField $event 'NewProcessId')
        # Process creation event without an executable field cannot supply a
        # usable candidate. Never emit the executable field to CI output.
        $exe=Read-OnlyField $event 'NewProcessName'
        if($null -eq $clientProcessNumber -or [string]::IsNullOrWhiteSpace($exe)){continue}
        $births+=([pscustomobject]@{pid=$clientProcessNumber;when=$event.when;imageId=(Get-VolvCITaskPseudonym -Identity $exe.ToLowerInvariant()); image=$exe})
    }
    $counts=[ordered]@{taskUpdateEvents=0;creationCandidate=0;creationMissing=0;creationAmbiguous=0;invalidUpdateEvidence=0;candidateImageIds=@();currentImageClasses=@()}
    foreach($raw in $UpdateEventXML){
        $event=Read-CIEvent $raw
        if($event.event -cne '4702' -or
           $event.provider -cne 'Microsoft-Windows-Security-Auditing'){continue}
        $name=Read-OnlyField $event 'TaskName'
        if($null -eq $name -or -not [string]::Equals($name,$TaskIdentity,[StringComparison]::OrdinalIgnoreCase)){continue}
        $counts.taskUpdateEvents++
        $clientProcessNumber=ConvertTo-VolvCIPidDecimal (Read-OnlyField $event 'ClientProcessId')
        if($null -eq $clientProcessNumber -or $null -eq $event.when){
            $counts.invalidUpdateEvidence++
            continue
        }
        $matches=@($births | Where-Object {
            $_.pid -ceq $clientProcessNumber -and $_.when -le $event.when -and
            $_.when -ge $event.when.AddMinutes(-30)
        })
        if($matches.Count -eq 1){
            $counts.creationCandidate++
            $counts.candidateImageIds=@(($counts.candidateImageIds+@($matches[0].imageId))|Sort-Object -Unique)
            if($InspectCurrentImage){
                $class=Get-VolvCICurrentWindowsImageClass -Image $matches[0].image
                $counts.currentImageClasses=@(($counts.currentImageClasses+@($matches[0].imageId+':'+$class))|Sort-Object -Unique)
            }
        }
        elseif($matches.Count -gt 1){$counts.creationAmbiguous++}
        else{$counts.creationMissing++}
    }
    return [pscustomobject]$counts
}

if($Mode -ceq 'Test'){
    $fixture='\Microsoft\Windows\Synthetic\NeverPublicTask'
    # Constant well-formed fixtures: no PowerShell array/concatenation precedence.
    $xmls=@(
        '<Event><System><EventID>140</EventID></System><EventData><Data Name="TaskName">\Microsoft\Windows\Synthetic\NeverPublicTask</Data><Data Name="UserName">NT AUTHORITY\NETWORK SERVICE</Data></EventData></Event>'
        '<Event><System><EventID>140</EventID></System><EventData><Data Name="TaskName">\Microsoft\Windows\Synthetic\NeverPublicTask</Data><Data Name="UserName">DOMAIN\PRIVATE-ACCOUNT</Data></EventData></Event>'
        '<Event><System><EventID>140</EventID></System><EventData><Data Name="TaskName">\Microsoft\Windows\Synthetic\NeverPublicTask</Data></EventData></Event>'
        '<Event><System><EventID>106</EventID></System><EventData><Data Name="TaskName">\Microsoft\Windows\Synthetic\NeverPublicTask</Data></EventData></Event>'
        '<Event><System><EventID>141</EventID></System><EventData><Data Name="TaskName">\Microsoft\Windows\Synthetic\NeverPublicTask</Data></EventData></Event>'
        '<Event><System><EventID>140</EventID></System><EventData><Data Name="TaskName">\Other\Task</Data></EventData></Event>'
        '<Event><System><EventID>200</EventID></System><EventData><Data Name="TaskName">\Microsoft\Windows\Synthetic\NeverPublicTask</Data></EventData></Event>'
    )
    # Stable known Windows task identity, derived from TaskPath+TaskName.
    $spp='\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask'
    if((Get-VolvCITaskPseudonym -Identity $spp) -cne '4023F1322DB1C44E'){
        throw 'NOT VERIFIED: Microsoft Software Protection task identity regression'
    }
    $summary=Get-VolvCIEventSummary -TaskIdentity $fixture -EventXML $xmls
    if($summary.registration -ne 1 -or $summary.updated -ne 3 -or $summary.deleted -ne 1 -or
       $summary.networkService -ne 1 -or $summary.other -ne 1 -or $summary.unknown -ne 1 -or
       $summary.system -ne 0 -or $summary.localService -ne 0){
        throw 'NOT VERIFIED: Scheduler event correlation failed synthetic event-count tests'
    }
    $empty=Get-VolvCIEventSummary -TaskIdentity $fixture -EventXML @()
    if($empty.registration -ne 0 -or $empty.updated -ne 0 -or $empty.deleted -ne 0){
        throw 'NOT VERIFIED: Scheduler event correlation accepted an empty inventory'
    }
    if((Get-VolvCITaskPseudonym -Identity $fixture) -cnotmatch '^[0-9A-F]{16}$'){
        throw 'NOT VERIFIED: anonymous identity digest malformed'
    }
    $badEvent='<Event><System><EventID>140</EventID><EventData>'
    $rejected=$false
    try{$null=Get-VolvCIEventSummary -TaskIdentity $fixture -EventXML @($badEvent)}
    catch {if($_.Exception.Message -like 'NOT VERIFIED: invalid synthetic*'){$rejected=$true}else{throw}}
    if(-not $rejected){throw 'NOT VERIFIED: malformed Scheduler event was not rejected'}

    $s4702='Microsoft-Windows-Security-Auditing'
    $sample4702='<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4702</EventID></System><EventData><Data Name="TaskName">\Microsoft\Windows\Synthetic\NeverPublicTask</Data><Data Name="ClientProcessId">0x1F4</Data><Data Name="ParentProcessId">264</Data><Data Name="TaskContentNew">PRIVATE XML MUST NOT BE PRINTED</Data></EventData></Event>'
    $missingPid='<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4702</EventID></System><EventData><Data Name="TaskName">\Microsoft\Windows\Synthetic\NeverPublicTask</Data></EventData></Event>'
    $invalidPid=$sample4702.Replace('0x1F4','not-a-pid')
    $wrongTask=$sample4702.Replace($fixture,'\Other\Task')
    $wrongProvider=$sample4702.Replace($s4702,'NOT-TRUSTED-PROVIDER')
    $wrongEventId=$sample4702.Replace('<EventID>4702</EventID>','<EventID>4698</EventID>')
    $duplicatePid=$sample4702.Replace('<Data Name="ClientProcessId">0x1F4</Data>',
        '<Data Name="ClientProcessId">0x1F4</Data><Data Name="ClientProcessId">0x1F5</Data>')
    $audit=Get-VolvCISecurity4702Summary -TaskIdentity $fixture -EventXML @(
        $sample4702,$missingPid,$invalidPid,$wrongTask,$wrongProvider,$wrongEventId,$duplicatePid
    )
    if($audit.matched4702 -ne 4 -or $audit.clientPidFieldPresent -ne 1 -or
       $audit.parentPidFieldPresent -ne 3 -or $audit.pidMissingOrInvalid -ne 3){
        throw 'NOT VERIFIED: Security 4702 strict task/provider/PID evidence classification regression'
    }
    if((Get-VolvCISecurity4702Summary -TaskIdentity $fixture -EventXML @()).matched4702 -ne 0){
        throw 'NOT VERIFIED: empty Security 4702 inventory accepted'
    }
    foreach($invalid in @('0','-1','4294967296','0xFFFFFFFF','not-a-pid','1.5','')) {
        if(Test-VolvCIEventPositivePid -Value $invalid){throw 'NOT VERIFIED: invalid PID treated as process evidence'}
    }
    foreach($valid in @('4','0x1F4','524')) {
        if(-not (Test-VolvCIEventPositivePid -Value $valid)){throw 'NOT VERIFIED: valid PID field rejected'}
    }
    $bad4702Rejected=$false
    try{$null=Get-VolvCISecurity4702Summary -TaskIdentity $fixture -EventXML @('<Event><System>')}
    catch{if($_.Exception.Message -eq 'NOT VERIFIED: invalid Security 4702 XML'){$bad4702Rejected=$true}else{throw}}
    if(-not $bad4702Rejected){throw 'NOT VERIFIED: malformed Security 4702 XML was accepted'}

    # No sensitive executable name, PID, username or complete event XML may
    # appear in diagnostic output. Matching is temporal and NEVER causal proof.
    $valid4702='<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4702</EventID><TimeCreated SystemTime="2026-11-21T11:01:00Z"/></System><EventData><Data Name="TaskName">\Microsoft\Windows\Synthetic\NeverPublicTask</Data><Data Name="ClientProcessId">0x1F4</Data></EventData></Event>'
    $birth4688='<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4688</EventID><TimeCreated SystemTime="2026-11-21T11:00:00Z"/></System><EventData><Data Name="NewProcessId">500</Data><Data Name="NewProcessName">C:\PRIVATE\SecretProgram.exe</Data></EventData></Event>'
    $match=Get-VolvCIProcessCreationCorrelation -TaskIdentity $fixture -UpdateEventXML @($valid4702) -CreationEventXML @($birth4688)
    if($match.taskUpdateEvents -ne 1 -or $match.creationCandidate -ne 1 -or
       $match.creationMissing -ne 0 -or $match.creationAmbiguous -ne 0 -or
       $match.invalidUpdateEvidence -ne 0){throw 'NOT VERIFIED: 4702/4688 synthetic correlation failed'}
    $miss=Get-VolvCIProcessCreationCorrelation -TaskIdentity $fixture -UpdateEventXML @($valid4702) -CreationEventXML @()
    if($miss.creationMissing -ne 1 -or $miss.creationCandidate -ne 0){throw 'NOT VERIFIED: missing birth event falsely matched'}
    $afterBirth=$birth4688.Replace('11:00:00Z','11:02:00Z')
    $late=Get-VolvCIProcessCreationCorrelation -TaskIdentity $fixture -UpdateEventXML @($valid4702) -CreationEventXML @($afterBirth)
    if($late.creationMissing -ne 1){throw 'NOT VERIFIED: future process creation accepted'}
    $oldBirth=$birth4688.Replace('11:00:00Z','10:00:00Z')
    $stale=Get-VolvCIProcessCreationCorrelation -TaskIdentity $fixture -UpdateEventXML @($valid4702) -CreationEventXML @($oldBirth)
    if($stale.creationMissing -ne 1){throw 'NOT VERIFIED: stale process creation accepted'}
    $ambiguous=Get-VolvCIProcessCreationCorrelation -TaskIdentity $fixture -UpdateEventXML @($valid4702) -CreationEventXML @($birth4688,$birth4688)
    if($ambiguous.creationAmbiguous -ne 1 -or $ambiguous.creationCandidate -ne 0){
        throw 'NOT VERIFIED: reused PID was falsely attributed'
    }
    $missingPID=Get-VolvCIProcessCreationCorrelation -TaskIdentity $fixture -UpdateEventXML @(
      $valid4702.Replace('0x1F4','0x0')) -CreationEventXML @($birth4688)
    if($missingPID.invalidUpdateEvidence -ne 1){throw 'NOT VERIFIED: invalid PID accepted'}
    $otherTask=Get-VolvCIProcessCreationCorrelation -TaskIdentity $fixture -UpdateEventXML @(
      $valid4702.Replace($fixture,'\Other\Task')) -CreationEventXML @($birth4688)
    if($otherTask.taskUpdateEvents -ne 0){throw 'NOT VERIFIED: foreign task correlated'}
    $otherProvider=Get-VolvCIProcessCreationCorrelation -TaskIdentity $fixture -UpdateEventXML @(
      $valid4702.Replace('Microsoft-Windows-Security-Auditing','Untrusted-Source')) -CreationEventXML @($birth4688)
    if($otherProvider.taskUpdateEvents -ne 0){throw 'NOT VERIFIED: forged event provider accepted'}
    $broken=$false
    try{$null=Get-VolvCIProcessCreationCorrelation -TaskIdentity $fixture -UpdateEventXML @('<Event>') -CreationEventXML @()}
    catch{if($_.Exception.Message -ceq 'NOT VERIFIED: malformed 4702/4688 event XML'){$broken=$true}else{throw}}
    if(-not $broken){throw 'NOT VERIFIED: invalid event XML accepted'}
    if(($match|ConvertTo-Json -Compress) -match 'PRIVATE|SecretProgram|0x1F4|500'){
        throw 'NOT VERIFIED: sensitive process evidence escaped the aggregate correlation'
    }
    if($match.currentImageClasses.Count -ne 0){throw 'Synthetic correlation must not inspect real executable files'}
    if((Get-VolvCICurrentWindowsImageClass -Image 'relative.exe') -cne 'unknown'){throw 'Relative image path accepted'}
    if((Get-VolvCICurrentWindowsImageClass -Image 'C:\\PRIVATE\\SecretProgram.exe') -cne 'outside_windows'){throw 'Non-Windows image path accepted'}
    if($match.candidateImageIds.Count -ne 1 -or $match.candidateImageIds[0] -cnotmatch '^[0-9A-F]{16}$'){throw 'NOT VERIFIED: pseudonymous candidate image missing'}
    if($ambiguous.candidateImageIds.Count -ne 0 -or $miss.candidateImageIds.Count -ne 0){throw 'NOT VERIFIED: unknown image falsely identified'}
    $differentBirth=$birth4688.Replace('SecretProgram.exe','AnotherProgram.exe')
    $otherImage=Get-VolvCIProcessCreationCorrelation -TaskIdentity $fixture -UpdateEventXML @($valid4702) -CreationEventXML @($differentBirth)
    if($otherImage.candidateImageIds[0] -ceq $match.candidateImageIds[0]){throw 'NOT VERIFIED: distinct image candidates share identity'}
    $edgeImage='C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe'
    if(-not (Test-VolvCIStandardEdgeUpdateImage -Image $edgeImage)){throw 'Known Edge Update path not recognized'}
    if((Get-VolvCITaskPseudonym -Identity $edgeImage.ToLowerInvariant()) -cne '725AAF9503CF81FA'){throw 'Edge Update diagnostic path digest regression'}
    foreach($foreign in @('MicrosoftEdgeUpdate.exe','C:\Temp\MicrosoftEdgeUpdate.exe','C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe.bak','C:\Program Files (x86)\Microsoft\EdgeUpdate\..\EdgeUpdate\MicrosoftEdgeUpdate.exe')){
        if(Test-VolvCIStandardEdgeUpdateImage -Image $foreign){throw 'Non-exact Edge Update image incorrectly classified'}
    }
    Write-Host 'PASS: exact Edge Update path classification; no causal attribution or baseline exemption'
    Write-Host 'PASS: SECURITY_4702_4688_CORRELATION synthetic time/PID candidate, missing/ambiguous/future/stale/reused PID rejection; process identity remains UNPROVEN'
    Write-Host 'PASS: SECURITY_4702_READ_ONLY classifies valid/missing/invalid PID fields, refuses duplicate PID, wrong provider, wrong task, malformed XML and never outputs private event data'
    Write-Host 'PASS: CI_TASK_EVENT_DIAGNOSTIC matches synthetic events 106/140/141, classifies actor accounts, and rejects wrong task, unlisted ID and malformed XML'
    Write-Host 'PASS: CI_TASK_EVENT_DIAGNOSTIC exposes no task names, event identities, usernames or command arguments'
    return
}

# Never inspect a real user PC. The protected recovery gate already failed;
# this independent postmortem runs only in GitHub's disposable Windows guest.
if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted'){
    throw 'REFUSED: Scheduler postmortem is permitted only on hosted Windows CI'
}
$system=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
if(($system.Manufacturer+' '+$system.Model) -notmatch '(?i:virtual machine|hyper-v|vmware|kvm|qemu|virtualbox)'){
    throw 'REFUSED: not a positively identified virtual machine'
}
$matchingTasks=@(Get-ScheduledTask -ErrorAction Stop | Where-Object {
    (Get-VolvCITaskPseudonym -Identity ([string]$_.TaskPath+[string]$_.TaskName)) -ceq $IdentityId.ToUpperInvariant()
})
if($matchingTasks.Count -ne 1){
    Write-Host ('CI TASK EVENT POSTMORTEM: identityMatchCount='+$matchingTasks.Count+'; eventAudit=unavailable; originalBaseline=FAILED')
    return
}
$fullIdentity=[string]$matchingTasks[0].TaskPath+[string]$matchingTasks[0].TaskName
$expectedSPP='\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask'
$identityClass='unattributed'
if([string]::Equals($fullIdentity,$expectedSPP,[StringComparison]::Ordinal)){
    $identityClass='windows-software-protection-service-restart'
}
if($AfterSecurityRecordId -lt 0 -or $AfterSchedulerRecordId -lt 0){throw 'Invalid event cursor'}
$eventXml=@()
try {
    $events=@(Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-TaskScheduler/Operational'
        Id=@(106,140,141)
        StartTime=(Get-Date).AddMinutes(-$Minutes)
    } -MaxEvents 2000 -ErrorAction Stop)
    $eventXml=@($events | Where-Object {$_.RecordId -gt $AfterSchedulerRecordId} | ForEach-Object {$_.ToXml()})
} catch {
    # Event history may be disabled or empty; never turn a missing event into
    # evidence of safety, nor reveal exception messages with raw identities.
    Write-Host 'CI TASK EVENT POSTMORTEM: eventAudit=unavailable; originalBaseline=FAILED'
    return
}

# Security 4702 auditing may not be enabled. Do not enable auditing, do not
# alter ACLs or fetch/update any process: absence of evidence remains unknown.
$securityStatus='unavailable'
$securitySummary=[pscustomobject]@{matched4702=0;clientPidFieldPresent=0;parentPidFieldPresent=0;pidMissingOrInvalid=0}
try {
    $securityEvents=@(Get-WinEvent -FilterHashtable @{
        LogName='Security'
        Id=4702
        StartTime=(Get-Date).AddMinutes(-$Minutes)
    } -MaxEvents 2000 -ErrorAction Stop)
    $securityEvents=@($securityEvents|Where-Object {$_.RecordId -gt $AfterSecurityRecordId})
    $securitySummary=Get-VolvCISecurity4702Summary -TaskIdentity $fullIdentity -EventXML @(
        $securityEvents | ForEach-Object {$_.ToXml()}
    )
    $securityStatus='available'
} catch {
    # Auditing disabled, insufficient rights or malformed event: no causal claim.
    $securityStatus='unavailable'
}


# Optional process creation audit is not enabled here: this is READ-ONLY.
# A timestamp/PID match alone is an investigative lead, not actor proof.
$creationAudit='unavailable'
$processCandidates=[pscustomobject]@{taskUpdateEvents=0;creationCandidate=0;creationMissing=0;creationAmbiguous=0;invalidUpdateEvidence=0;candidateImageIds=@();currentImageClasses=@()}
if($securityStatus -ceq 'available'){
    try {
        $creationEvents=@(Get-WinEvent -FilterHashtable @{
            LogName='Security';Id=4688;StartTime=(Get-Date).AddMinutes(-$Minutes)
        } -MaxEvents 2000 -ErrorAction Stop)
        $creationEvents=@($creationEvents|Where-Object {$_.RecordId -gt $AfterSecurityRecordId})
        $processCandidates=Get-VolvCIProcessCreationCorrelation -TaskIdentity $fullIdentity -UpdateEventXML @(
            $securityEvents | ForEach-Object {$_.ToXml()}
        ) -CreationEventXML @(
            $creationEvents | ForEach-Object {$_.ToXml()}
        ) -InspectCurrentImage
        $creationAudit='available'
    } catch {
        $creationAudit='unavailable'
    }
}

$summary=Get-VolvCIEventSummary -TaskIdentity $fullIdentity -EventXML $eventXml
Write-Host ('CI TASK EVENT POSTMORTEM: identityId='+$IdentityId.ToUpperInvariant()+
    '; registered='+$summary.registration+'; updated='+$summary.updated+
    '; deleted='+$summary.deleted+'; updateActorSystem='+$summary.system+
    '; updateActorNetworkService='+$summary.networkService+
    '; updateActorLocalService='+$summary.localService+
    '; updateActorOther='+$summary.other+'; updateActorUnknown='+$summary.unknown+
    '; identityClass='+$identityClass+'; scanLimit=2000; security4702='+$securityStatus+
    '; security4702Matching='+$securitySummary.matched4702+
    '; security4702ClientPidFields='+$securitySummary.clientPidFieldPresent+
    '; security4702ParentPidFields='+$securitySummary.parentPidFieldPresent+
    '; security4688='+$creationAudit+
    '; pidTemporalCandidate='+$processCandidates.creationCandidate+
    '; pidBirthAbsent='+$processCandidates.creationMissing+
    '; pidBirthAmbiguous='+$processCandidates.creationAmbiguous+
    '; candidateImageIds='+($processCandidates.candidateImageIds -join ',')+
    '; currentImageClasses='+($processCandidates.currentImageClasses -join ',')+
    '; cursorScoped='+($AfterSecurityRecordId -gt 0 -and $AfterSchedulerRecordId -gt 0)+
    '; processAttribution=UNPROVEN; originalBaseline=FAILED')
