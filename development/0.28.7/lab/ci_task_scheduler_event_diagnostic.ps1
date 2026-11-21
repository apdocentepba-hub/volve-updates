# VOLVE 0.28.7 - independent, READ-ONLY Windows CI post-failure diagnostics.
# Scheduler Event ID 140 indicates an updated task; NOT which XML field or
# which process caused it. An event correlation must NEVER override fail-closed.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Test','Investigate')][string]$Mode,
    [ValidatePattern('^[A-Fa-f0-9]{16}$')][string]$IdentityId='4023F1322DB1C44E',
    [ValidateRange(1,90)][int]$Minutes=45
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
$eventXml=@()
try {
    $events=@(Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-TaskScheduler/Operational'
        Id=@(106,140,141)
        StartTime=(Get-Date).AddMinutes(-$Minutes)
    } -MaxEvents 2000 -ErrorAction Stop)
    $eventXml=@($events | ForEach-Object {$_.ToXml()})
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
    $securitySummary=Get-VolvCISecurity4702Summary -TaskIdentity $fullIdentity -EventXML @(
        $securityEvents | ForEach-Object {$_.ToXml()}
    )
    $securityStatus='available'
} catch {
    # Auditing disabled, insufficient rights or malformed event: no causal claim.
    $securityStatus='unavailable'
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
    '; processAttribution=UNPROVEN; originalBaseline=FAILED')
