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
$summary=Get-VolvCIEventSummary -TaskIdentity $fullIdentity -EventXML $eventXml
Write-Host ('CI TASK EVENT POSTMORTEM: identityId='+$IdentityId.ToUpperInvariant()+
    '; registered='+$summary.registration+'; updated='+$summary.updated+
    '; deleted='+$summary.deleted+'; updateActorSystem='+$summary.system+
    '; updateActorNetworkService='+$summary.networkService+
    '; updateActorLocalService='+$summary.localService+
    '; updateActorOther='+$summary.other+'; updateActorUnknown='+$summary.unknown+
    '; identityClass='+$identityClass+'; scanLimit=2000; processAttribution=UNPROVEN; originalBaseline=FAILED')
