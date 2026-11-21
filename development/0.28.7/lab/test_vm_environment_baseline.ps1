# Read-only VM environment comparison contract; synthetic fixtures ONLY.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'vm_environment_baseline.ps1')
$expected=[pscustomobject][ordered]@{
    schema=2
    kind='VOLVE_VM_READ_ONLY_ENVIRONMENT'
    hostsSha256=('A'*64)
    dnsRecords=@('2|2|192.0.2.10,192.0.2.11','2|23|2001:db8::53')
    taskRecords=@(('\VOLVE-CATALOGO|'+('B'*64)),('\Microsoft\Windows\Maintenance\WindowsMaintenance|'+('C'*64)))
}
$clone=$expected|ConvertTo-Json -Depth 6|ConvertFrom-Json
if(-not (Assert-VolvVMBaselineState -Expected $expected -Actual $clone)){
    throw 'Identical read-only VM environment baseline must pass'
}
$cases=@(
    @{field='hostsSha256';value=('D'*64)},
    @{field='dnsRecords';value=@('2|2|192.0.2.55','2|23|2001:db8::53')},
    @{field='dnsRecords';value=@('2|2|192.0.2.10,192.0.2.11')},
    @{field='taskRecords';value=@(('\VOLVE-CATALOGO|'+('E'*64)),('\Microsoft\Windows\Maintenance\WindowsMaintenance|'+('C'*64)))},
    @{field='taskRecords';value=@(('\Microsoft\Windows\Maintenance\WindowsMaintenance|'+('C'*64)))},
    @{field='schema';value=3},
    @{field='kind';value='MALFORMED'},
    @{field='hostsSha256';remove=$true},
    @{field='dnsRecords';remove=$true},
    @{field='taskRecords';remove=$true}
)
foreach($case in $cases){
    $modified=$expected|ConvertTo-Json -Depth 6|ConvertFrom-Json
    if($case.ContainsKey('remove') -and $case.remove){
        $modified.PSObject.Properties.Remove($case.field)
    } else {
        $modified.PSObject.Properties[$case.field].Value=$case.value
    }
    $rejected=$false
    try {$null=Assert-VolvVMBaselineState -Expected $expected -Actual $modified}
    catch {
        if($_.Exception.Message -like 'NOT VERIFIED: *'){$rejected=$true}else{throw}
    }
    if(-not $rejected){throw ('Unsafe VM environment drift accepted for '+$case.field)}
}
$own='20261117123456123'
$other='20261117123456999'
$identityCases=@(
    @{name=('VOLVE-CI-StartupMotor-'+$own);path='\';excluded=$true},
    @{name=('VOLVE-CI-BootRecovery-'+$own);path='\';excluded=$true},
    @{name=('VOLVE-CI-StartupMotor-'+$other);path='\';excluded=$false},
    @{name=('VOLVE-CI-BootRecovery-'+$other);path='\';excluded=$false},
    @{name=('VOLVE-CI-StartupMotor-'+$own);path='\Microsoft\Windows\';excluded=$false},
    @{name=('VOLVE-CI-BootRecovery-'+$own);path='\Other\';excluded=$false},
    @{name=('volve-CI-StartupMotor-'+$own);path='\';excluded=$false},
    @{name='VOLVE-CATALOGO-0230';path='\';excluded=$false},
    @{name='WindowsMaintenance';path='\Microsoft\Windows\Maintenance\';excluded=$false}
)
foreach($c in $identityCases){
    $actual=Test-VolvVMBaselineExcludedTask -RunId $own -TaskPath $c.path -TaskName $c.name
    if($actual -ne $c.excluded){
        throw ('Unsafe task exclusion: '+$c.path+$c.name+' shouldExclude='+$c.excluded)
    }
}
# ANONYMOUS_DRIFT_HINT: a changing task must still fail closed, no raw values in CI.
$priorActions=$env:GITHUB_ACTIONS
try {
    $env:GITHUB_ACTIONS='true'
    $changed=$expected | ConvertTo-Json -Depth 6 | ConvertFrom-Json
    $changed.taskRecords[0]='\VOLVE-CATALOGO|'+('E'*64)
    $message=''
    try {$null=Assert-VolvVMBaselineState -Expected $expected -Actual $changed}
    catch {$message=$_.Exception.Message}
    if($message -notmatch '^NOT VERIFIED: VM taskRecords changed since Prepare \(first difference: definition changed for the same task; scope=other-folder; identityId=[A-F0-9]{16}; changedSections=unavailable\)$'){
        throw ('Unexpected CI drift response: '+$message)
    }
    if($message.Contains('VOLVE-CATALOGO') -or $message.Contains(('B'*64)) -or $message.Contains(('E'*64))){
        throw 'CI leaked the task name or definition hash'
    }
    $second=''
    try {$null=Assert-VolvVMBaselineState -Expected $expected -Actual $changed}
    catch {$second=$_.Exception.Message}
    if($message -cne $second){throw 'Task identity hash was not deterministic'}
    $renamed=$expected | ConvertTo-Json -Depth 6 | ConvertFrom-Json
    $renamed.taskRecords[0]='\UNRELATED-TASK|'+('B'*64)
    $message=''
    try {$null=Assert-VolvVMBaselineState -Expected $expected -Actual $renamed}
    catch {$message=$_.Exception.Message}
    if($message -cne 'NOT VERIFIED: VM taskRecords changed since Prepare (first difference: task identity changed)'){
        throw 'Renamed task did not fail closed without exposing identity'
    }
    $builtin=Get-VolvVMBaselineTaskDriftHint -ExpectedRecord ('\Microsoft\Windows\Maintenance\Task|'+('A'*64)) -ActualRecord ('\Microsoft\Windows\Maintenance\Task|'+('B'*64))
    if($builtin -notmatch 'scope=microsoft-windows-folder; identityId=[A-F0-9]{16}; changedSections=unavailable'){
        throw 'Microsoft Windows task folder scope not classified'
    }
    if((Get-VolvVMBaselineTaskDriftHint -ExpectedRecord 'bad' -ActualRecord 'bad') -cne ' (first difference: malformed task record)'){
        throw 'Malformed task record diagnostic failed'
    }
} finally {
    if($null -eq $priorActions){Remove-Item Env:\GITHUB_ACTIONS -ErrorAction SilentlyContinue}
    else {$env:GITHUB_ACTIONS=$priorActions}
}
# Synthetic XML only; compare entire Task XML and five independent section digests.
. (Join-Path $PSScriptRoot 'reboot_event_chain.ps1')
$testXML=@'
<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task" version="1.4"><RegistrationInfo><Author>LAB</Author></RegistrationInfo><Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers><Principals><Principal id="Author"><UserId>S-1-5-18</UserId></Principal></Principals><Settings><Enabled>true</Enabled></Settings><Actions Context="Author"><Exec><Command>cmd.exe</Command></Exec></Actions></Task>
'@
$baselineRecord=Get-VolvVMBaselineTaskRecord -TaskPath '\' -TaskName 'Synthetic-Task' -XMLText $testXML
if(@($baselineRecord.Split('|')).Count -ne 14){throw 'Missing five section hashes, six trigger forensic hashes and masked full-document digest'}
$mutations=@(
    @{name='RegistrationInfo';old='<Author>LAB</Author>';new='<Author>OTHER</Author>'},
    @{name='Triggers';old='<BootTrigger><Enabled>true</Enabled></BootTrigger>';new='<BootTrigger><Enabled>false</Enabled></BootTrigger>'},
    @{name='Principals';old='<UserId>S-1-5-18</UserId>';new='<UserId>S-1-5-19</UserId>'},
    @{name='Settings';old='<Settings><Enabled>true</Enabled></Settings>';new='<Settings><Enabled>false</Enabled></Settings>'},
    @{name='Actions';old='<Command>cmd.exe</Command>';new='<Command>notepad.exe</Command>'}
)
foreach($mutation in $mutations){
    if(-not $testXML.Contains($mutation.old)){throw 'Fixture mutation target absent'}
    $changedRecord=Get-VolvVMBaselineTaskRecord -TaskPath '\' -TaskName 'Synthetic-Task' -XMLText ($testXML.Replace($mutation.old,$mutation.new))
    if($baselineRecord -ceq $changedRecord){throw ('Whole task hash ignored '+$mutation.name)}
    $hint=Get-VolvVMBaselineTaskDriftHint -ExpectedRecord $baselineRecord -ActualRecord $changedRecord
    $categoryMarker='changedSections='+$mutation.name
    if(-not $hint.Contains($categoryMarker)){
        throw ('Wrong Task Scheduler XML drift group for '+$mutation.name+': '+$hint)
    }
    if($mutation.name -ceq 'Triggers'){
        if(-not $hint.Contains('changedTriggerFields=Enabled)')){
            throw 'Changed Triggers did not identify the Enabled subfield'
        }
    } elseif($hint.Contains('changedTriggerFields=')){
        throw 'Unrelated Task Scheduler section was mislabeled as Triggers'
    }
    if($hint.Contains('cmd.exe') -or $hint.Contains('notepad.exe') -or $hint.Contains('Synthetic-Task')){
        throw 'Task Scheduler XML information leaked into CI diagnostic'
    }
    $before=$expected|ConvertTo-Json -Depth 6|ConvertFrom-Json
    $after=$expected|ConvertTo-Json -Depth 6|ConvertFrom-Json
    $before.taskRecords=@($baselineRecord)
    $after.taskRecords=@($changedRecord)
    $rejected=$false
    try {$null=Assert-VolvVMBaselineState -Expected $before -Actual $after}
    catch {if($_.Exception.Message -like 'NOT VERIFIED: VM taskRecords changed since Prepare*'){$rejected=$true}else{throw}}
    if(-not $rejected){throw ('Unsafe XML drift accepted for '+$mutation.name)}
}
# SUBFIELD_TRIGGER_DIAGNOSTICS: each mutation must be rejected, and public
# diagnostics may reveal only a fixed, non-sensitive XML field category.
$triggerProbeXML=$testXML.Replace('<BootTrigger><Enabled>true</Enabled></BootTrigger>',
    '<BootTrigger><StartBoundary>2026-01-01T00:00:00</StartBoundary><Enabled>true</Enabled><Repetition><Interval>PT15M</Interval></Repetition><Delay>PT30S</Delay></BootTrigger>')
$triggerOrigin=Get-VolvVMBaselineTaskRecord -TaskPath '\' -TaskName 'Synthetic-Task' -XMLText $triggerProbeXML
$triggerCases=@(
    @{category='StartBoundary';old='2026-01-01T00:00:00';new='2026-01-02T00:00:00'},
    @{category='Enabled';old='<StartBoundary>2026-01-01T00:00:00</StartBoundary><Enabled>true</Enabled>';new='<StartBoundary>2026-01-01T00:00:00</StartBoundary><Enabled>false</Enabled>'},
    @{category='Repetition';old='<Interval>PT15M</Interval>';new='<Interval>PT30M</Interval>'},
    @{category='Delay';old='<Delay>PT30S</Delay>';new='<Delay>PT40S</Delay>'},
    @{category='Other';old='<BootTrigger>';new='<TimeTrigger>'}
)
foreach($tc in $triggerCases){
    if(-not $triggerProbeXML.Contains($tc.old)){throw 'Trigger fixture missing test mutation'}
    $changedXML=$triggerProbeXML.Replace($tc.old,$tc.new)
    if($tc.category -ceq 'Other'){
        $changedXML=$changedXML.Replace('</BootTrigger>','</TimeTrigger>')
    }
    $mutated=Get-VolvVMBaselineTaskRecord -TaskPath '\' -TaskName 'Synthetic-Task' -XMLText $changedXML
    $hint=Get-VolvVMBaselineTaskDriftHint -ExpectedRecord $triggerOrigin -ActualRecord $mutated
    if(-not $hint.Contains('changedSections=Triggers; changedTriggerFields='+$tc.category+')')){
        throw ('Trigger subfield diagnostic did not classify '+$tc.category+': '+$hint)
    }
    foreach($secret in @('Synthetic-Task','2026-01-01','2026-01-02','PT15M','PT30M','BootTrigger','TimeTrigger')){
        if($hint.Contains($secret)){throw 'CI leaked trigger identity or XML value'}
    }
    $beforeCase=$expected|ConvertTo-Json -Depth 6|ConvertFrom-Json
    $afterCase=$expected|ConvertTo-Json -Depth 6|ConvertFrom-Json
    $beforeCase.taskRecords=@($triggerOrigin)
    $afterCase.taskRecords=@($mutated)
    $rejected=$false
    try {$null=Assert-VolvVMBaselineState -Expected $beforeCase -Actual $afterCase}
    catch {if($_.Exception.Message -like 'NOT VERIFIED: VM taskRecords changed since Prepare*'){$rejected=$true}else{throw}}
    if(-not $rejected){throw ('Unsafe trigger field change accepted: '+$tc.category)}
}
$nonTrigger=$triggerProbeXML.Replace('<Command>cmd.exe</Command>','<Command>notepad.exe</Command>')
$nonTriggerRecord=Get-VolvVMBaselineTaskRecord -TaskPath '\' -TaskName 'Synthetic-Task' -XMLText $nonTrigger
$noLeak=Get-VolvVMBaselineTaskDriftHint -ExpectedRecord $triggerOrigin -ActualRecord $nonTriggerRecord
if($noLeak -match 'changedTriggerFields='){throw 'Unrelated action was mislabeled as a trigger change'}
Write-Host 'PASS: SUBFIELD_TRIGGER_DIAGNOSTICS classifies five synthetic trigger mutations, fails closed, and leaks no XML values'

# SPP special-case forensics is diagnostic only: even exact value-only drift
# MUST keep the integrity gate red pending actor attribution.
$sppTaskName='SvcRestartTask'
$sppTaskPath='\Microsoft\Windows\SoftwareProtectionPlatform\'
$sppOldXML=$triggerProbeXML
$sppNewXML=$sppOldXML.Replace('2026-01-01T00:00:00','2026-01-02T00:00:00')
$sppOld=Get-VolvVMBaselineTaskRecord -TaskPath $sppTaskPath -TaskName $sppTaskName -XMLText $sppOldXML
$sppNew=Get-VolvVMBaselineTaskRecord -TaskPath $sppTaskPath -TaskName $sppTaskName -XMLText $sppNewXML
if($sppOld.Split('|').Count -ne 14){throw 'SPP digest missing masked whole-document hash'}
$sppHint=Get-VolvVMBaselineTaskDriftHint -ExpectedRecord $sppOld -ActualRecord $sppNew
if(-not $sppHint.Contains('changedSections=Triggers; changedTriggerFields=StartBoundary; boundedSPPStartBoundary=OBSERVED_NOT_EXEMPT)')){
    throw ('Isolated SPP date value was not labeled non-exempt: '+$sppHint)
}
$oldEnv=$expected|ConvertTo-Json -Depth 6|ConvertFrom-Json
$newEnv=$expected|ConvertTo-Json -Depth 6|ConvertFrom-Json
$oldEnv.taskRecords=@($sppOld)
$newEnv.taskRecords=@($sppNew)
$denied=$false
try{$null=Assert-VolvVMBaselineState -Expected $oldEnv -Actual $newEnv}
catch{if($_.Exception.Message -like 'NOT VERIFIED: VM taskRecords changed since Prepare*'){$denied=$true}else{throw}}
if(-not $denied){throw 'SPP drift illegally bypassed strict integrity gate'}
$sppMutations=@(
    @{kind='action'; xml=$sppNewXML.Replace('<Command>cmd.exe</Command>','<Command>notepad.exe</Command>')},
    @{kind='principal'; xml=$sppNewXML.Replace('<UserId>S-1-5-18</UserId>','<UserId>S-1-5-19</UserId>')},
    @{kind='enabled'; xml=$sppNewXML.Replace('<Enabled>true</Enabled>','<Enabled>false</Enabled>')},
    @{kind='repetition'; xml=$sppNewXML.Replace('<Interval>PT15M</Interval>','<Interval>PT30M</Interval>')},
    @{kind='registration'; xml=$sppNewXML.Replace('<Author>LAB</Author>','<Author>OTHER</Author>')},
    @{kind='root'; xml=$sppNewXML.Replace('version="1.4"','version="1.5"')}
)
foreach($case in $sppMutations){
    if($case.xml -ceq $sppNewXML){throw ('SPP fixture did not mutate '+$case.kind)}
    $bad=Get-VolvVMBaselineTaskRecord -TaskPath $sppTaskPath -TaskName $sppTaskName -XMLText $case.xml
    $hint=Get-VolvVMBaselineTaskDriftHint -ExpectedRecord $sppOld -ActualRecord $bad
    if($hint.Contains('boundedSPPStartBoundary=')){throw ('SPP '+$case.kind+' falsely treated as only a date')}
    $newEnv.taskRecords=@($bad)
    $blocked=$false
    try{$null=Assert-VolvVMBaselineState -Expected $oldEnv -Actual $newEnv}
    catch{if($_.Exception.Message -like 'NOT VERIFIED: VM taskRecords changed since Prepare*'){$blocked=$true}else{throw}}
    if(-not $blocked){throw ('SPP '+$case.kind+' change bypassed strict integrity')}
}
$foreign=Get-VolvVMBaselineTaskRecord -TaskPath '\Microsoft\Windows\Unrelated\' -TaskName $sppTaskName -XMLText $sppNewXML
if((Get-VolvVMBaselineTaskDriftHint -ExpectedRecord $sppOld -ActualRecord $foreign).Contains('boundedSPPStartBoundary=')){
    throw 'Unrelated Scheduler task treated as protected SPP identity'
}
$legacy13=$sppOld.Substring(0,$sppOld.LastIndexOf('|'))
if((Get-VolvVMBaselineTaskDriftHint -ExpectedRecord $legacy13 -ActualRecord $sppNew).Contains('boundedSPPStartBoundary=')){
    throw 'Legacy digest without whole XML evidence treated as SPP proof'
}
Write-Host 'PASS: SPP_MASKED_WHOLE_XML_DIAGNOSTIC no-exemption; isolated StartBoundary classified, six unsafe mutations rejected, foreign task and legacy schema rejected'

$rejectedDoctype=$false
try {$null=Get-VolvVMBaselineTaskRecord -TaskPath '\' -TaskName 'Synthetic-Task' -XMLText ('<!DOCTYPE Task [<!ENTITY x "bad">]>'+$testXML)}
catch {$rejectedDoctype=$true}
if(-not $rejectedDoctype){throw 'Malformed or DTD-backed Task Scheduler XML was accepted'}
Write-Host 'PASS: FIVE_XML_DRIFT_SECTIONS anonymous diagnostics and full-document fail-closed tests'
Write-Host 'PASS: ANONYMOUS_DRIFT_HINT detects task drift without bypass or leaked task details'
Write-Host ('PASS: VM environment baseline matched and rejected '+$cases.Count+' synthetic HOSTS/DNS/all-folder-task drifts')
Write-Host ('PASS: '+$identityCases.Count+' task ownership cases; only two exact root tasks from current RunId are excluded')
