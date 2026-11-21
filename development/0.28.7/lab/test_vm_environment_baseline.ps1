# Read-only VM environment comparison contract; synthetic fixtures ONLY.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'vm_environment_baseline.ps1')
$expected=[pscustomobject][ordered]@{
    schema=1
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
    @{field='schema';value=2},
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
    if($message -notmatch '^NOT VERIFIED: VM taskRecords changed since Prepare \(first difference: definition changed for the same task; scope=other-folder; identityId=[A-F0-9]{16}\)$'){
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
    if($builtin -notmatch 'scope=microsoft-windows-folder; identityId=[A-F0-9]{16}'){
        throw 'Microsoft Windows task folder scope not classified'
    }
    if((Get-VolvVMBaselineTaskDriftHint -ExpectedRecord 'bad' -ActualRecord 'bad') -cne ' (first difference: malformed task record)'){
        throw 'Malformed task record diagnostic failed'
    }
} finally {
    if($null -eq $priorActions){Remove-Item Env:\GITHUB_ACTIONS -ErrorAction SilentlyContinue}
    else {$env:GITHUB_ACTIONS=$priorActions}
}
Write-Host 'PASS: ANONYMOUS_DRIFT_HINT detects task drift without bypass or leaked task details'
Write-Host ('PASS: VM environment baseline matched and rejected '+$cases.Count+' synthetic HOSTS/DNS/all-folder-task drifts')
Write-Host ('PASS: '+$identityCases.Count+' task ownership cases; only two exact root tasks from current RunId are excluded')
