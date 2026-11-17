# Read-only VM environment comparison contract; synthetic fixtures ONLY.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'vm_environment_baseline.ps1')
$expected=[pscustomobject][ordered]@{
    schema=1
    kind='VOLVE_VM_READ_ONLY_ENVIRONMENT'
    hostsSha256=('A'*64)
    dnsRecords=@('2|2|192.0.2.10,192.0.2.11','2|23|2001:db8::53')
    rootTaskRecords=@('VOLVE-CATALOGO|'+('B'*64),'WindowsMaintenance|'+('C'*64))
}
$clone=$expected|ConvertTo-Json -Depth 6|ConvertFrom-Json
if(-not (Assert-VolvVMBaselineState -Expected $expected -Actual $clone)){
    throw 'Identical read-only VM environment baseline must pass'
}
$cases=@(
    @{field='hostsSha256';value=('D'*64)},
    @{field='dnsRecords';value=@('2|2|192.0.2.55','2|23|2001:db8::53')},
    @{field='dnsRecords';value=@('2|2|192.0.2.10,192.0.2.11')},
    @{field='rootTaskRecords';value=@('VOLVE-CATALOGO|'+('E'*64),'WindowsMaintenance|'+('C'*64))},
    @{field='rootTaskRecords';value=@('WindowsMaintenance|'+('C'*64))},
    @{field='schema';value=2},
    @{field='kind';value='MALFORMED'},
    @{field='hostsSha256';remove=$true},
    @{field='dnsRecords';remove=$true},
    @{field='rootTaskRecords';remove=$true}
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
Write-Host ('PASS: VM environment baseline matched and rejected '+$cases.Count+' synthetic HOSTS/DNS/unrelated-task drifts')
