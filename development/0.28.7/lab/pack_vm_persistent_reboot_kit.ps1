# VOLVE 0.28.7 - package an isolated persistent Windows VM lab kit.
# This does NOT create a product release, sign a motor, install VOLVE,
# contact users or change Windows DNS, Task Scheduler or registry.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$MotorExe,
    [Parameter(Mandatory=$true)][string]$OutRoot
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
   [string]::IsNullOrWhiteSpace($env:GITHUB_SHA)){
    throw 'VM-only lab kit packaging requires a GitHub-hosted Windows CI run'
}
if(-not [IO.Path]::IsPathRooted($MotorExe) -or -not [IO.Path]::IsPathRooted($OutRoot)){
    throw 'Motor and output must use absolute paths'
}
$actual=Get-Item -LiteralPath $MotorExe -ErrorAction Stop
if($actual.PSIsContainer -or ($actual.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
   $actual.Length -lt 1048576 -or $actual.Length -gt 83886080){
    throw 'Invalid, linked, or out-of-range test-only motor binary'
}
if(Test-Path -LiteralPath $OutRoot){throw 'Refusing existing lab packaging output'}
$source=$PSScriptRoot
$names=@(
 'vm_full_motor_reboot_dns.ps1',
 'live_dns_boot_event_chain.ps1',
 'reboot_event_chain.ps1',
 'vm_direct_internet_probe.ps1',
 'vm_dns_reply_contract.ps1'
)
$required=$names+@('VM_FULL_DNS_REBOOT.md')
foreach($name in $required){
    $path=Join-Path $source $name
    $file=Get-Item -LiteralPath $path -ErrorAction Stop
    if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){
        throw ('Unsafe VM kit file '+$name)
    }
}
New-Item -ItemType Directory -Path $OutRoot -ErrorAction Stop|Out-Null
$motorName='VOLVE_CI_FreshDNS53.exe'
Copy-Item -LiteralPath $MotorExe -Destination (Join-Path $OutRoot $motorName) -ErrorAction Stop
foreach($name in $names){
    Copy-Item -LiteralPath (Join-Path $source $name) -Destination (Join-Path $OutRoot $name) -ErrorAction Stop
}
Copy-Item -LiteralPath (Join-Path $source 'VM_FULL_DNS_REBOOT.md') -Destination (Join-Path $OutRoot 'LEEME_SOLO_VM.md') -ErrorAction Stop
$warning=@'
VOLVE 0.28.7 - LABORATORIO SOLO PARA VM WINDOWS DESCARTABLE Y PERSISTENTE
NO ejecutar este motor ni estos scripts en la PC con VOLVE 0.28.6.
NO es un instalador, actualización, servicio productivo ni rescate firmado.
Se necesita una VM con snapshot y control de administrador; los scripts
rechazan equipos que no sean máquinas virtuales identificables.
Este kit prueba arranque de un MOTOR DE LABORATORIO, NO el rollback firmado
de la actualización del motor 0.28.6 -> 0.28.7.
No se realiza ningún reinicio automáticamente.
'@
[IO.File]::WriteAllText((Join-Path $OutRoot 'NO_EJECUTAR_EN_PC_REAL.txt'),
 $warning,[Text.UTF8Encoding]::new($false))
$manifest=[ordered]@{
 schema=1
 kind='VOLVE_CI_PERSISTENT_VM_PREBOOT_KIT'
 source_revision=$env:GITHUB_SHA
 source_workflow_run=$env:GITHUB_RUN_ID
 created_utc=[DateTime]::UtcNow.ToString('o')
 vm_only=$true
 publisher_signed=$false
 product_release=$false
 migration_from_0286_proven=$false
 persistent_reboot_proven=$false
 post_reboot_rollback_proven=$false
 expected_lab_catalog_lines=400005
 files=@()
}
foreach($name in @($motorName)+$names+@('LEEME_SOLO_VM.md','NO_EJECUTAR_EN_PC_REAL.txt')){
    $item=Get-Item -LiteralPath (Join-Path $OutRoot $name) -ErrorAction Stop
    $manifest.files+=([ordered]@{
      name=$name
      bytes=[int64]$item.Length
      sha256=(Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    })
}
$manifestPath=Join-Path $OutRoot 'SHA256_MANIFEST.json'
$manifest|ConvertTo-Json -Depth 7|Set-Content -LiteralPath $manifestPath -Encoding UTF8
$verified=Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8|ConvertFrom-Json -ErrorAction Stop
if($verified.schema -ne 1 -or $verified.files.Count -ne 8 -or
   $verified.source_revision -cne $env:GITHUB_SHA){
    throw 'VM lab package manifest failed strict roundtrip'
}
foreach($entry in $verified.files){
    if($entry.name -notin @($motorName)+$names+@('LEEME_SOLO_VM.md','NO_EJECUTAR_EN_PC_REAL.txt')){
        throw 'VM kit manifest contains an unexpected file'
    }
    $p=Join-Path $OutRoot $entry.name
    if((Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry.sha256){
        throw ('Package SHA256 differs from manifest: '+$entry.name)
    }
}
Write-Output 'VOLVE_CI_VM_PERSISTENT_KIT_HASHES_VERIFIED'
