# Ejecuta solo la inspección DNS53 local; guarda JSON junto al kit.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$here=Split-Path -Parent $MyInvocation.MyCommand.Path
$inspector=Join-Path $here 'VOLVE_0287_Proceso_DNS53_Solo_Lectura.ps1'
$raw=@(& $inspector)
$payload=($raw -join [Environment]::NewLine).Trim()
$result=$payload|ConvertFrom-Json -ErrorAction Stop
if($result.schema -ne 1 -or
   $result.tool -ne 'volve-0287-dns53-process-ownership-readonly' -or
   $result.may_modify_windows -ne $false -or
   $result.network_queries_sent -ne $false -or
   $result.migration_authorized -ne $false){
    throw 'Informe no reconocido; no se guarda.'
}
$name='VOLVE_PC_PROCESO_DNS53_SOLO_LECTURA_'+(Get-Date -Format 'yyyyMMdd_HHmmss')+'.json'
$file=Join-Path $here $name
[IO.File]::WriteAllText($file,$payload+[Environment]::NewLine,[Text.UTF8Encoding]::new($false))
Write-Host ('Informe de solo lectura guardado: '+$file)
