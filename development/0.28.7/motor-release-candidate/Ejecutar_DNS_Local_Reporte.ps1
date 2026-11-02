# Guarda una prueba DNS local limitada. No instala ni configura VOLVE.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$here=Split-Path -Parent $MyInvocation.MyCommand.Path
$checker=Join-Path $here 'VOLVE_0287_Respuestas_DNS_Loopback_Solo_Lectura.ps1'
$lines=@(& $checker)
$json=($lines -join [Environment]::NewLine).Trim()
$report=$json|ConvertFrom-Json -ErrorAction Stop
if($report.schema -ne 1 -or
   $report.tool -ne 'volve-0287-local-dualstack-dns-functional-readonly' -or
   $report.may_modify_windows -ne $false -or
   $report.migration_authorized -ne $false -or
   $report.queries_attempted -gt 6 -or $report.results.Count -gt 6){
    throw 'El resultado DNS no cumple el contrato de lectura limitada.'
}
$name='VOLVE_PC_DNS_LOCAL_SOLO_LECTURA_'+(Get-Date -Format 'yyyyMMdd_HHmmss')+'.json'
$file=Join-Path $here $name
[IO.File]::WriteAllText($file,$json+[Environment]::NewLine,[Text.UTF8Encoding]::new($false))
Write-Host ('Informe de DNS local guardado: '+$file)
Write-Host 'Adjunta el JSON al chat. No se modificó Windows.'
