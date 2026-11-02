# Wrapper: solo ejecuta diagnóstico de solo lectura y guarda su salida JSON.
# No instala, modifica DNS, tareas, procesos, archivos de VOLVE ni el registro.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$folder = Split-Path -Parent $MyInvocation.MyCommand.Path
$inspector = Join-Path $folder 'VOLVE_0287_Identidad_Motor_Solo_Lectura.ps1'
$lines = @(& $inspector)
$json = ($lines -join [Environment]::NewLine).Trim()
$report = $json | ConvertFrom-Json -ErrorAction Stop
if ($report.schema -ne 1 -or $report.tool -ne 'volve-0287-legacy-engine-review-readonly' -or
    $report.may_modify_windows -ne $false -or $report.migration_authorized -ne $false) {
    throw 'Resultado de diagnóstico desconocido: NO se guardará como verificado.'
}
$file = Join-Path $folder ('VOLVE_PC_IDENTIDAD_SOLO_LECTURA_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.json')
[IO.File]::WriteAllText($file, $json + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
Write-Host ''
Write-Host 'DIAGNOSTICO DE SOLO LECTURA GUARDADO:' -ForegroundColor Green
Write-Host $file
Write-Host 'Envia este archivo .json al chat. Tu DNS y las tareas no se han modificado.'
