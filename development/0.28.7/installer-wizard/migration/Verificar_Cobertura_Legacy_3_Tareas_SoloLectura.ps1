#requires -Version 5.1
# VOLVE 0.28.7 — lectura independiente de copia de acciones directas.
# NO AUTORIZA LIMPIEZA, instalación, detención ni restauración.
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][string]$BackupPath,
 [Parameter(Mandatory=$true)][string]$ThreeTasksBackupPath
)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
function Fail([string]$reason){throw ('VOLVE_THREE_TASKS_VERIFY_REFUSED: '+$reason)}
if($env:OS -ne 'Windows_NT'){Fail 'Solo Windows'}
$user=[Security.Principal.WindowsIdentity]::GetCurrent()
if(-not ([Security.Principal.WindowsPrincipal]::new($user)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
 Fail 'Requiere administrador para inspeccionar NTFS privado'}
$pd=[IO.Path]::GetFullPath([Environment]::GetFolderPath('CommonApplicationData')).TrimEnd('\')
function Strict-Path([string]$given,[string]$pattern){
 $path=[IO.Path]::GetFullPath($given).TrimEnd('\')
 if($path.StartsWith('\\') -or [IO.Path]::GetDirectoryName($path) -cne $pd -or
 [IO.Path]::GetFileName($path) -notmatch $pattern){Fail 'Ruta privada no permitida'}
 return $path
}
$original=Strict-Path $BackupPath '^VOLVE-Migration-Backup-[a-fA-F0-9]{32}$'
$snapshot=Strict-Path $ThreeTasksBackupPath '^VOLVE-Legacy-Three-Recovery-[a-fA-F0-9]{32}$'
function Check-ACL([string]$path){
 $node=Get-Item -LiteralPath $path -Force -ErrorAction Stop
 if(($node.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){Fail 'Backup redirigido'}
 $acl=Get-Acl -LiteralPath $path -ErrorAction Stop
 if(-not $acl.AreAccessRulesProtected){Fail 'Herencia NTFS inesperada'}
 if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')){
  Fail 'Propietario NTFS del respaldo no permitido'}
 $aces=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
 foreach($ace in $aces){
  if($ace.IsInherited -or $ace.AccessControlType -ne 'Allow' -or
   $ace.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')){
   Fail 'Principal ajeno tiene acceso a archivo de recuperacion'}
 }
 foreach($id in @('S-1-5-18','S-1-5-32-544')){
  if(@($aces|Where-Object{$_.IdentityReference.Value -eq $id}).Count -eq 0){
   Fail 'DACL incompleta en el respaldo'}
 }
}
Check-ACL $snapshot
$names=@('accion-000.exe','accion-001.ps1','accion-002.exe','recibo-tres-tareas.json')
$files=@(Get-ChildItem -LiteralPath $snapshot -Force -ErrorAction Stop | ForEach-Object{$_.Name})
if($files.Count -ne 4){Fail 'Archivo no declarado en copia de tres tareas'}
foreach($name in $names){
 if($name -notin $files){Fail 'Archivo de accion directo faltante'}
 Check-ACL (Join-Path $snapshot $name)
}
$receiptFile=Join-Path $snapshot 'recibo-tres-tareas.json'
if((Get-Item -LiteralPath $receiptFile).Length -gt 8192){Fail 'Recibo fuera de tamaño'}
try{
 $utf8=[Text.UTF8Encoding]::new($false,$true)
 $receipt=$utf8.GetString([IO.File]::ReadAllBytes($receiptFile))|ConvertFrom-Json -ErrorAction Stop
}catch{Fail 'Recibo de tres tareas ilegible'}
if($receipt.schema -ne 1 -or
 $receipt.component -cne 'VOLVE-THREE-LEGACY-TASKS-DIRECT-ACTIONS-BACKUP-V1' -or
 $receipt.state -cne 'PRIVATE_BACKUP_ONLY_NO_CLEANUP_NO_INSTALL' -or
 $receipt.direct_actions_only -cne $true -or
 $receipt.transitive_dependencies_certified -cne $false -or
 $receipt.recovery_after_reboot_verified -cne $false -or
 $receipt.publisher_authorization_verified -cne $false -or
 $receipt.cleanup_authorized -cne $false -or
 $receipt.install_authorized -cne $false){
 Fail 'El recibo intenta autorizar una operacion insegura'}
$initial=Join-Path $original 'manifest.json'
$expected=(Get-FileHash -LiteralPath $initial -Algorithm SHA256).Hash.ToLowerInvariant()
if($receipt.original_manifest_sha256 -cne $expected){Fail 'Recibo enlazado a otro backup inicial'}
$baseVerifier=Join-Path $PSScriptRoot 'Verificar_Respaldo_VOLVE_SoloLectura.ps1'
if(-not (Test-Path -LiteralPath $baseVerifier -PathType Leaf)){Fail 'Sin verificador independiente de DNS/HOSTS/tareas'}
$ps=Join-Path $PSHOME 'powershell.exe'
$out=@(& $ps -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $baseVerifier -BackupPath $original)
if($LASTEXITCODE -ne 0 -or
 @($out|Where-Object{$_ -match '^VOLVE_BACKUP_VALIDATED_READ_ONLY;'}).Count -ne 1){
 Fail 'El respaldo inicial no coincide con Windows'}
$rows=@($receipt.records)
if($rows.Count -ne 3){Fail 'No se cubren tres dependencias directas'}
$tasks=@('VOLVE-CATALOGO-0230','VOLVE-DNS-RESCUE-0270','VOLVE-DNS-SERVER-0270')
$kinds=@('catalog-executable','rescue-powershell-script','dns-server-executable')
for($i=0;$i -lt 3;$i++){
 $row=$rows[$i]
 $filename=$names[$i]
 if($row.task -cne $tasks[$i] -or $row.kind -cne $kinds[$i] -or
  $row.artifact -cne $filename){Fail 'Recibo de tarea distinto de la cobertura esperada'}
 $copy=Join-Path $snapshot $filename
 $currentHash=(Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash.ToLowerInvariant()
 $info=Get-Item -LiteralPath $copy -Force
 if($info.Length -lt 1 -or $info.Length -gt 80MB -or $info.Length -ne [int64]$row.original_size -or
  $currentHash -cne $row.original_sha256){Fail 'Contenido de respaldo modificado'}
 $task=@(Get-ScheduledTask -TaskName $tasks[$i] -ErrorAction Stop |
   Where-Object{$_.TaskName -ceq $tasks[$i] -and $_.TaskPath -ceq '\'})
 if($task.Count -ne 1){Fail 'Tarea origen desaparecida'}
 $action=@($task[0].Actions|Where-Object{$null -ne $_})
 if($action.Count -ne 1){Fail 'Acciones de la tarea cambiaron'}
 $candidate=''
 if($i -eq 1){
  $args=([string]$action[0].Arguments).Trim()
  if(-not ($args -match '(?i)(?:^|\s)-File\s+(?:"([^"]+)"|''([^'']+)''|(\S+))\s*
   Fail 'Argumentos de recuperacion no coinciden con respaldo'}
  $candidate=@($Matches[1],$Matches[2],$Matches[3] | Where-Object{$_})|Select-Object -First 1
 }else{
  $candidate=[string]$action[0].Execute
 }
 $live=[IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables(([string]$candidate).Trim().Trim('"')))
 if(-not $live.Equals([string]$row.source_path,[StringComparison]::OrdinalIgnoreCase)){
  Fail 'Ruta de accion difiere de archivo original'}
 if((Get-FileHash -LiteralPath $live -Algorithm SHA256).Hash.ToLowerInvariant() -cne $currentHash){
  Fail 'Ejecutable o script vivo difiere de respaldo'}
 $origManifest=Get-Content -LiteralPath $initial -Raw -Encoding UTF8 | ConvertFrom-Json
 $origRow=@($origManifest.current_tasks|Where-Object{$_.task_name -ceq $tasks[$i]})
 if($origRow.Count -ne 1 -or $origRow[0].xml_sha256 -cne $row.task_xml_sha256){
  Fail 'Tarea origen no coincide con XML inicial'}
}
Check-ACL $snapshot
foreach($name in $names){Check-ACL (Join-Path $snapshot $name)}
Write-Host 'VOLVE_THREE_TASKS_DIRECT_ACTIONS_VERIFIED_READ_ONLY; TASKS=3; FILES=3'
Write-Host 'CLEANUP_AUTHORIZED=NO; INSTALL_AUTHORIZED=NO; TRANSITIVE_DEPENDENCIES_VERIFIED=NO'
)){
   Fail 'Argumentos de recuperacion no coinciden con respaldo'}
  $candidate=@($Matches[1],$Matches[2],$Matches[3] | Where-Object{$_})|Select-Object -First 1
 }else{
  $candidate=[string]$action[0].Execute
 }
 $live=[IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables(([string]$candidate).Trim().Trim('"')))
 if(-not $live.Equals([string]$row.source_path,[StringComparison]::OrdinalIgnoreCase)){
  Fail 'Ruta de accion difiere de archivo original'}
 if((Get-FileHash -LiteralPath $live -Algorithm SHA256).Hash.ToLowerInvariant() -cne $currentHash){
  Fail 'Ejecutable o script vivo difiere de respaldo'}
 $origManifest=Get-Content -LiteralPath $initial -Raw -Encoding UTF8 | ConvertFrom-Json
 $origRow=@($origManifest.current_tasks|Where-Object{$_.task_name -ceq $tasks[$i]})
 if($origRow.Count -ne 1 -or $origRow[0].xml_sha256 -cne $row.task_xml_sha256){
  Fail 'Tarea origen no coincide con XML inicial'}
}
Check-ACL $snapshot
foreach($name in $names){Check-ACL (Join-Path $snapshot $name)}
Write-Host 'VOLVE_THREE_TASKS_DIRECT_ACTIONS_VERIFIED_READ_ONLY; TASKS=3; FILES=3'
Write-Host 'CLEANUP_AUTHORIZED=NO; INSTALL_AUTHORIZED=NO; TRANSITIVE_DEPENDENCIES_VERIFIED=NO'
