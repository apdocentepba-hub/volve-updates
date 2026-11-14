#requires -Version 5.1
# VOLVE 0.28.7 - Guardar MOTOR ANTIGUO como pieza de recuperacion.
# Requiere respaldo previo validado. No detiene procesos, modifica DNS,
# programa tareas, cambia registro ni borra archivos. NO autoriza migracion.
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$BackupPath
)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
function Reject([string]$msg){throw ('VOLVE_LEGACY_MOTOR_REFUSED: '+$msg)}
$wid=[Security.Principal.WindowsIdentity]::GetCurrent()
if(-not ([Security.Principal.WindowsPrincipal]::new($wid)).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator)){Reject 'Se necesita administrador para respaldar un motor SYSTEM'}
$pd=[IO.Path]::GetFullPath([Environment]::GetFolderPath('CommonApplicationData')).TrimEnd('\')
$backup=[IO.Path]::GetFullPath($BackupPath).TrimEnd('\')
if([IO.Path]::GetDirectoryName($backup) -cne $pd -or
 [IO.Path]::GetFileName($backup) -notmatch '^VOLVE-Migration-Backup-[a-fA-F0-9]{32}$' -or
 $backup.StartsWith('\\')){Reject 'Ruta del respaldo previo no permitida'}
$verifier=Join-Path $PSScriptRoot 'Verificar_Respaldo_VOLVE_SoloLectura.ps1'
if(-not (Test-Path -LiteralPath $verifier -PathType Leaf)){Reject 'Falta el verificador independiente'}
$ps=Join-Path $PSHOME 'powershell.exe'
$validation=@(& $ps -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $verifier -BackupPath $backup)
if($LASTEXITCODE -ne 0 -or
 @($validation | Where-Object {$_ -match '^VOLVE_BACKUP_VALIDATED_READ_ONLY;'}).Count -ne 1){
 Reject 'El respaldo preliminar no coincide con la configuración viva'}
$manifestFile=Join-Path $backup 'manifest.json'
$manifest=Get-Content -LiteralPath $manifestFile -Raw -Encoding UTF8 | ConvertFrom-Json
$record=@($manifest.current_tasks | Where-Object {
 $_.task_name -ceq 'VOLVE-DNS-SERVER-0270' -and $_.task_path -ceq '\'
})
if($record.Count -ne 1){Reject 'Motor antiguo no identificado en XML del respaldo previo'}
$task=@(Get-ScheduledTask -TaskName 'VOLVE-DNS-SERVER-0270' -ErrorAction Stop | Where-Object {
 $_.TaskName -ceq 'VOLVE-DNS-SERVER-0270' -and $_.TaskPath -ceq '\'
})
if($task.Count -ne 1){Reject 'Tarea de motor antigua ambigua'}
if([string]$task[0].Principal.UserId -notmatch '^(?i:SYSTEM|NT AUTHORITY\\SYSTEM|S-1-5-18)$'){
 Reject 'La tarea antigua ya no pertenece a SYSTEM'}
$actions=@($task[0].Actions | Where-Object {$null -ne $_})
if($actions.Count -ne 1){Reject 'La tarea tiene acciones múltiples o ninguna'}
if(([string]$actions[0].Arguments).Trim() -cne '--dns-service'){
 Reject 'El motor antiguo tiene argumentos no autorizados'}
$raw=([string]$actions[0].Execute).Trim().Trim('"')
$exe=[IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($raw))
if([IO.Path]::GetFileName($exe) -cne 'VOLVE_DNS_Server_0270.exe' -or
 $exe.StartsWith('\\')){Reject 'Nombre o ruta del motor no es el esperado'}
$roots=@($env:ProgramFiles,[Environment]::GetEnvironmentVariable('ProgramFiles(x86)'),
 $pd | Where-Object {$_})
$allowed=$false
foreach($root in $roots){
 $parent=[IO.Path]::GetFullPath($root).TrimEnd('\')+'\'
 if($exe.StartsWith($parent,[StringComparison]::OrdinalIgnoreCase)){$allowed=$true}
}
if(-not $allowed){Reject 'El motor heredado no se encuentra en una raíz protegida'}
# No aceptar junctions ni enlaces NTFS en ningún componente entre la raíz
# de instalación aprobada y el archivo del motor.
$current=$exe
while($current -and (Test-Path -LiteralPath $current)){
 $node=Get-Item -LiteralPath $current -Force -ErrorAction Stop
 if(($node.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){
  Reject 'Ruta del motor heredado contiene junction o enlace simbólico'
 }
 $current=[IO.Path]::GetDirectoryName($current)
 if([string]::IsNullOrWhiteSpace($current)){break}
}
$exeStat=Get-Item -LiteralPath $exe -Force -ErrorAction Stop
if($exeStat.PSIsContainer -or $exeStat.Length -lt 1 -or $exeStat.Length -gt 80MB){
 Reject 'Motor original inexistente o tamaño fuera de límite'}
$taskXML=Export-ScheduledTask -TaskName $task[0].TaskName -TaskPath $task[0].TaskPath -ErrorAction Stop
$utf8=[Text.UTF8Encoding]::new($false)
$xmlBytes=$utf8.GetBytes($taskXML)
$originalTaskFile=Join-Path $backup ([string]$record[0].xml_backup)
$oldXml=[IO.File]::ReadAllBytes($originalTaskFile)
$sha=[Security.Cryptography.SHA256]::Create()
try{
 $originalHash=([BitConverter]::ToString($sha.ComputeHash($oldXml))).Replace('-','').ToLowerInvariant()
 $currentHash=([BitConverter]::ToString($sha.ComputeHash($xmlBytes))).Replace('-','').ToLowerInvariant()
}finally{$sha.Dispose()}
if($originalHash -cne $currentHash -or $originalHash -cne $record[0].xml_sha256){
 Reject 'Definición de la tarea SYSTEM cambió desde el primer respaldo'}
$beforeHash=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
$beforeSize=$exeStat.Length
$system=[Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$admins=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$acl=[Security.AccessControl.DirectorySecurity]::new()
$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner($admins)
$inherit=[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
 [Security.AccessControl.InheritanceFlags]::ObjectInherit
foreach($sid in @($system,$admins)){
 $rule=[Security.AccessControl.FileSystemAccessRule]::new($sid,
  [Security.AccessControl.FileSystemRights]::FullControl,$inherit,
  [Security.AccessControl.PropagationFlags]::None,
  [Security.AccessControl.AccessControlType]::Allow)
 $acl.AddAccessRule($rule)
}
function Check-PrivateACL([string]$p){
 $a=Get-Acl -LiteralPath $p -ErrorAction Stop
 if(-not $a.AreAccessRulesProtected){Reject 'Backup de motor con ACL heredada'}
 if($a.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')){
  Reject 'Propietario NTFS del motor no permitido'}
 $aces=@($a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
 foreach($ace in $aces){
  if($ace.AccessControlType -ne 'Allow' -or $ace.IsInherited -or
   $ace.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')){
   Reject 'DACL del motor contiene usuarios ajenos'}
 }
 foreach($sid in @('S-1-5-18','S-1-5-32-544')){
  if(@($aces|Where-Object{$_.IdentityReference.Value -eq $sid}).Count -eq 0){
   Reject 'Falta SYSTEM/Administradores en ACL de motor'}
 }
}
# Carpeta NUEVA, nunca se modifican archivos del primer respaldo.
$dir=Join-Path $pd ('VOLVE-Legacy-Motor-Recovery-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($dir,$acl)
Check-PrivateACL $dir
function Save-PrivateFile([string]$name,[byte[]]$bytes){
 $target=Join-Path $script:dir $name
 $file=[IO.FileStream]::new($target,[IO.FileMode]::CreateNew,
  [IO.FileAccess]::Write,[IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough)
 try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
 $fa=[Security.AccessControl.FileSecurity]::new()
 $fa.SetAccessRuleProtection($true,$false);$fa.SetOwner($script:admins)
 foreach($sid in @($script:system,$script:admins)){
  $fa.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,
   [Security.AccessControl.FileSystemRights]::FullControl,
   [Security.AccessControl.AccessControlType]::Allow))
 }
 [IO.File]::SetAccessControl($target,$fa)
 Check-PrivateACL $target
 return (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
}
try{
 # Se limita a 80 MiB; la copia se lee del motor pero jamás lo ejecuta.
 $bytes=[IO.File]::ReadAllBytes($exe)
 if($bytes.Length -ne $beforeSize){Reject 'El motor cambió al copiar'}
 $copyHash=Save-PrivateFile 'motor-original.exe' $bytes
 if($copyHash -cne $beforeHash){Reject 'El motor respaldado no coincide con el original'}
 $xmlCopyHash=Save-PrivateFile 'tarea-system-original.xml' $xmlBytes
 if($xmlCopyHash -cne $originalHash){Reject 'XML respaldado no coincide con la tarea original'}
 $originalManifestHash=(Get-FileHash -LiteralPath $manifestFile -Algorithm SHA256).Hash.ToLowerInvariant()
 $receipt=[ordered]@{
  schema=1;component='VOLVE-LEGACY-MOTOR-BACKUP-UNSIGNED-ONLY'
  state='BACKUP_ONLY_NO_SWITCH_NO_CLEANUP_NO_INSTALL'
  original_backup_manifest_sha256=$originalManifestHash
  motor_file='motor-original.exe';motor_sha256=$copyHash;motor_bytes=$bytes.Length
  task_file='tarea-system-original.xml';task_sha256=$xmlCopyHash
  requires_publisher_signature=$true;cleanup_authorized=$false;install_authorized=$false
  recovered_after_reboot=$false
 }
 $receiptBytes=$utf8.GetBytes((ConvertTo-Json -InputObject $receipt -Depth 6 -Compress))
 $receiptHash=Save-PrivateFile 'recibo-motor.json' $receiptBytes
 if((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant() -cne $beforeHash){
  Reject 'La fuente del motor cambió durante la copia'}
 $latest=@(& $ps -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $verifier -BackupPath $backup)
 if($LASTEXITCODE -ne 0 -or
  @($latest|Where-Object{$_ -match '^VOLVE_BACKUP_VALIDATED_READ_ONLY;'}).Count -ne 1){
  Reject 'El respaldo DNS/tareas/HOSTS dejó de ser válido'}
 foreach($n in @('motor-original.exe','tarea-system-original.xml','recibo-motor.json')){
  Check-PrivateACL (Join-Path $dir $n)
 }
 Check-PrivateACL $dir
 $independent=Join-Path $PSScriptRoot 'Verificar_Motor_Legacy_Rescate_Sin_Limpieza.ps1'
 if(-not (Test-Path -LiteralPath $independent -PathType Leaf)){
  Reject 'No se encuentra verificador independiente de motor y tarea SYSTEM'
 }
 $check=@(& $ps -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $independent -OriginalBackupPath $backup -MotorBackupPath $dir)
 if($LASTEXITCODE -ne 0 -or
  @($check|Where-Object{$_ -match '^VOLVE_LEGACY_RECOVERY_VERIFIED_READ_ONLY;'}).Count -ne 1){
  Reject 'Copia de motor no superó la verificación independiente'
 }
 Write-Host 'VOLVE_MOTOR_VERIFICACION_INDEPENDIENTE=PASS; BORRADO_AUTORIZADO=NO'
 Write-Host 'VOLVE_LEGACY_MOTOR_BACKUP_OK; COPIA_VERIFICADA=SI; LIMPIEZA_AUTORIZADA=NO'
 Write-Host ('RECIBO_SHA256='+$receiptHash)
 Write-Host 'SISTEMA_INTACTO=SI; MOTOR_NO_MODIFICADO; TAREAS_INTACTAS; DNS_INTACTO'
 Write-Host 'NO COMPARTIR CARPETAS NI BINARIOS. NO HABILITA INSTALACION.'
}catch{
 throw
}
