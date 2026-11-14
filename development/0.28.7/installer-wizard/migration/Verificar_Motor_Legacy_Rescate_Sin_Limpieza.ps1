#requires -Version 5.1
# Independiente, solo lectura. Verifica copia del motor antiguo y XML de
# la tarea SYSTEM; nunca aprueba conmutación, eliminación ni instalación.
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][string]$OriginalBackupPath,
 [Parameter(Mandatory=$true)][string]$MotorBackupPath
)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
function Refuse([string]$reason){throw ('VOLVE_LEGACY_RECOVERY_INVALID: '+$reason)}
if($env:OS -ne 'Windows_NT'){Refuse 'Solo Windows'}
$ident=[Security.Principal.WindowsIdentity]::GetCurrent()
if(-not ([Security.Principal.WindowsPrincipal]::new($ident)).IsInRole(
 [Security.Principal.WindowsBuiltInRole]::Administrator)){Refuse 'Requiere administrador para leer backup SYSTEM'}
$pd=[IO.Path]::GetFullPath([Environment]::GetFolderPath('CommonApplicationData')).TrimEnd('\')
function Allow-PrivatePath([string]$provided,[string]$regex){
 $full=[IO.Path]::GetFullPath($provided).TrimEnd('\')
 if($full.StartsWith('\\') -or [IO.Path]::GetDirectoryName($full) -cne $pd -or
 [IO.Path]::GetFileName($full) -notmatch $regex){Refuse 'Ruta externa o no permitida'}
 return $full
}
$original=Allow-PrivatePath $OriginalBackupPath '^VOLVE-Migration-Backup-[0-9a-fA-F]{32}$'
$motor=Allow-PrivatePath $MotorBackupPath '^VOLVE-Legacy-Motor-Recovery-[0-9a-fA-F]{32}$'
if($original -ceq $motor){Refuse 'Backup original y motor indistinguibles'}
function Check-ACL([string]$node){
 $item=Get-Item -LiteralPath $node -Force -ErrorAction Stop
 if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){Refuse 'Reparse point en respaldo'}
 $acl=Get-Acl -LiteralPath $node -ErrorAction Stop
 if(-not $acl.AreAccessRulesProtected){Refuse 'ACL heredada'}
 if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')){
  Refuse 'Propietario fuera de SYSTEM/Administradores'}
 $aclRules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
 foreach($rule in $aclRules){
  if($rule.IsInherited -or $rule.AccessControlType -ne 'Allow' -or
   $rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')){
   Refuse 'Principal NTFS no autorizado'}
 }
 foreach($sid in @('S-1-5-18','S-1-5-32-544')){
  if(@($aclRules | Where-Object{$_.IdentityReference.Value -eq $sid}).Count -eq 0){
   Refuse 'Falta propietario autorizado para recuperar'}
 }
}
Check-ACL $motor
$required=@('motor-original.exe','tarea-system-original.xml','recibo-motor.json')
$members=@(Get-ChildItem -LiteralPath $motor -Force -ErrorAction Stop | ForEach-Object {$_.Name})
if($members.Count -ne 3){Refuse 'Cantidad inesperada de artefactos de rescate'}
foreach($name in $required){
 if($name -notin $members){Refuse 'Falta pieza del motor antiguo'}
 Check-ACL (Join-Path $motor $name)
}
$receiptFile=Join-Path $motor 'recibo-motor.json'
if((Get-Item -LiteralPath $receiptFile).Length -gt 4096){Refuse 'Recibo excesivo'}
try{
 $utf8=[Text.UTF8Encoding]::new($false,$true)
 $receipt=$utf8.GetString([IO.File]::ReadAllBytes($receiptFile)) | ConvertFrom-Json -ErrorAction Stop
}catch{Refuse 'Recibo del motor corrupto'}
if($receipt.schema -ne 1 -or
 $receipt.component -cne 'VOLVE-LEGACY-MOTOR-BACKUP-UNSIGNED-ONLY' -or
 $receipt.state -cne 'BACKUP_ONLY_NO_SWITCH_NO_CLEANUP_NO_INSTALL' -or
 $receipt.motor_file -cne 'motor-original.exe' -or
 $receipt.task_file -cne 'tarea-system-original.xml' -or
 $receipt.requires_publisher_signature -cne $true -or
 $receipt.cleanup_authorized -cne $false -or
 $receipt.install_authorized -cne $false -or
 $receipt.recovered_after_reboot -cne $false){
 Refuse 'Recibo no corresponde a respaldo sin autorización'}
$originalVerifier=Join-Path $PSScriptRoot 'Verificar_Respaldo_VOLVE_SoloLectura.ps1'
if(-not (Test-Path -LiteralPath $originalVerifier -PathType Leaf)){
 Refuse 'No se encuentra verificador original de HOSTS/DNS/SYSTEM'}
$ps=Join-Path $PSHOME 'powershell.exe'
$review=@(& $ps -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $originalVerifier -BackupPath $original)
if($LASTEXITCODE -ne 0 -or
 @($review|Where-Object{$_ -match '^VOLVE_BACKUP_VALIDATED_READ_ONLY;'}).Count -ne 1){
 Refuse 'El respaldo de DNS/HOSTS y tareas dejó de coincidir con Windows'}
$manifest=Join-Path $original 'manifest.json'
if((Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash.ToLowerInvariant() -cne
 $receipt.original_backup_manifest_sha256){
 Refuse 'Recibo del motor vinculado a otro respaldo original'}
$copy=Join-Path $motor 'motor-original.exe'
$xml=Join-Path $motor 'tarea-system-original.xml'
if((Get-Item -LiteralPath $copy).Length -ne [int64]$receipt.motor_bytes -or
 (Get-Item -LiteralPath $copy).Length -gt 80MB -or
 (Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash.ToLowerInvariant() -cne $receipt.motor_sha256){
 Refuse 'Bytes de motor de rescate alterados'}
if((Get-FileHash -LiteralPath $xml -Algorithm SHA256).Hash.ToLowerInvariant() -cne
 $receipt.task_sha256){Refuse 'XML de tarea original alterado'}
$t=@(Get-ScheduledTask -TaskName 'VOLVE-DNS-SERVER-0270' -ErrorAction Stop |
 Where-Object {$_.TaskName -ceq 'VOLVE-DNS-SERVER-0270' -and $_.TaskPath -ceq '\'})
if($t.Count -ne 1){Refuse 'Tarea SYSTEM antigua ausente o ambigua'}
$actions=@($t[0].Actions | Where-Object {$null -ne $_})
if($actions.Count -ne 1 -or
 ([string]$actions[0].Arguments).Trim() -cne '--dns-service'){
 Refuse 'Acción de motor SYSTEM modificada'}
if([string]$t[0].Principal.UserId -notmatch '^(?i:SYSTEM|NT AUTHORITY\\SYSTEM|S-1-5-18)$'){
 Refuse 'Principal SYSTEM diferente'}
$exe=[IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables(
 ([string]$actions[0].Execute).Trim().Trim('"')))
if([IO.Path]::GetFileName($exe) -cne 'VOLVE_DNS_Server_0270.exe' -or $exe.StartsWith('\\')){
 Refuse 'Motor live fuera de ruta esperada'}
if((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant() -cne
 $receipt.motor_sha256){Refuse 'Motor en ejecución difiere del respaldo'}
$taskXml=Export-ScheduledTask -TaskName $t[0].TaskName -TaskPath $t[0].TaskPath -ErrorAction Stop
$sha=[Security.Cryptography.SHA256]::Create()
try{
 $live=([BitConverter]::ToString($sha.ComputeHash(([Text.UTF8Encoding]::new($false)).GetBytes($taskXml)))).Replace('-','').ToLowerInvariant()
}finally{$sha.Dispose()}
if($live -cne $receipt.task_sha256){Refuse 'XML SYSTEM actual distinto de recuperación'}
Check-ACL $motor
foreach($name in $required){Check-ACL (Join-Path $motor $name)}
Write-Host 'VOLVE_LEGACY_RECOVERY_VERIFIED_READ_ONLY; MOTOR=OK; SYSTEM_XML=OK; PRIVATE_NTFS=OK'
Write-Host 'CLEANUP_AUTHORIZED=NO; INSTALL_AUTHORIZED=NO; AFTER_REBOOT_NOT_TESTED=YES'
