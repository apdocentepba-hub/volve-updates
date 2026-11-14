#requires -Version 5.1
# VOLVE 0.28.7 - Preparacion real de copia local ANTES de migrar.
# No altera DNS, tareas programadas, registro, navegadores ni HOSTS.
# NO autoriza borrar, detener ni instalar nada. Conserva IP y XML SOLO
# en un directorio nuevo de ProgramData con permisos SYSTEM/Admin.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

if ($env:OS -ne 'Windows_NT') { throw 'Solo Windows' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
 throw 'EJECUTAR COMO ADMINISTRADOR: solo lectura de Windows, escritura de un respaldo local'
}
$programData = [Environment]::GetFolderPath('CommonApplicationData')
if ([string]::IsNullOrWhiteSpace($programData) -or -not [IO.Path]::IsPathRooted($programData)) {
 throw 'ProgramData no es una ruta confiable'
}
$volume = Get-Volume -DriveLetter ([IO.Path]::GetPathRoot($programData).Substring(0,1)) -ErrorAction Stop
if ($volume.FileSystem -ne 'NTFS') { throw 'Requiere un volumen NTFS para sellar el respaldo' }

$system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$admins = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetAccessRuleProtection($true,$false)
$acl.SetOwner($admins)
$inherit = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
foreach($sid in @($system,$admins)) {
 $rule = [Security.AccessControl.FileSystemAccessRule]::new(
  $sid,[Security.AccessControl.FileSystemRights]::FullControl,$inherit,
  [Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)
 $acl.AddAccessRule($rule)
}
function Verify-RestrictedACL([string]$path) {
 $a = Get-Acl -LiteralPath $path -ErrorAction Stop
 if(-not $a.AreAccessRulesProtected) { throw 'Backup con herencia NTFS inesperada' }
 $ownerSid = $a.GetOwner([Security.Principal.SecurityIdentifier]).Value
 if($ownerSid -notin @('S-1-5-18','S-1-5-32-544')) {
  throw 'El respaldo no pertenece a SYSTEM/Administradores'
 }
 $rules = @($a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
 if($rules.Count -lt 2) { throw 'DACL incompleta en backup' }
 foreach($rule in $rules) {
  if($rule.IsInherited -or $rule.AccessControlType -ne 'Allow' -or
    $rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')) {
    throw 'Permisos NTFS ajenos en backup; rechazada la preparación'
  }
 }
 foreach($required in @('S-1-5-18','S-1-5-32-544')) {
  if(@($rules | Where-Object { $_.IdentityReference.Value -eq $required }).Count -eq 0) {
   throw 'Falta permiso de recuperación de SYSTEM/Administradores'
  }
 }
}
function Save-PrivateBytes([string]$name,[byte[]]$bytes) {
 if($name -notmatch '^[a-zA-Z0-9._-]{1,100}$') { throw 'Nombre de archivo inseguro' }
 $dst = Join-Path $script:backupDir $name
 $stream = [IO.FileStream]::new($dst,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,
  [IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough)
 try {
  $stream.Write($bytes,0,$bytes.Length)
  $stream.Flush($true)
 }finally { $stream.Dispose() }
 # The directory was sealed atomically BEFORE any private bytes were written.
 # Give each created file an independent non-inherited SYSTEM/Admin-only DACL.
 $fileACL = [Security.AccessControl.FileSecurity]::new()
 $fileACL.SetAccessRuleProtection($true,$false)
 $fileACL.SetOwner($script:admins)
 foreach($sid in @($script:system,$script:admins)) {
  $r=[Security.AccessControl.FileSystemAccessRule]::new(
   $sid,[Security.AccessControl.FileSystemRights]::FullControl,
   [Security.AccessControl.AccessControlType]::Allow)
  $fileACL.AddAccessRule($r)
 }
 [IO.File]::SetAccessControl($dst,$fileACL)
 Verify-RestrictedACL $dst
 $saved = [IO.File]::ReadAllBytes($dst)
 if([Convert]::ToBase64String($bytes) -cne [Convert]::ToBase64String($saved)) {
  throw 'Respaldo no pudo releerse bit por bit'
 }
 $h=Get-FileHash -LiteralPath $dst -Algorithm SHA256 -ErrorAction Stop
 return [ordered]@{name=$name;bytes=$bytes.Length;sha256=$h.Hash.ToLowerInvariant()}
}

$backupDir=Join-Path $programData ('VOLVE-Migration-Backup-'+[guid]::NewGuid().ToString('N'))
if(Test-Path -LiteralPath $backupDir) { throw 'Carpeta de respaldo ya existe' }
[void][IO.Directory]::CreateDirectory($backupDir,$acl)
Verify-RestrictedACL $backupDir
$utf8 = [Text.UTF8Encoding]::new($false)
$collected=@()
try {
 $tasks=@(Get-ScheduledTask -ErrorAction Stop | Where-Object {
  $_.TaskName -match '^(?i:VOLVE[-_])'
 } | Sort-Object TaskPath,TaskName)
 $taskRows=@()
 for($i=0;$i -lt $tasks.Count;$i++) {
  $t=$tasks[$i]
  $xml=Export-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop
  if([string]::IsNullOrWhiteSpace($xml)) { throw 'Task Scheduler devolvió XML vacío' }
  $entry=Save-PrivateBytes ('task-'+$i.ToString('000')+'.xml') ($utf8.GetBytes($xml))
  $collected+=$entry
  $taskRows+=[ordered]@{
   task_name=$t.TaskName
   task_path=$t.TaskPath
   principal_sid=[string]$t.Principal.UserId
   xml_backup=$entry.name
   xml_sha256=$entry.sha256
  }
 }
 $dns=@(Get-DnsClientServerAddress -ErrorAction Stop | ForEach-Object {
  [ordered]@{
   interface_index=[int]$_.InterfaceIndex
   family=[string]$_.AddressFamily
   servers=@($_.ServerAddresses | Where-Object {$_})
  }
 })
 $interfaces=@(Get-NetAdapter -IncludeHidden -ErrorAction Stop | ForEach-Object {
  [ordered]@{index=[int]$_.ifIndex;guid=[string]$_.InterfaceGuid;status=[string]$_.Status}
 })
 $routes=@(Get-NetRoute -ErrorAction Stop | Where-Object {
  $_.DestinationPrefix -eq '0.0.0.0/0' -or $_.DestinationPrefix -eq '::/0'
 } | ForEach-Object {
  [ordered]@{interface_index=[int]$_.InterfaceIndex;family=[string]$_.AddressFamily;prefix=[string]$_.DestinationPrefix}
 })
 # Preservar origen estatico o DHCP sin inferirlo a partir de servidores.
 $registry=@()
 foreach($item in $interfaces) {
  if($item.guid -notmatch '^[{]?[0-9a-fA-F-]{36}[}]?$') { continue }
  $id=$item.guid.Trim('{}')
  foreach($svc in @('Tcpip','Tcpip6')) {
   $keyPath="Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$svc\Parameters\Interfaces\{$id}"
   $values=[ordered]@{interface_guid=$id;service=$svc;key_exists=$false;values=@{}}
   if(Test-Path -LiteralPath $keyPath) {
    $key=Get-Item -LiteralPath $keyPath -ErrorAction Stop
    try{
     $values.key_exists=$true
     foreach($n in @('NameServer','DhcpNameServer','ProfileNameServer')) {
      if($n -in @($key.GetValueNames())){
       $v=$key.GetValue($n,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
       $values.values[$n]=@($v)
      }
     }
    }finally{$key.Close()}
   }
   $registry+=$values
  }
 }
 $network=[ordered]@{
  generated_utc=(Get-Date).ToUniversalTime().ToString('o')
  dns=$dns;adapters=$interfaces;default_routes=$routes;registry_dns_source=$registry
 }
 $networkEntry=Save-PrivateBytes 'original-dns-private.json' ($utf8.GetBytes((ConvertTo-Json -InputObject $network -Depth 12 -Compress)))
 $collected+=$networkEntry
 $hostsPath=Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
 $hostsBytes=[IO.File]::ReadAllBytes($hostsPath)
 $hostsEntry=Save-PrivateBytes 'original-hosts.bin' $hostsBytes
 $collected+=$hostsEntry
 $manifest=[ordered]@{
  schema=1;component='VOLVE-LOCAL-PRE-MIGRATION-BACKUP'
  state='PREPARED_ONLY_NO_CLEANUP_NO_INSTALL'
  generated_utc=(Get-Date).ToUniversalTime().ToString('o')
  current_tasks=$taskRows
  files=$collected
  safeguard=[ordered]@{
   dns_modified=$false;tasks_modified=$false;registry_modified=$false
   hosts_modified=$false;install_authorized=$false;cleanup_authorized=$false
   signed_production_rollback_ready=$false
  }
 }
 $manifestEntry=Save-PrivateBytes 'manifest.json' ($utf8.GetBytes((ConvertTo-Json -InputObject $manifest -Depth 12 -Compress)))
 Verify-RestrictedACL $backupDir
 foreach($entry in $collected) {
  $actual=(Get-FileHash -LiteralPath (Join-Path $backupDir $entry.name) -Algorithm SHA256).Hash.ToLowerInvariant()
  if($actual -cne $entry.sha256){throw 'Respaldo cambió luego de escritura: '+$entry.name}
 }
 Write-Host ('BACKUP_OK; TAREAS_VOLVE='+$taskRows.Count+'; DNS_FILAS='+$dns.Count+'; ARCHIVOS='+$collected.Count)
 Write-Host ('CARPETA_LOCAL_PROTEGIDA='+$backupDir)
 Write-Host ('MANIFEST_SHA256='+$manifestEntry.sha256)
 Write-Host 'NO SE MODIFICARON DNS, TAREAS, HOSTS NI REGISTRO.'
 Write-Host 'NO SE AUTORIZA LIMPIEZA NI INSTALACION. NO SUBIR ESTA CARPETA AL CHAT.'
}catch {
 Write-Error ('BACKUP_INCOMPLETO_NO_MIGRAR: '+$_.Exception.Message)
 throw
}
