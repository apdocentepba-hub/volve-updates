#requires -Version 5.1
# VOLVE 0.28.7 - VERIFICACIÓN INDEPENDIENTE DE BACKUP DE MIGRACIÓN.
# Solo lectura: no elimina tareas, no restaura ni configura DNS, no instala.
# Aun una verificación exitosa NO AUTORIZA LIMPIEZA: faltan firmas y watchdog.
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$BackupPath
)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
function Fail([string]$reason){ throw ('VOLVE_BACKUP_REJECTED: '+$reason) }
if($env:OS -ne 'Windows_NT'){ Fail 'Windows requerido' }
$id=[Security.Principal.WindowsIdentity]::GetCurrent()
$p=[Security.Principal.WindowsPrincipal]::new($id)
if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
 Fail 'La revisión de respaldo privado requiere Administrador'
}
$parent=[IO.Path]::GetFullPath([Environment]::GetFolderPath('CommonApplicationData')).TrimEnd('\')
$path=[IO.Path]::GetFullPath($BackupPath).TrimEnd('\')
$folder=[IO.Path]::GetFileName($path)
if([IO.Path]::GetDirectoryName($path) -cne $parent -or
 $folder -notmatch '^VOLVE-Migration-Backup-[0-9a-fA-F]{32}$'){
 Fail 'Ruta del backup fuera de carpeta local y formato autorizado'
}
if($path.StartsWith('\\')){Fail 'Respaldo UNC no autorizado'}
function Check-ACL([string]$p) {
 $item=Get-Item -LiteralPath $p -Force -ErrorAction Stop
 if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){
  Fail 'Enlace o reparse point detectado'
 }
 $acl=Get-Acl -LiteralPath $p -ErrorAction Stop
 if(-not $acl.AreAccessRulesProtected){Fail 'Archivo o carpeta con ACL heredable'}
 $owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
 if($owner -notin @('S-1-5-18','S-1-5-32-544')){Fail 'Propietario NTFS no autorizado'}
 $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
 foreach($rule in $rules){
  if($rule.IsInherited -or $rule.AccessControlType -ne 'Allow' -or
    $rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')){
   Fail 'ACL contiene un principal o permiso inesperado'
  }
 }
 foreach($sid in @('S-1-5-18','S-1-5-32-544')){
  if(@($rules | Where-Object {$_.IdentityReference.Value -eq $sid}).Count -eq 0){
   Fail 'Falta permiso NTFS de SYSTEM o Administradores'
  }
 }
}
if(-not (Test-Path -LiteralPath $path -PathType Container)){Fail 'No existe carpeta de backup'}
Check-ACL $path
$manifestFile=Join-Path $path 'manifest.json'
if(-not (Test-Path -LiteralPath $manifestFile -PathType Leaf)){Fail 'Sin manifiesto'}
Check-ACL $manifestFile
$info=Get-Item -LiteralPath $manifestFile
if($info.Length -lt 60 -or $info.Length -gt 262144){Fail 'Manifiesto inválido o excesivo'}
$manifestBytes=[IO.File]::ReadAllBytes($manifestFile)
$strict=[Text.UTF8Encoding]::new($false,$true)
try{$manifest=$strict.GetString($manifestBytes)|ConvertFrom-Json -ErrorAction Stop}catch{Fail 'Manifiesto UTF8/JSON inválido'}
if($manifest.schema -ne 1 -or
 $manifest.component -cne 'VOLVE-LOCAL-PRE-MIGRATION-BACKUP' -or
 $manifest.state -cne 'PREPARED_ONLY_NO_CLEANUP_NO_INSTALL'){
 Fail 'Manifiesto de otra versión o con autorización inesperada'
}
$flags=$manifest.safeguard
if($null -eq $flags -or
 $flags.dns_modified -cne $false -or
 $flags.tasks_modified -cne $false -or
 $flags.registry_modified -cne $false -or
 $flags.hosts_modified -cne $false -or
 $flags.install_authorized -cne $false -or
 $flags.cleanup_authorized -cne $false -or
 $flags.signed_production_rollback_ready -cne $false){
 Fail 'El respaldo pretende autorizar acciones no permitidas'
}
$entries=@($manifest.files)
if($entries.Count -lt 2 -or $entries.Count -gt 100){Fail 'Lista de archivos incompleta o excesiva'}
$expected=@{ 'original-dns-private.json'=$true; 'original-hosts.bin'=$true }
$seen=@{}
$taskFiles=@()
foreach($entry in $entries){
 $name=[string]$entry.name
 if($name -notmatch '^(task-[0-9]{3}\.xml|original-dns-private\.json|original-hosts\.bin)$'){
  Fail 'Nombre de archivo fuera del manifiesto permitido'
 }
 if($seen.ContainsKey($name)){Fail 'Archivo duplicado'}
 $seen[$name]=$true
 $f=Join-Path $path $name
 if(-not (Test-Path -LiteralPath $f -PathType Leaf)){Fail 'Archivo de respaldo faltante'}
 Check-ACL $f
 $fi=Get-Item -LiteralPath $f
 if($fi.Length -gt 4MB -or $fi.Length -lt 0 -or $fi.Length -ne [int64]$entry.bytes){
  Fail 'Tamaño de backup original inesperado'
 }
 $hash=(Get-FileHash -LiteralPath $f -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
 if($entry.sha256 -cne $hash){Fail 'SHA-256 del backup no coincide'}
 if($name -like 'task-*.xml'){$taskFiles+= $name}
}
foreach($required in @('original-dns-private.json','original-hosts.bin')){
 if(-not $seen.ContainsKey($required)){Fail 'Falta evidencia de DNS o HOSTS'}
}
$present=@(Get-ChildItem -LiteralPath $path -Force -ErrorAction Stop | ForEach-Object {$_.Name})
if($present.Count -ne $entries.Count+1 -or @($present | Where-Object {$_ -ne 'manifest.json' -and -not $seen.ContainsKey($_)}).Count -gt 0){
 Fail 'Archivo adicional o ausente en el directorio de respaldo'
}
$taskRows=@($manifest.current_tasks)
if($taskRows.Count -ne $taskFiles.Count){Fail 'XML y tareas del manifiesto desalineados'}
if($taskRows.Count -gt 95){Fail 'Cantidad de tareas excesiva'}
$utf8=[Text.UTF8Encoding]::new($false)
$tasksNow=@(Get-ScheduledTask -ErrorAction Stop | Where-Object {
 $_.TaskName -match '^(?i:VOLVE[-_])'
} | Sort-Object TaskPath,TaskName)
if($tasksNow.Count -ne $taskRows.Count){Fail 'El número de tareas VOLVE cambió desde el backup'}
$sha=[Security.Cryptography.SHA256]::Create()
try{
 for($i=0;$i -lt $tasksNow.Count;$i++){
  $current=$tasksNow[$i]
  $saved=$taskRows[$i]
  if([string]$saved.task_name -cne [string]$current.TaskName -or
    [string]$saved.task_path -cne [string]$current.TaskPath -or
    [string]$saved.principal_sid -cne [string]$current.Principal.UserId){
   Fail 'Identidad de tarea SYSTEM cambió desde el backup'
  }
  if(-not $seen.ContainsKey([string]$saved.xml_backup)){Fail 'XML de tarea no inventariado'}
  $xml=Export-ScheduledTask -TaskName $current.TaskName -TaskPath $current.TaskPath -ErrorAction Stop
  $sourceHash=([BitConverter]::ToString($sha.ComputeHash($utf8.GetBytes($xml)))).Replace('-','').ToLowerInvariant()
  if($sourceHash -cne $saved.xml_sha256){
   Fail 'Definición de tarea VOLVE cambió desde el backup'
  }
 }
}finally{$sha.Dispose()}

$networkFile=Join-Path $path 'original-dns-private.json'
$networkInfo=Get-Item -LiteralPath $networkFile
if($networkInfo.Length -gt 1048576){Fail 'Snapshot DNS fuera de límite'}
try{$network=$strict.GetString([IO.File]::ReadAllBytes($networkFile))|ConvertFrom-Json -ErrorAction Stop}
catch{Fail 'Snapshot DNS corrupto'}
$dnsBefore=@($network.dns | ForEach-Object {
 [pscustomobject][ordered]@{index=[int]$_.interface_index;family=[string]$_.family;servers=@($_.servers)}
} | Sort-Object index,family)
$dnsNow=@(Get-DnsClientServerAddress -ErrorAction Stop | ForEach-Object {
 [pscustomobject][ordered]@{index=[int]$_.InterfaceIndex;family=[string]$_.AddressFamily;servers=@($_.ServerAddresses|Where-Object {$_})}
} | Sort-Object index,family)
if($dnsBefore.Count -ne $dnsNow.Count){Fail 'La cantidad de interfaces DNS cambió'}
for($i=0;$i -lt $dnsBefore.Count;$i++){
 $a=$dnsBefore[$i];$b=$dnsNow[$i]
 if($a.index -ne $b.index -or $a.family -cne $b.family -or
  ($a.servers -join ',') -cne ($b.servers -join ',')){
  Fail 'DNS de Windows cambió desde el backup'
 }
}
$hostsNow=(Get-FileHash -LiteralPath (Join-Path $env:SystemRoot 'System32\drivers\etc\hosts') -Algorithm SHA256).Hash.ToLowerInvariant()
$hostsSaved=($entries|Where-Object {$_.name -eq 'original-hosts.bin'}|Select-Object -First 1).sha256
if($hostsNow -cne $hostsSaved){Fail 'HOSTS de Windows cambió desde el backup'}
Check-ACL $path
foreach($name in $seen.Keys){Check-ACL (Join-Path $path $name)}
Check-ACL $manifestFile
Write-Host ('VOLVE_BACKUP_VALIDATED_READ_ONLY; TASKS='+$taskRows.Count+'; DNS_ROWS='+$dnsNow.Count+'; HOSTS_OK=1')
Write-Host ('MANIFEST_SHA256='+((Get-FileHash -LiteralPath $manifestFile -Algorithm SHA256).Hash.ToLowerInvariant()))
Write-Host 'CLEANUP_AUTHORIZED=NO; INSTALL_AUTHORIZED=NO; DNS_CHANGED=NO; TASKS_CHANGED=NO'
