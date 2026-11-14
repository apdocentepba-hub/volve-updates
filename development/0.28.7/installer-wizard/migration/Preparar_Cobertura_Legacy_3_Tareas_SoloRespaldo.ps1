#requires -Version 5.1
# VOLVE 0.28.7 — complemento de recuperacion para las TRES tareas LEGACY.
# Crea una COPIA PRIVADA de dependencias directas conocidas; no ejecuta,
# desregistra, detiene, instala ni modifica DNS, HOSTS o registro.
# No promete cubrir dependencias transitivas de los scripts antiguos.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$BackupPath)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
function Refuse([string]$why){throw ('VOLVE_THREE_TASKS_BACKUP_REFUSED: '+$why)}
if($env:OS -ne 'Windows_NT'){Refuse 'Se requiere Windows'}
$user=[Security.Principal.WindowsIdentity]::GetCurrent()
if(-not ([Security.Principal.WindowsPrincipal]::new($user)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
 Refuse 'Acceso de administrador requerido para copiar tareas SYSTEM protegidas'
}
$pd=[IO.Path]::GetFullPath([Environment]::GetFolderPath('CommonApplicationData')).TrimEnd('\')
$original=[IO.Path]::GetFullPath($BackupPath).TrimEnd('\')
if($original.StartsWith('\\') -or [IO.Path]::GetDirectoryName($original) -cne $pd -or
 [IO.Path]::GetFileName($original) -notmatch '^VOLVE-Migration-Backup-[a-fA-F0-9]{32}$'){
 Refuse 'El respaldo base debe estar bajo ProgramData protegido'
}
$verifier=Join-Path $PSScriptRoot 'Verificar_Respaldo_VOLVE_SoloLectura.ps1'
if(-not (Test-Path -LiteralPath $verifier -PathType Leaf)){Refuse 'Falta verificador independiente original'}
$ps=Join-Path $PSHOME 'powershell.exe'
function Check-Original {
 $out=@(& $ps -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $verifier -BackupPath $original)
 if($LASTEXITCODE -ne 0 -or
  @($out|Where-Object{$_ -match '^VOLVE_BACKUP_VALIDATED_READ_ONLY;'}).Count -ne 1){
  Refuse 'El respaldo inicial no coincide con la configuracion viva'
 }
}
Check-Original
$manifestPath=Join-Path $original 'manifest.json'
$manifest=Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
$names=@('VOLVE-CATALOGO-0230','VOLVE-DNS-RESCUE-0270','VOLVE-DNS-SERVER-0270')
$rows=@($manifest.current_tasks)
if($rows.Count -ne 3){Refuse 'Este piloto requiere exactamente las tres tareas conocidas'}
foreach($name in $names){
 if(@($rows | Where-Object {$_.task_name -ceq $name -and $_.task_path -ceq '\'}).Count -ne 1){
  Refuse 'Falta tarea conocida en el respaldo original'
 }
}
$system=[Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$admins=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$dirACL=[Security.AccessControl.DirectorySecurity]::new()
$dirACL.SetAccessRuleProtection($true,$false);$dirACL.SetOwner($admins)
$flags=[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
foreach($sid in @($system,$admins)){
 $dirACL.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,
  [Security.AccessControl.FileSystemRights]::FullControl,$flags,
  [Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
}
function Verify-DACL([string]$path){
 $node=Get-Item -LiteralPath $path -Force -ErrorAction Stop
 if(($node.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){Refuse 'Reparse point en copia de recuperacion'}
 $acl=Get-Acl -LiteralPath $path -ErrorAction Stop
 if(-not $acl.AreAccessRulesProtected){Refuse 'ACL heredada en copia privada'}
 if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')){
  Refuse 'Propietario de recuperacion inesperado'
 }
 $aces=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
 foreach($ace in $aces){
  if($ace.IsInherited -or $ace.AccessControlType -ne 'Allow' -or
   $ace.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')){
   Refuse 'La carpeta o el archivo es accesible a otro principal'
  }
 }
 foreach($sid in @('S-1-5-18','S-1-5-32-544')){
  if(@($aces | Where-Object {$_.IdentityReference.Value -eq $sid}).Count -eq 0){
   Refuse 'ACL privada incompleta'
  }
 }
}
function Expand-SafeSource([string]$raw,[string]$name){
 $expanded=[Environment]::ExpandEnvironmentVariables($raw.Trim().Trim('"'))
 if(-not [IO.Path]::IsPathRooted($expanded) -or $expanded.StartsWith('\\')){Refuse 'Dependencia sin ruta local absoluta'}
 $full=[IO.Path]::GetFullPath($expanded)
 if([IO.Path]::GetFileName($full) -cne $name){Refuse 'Nombre del componente anterior no coincide con tarea'}
 $roots=@($env:ProgramFiles,[Environment]::GetEnvironmentVariable('ProgramFiles(x86)'),$pd)|Where-Object{$_}
 $permitted=$false
 foreach($r in $roots){
  $prefix=[IO.Path]::GetFullPath($r).TrimEnd('\')+'\'
  if($full.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)){$permitted=$true}
 }
 if(-not $permitted){Refuse 'Dependencia antigua fuera de ProgramFiles/ProgramData'}
 $cursor=$full
 while($cursor -and (Test-Path -LiteralPath $cursor)){
  $node=Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
  if(($node.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){
   Refuse 'Dependencia atraveso un junction o symlink'
  }
  $cursor=[IO.Path]::GetDirectoryName($cursor)
 }
 $stat=Get-Item -LiteralPath $full -Force -ErrorAction Stop
 if($stat.PSIsContainer -or $stat.Length -lt 1 -or $stat.Length -gt 80MB){
  Refuse 'Archivo de dependencia inexistente o fuera de limites'
 }
 return $full
}
function SHA-Bytes([byte[]]$data){
 $sha=[Security.Cryptography.SHA256]::Create()
 try{return ([BitConverter]::ToString($sha.ComputeHash($data))).Replace('-','').ToLowerInvariant()}
 finally{$sha.Dispose()}
}
$utf8=[Text.UTF8Encoding]::new($false)
$scheduled=@()
foreach($name in $names){
 $task=@(Get-ScheduledTask -TaskName $name -ErrorAction Stop |
  Where-Object{$_.TaskName -ceq $name -and $_.TaskPath -ceq '\'})
 if($task.Count -ne 1){Refuse 'La tarea SYSTEM es ambigua'}
 $t=$task[0]
 if([string]$t.Principal.UserId -notmatch '^(?i:SYSTEM|NT AUTHORITY\\SYSTEM|S-1-5-18)$'){
  Refuse 'Principal SYSTEM antiguo inesperado'
 }
 $acts=@($t.Actions|Where-Object{$null -ne $_})
 if($acts.Count -ne 1){Refuse 'Acciones multiples no cubiertas por el respaldo'}
 $a=$acts[0]
 $originalRow=@($rows|Where-Object{$_.task_name -ceq $name})[0]
 $xml=Export-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop
 $xmlHash=SHA-Bytes ($utf8.GetBytes($xml))
 if($xmlHash -cne $originalRow.xml_sha256){Refuse 'XML SYSTEM cambio desde respaldo original'}
 $params=([string]$a.Arguments).Trim()
 $source=''
 $type=''
 switch($name){
  'VOLVE-CATALOGO-0230' {
   $source=Expand-SafeSource ([string]$a.Execute) 'VOLVE_Motor_0210.exe'
   # Los argumentos historicos no se interpretan: el XML preservado es la
   # unica fuente. No ejecutar ni reconstruir comandos con ellos.
   $type='catalog-executable'
  }
  'VOLVE-DNS-SERVER-0270' {
   if($params -cne '--dns-service'){Refuse 'Argumentos del servidor no reconocidos'}
   $source=Expand-SafeSource ([string]$a.Execute) 'VOLVE_DNS_Server_0270.exe'
   $type='dns-server-executable'
  }
  'VOLVE-DNS-RESCUE-0270' {
   $shell=[IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables(([string]$a.Execute).Trim().Trim('"')))
   $winPS=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
   if(-not $shell.Equals($winPS,[StringComparison]::OrdinalIgnoreCase)){
    Refuse 'El motor de rescate no usa powershell.exe de Windows confiable'
   }
   if($params -match '(?i)-(?:command|encodedcommand|enc)\b'){Refuse 'Comandos embebidos no permitidos'}
   if(-not ($params -match '(?i)(?:^|\s)-File\s+(?:"([^"]+)"|''([^'']+)''|(\S+))\s*
    Refuse 'No se pudo identificar el script de rescate -File'
   }
   $candidate=@($Matches[1],$Matches[2],$Matches[3]|Where-Object{$_})|Select-Object -First 1
   $base=[IO.Path]::GetFileName([string]$candidate)
   if($base -notmatch '(?i)^VOLVE[_-].+\.ps1$'){Refuse 'Script de rescate ajeno a VOLVE'}
   $source=Expand-SafeSource ([string]$candidate) $base
   $type='rescue-powershell-script'
  }
 }
 $scheduled+= [pscustomobject]@{task=$name;kind=$type;source=$source;source_sha=(Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant();xml_sha=$xmlHash}
}
# Ninguna escritura privada comienza hasta validar las 3 tareas y archivos.
$folder=Join-Path $pd ('VOLVE-Legacy-Three-Recovery-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($folder,$dirACL)
Verify-DACL $folder
function Save-Sealed([string]$filename,[byte[]]$data){
 $target=Join-Path $script:folder $filename
 $stream=[IO.FileStream]::new($target,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,
  [IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough)
 try{$stream.Write($data,0,$data.Length);$stream.Flush($true)}finally{$stream.Dispose()}
 $acl=[Security.AccessControl.FileSecurity]::new()
 $acl.SetAccessRuleProtection($true,$false);$acl.SetOwner($script:admins)
 foreach($sid in @($script:system,$script:admins)){
  $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,
   [Security.AccessControl.FileSystemRights]::FullControl,
   [Security.AccessControl.AccessControlType]::Allow))
 }
 [IO.File]::SetAccessControl($target,$acl)
 Verify-DACL $target
 $hash=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
 if($hash -cne (SHA-Bytes $data)){Refuse 'Copia de archivo no coincide con memoria'}
 return $hash
}
$records=@()
for($i=0;$i -lt $scheduled.Count;$i++){
 $s=$scheduled[$i]
 $data=[IO.File]::ReadAllBytes($s.source)
 if($data.Length -lt 1 -or $data.Length -gt 80MB -or
  (SHA-Bytes $data) -cne $s.source_sha){Refuse 'Dependencia modificada durante copia'}
 $target='accion-'+$i.ToString('000')+[IO.Path]::GetExtension($s.source)
 $copyHash=Save-Sealed $target $data
 $records+= [ordered]@{
  task=$s.task;kind=$s.kind;artifact=$target
  source_path=$s.source;original_sha256=$copyHash
  original_size=$data.Length;task_xml_sha256=$s.xml_sha
 }
}
$receipt=[ordered]@{
 schema=1;component='VOLVE-THREE-LEGACY-TASKS-DIRECT-ACTIONS-BACKUP-V1'
 state='PRIVATE_BACKUP_ONLY_NO_CLEANUP_NO_INSTALL'
 original_manifest_sha256=(Get-FileHash -LiteralPath (Join-Path $original 'manifest.json') -Algorithm SHA256).Hash.ToLowerInvariant()
 records=$records
 direct_actions_only=$true
 transitive_dependencies_certified=$false
 recovery_after_reboot_verified=$false
 publisher_authorization_verified=$false
 cleanup_authorized=$false
 install_authorized=$false
}
$receiptHash=Save-Sealed 'recibo-tres-tareas.json' ($utf8.GetBytes((ConvertTo-Json -InputObject $receipt -Depth 9 -Compress)))
foreach($s in $scheduled){
 if((Get-FileHash -LiteralPath $s.source -Algorithm SHA256).Hash.ToLowerInvariant() -cne $s.source_sha){
  Refuse 'Archivo fuente cambio desde la lectura'}
}
Check-Original
Verify-DACL $folder
foreach($r in $records){Verify-DACL (Join-Path $folder $r.artifact)}
$independent=Join-Path $PSScriptRoot 'Verificar_Cobertura_Legacy_3_Tareas_SoloLectura.ps1'
if(-not (Test-Path -LiteralPath $independent -PathType Leaf)){Refuse 'Falta revisor independiente de tres tareas'}
$check=@(& $ps -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $independent -BackupPath $original -ThreeTasksBackupPath $folder)
if($LASTEXITCODE -ne 0 -or
 @($check|Where-Object{$_ -match '^VOLVE_THREE_TASKS_DIRECT_ACTIONS_VERIFIED_READ_ONLY;'}).Count -ne 1){
 Refuse 'La copia de las tres acciones no paso verificacion independiente'
}
Write-Host 'VOLVE_THREE_TASKS_INDEPENDENT_REVIEW=PASS; CLEANUP=NO'
Write-Host 'VOLVE_LEGACY_THREE_TASKS_DIRECT_ACTIONS_BACKUP_OK; TASKS=3; COPIES=3'
Write-Host ('RECEIPT_SHA256='+$receiptHash)
Write-Host 'CLEANUP_AUTHORIZED=NO; INSTALL_AUTHORIZED=NO; TRANSITIVE_DEPENDENCIES_VERIFIED=NO'
)){
    Refuse 'No se pudo identificar el script de rescate -File'
   }
   $candidate=@($Matches[1],$Matches[2],$Matches[3]|Where-Object{$_})|Select-Object -First 1
   $base=[IO.Path]::GetFileName([string]$candidate)
   if($base -notmatch '(?i)^VOLVE[_-].+\.ps1$'){Refuse 'Script de rescate ajeno a VOLVE'}
   $source=Expand-SafeSource ([string]$candidate) $base
   $type='rescue-powershell-script'
  }
 }
 $scheduled+= [pscustomobject]@{task=$name;kind=$type;source=$source;source_sha=(Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant();xml_sha=$xmlHash}
}
# Ninguna escritura privada comienza hasta validar las 3 tareas y archivos.
$folder=Join-Path $pd ('VOLVE-Legacy-Three-Recovery-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($folder,$dirACL)
Verify-DACL $folder
function Save-Sealed([string]$filename,[byte[]]$data){
 $target=Join-Path $script:folder $filename
 $stream=[IO.FileStream]::new($target,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,
  [IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough)
 try{$stream.Write($data,0,$data.Length);$stream.Flush($true)}finally{$stream.Dispose()}
 $acl=[Security.AccessControl.FileSecurity]::new()
 $acl.SetAccessRuleProtection($true,$false);$acl.SetOwner($script:admins)
 foreach($sid in @($script:system,$script:admins)){
  $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,
   [Security.AccessControl.FileSystemRights]::FullControl,
   [Security.AccessControl.AccessControlType]::Allow))
 }
 [IO.File]::SetAccessControl($target,$acl)
 Verify-DACL $target
 $hash=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
 if($hash -cne (SHA-Bytes $data)){Refuse 'Copia de archivo no coincide con memoria'}
 return $hash
}
$records=@()
for($i=0;$i -lt $scheduled.Count;$i++){
 $s=$scheduled[$i]
 $data=[IO.File]::ReadAllBytes($s.source)
 if($data.Length -lt 1 -or $data.Length -gt 80MB -or
  (SHA-Bytes $data) -cne $s.source_sha){Refuse 'Dependencia modificada durante copia'}
 $target='accion-'+$i.ToString('000')+[IO.Path]::GetExtension($s.source)
 $copyHash=Save-Sealed $target $data
 $records+= [ordered]@{
  task=$s.task;kind=$s.kind;artifact=$target
  source_path=$s.source;original_sha256=$copyHash
  original_size=$data.Length;task_xml_sha256=$s.xml_sha
 }
}
$receipt=[ordered]@{
 schema=1;component='VOLVE-THREE-LEGACY-TASKS-DIRECT-ACTIONS-BACKUP-V1'
 state='PRIVATE_BACKUP_ONLY_NO_CLEANUP_NO_INSTALL'
 original_manifest_sha256=(Get-FileHash -LiteralPath (Join-Path $original 'manifest.json') -Algorithm SHA256).Hash.ToLowerInvariant()
 records=$records
 direct_actions_only=$true
 transitive_dependencies_certified=$false
 recovery_after_reboot_verified=$false
 publisher_authorization_verified=$false
 cleanup_authorized=$false
 install_authorized=$false
}
$receiptHash=Save-Sealed 'recibo-tres-tareas.json' ($utf8.GetBytes((ConvertTo-Json -InputObject $receipt -Depth 9 -Compress)))
foreach($s in $scheduled){
 if((Get-FileHash -LiteralPath $s.source -Algorithm SHA256).Hash.ToLowerInvariant() -cne $s.source_sha){
  Refuse 'Archivo fuente cambio desde la lectura'}
}
Check-Original
Verify-DACL $folder
foreach($r in $records){Verify-DACL (Join-Path $folder $r.artifact)}
$independent=Join-Path $PSScriptRoot 'Verificar_Cobertura_Legacy_3_Tareas_SoloLectura.ps1'
if(-not (Test-Path -LiteralPath $independent -PathType Leaf)){Refuse 'Falta revisor independiente de tres tareas'}
$check=@(& $ps -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $independent -BackupPath $original -ThreeTasksBackupPath $folder)
if($LASTEXITCODE -ne 0 -or
 @($check|Where-Object{$_ -match '^VOLVE_THREE_TASKS_DIRECT_ACTIONS_VERIFIED_READ_ONLY;'}).Count -ne 1){
 Refuse 'La copia de las tres acciones no paso verificacion independiente'
}
Write-Host 'VOLVE_THREE_TASKS_INDEPENDENT_REVIEW=PASS; CLEANUP=NO'
Write-Host 'VOLVE_LEGACY_THREE_TASKS_DIRECT_ACTIONS_BACKUP_OK; TASKS=3; COPIES=3'
Write-Host ('RECEIPT_SHA256='+$receiptHash)
Write-Host 'CLEANUP_AUTHORIZED=NO; INSTALL_AUTHORIZED=NO; TRANSITIVE_DEPENDENCIES_VERIFIED=NO'
