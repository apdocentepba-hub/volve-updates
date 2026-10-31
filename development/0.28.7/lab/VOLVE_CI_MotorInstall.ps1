# VOLVE v0.28.7 -- CI-only disposable VM installer. Not for distribution.
# Does not alter Windows DNS, hosts, policies, firewall, or production tasks.
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][ValidateSet('Install','Verify','Remove')][string]$Mode,
 [Parameter(Mandatory=$true)][ValidatePattern('^[0-9]{6,20}$')][string]$LabId,
 [string]$SourceExe='',
 [string]$SourceRescue='',
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedSHA256,
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedRescueSHA256
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'REFUSED: not a GitHub-hosted disposable VM'}
$vm=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
if(($vm.Manufacturer+' '+$vm.Model) -notmatch '(?i:virtual machine|vmware|hyper-v|kvm|qemu|virtualbox)'){throw 'REFUSED: hardware not identified as virtual'}
$admin=([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if(-not $admin){throw 'REFUSED: administrator privileges missing'}
foreach($prod in @('VOLVE-DNS-SERVER-0270','VOLVE-DNS-RESCUE-0270')){
 if(Get-ScheduledTask -TaskName $prod -ErrorAction SilentlyContinue){throw ('REFUSED: production task '+$prod)}
}
$root=Join-Path $env:ProgramData ('VOLVE-CI-MotorInstall-'+$LabId)
$dataRoot=Join-Path $env:ProgramData ('VOLVE-CI-FreshDNS53-'+$LabId)
$task='VOLVE-CI-FreshMotor-'+$LabId
$rescueTask='VOLVE-CI-FreshRescue-'+$LabId
$exe=Join-Path $root 'VOLVE_CI_FreshDNS53.exe'
$rescue=Join-Path $root 'VOLVE_CI_MotorRescue.ps1'
$proof=Join-Path $root 'ci-rescue-result.json'
$powershellExe=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
$receipt=Join-Path $root 'ci-install-receipt.json'
$sha=$ExpectedSHA256.ToLowerInvariant()
$rescueSHA=$ExpectedRescueSHA256.ToLowerInvariant()
$rescueArgs='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$rescue+'" -LabId '+$LabId+' -ExpectedSHA256 '+$sha+' -ExpectedRescueSHA256 '+$rescueSHA
$argsText='--ci-fresh-dns53 "'+$dataRoot+'" VOLVE-CI-GITHUB-HOSTED-VM-DNS53-ONLY'
function RegularNode([string]$path){
 $node=Get-Item -LiteralPath $path -Force -ErrorAction Stop
 if(($node.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw ('Refused reparse point '+$path)}
 return $node
}
function VerifiedTask(){
 $tasks=@(Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue)
 if($tasks.Count -ne 1){throw 'Task missing or duplicated'}
 $one=$tasks[0]
 if($one.TaskPath -ne '\' -or $one.Principal.UserId -notin @('SYSTEM','S-1-5-18')){throw 'SYSTEM task identity mismatch'}
 if(@($one.Actions).Count -ne 1 -or [string]$one.Actions[0].Execute -ine $exe -or [string]$one.Actions[0].Arguments -cne $argsText){throw 'Task action mismatch'}
 $xml=[xml](Export-ScheduledTask -TaskName $task -TaskPath '\' -ErrorAction Stop)
 if(@($xml.SelectNodes("//*[local-name()='BootTrigger']")).Count -ne 1){throw 'Task lacks boot trigger'}
 return $one
}
function VerifiedRescueTask(){
 $tasks=@(Get-ScheduledTask -TaskName $rescueTask -ErrorAction SilentlyContinue)
 if($tasks.Count -ne 1){throw 'Recovery task missing or duplicated'}
 $one=$tasks[0]
 if($one.TaskPath -ne '\' -or $one.Principal.UserId -notin @('SYSTEM','S-1-5-18')){throw 'Recovery SYSTEM task identity mismatch'}
 if(@($one.Actions).Count -ne 1 -or [string]$one.Actions[0].Execute -ine $powershellExe -or [string]$one.Actions[0].Arguments -cne $rescueArgs){throw 'Recovery action changed'}
 $rescueXML=[xml](Export-ScheduledTask -TaskName $rescueTask -TaskPath '\\' -ErrorAction Stop)
 $watchTick=$rescueXML.SelectSingleNode("//*[local-name()='TimeTrigger']/*[local-name()='Repetition']/*[local-name()='Interval']")
 if($null -eq $watchTick -or $watchTick.InnerText -ne 'PT1M'){throw 'Independent SYSTEM watchdog is not scheduled every minute'}
 return $one
}
function VerifyInstall(){
 if(-not (RegularNode $root).PSIsContainer){throw 'Invalid install root'}
 $node=RegularNode $exe
 if($node.PSIsContainer -or $node.Length -lt 1000000 -or $node.Length -gt 80000000){throw 'Invalid installed executable'}
 if((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant() -cne $sha){throw 'Installed EXE SHA256 mismatch'}
 $node=RegularNode $rescue
 if($node.PSIsContainer -or $node.Length -lt 1000 -or $node.Length -gt 100000){throw 'Invalid independent recovery'}
 if((Get-FileHash -LiteralPath $rescue -Algorithm SHA256).Hash.ToLowerInvariant() -cne $rescueSHA){throw 'Recovery code hash mismatch'}
 $node=RegularNode $receipt
 if($node.PSIsContainer -or $node.Length -gt 2048){throw 'Malformed install receipt'}
 $saved=Get-Content -LiteralPath $receipt -Encoding UTF8 -Raw | ConvertFrom-Json -ErrorAction Stop
 if($saved.schema -ne 1 -or $saved.version -ne '0.28.7-CI' -or $saved.sha256 -cne $sha -or $saved.exe -cne $exe -or $saved.task -cne $task -or $saved.dataRoot -cne $dataRoot -or $saved.rescueSHA256 -cne $rescueSHA -or $saved.rescueScript -cne $rescue -or $saved.rescueTask -cne $rescueTask){throw 'Receipt inconsistent with independently supplied parameters'}
 $children=@(Get-ChildItem -LiteralPath $root -Force)
 if($children.Count -lt 3 -or $children.Count -gt 4 -or @($children | Where-Object Name -NotIn @('VOLVE_CI_FreshDNS53.exe','ci-install-receipt.json','VOLVE_CI_MotorRescue.ps1','ci-rescue-result.json')).Count -ne 0){throw 'Unknown install files'}
 if($children.Count -eq 4 -and -not (Test-Path -LiteralPath $proof -PathType Leaf)){throw 'Unknown fourth install file'}
 $null=VerifiedTask
 $null=VerifiedRescueTask
}
function VerifyDataSubtree(){
 if(-not (Test-Path -LiteralPath $dataRoot)){return}
 $catalog=Join-Path $dataRoot 'catalog'
 $feeds=Join-Path $catalog 'feeds'
 $feed=Join-Path $feeds 'hagezi_gambling_full.txt'
 foreach($p in @($dataRoot,$catalog,$feeds,$feed)){$null=RegularNode $p}
 foreach($dir in @($dataRoot,$catalog,$feeds)){
  if(@(Get-ChildItem -LiteralPath $dir -Force).Count -ne 1){throw 'Unknown files in data directory'}
 }
 $node=RegularNode $feed
 if($node.PSIsContainer -or $node.Length -gt 30000000){throw 'Invalid catalog data'}
}
if($Mode -eq 'Install'){
 if(-not $SourceExe -or -not $SourceRescue){throw 'SourceExe and SourceRescue required'}
 $rescueSource=RegularNode $SourceRescue
 if($rescueSource.PSIsContainer -or $rescueSource.Length -lt 1000 -or $rescueSource.Length -gt 100000){throw 'Invalid source recovery'}
 if((Get-FileHash -LiteralPath $SourceRescue -Algorithm SHA256).Hash.ToLowerInvariant() -cne $rescueSHA){throw 'Recovery source SHA256 mismatch'}
 $source=RegularNode $SourceExe
 if($source.PSIsContainer -or $source.Length -lt 1000000 -or $source.Length -gt 80000000){throw 'Invalid source binary'}
 if((Get-FileHash -LiteralPath $SourceExe -Algorithm SHA256).Hash.ToLowerInvariant() -cne $sha){throw 'Source SHA256 mismatch'}
 if((Test-Path -LiteralPath $root) -or (Test-Path -LiteralPath $dataRoot)){throw 'Existing lab installation: no overwrite'}
 if(Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue){throw 'Existing lab task: no overwrite'}
 if(Get-ScheduledTask -TaskName $rescueTask -ErrorAction SilentlyContinue){throw 'Existing recovery task: no overwrite'}
 foreach($ip in @('127.0.0.1','::1')){
  if(@(Get-NetUDPEndpoint -LocalAddress $ip -LocalPort 53 -ErrorAction SilentlyContinue).Count -gt 0){throw ('Local port 53 occupied: '+$ip)}
 }
 $created=$false;$registered=$false;$rescueRegistered=$false
 try{
  $null=New-Item -ItemType Directory -Path $root -ErrorAction Stop
  $created=$true
  & icacls.exe $root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
  if($LASTEXITCODE -ne 0){throw 'Cannot secure install root ACL'}
  Copy-Item -LiteralPath $SourceExe -Destination $exe -ErrorAction Stop
  if((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant() -cne $sha){throw 'Copy SHA256 mismatch'}
  Copy-Item -LiteralPath $SourceRescue -Destination $rescue -ErrorAction Stop
  if((Get-FileHash -LiteralPath $rescue -Algorithm SHA256).Hash.ToLowerInvariant() -cne $rescueSHA){throw 'Copied recovery SHA256 mismatch'}
  $info=[ordered]@{schema=1;version='0.28.7-CI';sha256=$sha;exe=$exe;task=$task;dataRoot=$dataRoot;rescueSHA256=$rescueSHA;rescueScript=$rescue;rescueTask=$rescueTask}
  [IO.File]::WriteAllText($receipt,($info|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
  # Independent recovery is registered BEFORE the motor startup task.
  $rescueAction=New-ScheduledTaskAction -Execute $powershellExe -Argument $rescueArgs
  # A genuine scheduled watchdog: independent SYSTEM process every minute.
  # Initial scan is delayed to allow the installer to finish and record state.
  # The CI watchdog is intentionally bounded to a 12-hour disposable VM window.
  $rescueTrigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Hours 12)
  $rescueSettings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
  Register-ScheduledTask -TaskName $rescueTask -Action $rescueAction -Trigger $rescueTrigger -Settings $rescueSettings -User SYSTEM -RunLevel Highest -ErrorAction Stop | Out-Null
  $rescueRegistered=$true
  $null=VerifiedRescueTask
  $action=New-ScheduledTaskAction -Execute $exe -Argument $argsText
  $trigger=New-ScheduledTaskTrigger -AtStartup
  $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 3)
  Register-ScheduledTask -TaskName $task -Action $action -Trigger $trigger -Settings $settings -User 'SYSTEM' -RunLevel Highest -ErrorAction Stop|Out-Null
  $registered=$true
  VerifyInstall
  Write-Output ('CI_MOTOR_INSTALL_OK '+$exe)
 }catch{
  $reason=$_
  if($registered){Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue}
  if($rescueRegistered){Unregister-ScheduledTask -TaskName $rescueTask -Confirm:$false -ErrorAction SilentlyContinue}
  if($created){
   if(Test-Path -LiteralPath $exe){Remove-Item -LiteralPath $exe -Force -ErrorAction SilentlyContinue}
   if(Test-Path -LiteralPath $receipt){Remove-Item -LiteralPath $receipt -Force -ErrorAction SilentlyContinue}
   if(Test-Path -LiteralPath $rescue){Remove-Item -LiteralPath $rescue -Force -ErrorAction SilentlyContinue}
   Remove-Item -LiteralPath $root -ErrorAction SilentlyContinue
  }
  throw $reason
 }
}elseif($Mode -eq 'Verify'){
 VerifyInstall
 Write-Output ('CI_MOTOR_VERIFY_OK '+$exe)
}else{
 VerifyInstall
 VerifyDataSubtree
 $t=Get-ScheduledTask -TaskName $task -ErrorAction Stop
 if($t.State -eq 'Running'){
  Stop-ScheduledTask -TaskName $task -ErrorAction Stop
  $until=(Get-Date).AddSeconds(25)
  do{
   Start-Sleep -Milliseconds 400
   $t=Get-ScheduledTask -TaskName $task -ErrorAction Stop
  }until($t.State -ne 'Running' -or (Get-Date) -ge $until)
  if($t.State -eq 'Running'){throw 'Engine still running; installation retained'}
 }
 Unregister-ScheduledTask -TaskName $rescueTask -Confirm:$false -ErrorAction Stop
 if(Get-ScheduledTask -TaskName $rescueTask -ErrorAction SilentlyContinue){throw 'Recovery task removal not confirmed'}
 Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction Stop
 if(Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue){throw 'Task removal not confirmed'}
 Remove-Item -LiteralPath $exe -Force -ErrorAction Stop
 Remove-Item -LiteralPath $receipt -Force -ErrorAction Stop
 Remove-Item -LiteralPath $rescue -Force -ErrorAction Stop
 if(Test-Path -LiteralPath $proof){Remove-Item -LiteralPath $proof -Force -ErrorAction Stop}
 Remove-Item -LiteralPath $root -ErrorAction Stop
 if(Test-Path -LiteralPath $dataRoot){
  $feed=Join-Path $dataRoot 'catalog\feeds\hagezi_gambling_full.txt'
  Remove-Item -LiteralPath $feed -Force -ErrorAction Stop
  Remove-Item -LiteralPath (Split-Path $feed -Parent) -ErrorAction Stop
  Remove-Item -LiteralPath (Join-Path $dataRoot 'catalog') -ErrorAction Stop
  Remove-Item -LiteralPath $dataRoot -ErrorAction Stop
 }
 Write-Output 'CI_MOTOR_REMOVED_OK'
}
