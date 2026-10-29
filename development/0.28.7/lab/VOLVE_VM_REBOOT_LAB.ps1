# VOLVÉ VM REBOOT LAB — development only, never production.
# Only disposable VM tasks and dummy binaries. Does NOT change DNS, hosts,
# firewall, installed VOLVÉ files, browser policies, or network settings.
# No automatic restart: an operator must reboot the disposable VM explicitly.
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][ValidateSet('ValidateScript','Prepare','Recover','Verify','Cleanup')][string]$Mode,
  [Parameter(Mandatory=$true)][ValidatePattern('^[0-9]{6,12}$')][string]$LabId,
  [string]$JournalExe='',
  [switch]$ConfirmVirtualMachine
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if($Mode -eq 'ValidateScript'){
  Write-Host "OK: reboot lab script parsed, no Windows settings inspected or changed."
  return
}
$root=Join-Path $env:ProgramData ("VOLVE-VM-BOOTLAB-"+$LabId)
$oldTask="VOLVE-CI-VM-Motor-"+$LabId
$watchdog="VOLVE-CI-VM-Watchdog-"+$LabId
$oldExe=Join-Path $env:WINDIR 'System32\cmd.exe'
$newExe=Join-Path $env:WINDIR 'System32\notepad.exe'
$journal=Join-Path $root 'recovery.json'
$taskXML=Join-Path $root 'original-task.xml'
$oldBin=Join-Path $root 'old-dummy-motor.bin'
$newBin=Join-Path $root 'new-dummy-motor.bin'
$labTool=Join-Path $root 'volve-journal-lab.exe'
$bootRecord=Join-Path $root 'boot-before.txt'
$recoveryFile=Join-Path $root 'recovery-result.txt'
$scriptCopy=Join-Path $root 'VOLVE_VM_REBOOT_LAB.ps1'

function Require-DisposableVM {
  $cs=Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
  $vm=($cs.Manufacturer+' '+$cs.Model)
  if($vm -notmatch '(?i:virtual|vmware|qemu|kvm|virtualbox|hyper-v|parallels|bochs|hvm)'){
    throw "This machine is not positively identified as a VM; REFUSED: "+$vm
  }
  $current=[Security.Principal.WindowsIdentity]::GetCurrent()
  if($Mode -eq 'Recover'){
    if($current.User.Value -ne 'S-1-5-18'){throw 'Recovery MUST run as SYSTEM'}
  } else {
    $admin=([Security.Principal.WindowsPrincipal]::new($current)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if(-not $admin){throw 'Run in elevated PowerShell on a disposable VM'}
  }
}
function BootTicks {
  $os=Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
  return $os.LastBootUpTime.ToUniversalTime().Ticks
}
function Invoke-Journal([string[]]$argv){
  if(-not (Test-Path -LiteralPath $labTool -PathType Leaf)){throw 'Journal helper missing from VM lab'}
  $out=& $labTool @argv
  if($LASTEXITCODE -ne 0){throw ('Verified journal command rejected: '+$argv[0])}
  return $out
}
function Assert-Task([string]$name,[string]$expectedExe,[string]$expectedArgs){
  $task=Get-ScheduledTask -TaskName $name -ErrorAction Stop
  if($task.TaskPath -ne '\' -or $task.Principal.UserId -notin @('SYSTEM','S-1-5-18')){
    throw ('Unexpected identity of disposable task '+$name)
  }
  $acts=@($task.Actions)
  if($acts.Count -ne 1){throw 'Unexpected number of task actions'}
  $action=$acts[0]
  if($action.Execute -ne $expectedExe -or ($action.Arguments+'').Trim() -ne $expectedArgs){
    throw ('Task action unexpected for '+$name)
  }
}
function Validate-Watchdog {
  $t=Get-ScheduledTask -TaskName $watchdog -ErrorAction Stop
  if($t.TaskPath -ne '\' -or $t.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or @($t.Actions).Count -ne 1){
    throw 'Unexpected watchdog task identity'
  }
  if(@($t.Triggers).Count -ne 1 -or $t.Triggers[0].CimClass.CimClassName -ne 'MSFT_TaskBootTrigger'){
    throw 'Watchdog does not have an at-startup trigger'
  }
  $winPS=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
  if($t.Actions[0].Execute -ne $winPS -or $t.Actions[0].Arguments -notlike ('*-File "'+$scriptCopy+'" -Mode Recover*')){
    throw 'Watchdog does not execute the expected lab script'
  }
}
Require-DisposableVM

if($Mode -eq 'Prepare'){
  if(-not $ConfirmVirtualMachine){throw 'Explicit -ConfirmVirtualMachine required'}
  if(Test-Path -LiteralPath $root){throw 'Lab folder already exists; refuse overwrite'}
  if(Get-ScheduledTask -TaskName $oldTask -ErrorAction SilentlyContinue){throw 'Disposable task name already exists'}
  if(Get-ScheduledTask -TaskName $watchdog -ErrorAction SilentlyContinue){throw 'Watchdog task name already exists'}
  if(-not (Test-Path -LiteralPath $JournalExe -PathType Leaf)){throw 'An existing journal lab executable is required'}
  if(-not [IO.Path]::IsPathRooted($JournalExe)){throw 'Journal helper path must be absolute'}
  New-Item -ItemType Directory -Path $root -ErrorAction Stop | Out-Null
  & icacls.exe $root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
  if($LASTEXITCODE -ne 0){throw 'Could not protect VM lab folder ACL'}
  Copy-Item -LiteralPath $PSCommandPath -Destination $scriptCopy -ErrorAction Stop
  Copy-Item -LiteralPath $JournalExe -Destination $labTool -ErrorAction Stop
  [IO.File]::WriteAllBytes($oldBin,[Text.Encoding]::ASCII.GetBytes('MZ_disposable_VM_old_test'))
  [IO.File]::WriteAllBytes($newBin,[Text.Encoding]::ASCII.GetBytes('MZ_disposable_VM_new_test'))
  [IO.File]::WriteAllText($bootRecord,[string](BootTicks),[Text.Encoding]::ASCII)
  $trigger=New-ScheduledTaskTrigger -Once -At ((Get-Date).AddYears(1))
  Register-ScheduledTask -TaskName $oldTask -Action (New-ScheduledTaskAction -Execute $oldExe -Argument '/C exit 0') -Trigger $trigger -User SYSTEM -RunLevel Highest | Out-Null
  Assert-Task $oldTask $oldExe '/C exit 0'
  [IO.File]::WriteAllText($taskXML,(Export-ScheduledTask -TaskName $oldTask),[Text.UTF8Encoding]::new($false))
  Invoke-Journal -argv @('prepare',$journal,$oldBin,$newBin,$taskXML,'0.29.0') | Out-Null
  # Install the rollback-at-startup task BEFORE changing the dummy motor task.
  $winPS=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
  $args='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$scriptCopy+'" -Mode Recover -LabId '+$LabId
  Register-ScheduledTask -TaskName $watchdog -Action (New-ScheduledTaskAction -Execute $winPS -Argument $args) -Trigger (New-ScheduledTaskTrigger -AtStartup) -User SYSTEM -RunLevel Highest | Out-Null
  Validate-Watchdog
  Invoke-Journal -argv @('advance',$journal,'switching') | Out-Null
  Set-ScheduledTask -TaskName $oldTask -Action (New-ScheduledTaskAction -Execute $newExe) | Out-Null
  Assert-Task $oldTask $newExe ''
  Invoke-Journal -argv @('advance',$journal,'proving') | Out-Null
  Write-Host 'PREPARED: dummy motor task switched and SYSTEM recovery task armed.'
  Write-Host 'DO NOT run this on your daily computer. On this disposable VM only, reboot Windows manually.'
  Write-Host 'Then run: powershell.exe -File "'+$scriptCopy+'" -Mode Verify -LabId '+$LabId
  return
}

if(-not (Test-Path -LiteralPath $root -PathType Container)){throw 'No such VM lab'}
if($Mode -eq 'Recover'){
  # A non-reboot invocation MUST NOT be mistaken for a successful real boot.
  try {
    $before=[long][IO.File]::ReadAllText($bootRecord)
    $after=[long](BootTicks)
    if($after -le $before){throw 'No OS reboot detected; refusing simulated recovery'}
    Validate-Watchdog
    $status=Invoke-Journal -argv @('status',$journal)
    if($status -eq 'NO_ROLLBACK:restored'){return}
    if($status -ne 'ROLLBACK_REQUIRED'){throw ('Unrecognized recovery journal state: '+$status)}
    Invoke-Journal -argv @('verify-snapshot',$journal,$taskXML) | Out-Null
    Invoke-Journal -argv @('verify-previous',$journal,$oldBin) | Out-Null
    # Handles a crash during previous recovery as well.
    $t=Get-ScheduledTask -TaskName $oldTask
    $action=@($t.Actions)[0]
    if($action.Execute -eq $newExe){Assert-Task $oldTask $newExe ''}
    elseif($action.Execute -eq $oldExe){Assert-Task $oldTask $oldExe '/C exit 0'}
    else{throw 'Neither owned candidate nor owned previous task'}
    $j=(Get-Content -LiteralPath $journal -Raw | ConvertFrom-Json)
    if($j.phase -ne 'restoring'){Invoke-Journal -argv @('advance',$journal,'restoring') | Out-Null}
    if($action.Execute -eq $newExe){
      $xml=[IO.File]::ReadAllText($taskXML)
      if($xml -notmatch 'cmd\.exe'){throw 'Original task snapshot does not identify the dummy engine'}
      Register-ScheduledTask -TaskName $oldTask -Xml $xml -Force | Out-Null
    }
    Assert-Task $oldTask $oldExe '/C exit 0'
    Invoke-Journal -argv @('advance',$journal,'restored') | Out-Null
    [IO.File]::WriteAllText($recoveryFile,'RESTORED_AFTER_REAL_BOOT',[Text.Encoding]::ASCII)
  } catch {
    [IO.File]::WriteAllText($recoveryFile,('FAILED: '+$_.Exception.Message),[Text.Encoding]::UTF8)
    throw
  }
  return
}

if($Mode -eq 'Verify'){
  $before=[long][IO.File]::ReadAllText($bootRecord)
  $after=[long](BootTicks)
  if($after -le $before){throw 'Real reboot has NOT happened'}
  Validate-Watchdog
  if(-not (Test-Path -LiteralPath $recoveryFile -PathType Leaf)){throw 'Watchdog never recorded success'}
  if([IO.File]::ReadAllText($recoveryFile) -ne 'RESTORED_AFTER_REAL_BOOT'){
    throw ('Watchdog failed: '+[IO.File]::ReadAllText($recoveryFile))
  }
  Assert-Task $oldTask $oldExe '/C exit 0'
  $status=Invoke-Journal -argv @('status',$journal)
  if($status -ne 'NO_ROLLBACK:restored'){throw 'Recovery journal did not reach restored'}
  Write-Host 'PASS: verified Windows reboot and SYSTEM restoration of original VM-only task.'
  Write-Host 'Run Cleanup on this disposable VM to remove the temporary scheduled tasks.'
  return
}

if($Mode -eq 'Cleanup'){
  if(-not $ConfirmVirtualMachine){throw 'Explicit -ConfirmVirtualMachine required'}
  if(-not (Test-Path -LiteralPath $recoveryFile -PathType Leaf)){throw 'Cannot clean up without verified recovery evidence'}
  if([IO.File]::ReadAllText($recoveryFile) -ne 'RESTORED_AFTER_REAL_BOOT'){throw 'Recovery did not succeed; preserve for diagnosis'}
  Assert-Task $oldTask $oldExe '/C exit 0'
  Validate-Watchdog
  Unregister-ScheduledTask -TaskName $watchdog -Confirm:$false
  Unregister-ScheduledTask -TaskName $oldTask -Confirm:$false
  Write-Host 'Temporary VM scheduled tasks removed. Diagnostic folder retained for audit: '+$root
  return
}
