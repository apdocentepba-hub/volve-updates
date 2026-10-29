# VOLVE Windows CI ONLY. Simulates an on-startup recovery watchdog without rebooting.
# No production VOLVE tasks, DNS settings, network listeners or browser policies are altered.
param(
 [Parameter(Mandatory=$true)][ValidateSet('stage','recover','verify')][string]$Mode,
 [Parameter(Mandatory=$true)][string]$TaskName,
 [Parameter(Mandatory=$true)][string]$WatchdogName,
 [Parameter(Mandatory=$true)][string]$Workspace,
 [Parameter(Mandatory=$true)][string]$JournalExe
)
$ErrorActionPreference='Stop'
if($TaskName -cnotmatch '^VOLVE-CI-StartupMotor-[0-9]+$' -or $WatchdogName -cnotmatch '^VOLVE-CI-BootRecovery-[0-9]+$'){
 throw 'Refusing to target a non-disposable CI task'
}
if(-not [IO.Path]::IsPathRooted($Workspace) -or $Workspace -notmatch '[\\/]VOLVE-CI-BOOT-[0-9]+$'){
 throw 'Refusing unrecognized test directory'
}
if(-not (Test-Path -LiteralPath $JournalExe -PathType Leaf)){ throw 'Journal test executable not found' }
$old=Join-Path $Workspace 'old-test-engine.bin'
$new=Join-Path $Workspace 'new-test-engine.bin'
$xmlPath=Join-Path $Workspace 'old-task.xml'
$journal=Join-Path $Workspace 'recovery.json'
$success=Join-Path $Workspace 'boot-recovery-success.marker'
$failure=Join-Path $Workspace 'boot-recovery-failed.marker'
$cmd=Join-Path $env:WINDIR 'System32\cmd.exe'
$notepad=Join-Path $env:WINDIR 'System32\notepad.exe'
function Journal([string[]]$Arguments){
 $output = & $JournalExe @Arguments
 if($LASTEXITCODE -ne 0){throw ('Journal helper rejected operation '+($Arguments[0]))}
 return $output
}
function TaskAction([string]$name,[string]$expectedExe,[string]$expectedArgs){
 $t=Get-ScheduledTask -TaskName $name -ErrorAction Stop
 if($t.TaskPath -ne '\' -or $t.Principal.UserId -notin @('SYSTEM','S-1-5-18')){throw 'Unowned or unexpected task principal/path'}
 if(@($t.Actions).Count -ne 1){throw 'Unexpected task action count'}
 $a=@($t.Actions)[0]
 if($a.Execute -ne $expectedExe -or ($a.Arguments+'').Trim() -ne $expectedArgs){throw 'Unexpected scheduled task action'}
}
if($Mode -eq 'stage'){
 if(Test-Path -LiteralPath $Workspace){throw 'Refusing to overwrite an existing lab workspace'}
 if(Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue){throw 'Lab task already exists'}
 if(Get-ScheduledTask -TaskName $WatchdogName -ErrorAction SilentlyContinue){throw 'Watchdog task already exists'}
 $identity=([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()))
 if(-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'CI runner must be elevated'}
 New-Item -ItemType Directory $Workspace | Out-Null
 [IO.File]::WriteAllBytes($old,[Text.Encoding]::ASCII.GetBytes('MZ_disposable_old_motor'))
 [IO.File]::WriteAllBytes($new,[Text.Encoding]::ASCII.GetBytes('MZ_disposable_candidate_motor'))
 $trig=New-ScheduledTaskTrigger -Once -At ((Get-Date).AddYears(1))
 $action=New-ScheduledTaskAction -Execute $cmd -Argument '/C exit 0'
 Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trig -User SYSTEM -RunLevel Highest | Out-Null
 TaskAction $TaskName $cmd '/C exit 0'
 [IO.File]::WriteAllText($xmlPath,(Export-ScheduledTask -TaskName $TaskName),[Text.UTF8Encoding]::new($false))
 Journal @('prepare',$journal,$old,$new,$xmlPath,'0.29.0') | Out-Null
 Journal @('advance',$journal,'switching') | Out-Null
 Set-ScheduledTask -TaskName $TaskName -Action (New-ScheduledTaskAction -Execute $notepad) | Out-Null
 TaskAction $TaskName $notepad ''
 Journal @('advance',$journal,'proving') | Out-Null
 # This recovery task *would* run on a boot; for CI it is manually started.
 # It cannot be published/installed; only exact CI disposable task names accepted.
 $script=$PSCommandPath
 $pwsh=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
 $args='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$script+'" -Mode recover -TaskName "'+$TaskName+'" -WatchdogName "'+$WatchdogName+'" -Workspace "'+$Workspace+'" -JournalExe "'+$JournalExe+'"'
 $wdTrigger=New-ScheduledTaskTrigger -AtStartup
 Register-ScheduledTask -TaskName $WatchdogName -Action (New-ScheduledTaskAction -Execute $pwsh -Argument $args) -Trigger $wdTrigger -User SYSTEM -RunLevel Highest | Out-Null
 $wd=Get-ScheduledTask -TaskName $WatchdogName
 if($wd.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or @($wd.Triggers).Count -ne 1 -or $wd.Triggers[0].CimClass.CimClassName -ne 'MSFT_TaskBootTrigger'){throw 'Boot watchdog not configured to run as SYSTEM on boot'}
 Write-Host 'STAGED: disposable motor task switched; SYSTEM startup watchdog installed (not triggered yet).'
 exit 0
}
if($Mode -eq 'recover'){
 try{
  $who=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  if($who -ne 'S-1-5-18'){throw ('Boot recovery not running as SYSTEM: '+$who)}
  $state=Journal @('status',$journal)
  if($state -ne 'ROLLBACK_REQUIRED'){throw 'Recovery is not required'}
  Journal @('verify-snapshot',$journal,$xmlPath) | Out-Null
  Journal @('verify-previous',$journal,$old) | Out-Null
  TaskAction $TaskName $notepad ''
  Journal @('advance',$journal,'restoring') | Out-Null
  $saved=[IO.File]::ReadAllText($xmlPath)
  if($saved -notmatch 'cmd\.exe'){throw 'Unexpected original task executable'}
  Register-ScheduledTask -TaskName $TaskName -Xml $saved -Force | Out-Null
  TaskAction $TaskName $cmd '/C exit 0'
  Journal @('advance',$journal,'restored') | Out-Null
  [IO.File]::WriteAllText($success,'RESTORED_BY_SYSTEM_STARTUP_TASK',[Text.Encoding]::ASCII)
  Write-Host 'PASS: SYSTEM startup recovery restored original test task.'
  exit 0
 }catch{
  [IO.File]::WriteAllText($failure,$_.Exception.Message,[Text.Encoding]::UTF8)
  throw
 }
}
if($Mode -eq 'verify'){
 $wd=Get-ScheduledTask -TaskName $WatchdogName -ErrorAction Stop
 if(@($wd.Triggers).Count -ne 1 -or $wd.Triggers[0].CimClass.CimClassName -ne 'MSFT_TaskBootTrigger'){throw 'Boot task no longer has startup trigger'}
 if(-not (Test-Path -LiteralPath $success -PathType Leaf)){throw 'SYSTEM startup watchdog did not report successful restore'}
 if(Test-Path -LiteralPath $failure){throw ('Startup watchdog reported failure: '+[IO.File]::ReadAllText($failure))}
 if([IO.File]::ReadAllText($success) -ne 'RESTORED_BY_SYSTEM_STARTUP_TASK'){throw 'Unexpected result marker'}
 TaskAction $TaskName $cmd '/C exit 0'
 $state=Journal @('status',$journal)
 if($state -ne 'NO_ROLLBACK:restored'){throw ('Unexpected journal state: '+$state)}
 Write-Host 'PASS: boot-triggered SYSTEM watchdog manually invoked and restored original harmless test task.'
 exit 0
}
