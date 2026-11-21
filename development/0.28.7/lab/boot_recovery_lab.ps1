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
 Journal -Arguments @('prepare',$journal,$old,$new,$xmlPath,'0.29.0') | Out-Null
 Journal -Arguments @('advance',$journal,'switching') | Out-Null
 # Seal the recovery code and original fixture BEFORE registering the boot
 # trigger or changing the disposable task. Both the seal and its inputs
 # reside under the ACL-protected VM kit for a persistent-VM trial.
 $verificationLib=Join-Path $PSScriptRoot 'reboot_event_chain.ps1'
 if(-not (Test-Path -LiteralPath $verificationLib -PathType Leaf)){throw 'Recovery verification library missing before arming watchdog'}
 $seal=[ordered]@{
  schema=1
  taskName=$TaskName
  watchdogName=$WatchdogName
  workspace=$Workspace
  labScriptSha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $PSCommandPath).Hash
  verificationLibSha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $verificationLib).Hash
  journalHelperSha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $JournalExe).Hash
  originalTaskXMLSha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $xmlPath).Hash
  previousFixtureSha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $old).Hash
 }
 $seal | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $Workspace 'recovery-code-seal.json') -Encoding UTF8 -ErrorAction Stop
 # CRITICAL ORDER: arm and positively verify the independent SYSTEM watchdog
 # BEFORE changing even the disposable candidate task. A crash after arming,
 # but before switching, must be recoverable as "original already intact".
 # Neither the fixture nor its successor is a production installer.
 $script=$PSCommandPath
 $pwsh=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
 $args='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$script+'" -Mode recover -TaskName "'+$TaskName+'" -WatchdogName "'+$WatchdogName+'" -Workspace "'+$Workspace+'" -JournalExe "'+$JournalExe+'"'
 $wdTrigger=New-ScheduledTaskTrigger -AtStartup
 Register-ScheduledTask -TaskName $WatchdogName -Action (New-ScheduledTaskAction -Execute $pwsh -Argument $args) -Trigger $wdTrigger -User SYSTEM -RunLevel Highest | Out-Null
 $wd=Get-ScheduledTask -TaskName $WatchdogName
 if($wd.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or @($wd.Triggers).Count -ne 1 -or $wd.Triggers[0].CimClass.CimClassName -ne 'MSFT_TaskBootTrigger'){throw 'Boot watchdog not configured to run as SYSTEM on boot'}
 if($env:VOLVE_CI_ABORT_BEFORE_CANDIDATE -eq '1'){
  # Disposable CI-only fault injection. Do not touch the candidate; leave the
  # pending journal and boot-triggered watchdog to exercise pre-switch rescue.
  if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){
   throw 'Pre-switch fault injection only allowed on GitHub-hosted isolated CI VM'
  }
  Write-Host 'FAULT INJECTION: watchdog armed before candidate switch; original task intact.'
  exit 0
 }
 Set-ScheduledTask -TaskName $TaskName -Action (New-ScheduledTaskAction -Execute $notepad) | Out-Null
 TaskAction $TaskName $notepad ''
 Journal -Arguments @('advance',$journal,'proving') | Out-Null
 Write-Host 'STAGED: independent SYSTEM watchdog verified BEFORE disposable candidate switch (not boot-triggered yet).'
 exit 0
}
if($Mode -eq 'recover'){
 try{
  $who=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  if($who -ne 'S-1-5-18'){throw ('Boot recovery not running as SYSTEM: '+$who)}
  # Validate independently staged code identity BEFORE reading the journal,
  # importing XML, or altering the temporary task. A missing/mutated
  # verifier must never convert a pending rollback into a false success.
  $sealPath=Join-Path $Workspace 'recovery-code-seal.json'
  if(-not (Test-Path -LiteralPath $sealPath -PathType Leaf)){
   throw 'Recovery code seal missing; journal remains pending'
  }
  $seal=Get-Content -LiteralPath $sealPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
  if($seal.schema -ne 1 -or $seal.taskName -cne $TaskName -or
     $seal.watchdogName -cne $WatchdogName -or $seal.workspace -cne $Workspace){
   throw 'Recovery code seal identity mismatch; journal remains pending'
  }
  foreach($check in @(
   @{label='lab script';path=$PSCommandPath;digest=$seal.labScriptSha256},
   @{label='verification library';path=(Join-Path $PSScriptRoot 'reboot_event_chain.ps1');digest=$seal.verificationLibSha256},
   @{label='journal helper';path=$JournalExe;digest=$seal.journalHelperSha256},
   @{label='original task XML';path=$xmlPath;digest=$seal.originalTaskXMLSha256},
   @{label='previous fixture';path=$old;digest=$seal.previousFixtureSha256}
  )){
   if([string]::IsNullOrWhiteSpace([string]$check.digest) -or
      ([string]$check.digest).Length -ne 64 -or
      -not (Test-Path -LiteralPath $check.path -PathType Leaf)){
    throw ('Recovery seal missing or malformed: '+$check.label)
   }
   if((Get-FileHash -Algorithm SHA256 -LiteralPath $check.path).Hash -cne [string]$check.digest){
    throw ('Recovery seal hash mismatch: '+$check.label+'; journal remains pending')
   }
  }
  $state=Journal -Arguments @('status',$journal)
  if($state -ne 'ROLLBACK_REQUIRED'){throw 'Recovery is not required'}
  Journal -Arguments @('verify-snapshot',$journal,$xmlPath) | Out-Null
  Journal -Arguments @('verify-previous',$journal,$old) | Out-Null
  # Fail closed on all unexpected actions, including an unrelated task that
  # took over our disposable name. Pre-switch crash: leave original untouched.
  $current=Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
  if($current.TaskPath -ne '\' -or $current.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or @($current.Actions).Count -ne 1){
   throw 'Unexpected disposable motor identity during recovery'
  }
  $action=@($current.Actions)[0]
  $alreadyOriginal=($action.Execute -eq $cmd -and [string]$action.Arguments -eq '/C exit 0')
  $switched=($action.Execute -eq $notepad -and [string]::IsNullOrWhiteSpace([string]$action.Arguments))
  if(-not $alreadyOriginal -and -not $switched){throw 'Unrecognized disposable motor action; refusing restore'}
  Journal -Arguments @('advance',$journal,'restoring') | Out-Null
  $saved=[IO.File]::ReadAllText($xmlPath)
  if($saved -notmatch 'cmd\.exe'){throw 'Unexpected original task executable'}
  if($switched) {
   Register-ScheduledTask -TaskName $TaskName -Xml $saved -Force | Out-Null
  }
  TaskAction $TaskName $cmd '/C exit 0'
  # A correct-looking action is not sufficient. The SYSTEM watchdog itself
  # must verify the whole task definition BEFORE marking the journal restored.
  # This exact helper is shipped alongside this fixture in the protected VM
  # kit; if missing or unparseable, fail closed and retain recovery evidence.
  $xmlVerifier=Join-Path $PSScriptRoot 'reboot_event_chain.ps1'
  if(-not (Test-Path -LiteralPath $xmlVerifier -PathType Leaf)){
   throw 'Full XML recovery verifier is missing; journal remains pending'
  }
  . $xmlVerifier
  $actualXML=Export-ScheduledTask -TaskName $TaskName -TaskPath '\' -ErrorAction Stop
  if(-not (Assert-VolvRestoredTaskXML -SavedXML $saved -RestoredXML $actualXML)){
   throw 'Full original Task Scheduler XML was not recovered'
  }
  Journal -Arguments @('advance',$journal,'restored') | Out-Null
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
 $state=Journal -Arguments @('status',$journal)
 if($state -ne 'NO_ROLLBACK:restored'){throw ('Unexpected journal state: '+$state)}
 Write-Host 'PASS: boot-triggered SYSTEM watchdog manually invoked and restored original harmless test task.'
 exit 0
}
