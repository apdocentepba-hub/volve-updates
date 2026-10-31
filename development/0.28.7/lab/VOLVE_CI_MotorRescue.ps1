# VOLVE CI-only independent SYSTEM rescue. Never use on a user's PC.
# It disables ONLY the allowlisted disposable motor task and records proof.
# No DNS, firewall, hosts, registry, user files or production task modifications.
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][ValidatePattern('^[0-9]{6,20}$')][string]$LabId,
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedSHA256,
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedRescueSHA256
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'CI rescue refused: runner identity'}
$computer=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
if(($computer.Manufacturer+' '+$computer.Model) -notmatch '(?i:virtual machine|vmware|hyper-v|kvm|qemu|virtualbox)'){throw 'CI rescue refused: nonvirtual host'}
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18'){throw 'CI rescue refused: not SYSTEM'}
$root=Join-Path $env:ProgramData ('VOLVE-CI-MotorInstall-'+$LabId)
$motorTask='VOLVE-CI-FreshMotor-'+$LabId
$rescueTask='VOLVE-CI-FreshRescue-'+$LabId
$exe=Join-Path $root 'VOLVE_CI_FreshDNS53.exe'
$rescue=Join-Path $root 'VOLVE_CI_MotorRescue.ps1'
$receipt=Join-Path $root 'ci-install-receipt.json'
$proof=Join-Path $root 'ci-rescue-result.json'
$sha=$ExpectedSHA256.ToLowerInvariant()
$rescueSHA=$ExpectedRescueSHA256.ToLowerInvariant()
function NormalFile([string]$path){
 $f=Get-Item -LiteralPath $path -Force -ErrorAction Stop
 if($f.PSIsContainer -or (($f.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)){throw ('Untrusted recovery file: '+$path)}
 return $f
}
$dir=Get-Item -LiteralPath $root -Force -ErrorAction Stop
if(-not $dir.PSIsContainer -or (($dir.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)){throw 'Unsafe recovery root'}
$acl=Get-Acl -LiteralPath $root -ErrorAction Stop
if(-not $acl.AreAccessRulesProtected){throw 'Recovery root ACL has inheritance'}
foreach($rule in @($acl.Access)){
 if($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow){continue}
 $sid=$rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
 if($sid -notin @('S-1-5-18','S-1-5-32-544')){throw ('Recovery root grants unexpected SID: '+$sid)}
}
$null=NormalFile $exe
$null=NormalFile $rescue
$null=NormalFile $receipt
if((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant() -cne $sha){throw 'Installed motor hash mismatch'}
if((Get-FileHash -LiteralPath $rescue -Algorithm SHA256).Hash.ToLowerInvariant() -cne $rescueSHA){throw 'Independent rescue script hash mismatch'}
$record=Get-Content -LiteralPath $receipt -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
if($record.schema -ne 1 -or $record.version -ne '0.28.7-CI' -or
 $record.sha256 -cne $sha -or $record.exe -cne $exe -or $record.task -cne $motorTask -or
 $record.rescueSHA256 -cne $rescueSHA -or $record.rescueScript -cne $rescue -or
 $record.rescueTask -cne $rescueTask){throw 'Installed rescue inventory not bound to motor'}
$motor=@(Get-ScheduledTask -TaskName $motorTask -ErrorAction Stop)
if($motor.Count -ne 1){throw 'Ambiguous motor task'}
$t=$motor[0]
if($t.TaskPath -ne '\' -or $t.Principal.UserId -notin @('SYSTEM','S-1-5-18')){throw 'Unexpected motor task principal/path'}
$expectedArgs='--ci-fresh-dns53 "'+$record.dataRoot+'" VOLVE-CI-GITHUB-HOSTED-VM-DNS53-ONLY'
if(@($t.Actions).Count -ne 1 -or
 [string]$t.Actions[0].Execute -ine $exe -or
 [string]$t.Actions[0].Arguments -cne $expectedArgs){throw 'Unexpected motor task action'}
if(@([xml](Export-ScheduledTask -TaskName $motorTask)).Count -ne 1){throw 'Unable to inspect task XML'}
$rescueEntry=@(Get-ScheduledTask -TaskName $rescueTask -ErrorAction Stop)
if($rescueEntry.Count -ne 1 -or $rescueEntry[0].Principal.UserId -notin @('SYSTEM','S-1-5-18')){throw 'Unexpected recovery task identity'}
if(@($rescueEntry[0].Actions).Count -ne 1){throw 'Unexpected recovery task actions'}
# Never interfere with another live DNS listener. Exact port ownership is
# audited in the health check before arming recovery. Recovery itself only
# disables our own task after the resident motor has ceased.
$processes=@(Get-CimInstance Win32_Process -Filter "Name='VOLVE_CI_FreshDNS53.exe'" -ErrorAction Stop |
 Where-Object {[string]$_.ExecutablePath -ieq $exe})
if($processes.Count -ne 0){throw 'Motor still running: refuse forced recovery'}
foreach($ip in @('127.0.0.1','::1')){
 if(@(Get-NetUDPEndpoint -LocalAddress $ip -LocalPort 53 -ErrorAction SilentlyContinue).Count -ne 0){
  throw ('DNS port occupied: recovery would be ambiguous '+$ip)
 }
}
if(Test-Path -LiteralPath $proof){throw 'Recovery already recorded; no second recovery'}
# This is fresh-install rollback: the original state had no motor task. Keep
# the task registered but disabled so installer Verify/Remove can audit it.
Disable-ScheduledTask -TaskName $motorTask -ErrorAction Stop | Out-Null
$disabled=Get-ScheduledTask -TaskName $motorTask -ErrorAction Stop
if($disabled.State -ne 'Disabled'){throw 'Motor task not disabled'}
# Atomic, create-only evidence. Receipt is left unchanged.
$result=[ordered]@{
 schema=1;state='motor-disabled-after-crash';labId=$LabId
 motorSHA256=$sha;rescueSHA256=$rescueSHA
 motorTask=$motorTask;rescueTask=$rescueTask
}
$json=$result | ConvertTo-Json -Compress
$fd=[IO.File]::Open($proof,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try{
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes($json)
 $fd.Write($bytes,0,$bytes.Length)
 $fd.Flush($true)
}finally{$fd.Dispose()}
Write-Output 'CI_RESCUE_SUCCESS: independent SYSTEM task disabled crashed disposable motor without touching system DNS'
