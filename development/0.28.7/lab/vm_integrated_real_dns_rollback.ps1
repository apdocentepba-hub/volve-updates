# VOLVE 0.28.7 — isolated Windows VM ONLY. Integrated REAL old Full DNS motor
# + DISPOSABLE CRASHING CANDIDATE + independent SYSTEM boot recovery.
# No production task, Windows adapter, hosts, browser, registry, or firewall changes.
# THIS DOES NOT PERMIT OR INSTALL a signed 0.28.6 -> 0.28.7 product upgrade.
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][ValidateSet('Probe','Arm','Recover','Verify','Cleanup')][string]$Mode,
 [ValidatePattern('^[0-9]{14,18}$')][string]$LabId=''
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
function VMGuard([bool]$needSystem){
 $vm=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
 if(($vm.Manufacturer+' '+$vm.Model) -notmatch '(?i:virtual machine|vmware|hyper-v|virtualbox|kvm|qemu|parallels|xen)'){
  throw 'REFUSED: not a positively identified disposable VM'
 }
 $who=[Security.Principal.WindowsIdentity]::GetCurrent()
 if($needSystem){
  if($who.User.Value -cne 'S-1-5-18'){throw 'REFUSED: independent boot restorer requires SYSTEM'}
 }else{
  $p=[Security.Principal.WindowsPrincipal]::new($who)
  if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'REFUSED: VM administrator required'}
 }
}
function SHA([string]$path){
 return (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
}
function BootUTC{
 return ([datetime](Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime).ToUniversalTime()
}
function RequireFile([string]$path){
 $f=Get-Item -LiteralPath $path -Force -ErrorAction Stop
 if($f.PSIsContainer -or (($f.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)){throw ('Unsafe asset: '+$path)}
}
function ProtectedRoot([string]$root){
 $d=Get-Item -LiteralPath $root -Force -ErrorAction Stop
 if(-not $d.PSIsContainer -or (($d.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)){throw 'Unsafe root'}
 $a=Get-Acl -LiteralPath $root
 if(-not $a.AreAccessRulesProtected){throw 'Recovery root inherits unsafe NTFS permissions'}
 $allow=@('S-1-5-18','S-1-5-32-544')
 $owner=$a.GetOwner([Security.Principal.SecurityIdentifier]).Value
 if($owner -notin $allow){throw 'Untrusted recovery owner'}
 foreach($entry in @($a.Access)){
  $sid=$entry.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
  if($entry.IsInherited -or $entry.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or $sid -notin $allow){
   throw ('Unexpected NTFS recovery trustee: '+$sid)
  }
 }
}
function TaskExact([string]$name,[string]$expectedExecutable,[string]$expectedArguments,[bool]$boot){
 $t=Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction Stop
 if($t.TaskPath -ne '\' -or $t.Principal.UserId -notin @('SYSTEM','S-1-5-18')){
  throw ('Untrusted disposable task path or principal '+$name)
 }
 if(@($t.Actions).Count -ne 1 -or @($t.Triggers).Count -ne 1){
  throw ('Unexpected disposable task action/trigger count '+$name)
 }
 if([string]$t.Actions[0].Execute -ine $expectedExecutable){
  throw ('Untrusted disposable task executable '+$name)
 }
 if([string]$t.Actions[0].Arguments -cne $expectedArguments){
  throw ('Untrusted disposable task arguments '+$name)
 }
 if($boot -and $t.Triggers[0].CimClass.CimClassName -ne 'MSFT_TaskBootTrigger'){
  throw ('Untrusted disposable task startup trigger '+$name)
 }
 return $t
}
function NetworkSnapshot{
 return (@(Get-DnsClientServerAddress -ErrorAction Stop |
  Sort-Object InterfaceIndex,AddressFamily |
  Select-Object InterfaceIndex,AddressFamily,ServerAddresses) | ConvertTo-Json -Depth 6 -Compress)
}
function DNSRCode([string]$ip,[string]$domain){
 $family=[Net.Sockets.AddressFamily]::InterNetwork
 if($ip -eq '::1'){$family=[Net.Sockets.AddressFamily]::InterNetworkV6}
 $udp=[Net.Sockets.UdpClient]::new($family)
 try {
  $udp.Client.ReceiveTimeout=2000
  $udp.Connect([Net.IPAddress]::Parse($ip),53)
  $id=Get-Random -Minimum 1024 -Maximum 65000
  $bytes=[Collections.Generic.List[byte]]::new()
  foreach($b in @([byte](($id -shr 8) -band 255),[byte]($id -band 255),[byte]1,[byte]0,[byte]0,[byte]1,[byte]0,[byte]0,[byte]0,[byte]0,[byte]0,[byte]0)){$bytes.Add($b)}
  foreach($part in $domain.Split('.')){
   $label=[Text.Encoding]::ASCII.GetBytes($part)
   if($label.Length -lt 1 -or $label.Length -gt 63){throw 'Invalid DNS label'}
   $bytes.Add([byte]$label.Length);foreach($b in $label){$bytes.Add($b)}
  }
  foreach($b in @([byte]0,[byte]0,[byte]1,[byte]0,[byte]1)){$bytes.Add($b)}
  [byte[]]$req=$bytes.ToArray()
  $null=$udp.Send($req,$req.Length)
  $any=[Net.IPAddress]::Any
  if($ip -eq '::1'){$any=[Net.IPAddress]::IPv6Any}
  $remote=[Net.IPEndPoint]::new($any,0)
  [byte[]]$reply=$udp.Receive([ref]$remote)
  return Assert-VolvVmDnsReply -Request $req -Reply $reply
 }finally{$udp.Dispose()}
}
function SixDNS {
 foreach($ip in @('127.0.0.1','::1')){
  foreach($item in @(@{name='stake.com';rcode=3},@{name='betwarrior.bet.ar';rcode=3},@{name='example.org';rcode=0})){
   $rcode=DNSRCode $ip $item.name
   if($rcode -ne $item.rcode){throw ('DNS wrong: '+$ip+' '+$item.name+' rcode '+$rcode)}
  }
 }
}
function EngineIdentity([string]$exe){
 $procs=@(Get-CimInstance Win32_Process -ErrorAction Stop |
  Where-Object {[string]$_.ExecutablePath -ieq $exe})
 if($procs.Count -ne 1){throw ('Expected exactly one running original motor; observed '+$procs.Count)}
 $p=$procs[0]
 $sid=Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid -ErrorAction Stop
 if($sid.ReturnValue -ne 0 -or $sid.Sid -ne 'S-1-5-18'){throw 'Original DNS motor is not SYSTEM'}
 foreach($ip in @('127.0.0.1','::1')){
  $ports=@(Get-NetUDPEndpoint -LocalAddress $ip -LocalPort 53 -ErrorAction Stop)
  if($ports.Count -ne 1 -or $ports[0].OwningProcess -ne $p.ProcessId){throw ('Original motor does not exclusively own DNS53 '+$ip)}
 }
 return $p
}
function VerifiedInputs($plan,[string]$root){
 ProtectedRoot $root
 $v=@{
  'original-task.xml'=$plan.xmlSHA256
  'VOLVE_CI_FreshDNS53.exe'=$plan.motorSHA256
  'catalog\feeds\hagezi_gambling_full.txt'=$plan.catalogSHA256
  'vm_integrated_real_dns_rollback.ps1'=$plan.recoverySHA256
  'reboot_event_chain.ps1'=$plan.eventParserSHA256
  'vm_dns_reply_contract.ps1'=$plan.dnsParserSHA256
 }
 foreach($rel in $v.Keys){
  $p=Join-Path $root $rel
  RequireFile $p
  if((SHA $p) -cne [string]$v[$rel]){throw ('Recovery protected file modified: '+$rel)}
 }
}
VMGuard ($Mode -eq 'Recover')
if($Mode -eq 'Probe'){
 Write-Host 'PASS: isolated VM and administrator; no modifications.'
 return
}
if(-not $LabId){throw 'A unique LabId is mandatory'}
$root=Join-Path $env:ProgramData ('VOLVE-CI-FreshDNS53-'+$LabId)
$motor=Join-Path $root 'VOLVE_CI_FreshDNS53.exe'
$catalog=Join-Path $root 'catalog\feeds\hagezi_gambling_full.txt'
$task='VOLVE-CI-FreshMotor-'+$LabId
$watch='VOLVE-CI-BootRecovery-'+$LabId
$cmd=Join-Path $env:WINDIR 'System32\cmd.exe'
$oldArg='--ci-boot-dns53 "'+$root+'" VOLVE-CI-GITHUB-HOSTED-VM-DNS53-ONLY'
$candidateArg='/C exit 83'
$oldXML=Join-Path $root 'original-task.xml'
$planPath=Join-Path $root 'integrated-rollback-plan.json'
$receiptPath=Join-Path $root 'integrated-rollback-receipt.json'
$recoverScript=Join-Path $root 'vm_integrated_real_dns_rollback.ps1'
$winPS=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
$watchArgs='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$recoverScript+'" -Mode Recover -LabId '+$LabId
$hosts=Join-Path $env:WINDIR 'System32\drivers\etc\hosts'
if($Mode -eq 'Arm'){
 if(-not (Test-Path -LiteralPath $root -PathType Container)){throw 'First run vm_full_motor_reboot_dns.ps1 -Mode Prepare for a NEW LabId'}
 ProtectedRoot $root
 $beforePath=Join-Path $root 'boot-dns-before.json'
 RequireFile $beforePath
 $before=Get-Content -LiteralPath $beforePath -Raw | ConvertFrom-Json -ErrorAction Stop
 if($before.labId -cne $LabId -or $before.mode -cne 'VM_ONLY_CI_UNSIGNED_NO_PRODUCTION' -or
   $before.motorTask -cne $task -or $before.rules -ne 400005 -or
   $before.computer -cne $env:COMPUTERNAME){throw 'Unexpected Full motor preboot lab identity'}
 if((SHA $motor) -cne $before.motorSHA256 -or (SHA $catalog) -cne $before.catalogSHA256){throw 'Original real motor/catalog changed'}
 $original=TaskExact $task $motor $oldArg $true
 if($original.State -eq 'Running'){throw 'Refusing to switch a running Full DNS motor'}
 foreach($ip in @('127.0.0.1','::1')){
  if(@(Get-NetUDPEndpoint -LocalAddress $ip -LocalPort 53 -ErrorAction SilentlyContinue).Count -ne 0){throw 'DNS53 occupied before simulated interruption'}
 }
 if(Get-ScheduledTask -TaskName $watch -ErrorAction SilentlyContinue){throw 'Watchdog task already exists'}
 foreach($path in @($planPath,$oldXML,$recoverScript,$receiptPath)){
  if(Test-Path -LiteralPath $path){throw ('Refusing existing lab recovery asset: '+$path)}
 }
 if((NetworkSnapshot) -cne $before.networkJSON -or (SHA $hosts) -cne $before.hostsSHA256){throw 'Network/hosts changed since Full motor preflight'}
 if(-not (Get-WinEvent -ListLog 'Microsoft-Windows-TaskScheduler/Operational' -ErrorAction Stop).IsEnabled){throw 'Task history is disabled'}
 [IO.File]::WriteAllText($oldXML,(Export-ScheduledTask -TaskName $task -TaskPath '\' -ErrorAction Stop),[Text.UTF8Encoding]::new($false))
 Copy-Item -LiteralPath $PSCommandPath -Destination $recoverScript -ErrorAction Stop
 $meta=[ordered]@{
  schema=1;kind='VOLVE_VM_REAL_MOTOR_ROLLBACK_PENDING';labId=$LabId;computer=$env:COMPUTERNAME;
  bootBeforeUtc=(BootUTC).ToString('o');oldTask=$task;watchdog=$watch;
  motorSHA256=(SHA $motor);catalogSHA256=(SHA $catalog);
  xmlSHA256=(SHA $oldXML);recoverySHA256=(SHA $recoverScript);
  eventParserSHA256=(SHA (Join-Path $root 'reboot_event_chain.ps1'));
  dnsParserSHA256=(SHA (Join-Path $root 'vm_dns_reply_contract.ps1'));
  networkJSON=$before.networkJSON;hostsSHA256=$before.hostsSHA256;
  originalArgs=$oldArg;candidateArgs=$candidateArg;status='recovery-required';
  signedPublisherPermit=$false;productionMotorMigration=$false
 }
 $meta|ConvertTo-Json -Depth 6|Set-Content -LiteralPath $planPath -Encoding UTF8 -ErrorAction Stop
 $plan=Get-Content -LiteralPath $planPath -Raw | ConvertFrom-Json
 VerifiedInputs $plan $root
 $trigger=New-ScheduledTaskTrigger -AtStartup
 $action=New-ScheduledTaskAction -Execute $winPS -Argument $watchArgs
 Register-ScheduledTask -TaskName $watch -TaskPath '\' -Action $action -Trigger $trigger -User SYSTEM -RunLevel Highest -ErrorAction Stop|Out-Null
 $null=TaskExact $watch $winPS $watchArgs $true
 # After the independent SYSTEM watchdog is armed, replace ONLY the exact
 # disposable task action. cmd /C exit 83 simulates a crashing new candidate.
 Set-ScheduledTask -TaskName $task -TaskPath '\' -Action (New-ScheduledTaskAction -Execute $cmd -Argument $candidateArg) -ErrorAction Stop|Out-Null
 $null=TaskExact $task $cmd $candidateArg $true
 Write-Host 'ARMED: real Full original DNS motor backed up; independent SYSTEM boot recovery prearmed.'
 Write-Host 'The disposable candidate is cmd.exe /C exit 83. No product publisher signature is asserted.'
 Write-Host 'NEXT: reboot ONLY the disposable VM; then run Verify from C:\Lab.'
 return
}
RequireFile $planPath
$plan=Get-Content -LiteralPath $planPath -Raw|ConvertFrom-Json -ErrorAction Stop
if($plan.schema -ne 1 -or $plan.kind -cne 'VOLVE_VM_REAL_MOTOR_ROLLBACK_PENDING' -or
 $plan.status -cne 'recovery-required' -or $plan.labId -cne $LabId -or
 $plan.computer -cne $env:COMPUTERNAME -or $plan.oldTask -cne $task -or $plan.watchdog -cne $watch -or
 $plan.originalArgs -cne $oldArg -or $plan.candidateArgs -cne $candidateArg -or
 $plan.signedPublisherPermit -ne $false -or $plan.productionMotorMigration -ne $false){
 throw 'Invalid/unauthorized integrated lab plan'
}
VerifiedInputs $plan $root
$bootBefore=[DateTime]::Parse([string]$plan.bootBeforeUtc,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
$bootAfter=BootUTC
$null=TaskExact $watch $winPS $watchArgs $true
if($Mode -eq 'Recover'){
 if($bootAfter -le $bootBefore.AddSeconds(5)){throw 'Recovery prohibited without an authentic NEW Windows boot'}
 if(Test-Path -LiteralPath $receiptPath){return}
 $live=Get-ScheduledTask -TaskName $task -TaskPath '\' -ErrorAction Stop
 $candidate=([string]$live.Actions[0].Execute -ieq $cmd -and [string]$live.Actions[0].Arguments -ceq $candidateArg)
 $restored=([string]$live.Actions[0].Execute -ieq $motor -and [string]$live.Actions[0].Arguments -ceq $oldArg)
 if(-not ($candidate -or $restored)){throw 'Unrecognized task: refusing to restore'}
 if($candidate){$null=TaskExact $task $cmd $candidateArg $true}
 # Even if a previous recovery was interrupted after importing the old
 # task, verify the exact original XML and its target before re-import.
 if((SHA $motor) -cne $plan.motorSHA256 -or
   (SHA $oldXML) -cne $plan.xmlSHA256){throw 'Original full motor or task snapshot changed'}
 $running=@(Get-CimInstance Win32_Process|Where-Object{[string]$_.ExecutablePath -ieq $motor})
 if($running.Count -gt 0 -and $candidate){throw 'Unsafe: original motor running while candidate task is selected'}
 if($candidate){
  foreach($ip in @('127.0.0.1','::1')){
   if(@(Get-NetUDPEndpoint -LocalAddress $ip -LocalPort 53 -ErrorAction SilentlyContinue).Count -ne 0){throw 'Port53 not free for original recovery'}
  }
  $xml=[IO.File]::ReadAllText($oldXML)
  if($xml -notmatch 'VOLVE_CI_FreshDNS53.exe'){throw 'Original task XML does not identify Full CI motor'}
  Register-ScheduledTask -TaskName $task -TaskPath '\' -Xml $xml -Force -ErrorAction Stop|Out-Null
 }
 $null=TaskExact $task $motor $oldArg $true
 $running=@(Get-CimInstance Win32_Process|Where-Object{[string]$_.ExecutablePath -ieq $motor})
 if($running.Count -eq 0){Start-ScheduledTask -TaskName $task -TaskPath '\' -ErrorAction Stop}
 . (Join-Path $root 'vm_dns_reply_contract.ps1')
 $healthy=$false;$reason='No DNS checked'
 for($i=0;$i -lt 40;$i++){
  Start-Sleep -Milliseconds 900
  try {$null=EngineIdentity $motor;SixDNS;$healthy=$true;break}
  catch {$reason=$_.Exception.Message}
 }
 if(-not $healthy){throw ('Original Full DNS motor not verified after rescue: '+$reason)}
 if((NetworkSnapshot) -cne $plan.networkJSON -or (SHA $hosts) -cne $plan.hostsSHA256){
  throw 'VM network/hosts changed during rollback'
 }
 # Create-only receipt AFTER the recovered real motor replies correctly.
 $record=[ordered]@{
  schema=1;kind='VOLVE_VM_INTEGRATED_FULL_DNS_ROLLBACK';labId=$LabId;
  bootBeforeUtc=$plan.bootBeforeUtc;bootAfterUtc=$bootAfter.ToString('o');
  restoredUtc=[DateTime]::UtcNow.ToString('o');motorSHA256=$plan.motorSHA256;
  originalTaskSHA256=$plan.xmlSHA256;restoredBySystem=$true;
  dnsChecks=6;result='restored-real-lab-dns';publisherSigned=$false
 }
 [byte[]]$buf=[Text.UTF8Encoding]::new($false).GetBytes(($record|ConvertTo-Json -Compress))
 $handle=[IO.File]::Open($receiptPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
 try {$handle.Write($buf,0,$buf.Length);$handle.Flush($true)}finally{$handle.Dispose()}
 Write-Host 'RECOVERED: independent SYSTEM restored the original full CI DNS motor and verified 6/6.'
 return
}
if($Mode -eq 'Verify'){
 if($bootAfter -le $bootBefore.AddSeconds(5)){throw 'NOT VERIFIED: no actual Windows restart'}
 RequireFile $receiptPath
 $receipt=Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json -ErrorAction Stop
 if($receipt.schema -ne 1 -or $receipt.kind -cne 'VOLVE_VM_INTEGRATED_FULL_DNS_ROLLBACK' -or
  $receipt.labId -cne $LabId -or $receipt.result -cne 'restored-real-lab-dns' -or
  $receipt.restoredBySystem -ne $true -or $receipt.publisherSigned -ne $false -or $receipt.dnsChecks -ne 6 -or
  $receipt.motorSHA256 -cne $plan.motorSHA256 -or $receipt.originalTaskSHA256 -cne $plan.xmlSHA256){
  throw 'NOT VERIFIED: unexpected or incomplete SYSTEM receipt'
 }
 $null=TaskExact $task $motor $oldArg $true
 $taskInfo=Get-ScheduledTaskInfo -TaskName $watch -TaskPath '\' -ErrorAction Stop
 if($taskInfo.LastTaskResult -ne 0 -or $taskInfo.LastRunTime.ToUniversalTime() -lt $bootAfter.AddSeconds(-3)){
  throw 'NOT VERIFIED: independent watchdog did not complete successfully after boot'
 }
 . (Join-Path $root 'reboot_event_chain.ps1')
 $chain=Get-VolvRealBootChain -TaskName ('\'+$watch) -BootUTC $bootAfter
 $p=EngineIdentity $motor
 . (Join-Path $root 'vm_dns_reply_contract.ps1')
 SixDNS
 . (Join-Path $root 'vm_direct_internet_probe.ps1')
 $tcp=Assert-VolvDirectInternetTCP
 if(-not $tcp.Verified -or $tcp.Transport -cne 'direct-ipv4-tcp'){throw 'NOT VERIFIED: no direct TCP Internet after rollback'}
 if((NetworkSnapshot) -cne $plan.networkJSON -or (SHA $hosts) -cne $plan.hostsSHA256){throw 'NOT VERIFIED: VM DNS adapter/hosts changed'}
 $result=[ordered]@{
  schema=1;kind='VOLVE_VM_INTEGRATED_REAL_MOTOR_ROLLBACK_PROOF';
  labId=$LabId;computer=$env:COMPUTERNAME;
  bootBeforeUtc=$plan.bootBeforeUtc;bootAfterUtc=$bootAfter.ToString('o');
  verifiedUtc=[DateTime]::UtcNow.ToString('o');watchdog=$watch;motorTask=$task;
  watchdogEventIds=$chain.EventIds;watchdogEventRecordIds=$chain.RecordIds;
  watchdogInstanceId=$chain.InstanceId;watchdogLastTaskResult=[int]$taskInfo.LastTaskResult;
  motorPid=[int]$p.ProcessId;motorSHA256=$plan.motorSHA256;catalogSHA256=$plan.catalogSHA256;
  originalTaskXMLSHA256=$plan.xmlSHA256;dnsIPv4IPv6Expected=6;dnsCorrect=6;
  directInternetTCP=$true;internetEndpoint=$tcp.Endpoint;
  signedProductionMigrationProven=$false;simulatedCandidate='cmd.exe /C exit 83';
  receiptSHA256=(SHA $receiptPath)
 }
 $dst=Join-Path $root 'integrated-rollback-proof.json'
 if(Test-Path -LiteralPath $dst){throw 'Proof already exists: no overwrite'}
 $result|ConvertTo-Json -Depth 7|Set-Content -LiteralPath $dst -Encoding UTF8 -ErrorAction Stop
 Write-Host ('PASS: real Windows VM reboot; independent SYSTEM restored REAL Full DNS motor, IPv4+IPv6 6/6 and TCP Internet. Evidence: '+$dst)
 Write-Host 'NOT a production signed 0.28.6 -> 0.28.7 migration.'
 return
}
if($Mode -eq 'Cleanup'){
 RequireFile $receiptPath
 $null=TaskExact $task $motor $oldArg $true
 $wd=TaskExact $watch $winPS $watchArgs $true
 $t=Get-ScheduledTask -TaskName $task -TaskPath '\'
 if($t.State -eq 'Running'){Stop-ScheduledTask -TaskName $task -TaskPath '\' -ErrorAction Stop}
 Unregister-ScheduledTask -TaskName $watch -TaskPath '\' -Confirm:$false -ErrorAction Stop
 Unregister-ScheduledTask -TaskName $task -TaskPath '\' -Confirm:$false -ErrorAction Stop
 if((Get-ScheduledTask -TaskName $watch -ErrorAction SilentlyContinue) -or
  (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue)){throw 'Disposable task cleanup incomplete'}
 Write-Host 'CLEAN: only two disposable integrated VM tasks removed; all protected evidence retained.'
}
