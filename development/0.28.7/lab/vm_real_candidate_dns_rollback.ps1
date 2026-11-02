# VOLVE 0.28.7 — isolated Windows VM ONLY. Integrated REAL old Full DNS motor
# + DISPOSABLE CRASHING CANDIDATE + independent SYSTEM boot recovery.
# No production task, Windows adapter, hosts, browser, registry, or firewall changes.
# THIS DOES NOT PERMIT OR INSTALL a signed 0.28.6 -> 0.28.7 product upgrade.
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][ValidateSet('Probe','Arm','Recover','Verify','Cleanup')][string]$Mode,
 [ValidatePattern('^[0-9]{14,18}$')][string]$LabId='',
 [string]$SourceCandidate=''
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
  'vm_real_candidate_dns_rollback.ps1'=$plan.recoverySHA256
  'VOLVE_CI_Failing_Candidate.exe'=$plan.candidateSHA256
  'reboot_event_chain.ps1'=$plan.eventParserSHA256
  'vm_dns_reply_contract.ps1'=$plan.dnsParserSHA256
 }
 foreach($rel in $v.Keys){
  $p=Join-Path $root $rel
  RequireFile $p
  if((SHA $p) -cne [string]$v[$rel]){throw ('Recovery protected file modified: '+$rel)}
 }
}
function Assert-CandidateStage($plan){
 RequireFile $candidateProof
 RequireFile $candidateStageProof
 $p=Get-Content -LiteralPath $candidateProof -Raw|ConvertFrom-Json -ErrorAction Stop
 $q=Get-Content -LiteralPath $candidateStageProof -Raw|ConvertFrom-Json -ErrorAction Stop
 if($p.schema -ne 1 -or $p.kind -cne 'VOLVE_CI_REAL_CANDIDATE_FAIL_DNS53' -or
   $p.dns_checks -ne 6 -or $p.simulated_exit_code -ne 83 -or
   $p.publisher_signed -ne $false -or $p.pid -le 0 -or
   $p.motor_sha256 -cne $plan.candidateSHA256 -or
   $q.schema -ne 1 -or $q.labId -cne $plan.labId -or
   $q.candidateSHA256 -cne $plan.candidateSHA256 -or
   $q.candidateProofSHA256 -cne (SHA $candidateProof) -or
   $q.lastTaskResult -ne 83 -or $q.pid -ne $p.pid){
  throw 'Untrusted candidate preboot proof'
 }
 $boot=[DateTime]::Parse([string]$plan.bootBeforeUtc).ToUniversalTime()
 $armed=[DateTime]::Parse([string]$q.armedUtc).ToUniversalTime()
 if($armed -lt $boot -or $armed -gt [DateTime]::UtcNow.AddSeconds(3)){
  throw 'CI candidate evidence timestamp inconsistent'
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
$candidateExe=Join-Path $root 'VOLVE_CI_Failing_Candidate.exe'
$candidateProof=Join-Path $root 'ci-candidate-dns53-confirmed.json'
$candidateStageProof=Join-Path $root 'ci-real-candidate-preboot.json'
$oldArg='--ci-boot-dns53 "'+$root+'" VOLVE-CI-GITHUB-HOSTED-VM-DNS53-ONLY'
$candidateArg='--ci-failing-candidate-dns53 "'+$root+'" VOLVE-CI-GITHUB-HOSTED-VM-DNS53-ONLY'
$oldXML=Join-Path $root 'original-task.xml'
$planPath=Join-Path $root 'integrated-rollback-plan.json'
$receiptPath=Join-Path $root 'integrated-rollback-receipt.json'
$recoverScript=Join-Path $root 'vm_real_candidate_dns_rollback.ps1'
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
 if([string]::IsNullOrWhiteSpace($SourceCandidate) -or
   -not [IO.Path]::IsPathRooted($SourceCandidate) -or
   [IO.Path]::GetFileName($SourceCandidate) -cne 'VOLVE_CI_Failing_Candidate.exe'){
   throw 'Arm requires separate VM-only failing candidate executable'
 }
 RequireFile $SourceCandidate
 $size=(Get-Item -LiteralPath $SourceCandidate).Length
 if($size -lt 1048576 -or $size -gt 83886080 -or (SHA $SourceCandidate) -ceq (SHA $motor)){
  throw 'Invalid or duplicate candidate binary'
 }
 $original=TaskExact $task $motor $oldArg $true
 if($original.State -eq 'Running'){throw 'Refusing to switch a running Full DNS motor'}
 foreach($ip in @('127.0.0.1','::1')){
  if(@(Get-NetUDPEndpoint -LocalAddress $ip -LocalPort 53 -ErrorAction SilentlyContinue).Count -ne 0){throw 'DNS53 occupied before simulated interruption'}
 }
 if(Get-ScheduledTask -TaskName $watch -ErrorAction SilentlyContinue){throw 'Watchdog task already exists'}
 foreach($path in @($planPath,$oldXML,$recoverScript,$receiptPath,$candidateExe,$candidateProof,$candidateStageProof)){
  if(Test-Path -LiteralPath $path){throw ('Refusing existing lab recovery asset: '+$path)}
 }
 if((NetworkSnapshot) -cne $before.networkJSON -or (SHA $hosts) -cne $before.hostsSHA256){throw 'Network/hosts changed since Full motor preflight'}
 if(-not (Get-WinEvent -ListLog 'Microsoft-Windows-TaskScheduler/Operational' -ErrorAction Stop).IsEnabled){throw 'Task history is disabled'}
 [IO.File]::WriteAllText($oldXML,(Export-ScheduledTask -TaskName $task -TaskPath '\' -ErrorAction Stop),[Text.UTF8Encoding]::new($false))
 Copy-Item -LiteralPath $PSCommandPath -Destination $recoverScript -ErrorAction Stop
 Copy-Item -LiteralPath $SourceCandidate -Destination $candidateExe -ErrorAction Stop
 if((SHA $candidateExe) -cne (SHA $SourceCandidate)){throw 'CI candidate EXE changed on copy'}
 $meta=[ordered]@{
  schema=1;kind='VOLVE_VM_REAL_CANDIDATE_DNS_ROLLBACK_PENDING';labId=$LabId;computer=$env:COMPUTERNAME;
  bootBeforeUtc=(BootUTC).ToString('o');oldTask=$task;watchdog=$watch;
  motorSHA256=(SHA $motor);catalogSHA256=(SHA $catalog);
  candidateSHA256=(SHA $candidateExe);
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
 # Install the distinct REAL Full DNS candidate with a one-time trigger
 # seven days in the future. This prevents a boot race with the independent
 # watchdog; it runs exactly once by an explicit SYSTEM Start-ScheduledTask.
 $future=New-ScheduledTaskTrigger -Once -At (Get-Date).AddDays(7)
 Set-ScheduledTask -TaskName $task -TaskPath '\' -Action (New-ScheduledTaskAction -Execute $candidateExe -Argument $candidateArg) -Trigger $future -ErrorAction Stop|Out-Null
 $ct=TaskExact $task $candidateExe $candidateArg $false
 if($ct.Triggers[0].CimClass.CimClassName -ne 'MSFT_TaskTimeTrigger'){throw 'Candidate cannot have a boot trigger'}
 $started=[DateTime]::UtcNow.AddSeconds(-2)
 Start-ScheduledTask -TaskName $task -TaskPath '\' -ErrorAction Stop
 $failed=$false
 $limit=(Get-Date).AddSeconds(65)
 while((Get-Date) -lt $limit){
  Start-Sleep -Milliseconds 400
  $ct=TaskExact $task $candidateExe $candidateArg $false
  $status=Get-ScheduledTaskInfo -TaskName $task -TaskPath '\' -ErrorAction Stop
  if($status.LastRunTime.ToUniversalTime() -gt $started -and $ct.State -ne 'Running' -and $status.LastTaskResult -eq 83){
   $failed=$true;break
  }
  if($status.LastRunTime.ToUniversalTime() -gt $started -and $ct.State -ne 'Running' -and $status.LastTaskResult -notin @(0,267009)){
   throw ('Candidate exited with unexpected result '+$status.LastTaskResult)
  }
 }
 if(-not $failed){throw 'Real candidate failed to terminate with exit 83'}
 RequireFile $candidateProof
 $p=Get-Content -LiteralPath $candidateProof -Raw|ConvertFrom-Json -ErrorAction Stop
 if($p.schema -ne 1 -or $p.kind -cne 'VOLVE_CI_REAL_CANDIDATE_FAIL_DNS53' -or
    $p.motor_sha256 -cne $plan.candidateSHA256 -or $p.dns_checks -ne 6 -or
    $p.simulated_exit_code -ne 83 -or $p.publisher_signed -ne $false -or $p.pid -le 0){
  throw 'Full DNS candidate did not prove six dual-stack answers before crashing'
 }
 foreach($ip in @('127.0.0.1','::1')){
  if(@(Get-NetUDPEndpoint -LocalAddress $ip -LocalPort 53 -ErrorAction SilentlyContinue).Count -ne 0){
   throw ('Candidate exited but UDP53 remains occupied '+$ip)
  }
 }
 if((NetworkSnapshot) -cne $plan.networkJSON -or (SHA $hosts) -cne $plan.hostsSHA256){
  throw 'Real CI candidate changed DNS adapters/hosts'
 }
 $stage=[ordered]@{schema=1;labId=$LabId;candidateSHA256=$plan.candidateSHA256;
  candidateProofSHA256=(SHA $candidateProof);lastTaskResult=83;pid=$p.pid;
  armedUtc=[DateTime]::UtcNow.ToString('o')}
 [byte[]]$buf=[Text.UTF8Encoding]::new($false).GetBytes(($stage|ConvertTo-Json -Compress))
 $fd=[IO.File]::Open($candidateStageProof,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
 try{$fd.Write($buf,0,$buf.Length);$fd.Flush($true)}finally{$fd.Dispose()}
 Write-Host 'ARMED: REAL Full CI DNS candidate ran 6/6 as SYSTEM then crashed with exit83; original motor preserved; watchdog registered.'
 Write-Host 'NEXT: manually reboot only the VM then invoke Verify.'
 return
}
RequireFile $planPath
$plan=Get-Content -LiteralPath $planPath -Raw|ConvertFrom-Json -ErrorAction Stop
if($plan.schema -ne 1 -or $plan.kind -cne 'VOLVE_VM_REAL_CANDIDATE_DNS_ROLLBACK_PENDING' -or
 $plan.status -cne 'recovery-required' -or $plan.labId -cne $LabId -or
 $plan.computer -cne $env:COMPUTERNAME -or $plan.oldTask -cne $task -or $plan.watchdog -cne $watch -or
 $plan.originalArgs -cne $oldArg -or $plan.candidateArgs -cne $candidateArg -or
 $plan.signedPublisherPermit -ne $false -or $plan.productionMotorMigration -ne $false){
 throw 'Invalid/unauthorized integrated lab plan'
}
VerifiedInputs $plan $root
Assert-CandidateStage $plan
$bootBefore=[DateTime]::Parse([string]$plan.bootBeforeUtc,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
$bootAfter=BootUTC
$null=TaskExact $watch $winPS $watchArgs $true
if($Mode -eq 'Recover'){
 if($bootAfter -le $bootBefore.AddSeconds(5)){throw 'Recovery prohibited without an authentic NEW Windows boot'}
 if(Test-Path -LiteralPath $receiptPath){return}
 $live=Get-ScheduledTask -TaskName $task -TaskPath '\' -ErrorAction Stop
 $selected=([string]$live.Actions[0].Execute -ieq $candidateExe -and [string]$live.Actions[0].Arguments -ceq $candidateArg)
 $restored=([string]$live.Actions[0].Execute -ieq $motor -and [string]$live.Actions[0].Arguments -ceq $oldArg)
 if(-not ($selected -or $restored)){throw 'Unrecognized task: refusing to restore'}
 if($selected){
  $c=TaskExact $task $candidateExe $candidateArg $false
  if($c.Triggers[0].CimClass.CimClassName -ne 'MSFT_TaskTimeTrigger'){throw 'Unsafe candidate startup trigger'}
 }
 # Even if a previous recovery was interrupted after importing the old
 # task, verify the exact original XML and its target before re-import.
 if((SHA $motor) -cne $plan.motorSHA256 -or
   (SHA $oldXML) -cne $plan.xmlSHA256){throw 'Original full motor or task snapshot changed'}
 $running=@(Get-CimInstance Win32_Process|Where-Object{[string]$_.ExecutablePath -ieq $motor})
 if($running.Count -gt 0 -and $selected){throw 'Unsafe: original motor running while candidate task is selected'}
 if($selected){
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
  schema=1;kind='VOLVE_VM_REAL_CANDIDATE_DNS_ROLLBACK';labId=$LabId;
  bootBeforeUtc=$plan.bootBeforeUtc;bootAfterUtc=$bootAfter.ToString('o');
  restoredUtc=[DateTime]::UtcNow.ToString('o');motorSHA256=$plan.motorSHA256;
  originalTaskSHA256=$plan.xmlSHA256;restoredBySystem=$true;
  dnsChecks=6;result='restored-after-real-candidate-crash';
  candidateProofSHA256=(SHA $candidateProof);publisherSigned=$false
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
 if($receipt.schema -ne 1 -or $receipt.kind -cne 'VOLVE_VM_REAL_CANDIDATE_DNS_ROLLBACK' -or
  $receipt.labId -cne $LabId -or $receipt.result -cne 'restored-after-real-candidate-crash' -or
  $receipt.restoredBySystem -ne $true -or $receipt.publisherSigned -ne $false -or $receipt.dnsChecks -ne 6 -or
  $receipt.motorSHA256 -cne $plan.motorSHA256 -or $receipt.originalTaskSHA256 -cne $plan.xmlSHA256 -or
  $receipt.candidateProofSHA256 -cne (SHA $candidateProof)){
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
  schema=1;kind='VOLVE_VM_REAL_CANDIDATE_DNS_ROLLBACK_PROOF';
  labId=$LabId;computer=$env:COMPUTERNAME;
  bootBeforeUtc=$plan.bootBeforeUtc;bootAfterUtc=$bootAfter.ToString('o');
  verifiedUtc=[DateTime]::UtcNow.ToString('o');watchdog=$watch;motorTask=$task;
  watchdogEventIds=$chain.EventIds;watchdogEventRecordIds=$chain.RecordIds;
  watchdogInstanceId=$chain.InstanceId;watchdogLastTaskResult=[int]$taskInfo.LastTaskResult;
  motorPid=[int]$p.ProcessId;motorSHA256=$plan.motorSHA256;catalogSHA256=$plan.catalogSHA256;
  originalTaskXMLSHA256=$plan.xmlSHA256;dnsIPv4IPv6Expected=6;dnsCorrect=6;
  directInternetTCP=$true;internetEndpoint=$tcp.Endpoint;
  signedProductionMigrationProven=$false;candidateMode='REAL_FULL_CI_DNS_EXIT_83';
  candidateSHA256=$plan.candidateSHA256;candidateProofSHA256=(SHA $candidateProof);
  prebootReceiptSHA256=(SHA $candidateStageProof);
  receiptSHA256=(SHA $receiptPath)
 }
 $dst=Join-Path $root 'real-candidate-rollback-proof.json'
 if(Test-Path -LiteralPath $dst){throw 'Proof already exists: no overwrite'}
 $result|ConvertTo-Json -Depth 7|Set-Content -LiteralPath $dst -Encoding UTF8 -ErrorAction Stop
 Write-Host ('PASS: real Windows VM reboot; distinct real Full CI candidate exited83, SYSTEM restored original Full DNS motor, IPv4+IPv6 6/6 and TCP Internet. Evidence: '+$dst)
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
 Write-Host 'CLEAN: two disposable real-candidate VM tasks removed; all protected evidence retained.'
}
