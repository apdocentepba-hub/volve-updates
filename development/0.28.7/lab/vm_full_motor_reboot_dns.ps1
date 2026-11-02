# VOLVE 0.28.7 -- REAL full-motor reboot rehearsal; ONLY an isolated disposable Windows VM.
# No automatic reboot, production task, DNS adapter or hosts modifications.
# Requires a developer-built, UNSIGNED and CI-tagged VOLVE_CI_FreshDNS53.exe.
# This is NOT an installer or a production watchdog/publisher authorization.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Probe','Prepare','Verify','Cleanup')][string]$Mode,
    [ValidatePattern('^[0-9]{6,20}$')][string]$LabId,
    [string]$MotorExe=''
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'

function Assert-VM {
    $cs=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    $hardware=($cs.Manufacturer+' '+$cs.Model)
    if($hardware -notmatch '(?i:virtual machine|vmware|hyper-v|virtualbox|kvm|qemu|parallels|xen)'){
        throw 'REFUSED: not a positively identified disposable VM'
    }
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=[Security.Principal.WindowsPrincipal]::new($identity)
    if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
        throw 'REFUSED: elevated Windows administrator is required in the disposable VM'
    }
}
function Digest([string]$p){
    $stream=[IO.File]::Open($p,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try{
        $hash=[Security.Cryptography.SHA256]::Create()
        try{return ([BitConverter]::ToString($hash.ComputeHash($stream))).Replace('-','').ToLowerInvariant()}
        finally{$hash.Dispose()}
    }finally{$stream.Dispose()}
}
function BootUTC {
    return ([datetime](Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime).ToUniversalTime()
}
function Assert-Regular([string]$p){
    $item=Get-Item -LiteralPath $p -ErrorAction Stop
    if($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)){
        throw ('Linked/nonregular VM asset rejected: '+$p)
    }
}
function Assert-Task([string]$name,[string]$exe,[string]$arg){
    $t=Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction Stop
    if($t.TaskPath -ne '\' -or $t.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or
       @($t.Actions).Count -ne 1 -or @($t.Triggers).Count -ne 1 -or
       $t.Triggers[0].CimClass.CimClassName -ne 'MSFT_TaskBootTrigger' -or
       [string]$t.Actions[0].Execute -ine $exe -or
       [string]$t.Actions[0].Arguments -cne $arg){
        throw 'Refused: disposable SYSTEM task definition changed'
    }
    return $t
}
function CurrentNetwork {
    return (@(Get-DnsClientServerAddress -ErrorAction Stop |
        Sort-Object InterfaceIndex,AddressFamily |
        Select-Object InterfaceIndex,AddressFamily,ServerAddresses) |
        ConvertTo-Json -Depth 6 -Compress)
}
function OwnDNSProcess([string]$exe){
    $processes=@(Get-CimInstance Win32_Process -ErrorAction Stop |
        Where-Object { [string]$_.ExecutablePath -ieq $exe })
    if($processes.Count -ne 1){throw 'Expected exactly one CI motor process'}
    $p=$processes[0]
    $owner=Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid -ErrorAction Stop
    if($owner.ReturnValue -ne 0 -or $owner.Sid -ne 'S-1-5-18'){
        throw 'VM DNS motor is not running as LocalSystem'
    }
    foreach($hostIP in @('127.0.0.1','::1')){
        $endpoints=@(Get-NetUDPEndpoint -LocalAddress $hostIP -LocalPort 53 -ErrorAction Stop)
        if($endpoints.Count -ne 1 -or $endpoints[0].OwningProcess -ne $p.ProcessId){
            throw ('DNS/53 is not exclusively owned by CI SYSTEM motor on '+$hostIP)
        }
    }
    return $p
}
function DNSRCode([string]$ip,[string]$domain){
    # A real UDP DNS query, using .NET only, without asking Windows to change resolvers.
    $family=[Net.Sockets.AddressFamily]::InterNetwork
    if($ip -eq '::1'){$family=[Net.Sockets.AddressFamily]::InterNetworkV6}
    $socket=[Net.Sockets.UdpClient]::new($family)
    try{
        $socket.Client.ReceiveTimeout=2400
        $socket.Connect([Net.IPAddress]::Parse($ip),53)
        $id=Get-Random -Minimum 1024 -Maximum 65000
        $message=[Collections.Generic.List[byte]]::new()
        foreach($b in @([byte](($id -shr 8) -band 255),[byte]($id -band 255),
           [byte]1,[byte]0,[byte]0,[byte]1,[byte]0,[byte]0,[byte]0,[byte]0,[byte]0,[byte]0)){
            $message.Add($b)
        }
        foreach($part in $domain.Split('.')){
            $bytes=[Text.Encoding]::ASCII.GetBytes($part)
            if($bytes.Length -lt 1 -or $bytes.Length -gt 63){throw 'Invalid DNS label'}
            $message.Add([byte]$bytes.Length)
            foreach($b in $bytes){$message.Add([byte]$b)}
        }
        foreach($b in @([byte]0,[byte]0,[byte]1,[byte]0,[byte]1)){$message.Add($b)}
        [byte[]]$packet=$message.ToArray()
        $null=$socket.Send($packet,$packet.Length)
        $any=[Net.IPAddress]::Any
        if($ip -eq '::1'){$any=[Net.IPAddress]::IPv6Any}
        $remote=[Net.IPEndPoint]::new($any,0)
        [byte[]]$reply=$socket.Receive([ref]$remote)
        if($reply.Length -lt 12 -or $reply[0] -ne $packet[0] -or
           $reply[1] -ne $packet[1] -or ($reply[2] -band 128) -eq 0){
            throw 'Invalid DNS response ID/flags'
        }
        return [int]($reply[3] -band 15)
    }finally{$socket.Dispose()}
}
function Assert-RealDNS {
    foreach($ip in @('127.0.0.1','::1')){
        foreach($item in @(
            @{name='stake.com';rcode=3},
            @{name='betwarrior.bet.ar';rcode=3},
            @{name='example.org';rcode=0}
        )){
            $answer=DNSRCode $ip $item.name
            if($answer -ne $item.rcode){
                throw ('Wrong real VOLVE DNS response: '+$ip+' '+$item.name+' RCODE='+$answer)
            }
        }
    }
}
function Assert-KitACL([string]$dir){
    $acl=Get-Acl -LiteralPath $dir -ErrorAction Stop
    if(-not $acl.AreAccessRulesProtected){throw 'VM lab DACL inherits permissions'}
    $allowed=@('S-1-5-18','S-1-5-32-544')
    $owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if($owner -notin $allowed){throw 'Untrusted VM lab folder owner'}
    $seen=@{}
    foreach($ace in @($acl.Access)){
        $sid=$ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if($sid -notin $allowed -or
           $ace.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow){
            throw ('Foreign or deny ACE in lab folder: '+$sid)
        }
        $seen[$sid]=$true
    }
    foreach($sid in $allowed){
        if(-not $seen.ContainsKey($sid)){throw ('Missing trustee in VM lab folder: '+$sid)}
    }
}

Assert-VM
if($Mode -eq 'Probe'){
    Write-Host 'PASS: disposable VM, administrator. No tasks or DNS changed.'
    return
}
if([string]::IsNullOrWhiteSpace($LabId)){throw '-LabId is mandatory'}
$root=Join-Path $env:ProgramData ('VOLVE-CI-FreshDNS53-'+$LabId)
$exe=Join-Path $root 'VOLVE_CI_FreshDNS53.exe'
$task='VOLVE-CI-FreshMotor-'+$LabId
$arg='--ci-boot-dns53 "'+$root+'" VOLVE-CI-GITHUB-HOSTED-VM-DNS53-ONLY'
$state=Join-Path $root 'boot-dns-before.json'
$proof=Join-Path $root 'boot-dns-after.json'
$catalog=Join-Path $root 'catalog\feeds\hagezi_gambling_full.txt'
$helper=Join-Path $root 'live_dns_boot_event_chain.ps1'
$eventParser=Join-Path $root 'reboot_event_chain.ps1'
$internetHelper=Join-Path $root 'vm_direct_internet_probe.ps1'

if($Mode -eq 'Prepare'){
    if([string]::IsNullOrWhiteSpace($MotorExe) -or
       -not [IO.Path]::IsPathRooted($MotorExe) -or
       [IO.Path]::GetFileName($MotorExe) -cne 'VOLVE_CI_FreshDNS53.exe'){
        throw 'Provide the explicitly built CI-tagged Windows VOLVE_CI_FreshDNS53.exe'
    }
    Assert-Regular $MotorExe
    $bytes=(Get-Item -LiteralPath $MotorExe).Length
    if($bytes -lt 1048576 -or $bytes -gt 83886080){throw 'Unexpected VM binary size'}
    foreach($p in @($root)){
        if(Test-Path -LiteralPath $p){throw 'Refusing an existing VM trial'}
    }
    if(Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue){throw 'Disposable task collision'}
    if(Get-ScheduledTask -TaskName 'VOLVE-DNS-SERVER-0270' -ErrorAction SilentlyContinue){
        throw 'REFUSED: a production VOLVE task exists on this VM'
    }
    $eventLog=Get-WinEvent -ListLog 'Microsoft-Windows-TaskScheduler/Operational' -ErrorAction Stop
    if(-not $eventLog.IsEnabled){throw 'Enable Task Scheduler Operational history on this disposable VM first'}
    foreach($ip in @('127.0.0.1','::1')){
        if(@(Get-NetUDPEndpoint -LocalAddress $ip -LocalPort 53 -ErrorAction SilentlyContinue).Count -ne 0){
            throw ('DNS/53 occupied before VM trial on '+$ip)
        }
    }
    $beforeNetwork=CurrentNetwork
    $hosts=Join-Path $env:WINDIR 'System32\drivers\etc\hosts'
    $beforeHosts=Digest $hosts
    $boot=(BootUTC).ToString('o')
    New-Item -ItemType Directory -Path $root -ErrorAction Stop|Out-Null
    & icacls.exe $root '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if($LASTEXITCODE -ne 0){throw 'Cannot restrict VM root DACL'}
    & icacls.exe $root '/setowner' '*S-1-5-32-544'|Out-Null
    if($LASTEXITCODE -ne 0){throw 'Cannot set VM root owner'}
    Assert-KitACL $root
    Copy-Item -LiteralPath $MotorExe -Destination $exe -ErrorAction Stop
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'live_dns_boot_event_chain.ps1') -Destination $helper -ErrorAction Stop
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'reboot_event_chain.ps1') -Destination $eventParser -ErrorAction Stop
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'vm_direct_internet_probe.ps1') -Destination $internetHelper -ErrorAction Stop
    # The protected kit folder already exists; an ordinary DNS start refuses
    # to guess or generate a missing feed. Bootstrap it explicitly, while
    # still unprivileged with respect to DNS/53 or Task Scheduler.
    & $exe --ci-prepare-full-catalog $root VOLVE-CI-GITHUB-HOSTED-VM-DNS53-ONLY
    if($LASTEXITCODE -ne 0){throw 'The CI-tagged motor refused deterministic Full catalog bootstrap'}
    Assert-Regular $catalog
    $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 35) -AllowStartIfOnBatteries
    $action=New-ScheduledTaskAction -Execute $exe -Argument $arg
    $trigger=New-ScheduledTaskTrigger -AtStartup
    Register-ScheduledTask -TaskName $task -TaskPath '\' -Action $action -Trigger $trigger -Settings $settings -User SYSTEM -RunLevel Highest -ErrorAction Stop | Out-Null
    $null=Assert-Task $task $exe $arg
    Start-ScheduledTask -TaskName $task -ErrorAction Stop
    try{
        $ok=$false
        $lastFailure='No DNS probe attempted'
        for($i=0;$i -lt 45;$i++){
            Start-Sleep -Milliseconds 800
            try{
                $null=OwnDNSProcess $exe
                Assert-RealDNS
                $ok=$true
                break
            }catch{
                $lastFailure=$_.Exception.Message
            }
        }
        if(-not $ok){
            $taskState=Get-ScheduledTask -TaskName $task -ErrorAction Stop
            $taskInfo=Get-ScheduledTaskInfo -TaskName $task -ErrorAction Stop
            throw ('VM actual VOLVE dual-stack DNS not ready; task state '+
                $taskState.State+' result '+$taskInfo.LastTaskResult+
                '; last local DNS failure: '+$lastFailure)
        }
        Assert-Regular $catalog
        $count=0
        foreach($line in [IO.File]::ReadLines($catalog)){$count++}
        if($count -ne 400005){throw ('Full laboratory catalog count invalid: '+$count)}
        $record=[ordered]@{
            schema=1;labId=$LabId;computer=$env:COMPUTERNAME;
            bootBeforeUtc=$boot;motorTask=$task;
            motorSHA256=(Digest $exe);catalogSHA256=(Digest $catalog);
            helperSHA256=(Digest $helper);parserSHA256=(Digest $eventParser);
            internetHelperSHA256=(Digest $internetHelper);
            networkJSON=$beforeNetwork;hostsSHA256=$beforeHosts;
            rules=$count;mode='VM_ONLY_CI_UNSIGNED_NO_PRODUCTION';
        }
        $record|ConvertTo-Json -Depth 6|Set-Content -LiteralPath $state -Encoding UTF8
    }finally{
        # No test DNS process may continue BEFORE the actual VM reboot.
        $t=Get-ScheduledTask -TaskName $task -ErrorAction Stop
        if($t.State -eq 'Running'){Stop-ScheduledTask -TaskName $task -ErrorAction Stop}
    }
    if((CurrentNetwork) -cne $beforeNetwork -or (Digest $hosts) -cne $beforeHosts){
        throw 'Host DNS configuration changed during VM preflight'
    }
    Write-Host ('PREPARED: isolated full-motor DNS trial '+$LabId+'; 400005 catalog lines; protected evidence.')
    Write-Host 'NEXT: reboot ONLY this disposable VM manually. Verify within 30 minutes of its boot.'
    return
}

if(-not (Test-Path -LiteralPath $root -PathType Container)){throw 'No matching persistent VM kit'}
Assert-KitACL $root
if(-not (Test-Path -LiteralPath $state -PathType Leaf)){throw 'No protected pre-boot evidence'}
$before=Get-Content -LiteralPath $state -Raw|ConvertFrom-Json
if($before.schema -ne 1 -or $before.labId -cne $LabId -or
   $before.computer -cne $env:COMPUTERNAME -or $before.motorTask -cne $task -or
   $before.rules -ne 400005 -or $before.mode -cne 'VM_ONLY_CI_UNSIGNED_NO_PRODUCTION'){
    throw 'VM boot trial identity is inconsistent'
}
foreach($p in @($exe,$catalog,$helper,$eventParser,$internetHelper)){Assert-Regular $p}
if((Digest $exe) -cne $before.motorSHA256 -or
   (Digest $catalog) -cne $before.catalogSHA256 -or
   (Digest $helper) -cne $before.helperSHA256 -or
   (Digest $eventParser) -cne $before.parserSHA256 -or
   (Digest $internetHelper) -cne $before.internetHelperSHA256){
    throw 'VM boot trial files changed after the pre-boot snapshot'
}
$null=Assert-Task $task $exe $arg
if($Mode -eq 'Verify'){
    if(Test-Path -LiteralPath $proof){throw 'Proof already exists; will not overwrite'}
    $previous=[DateTime]::Parse([string]$before.bootBeforeUtc,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
    $current=BootUTC
    if($current -le $previous.AddSeconds(5)){throw 'NOT VERIFIED: Windows did not reboot'}
    if([DateTime]::UtcNow -gt $current.AddMinutes(30)){throw 'NOT VERIFIED: boot test engine observation window expired'}
    . $eventParser
    . $helper
    . $internetHelper
    $log='Microsoft-Windows-TaskScheduler/Operational'
    $logStatus=Get-WinEvent -ListLog $log -ErrorAction Stop
    if(-not $logStatus.IsEnabled){throw 'Task Scheduler event history disabled'}
    $events=@(Get-WinEvent -FilterHashtable @{
        LogName=$log;Id=@(118,100,200,201,102);
        StartTime=$current.AddSeconds(-3)
    } -ErrorAction SilentlyContinue | ForEach-Object {ConvertTo-VolvSchedulerEvent $_})
    $chain=Assert-VolvLiveDNSBootChain -Events $events -TaskName ('\'+$task) -BootUTC $current
    $t=Get-ScheduledTask -TaskName $task -ErrorAction Stop
    if($t.State -ne 'Running'){throw 'Full motor SYSTEM task is not running after reboot'}
    $process=OwnDNSProcess $exe
    Assert-RealDNS
    $internet=Assert-VolvDirectInternetTCP
    if(-not $internet.Verified -or $internet.Transport -cne 'direct-ipv4-tcp'){
        throw 'NOT VERIFIED: direct TCP Internet probe failed after reboot'
    }
    $hosts=Join-Path $env:WINDIR 'System32\drivers\etc\hosts'
    if((CurrentNetwork) -cne $before.networkJSON -or (Digest $hosts) -cne $before.hostsSHA256){
        throw 'Windows DNS adapters/hosts differ from the pre-boot snapshot'
    }
    $result=[ordered]@{
        schema=1;kind='VOLVE_LAB_REAL_FULL_MOTOR_BOOT_DNS53';labId=$LabId;
        computer=$env:COMPUTERNAME;bootBeforeUtc=$before.bootBeforeUtc;
        bootAfterUtc=$current.ToString('o');verifiedUTC=[DateTime]::UtcNow.ToString('o');
        motorTask=$task;motorSHA256=$before.motorSHA256;catalogSHA256=$before.catalogSHA256;
        catalogRules=400005;systemPID=[int]$process.ProcessId;
        schedulerInstance=$chain.InstanceId;schedulerEvents=$chain.EventIds;
        schedulerRecordIds=$chain.RecordIds;dnsTransport=@('127.0.0.1:53','[::1]:53');
        blocked=@('stake.com','betwarrior.bet.ar');allowed=@('example.org');
        directInternetTCPVerified=$true;directInternetTCPEndpoint=$internet.Endpoint;
        productionMigrationProven=$false;editorSignedPermitProven=$false;
    }
    $result|ConvertTo-Json -Depth 6|Set-Content -LiteralPath $proof -Encoding UTF8
    Write-Host ('PASS: REAL VM reboot, same SYSTEM startup instance and full VOLVE dual-stack DNS53. Evidence: '+$proof)
    Write-Host 'This is NOT the product updater/rollback or publisher signing gate.'
    return
}
if($Mode -eq 'Cleanup'){
    # Remove only the one exact disposable task. Preserve evidence for audit.
    $t=Assert-Task $task $exe $arg
    if($t.State -eq 'Running'){Stop-ScheduledTask -TaskName $task -ErrorAction Stop}
    Unregister-ScheduledTask -TaskName $task -TaskPath '\' -Confirm:$false -ErrorAction Stop
    if(Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue){
        throw 'Disposable task cleanup not verified'
    }
    Write-Host 'CLEAN: only CI motor task removed; trial files and evidence retained.'
}
