# Hosted CI, isolated Windows guest only. No adapter writes, no product
# task, no external network. Run exact CI-tagged production DNS code against
# the already-armed localhost assignments; stop it to induce the DNS fault.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$MotorExe,
      [Parameter(Mandatory=$true)][ValidatePattern('^[A-F0-9]{64}$')][string]$MotorSHA,
      [Parameter(Mandatory=$true)][ValidatePattern('^[0-9]{6,20}$')][string]$Trial)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:VOLVE_CI_NESTED_GUEST_DNS -cne 'PRIVATE_GUEST_ONLY'){throw 'Isolated hosted CI only'}
$cs=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
if(($cs.Manufacturer+' '+$cs.Model) -notmatch '(?i)virtual machine|hyper-v'){throw 'Not a verified Hyper-V guest'}
$nic=@(Get-NetAdapter -ErrorAction Stop)
if($nic.Count -ne 1 -or $nic[0].Name -cne 'VOLVE-CI-PRIVATE-DNS' -or $nic[0].Status -ne 'Up'){throw 'Unexpected private NIC'}
if(@(Get-NetRoute -ErrorAction Stop|Where-Object {$_.DestinationPrefix -in @('0.0.0.0/0','::/0')}).Count -ne 0){throw 'Default route detected'}
if(Get-ScheduledTask -TaskName 'VOLVE-DNS-SERVER-0270' -ErrorAction SilentlyContinue){throw 'Product motor present'}
$root='C:\VOLVE-CI-FreshDNS53-'+$Trial
$task='VOLVE-CI-IntegratedMotor-'+$Trial
$exe='C:\VOLVE-CI-PrivateDNS\VOLVE-CI-ActualMotor.exe'
if($MotorExe -ine $exe -or (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash -cne $MotorSHA){throw 'Motor path or executable hash mismatch'}
if((Test-Path -LiteralPath $root) -or (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue)){throw 'Fresh fixture collision'}
function Assert-LoopbackAssignments {
    $v4=@(Get-DnsClientServerAddress -InterfaceIndex $nic[0].InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop)
    $v6=@(Get-DnsClientServerAddress -InterfaceIndex $nic[0].InterfaceIndex -AddressFamily IPv6 -ErrorAction Stop)
    if($v4.Count -ne 1 -or $v6.Count -ne 1 -or ($v4[0].ServerAddresses -join ',') -cne '127.0.0.1' -or ($v6[0].ServerAddresses -join ',') -cne '::1'){throw 'Armed loopback assignments not exact'}
}
function Assert-FreeDNS53 {
    if(@(Get-NetUDPEndpoint -ErrorAction Stop|Where-Object {$_.LocalPort -eq 53}).Count -ne 0 -or @(Get-NetTCPConnection -State Listen -ErrorAction Stop|Where-Object {$_.LocalPort -eq 53}).Count -ne 0){throw 'Unexpected DNS53 listener'}
}
Assert-LoopbackAssignments
Assert-FreeDNS53
New-Item -ItemType Directory -Path $root -ErrorAction Stop|Out-Null
& icacls.exe $root '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'|Out-Null
if($LASTEXITCODE -ne 0){throw 'Cannot seal motor fixture'}
& $exe --ci-prepare-full-catalog $root VOLVE-CI-GITHUB-HOSTED-VM-DNS53-ONLY
if($LASTEXITCODE -ne 0){throw 'Actual motor catalog preparation failed'}
$catalog=Join-Path $root 'catalog\feeds\hagezi_gambling_full.txt'
$catalogPin=(Get-FileHash -LiteralPath $catalog -Algorithm SHA256).Hash
$argument='--ci-boot-dns53 "'+$root+'" VOLVE-CI-GITHUB-HOSTED-VM-DNS53-ONLY'
$action=New-ScheduledTaskAction -Execute $exe -Argument $argument -WorkingDirectory $root
$principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 31) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
$owned=$false
$report=$null
try{
    Register-ScheduledTask -TaskName $task -TaskPath '\' -Action $action -Principal $principal -Settings $settings -ErrorAction Stop|Out-Null
    $owned=$true
    $registered=Get-ScheduledTask -TaskName $task -TaskPath '\' -ErrorAction Stop
    if($registered.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or @($registered.Actions).Count -ne 1 -or [string]$registered.Actions[0].Execute -ine $exe -or [string]$registered.Actions[0].Arguments -cne $argument){throw 'Unexpected registered motor task'}
    Start-ScheduledTask -TaskName $task -TaskPath '\' -ErrorAction Stop
    $deadline=[datetime]::UtcNow.AddSeconds(90)
    $ready=$false
    do{
        $p=@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.ExecutablePath -ieq $exe})
        if($p.Count -eq 1){
            $pidNumber=[uint32]$p[0].ProcessId
            $udp=@(Get-NetUDPEndpoint -ErrorAction Stop|Where-Object {$_.LocalPort -eq 53})
            $tcp=@(Get-NetTCPConnection -State Listen -ErrorAction Stop|Where-Object {$_.LocalPort -eq 53})
            $ready=($udp.Count -eq 2 -and $tcp.Count -eq 2 -and @($udp+$tcp|Where-Object {$_.OwningProcess -ne $pidNumber}).Count -eq 0 -and @($udp|Where-Object {$_.LocalAddress -ceq '127.0.0.1'}).Count -eq 1 -and @($udp|Where-Object {$_.LocalAddress -ceq '::1'}).Count -eq 1 -and @($tcp|Where-Object {$_.LocalAddress -ceq '127.0.0.1'}).Count -eq 1 -and @($tcp|Where-Object {$_.LocalAddress -ceq '::1'}).Count -eq 1)
            if($ready){break}
        }
        Start-Sleep -Seconds 1
    }while([datetime]::UtcNow -lt $deadline)
    if(-not $ready){throw 'Real motor did not own four loopback sockets'}
    $owner=Invoke-CimMethod -InputObject $p[0] -MethodName GetOwnerSid -ErrorAction Stop
    if($owner.ReturnValue -ne 0 -or $owner.Sid -cne 'S-1-5-18'){throw 'Motor not actually LocalSystem'}
    $creation=$p[0].CreationDate
    $checks=0
    foreach($address in @('127.0.0.1','::1')){
        foreach($transport in @('Default','TCP')){
            $args=@{Server=$address;Name='example.org.';Type='A';DnsOnly=$true;NoHostsFile=$true;QuickTimeout=$true;ErrorAction='Stop'}
            if($transport -ceq 'TCP'){$args.TcpOnly=$true}
            $answers=@(Resolve-DnsName @args|Where-Object {$_.PSObject.Properties['IPAddress'] -and [string]$_.Type -eq 'A'})
            if($answers.Count -ne 1 -or $answers[0].IPAddress -cne '203.0.113.7'){throw 'Actual motor failed allowed domain'}
            foreach($blocked in @('stake.com.','betwarrior.bet.ar.')){
                $args.Name=$blocked
                $denied=$false
                try{$null=Resolve-DnsName @args}catch{
                    if([string]$_.FullyQualifiedErrorId -cmatch '^DNS_ERROR_RCODE_NAME_ERROR(,|$)'){$denied=$true}else{throw}
                }
                if(-not $denied){throw 'Real motor failed to reject blocked domain with NXDOMAIN'}
            }
            $checks++
        }
    }
    # Never specify -Server here. Unique reserved names avoid cache hits
    # and demonstrate use of the configured localhost resolver.
    foreach($transport in @('Default','TCP')){
        $challenge=[guid]::NewGuid().ToString('N')+'.volve-motor-ci.test.'
        $args=@{Name=$challenge;Type='A';DnsOnly=$true;NoHostsFile=$true;QuickTimeout=$true;ErrorAction='Stop'}
        if($transport -ceq 'TCP'){$args.TcpOnly=$true}
        $answers=@(Resolve-DnsName @args|Where-Object {$_.PSObject.Properties['IPAddress'] -and [string]$_.Type -eq 'A'})
        if($answers.Count -ne 1 -or $answers[0].IPAddress -cne '203.0.113.7' -or ([string]$answers[0].Name).TrimEnd('.') -cne $challenge.TrimEnd('.')){throw 'Configured Windows resolver did not reach actual motor'}
    }
    Assert-LoopbackAssignments
    $again=@(Get-CimInstance Win32_Process -Filter ('ProcessId='+$pidNumber) -ErrorAction Stop)
    if($again.Count -ne 1 -or $again[0].CreationDate -ne $creation -or $again[0].ExecutablePath -ine $exe){throw 'Motor replaced during test'}
    if((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash -cne $MotorSHA -or (Get-FileHash -LiteralPath $catalog -Algorithm SHA256).Hash -cne $catalogPin){throw 'Motor/catalog changed during probe'}
    $report=[ordered]@{actual_system_motor=$true;motor_sha256=$MotorSHA;catalog_sha256=$catalogPin;dual_stack_transport_checks=$checks;configured_resolver_default=$true;configured_resolver_tcp=$true;blocked_domains_verified=$true;synthetic_upstream_only=$true}
}finally{
    if($owned){
        $registered=Get-ScheduledTask -TaskName $task -TaskPath '\' -ErrorAction Stop
        if($registered.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or @($registered.Actions).Count -ne 1 -or [string]$registered.Actions[0].Execute -ine $exe -or [string]$registered.Actions[0].Arguments -cne $argument){throw 'Refuse cleanup of unexpected task identity'}
        Stop-ScheduledTask -TaskName $task -TaskPath '\' -ErrorAction Stop
        $deadline=[datetime]::UtcNow.AddSeconds(30)
        do{
            $left=@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.ExecutablePath -ieq $exe})
            if($left.Count -eq 0){break}
            Start-Sleep -Seconds 1
        }while([datetime]::UtcNow -lt $deadline)
        if($left.Count -ne 0){throw 'Actual motor did not stop'}
        Unregister-ScheduledTask -TaskName $task -TaskPath '\' -Confirm:$false -ErrorAction Stop
        Assert-FreeDNS53
        Assert-LoopbackAssignments
    }
}
if($null -eq $report){throw 'Actual motor verification incomplete'}
$report.motor_stopped=$true
[pscustomobject]$report
