# Hosted CI, isolated Windows guest only. No adapter writes, no product
# task, no external network. Run exact CI-tagged production DNS code against
# the already-armed localhost assignments; stop it to induce the DNS fault.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$MotorExe,
      [Parameter(Mandatory=$true)][ValidatePattern('^[A-F0-9]{64}$')][string]$MotorSHA,
      [Parameter(Mandatory=$true)][string]$WireProbeExe,
      [Parameter(Mandatory=$true)][ValidatePattern('^[A-F0-9]{64}$')][string]$WireProbeSHA,
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
$probe='C:\VOLVE-CI-PrivateDNS\VOLVE-CI-ActualMotorProbe.test.exe'
if($WireProbeExe -ine $probe -or (Get-FileHash -LiteralPath $probe -Algorithm SHA256).Hash -cne $WireProbeSHA){throw 'Independent wire probe hash or path mismatch'}
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
& $exe --ci-prepare-full-catalog $root VOLVE-CI-GITHUB-HOSTED-VM-DNS53-ONLY | Out-Null
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
    # Use the already exercised independent raw DNS wire client, not
    # Resolve-DnsName's potentially cached per-server result, for the
    # four direct transport/address-family blocking and allow checks.
    $env:VOLVE_CI_FRESH_DNS53_PROBE='GITHUB-HOSTED-VM-ONLY'
    $proof=@(& $probe '-test.run=^TestCIFreshResidentSYSTEMPort53$' '-test.v' '-test.timeout=1m' 2>&1)
    $proofExit=$LASTEXITCODE
    if($proofExit -ne 0 -or @($proof|Where-Object {[string]$_ -match '^--- PASS: TestCIFreshResidentSYSTEMPort53 '}).Count -ne 1 -or @($proof|Where-Object {[string]$_ -match 'actually forwards an allowed A record'}).Count -ne 1){
        throw ('Independent raw wire DNS proof failed: '+($proof -join [Environment]::NewLine))
    }
    if((Get-FileHash -LiteralPath $probe -Algorithm SHA256).Hash -cne $WireProbeSHA){throw 'Wire probe changed during execution'}
    $checks=4
    # Never specify -Server here. Unique reserved names avoid cache hits
    # and demonstrate use of the configured localhost resolver.
    Write-Host 'PASS VOLVE_PRIVATE_MOTOR_RAW_WIRE_FOUR_TRANSPORTS_SYSTEM'
    # Recheck transient socket errors, never accept them as success.
    $resolverAttempts=@()
    $tcpKnownFailure=$false
    foreach($transport in @('Default','TCP')){
        $resolved=$false
        for($attempt=1;$attempt -le 3;$attempt++){
            Assert-LoopbackAssignments
            $challenge=[guid]::NewGuid().ToString('N')+'.volve-motor-ci.test.'
            $queryParams=@{Name=$challenge;Type='A';DnsOnly=$true;NoHostsFile=$true;ErrorAction='Stop'}
            if($transport -ceq 'TCP'){$queryParams.TcpOnly=$true}
            try{
                $answers=@(Resolve-DnsName @queryParams|Where-Object {$_.PSObject.Properties['IPAddress'] -and [string]$_.Type -eq 'A'})
            }catch{
                $id=[string]$_.FullyQualifiedErrorId
                $transient=$id -cmatch '^(10054|10057|10061|10060|WSAECONNRESET|WSAENOTCONN|WSAECONNREFUSED|WSAETIMEDOUT|ERROR_TIMEOUT),Microsoft\.DnsClient\.Commands\.ResolveDnsName$'
                Write-Host ('CI configured resolver: transport='+$transport+' attempt='+$attempt+' error='+$id)
                $resolverAttempts+=@([pscustomobject]@{transport=$transport;attempt=$attempt;success=$false;error_id=$id})
                if(-not $transient){throw}
                if($attempt -eq 3){
                    # Only the exact reproduced TCP failure is eligible for
                    # continued recovery evidence. It remains a failed gate.
                    $tcpFailures=@($resolverAttempts|Where-Object {$_.transport -ceq 'TCP' -and -not $_.success -and $_.error_id -cmatch '^(10057|WSAENOTCONN),Microsoft\.DnsClient\.Commands\.ResolveDnsName$'})
                    if($transport -ceq 'TCP' -and $tcpFailures.Count -eq 3){$tcpKnownFailure=$true;break}
                    throw
                }
                Start-Sleep -Seconds 5
                continue
            }
            if($answers.Count -ne 1 -or $answers[0].IPAddress -cne '203.0.113.7' -or ([string]$answers[0].Name).TrimEnd('.') -cne $challenge.TrimEnd('.')){throw 'Configured Windows resolver did not reach actual motor'}
            $resolverAttempts+=@([pscustomobject]@{transport=$transport;attempt=$attempt;success=$true;error_id=$null})
            Write-Host ('PASS VOLVE_CONFIGURED_RESOLVER_'+$transport+' attempt='+$attempt)
            $resolved=$true
            break
        }
        if(-not $resolved -and -not ($transport -ceq 'TCP' -and $tcpKnownFailure)){throw ('Configured resolver not verified: '+$transport)}
    }
    # A separate native DNS API call distinguishes a cmdlet-specific issue
    # from a Windows resolver issue. It is diagnostic, never an exemption.
    $nativeProof=@(& $probe '-test.run=^TestCIConfiguredNativeTCPDNS$' '-test.v' '-test.timeout=30s' 2>&1)
    $nativeExit=$LASTEXITCODE
    $nativeTCP=($nativeExit -eq 0 -and @($nativeProof|Where-Object {[string]$_ -match '^--- PASS: TestCIConfiguredNativeTCPDNS '}).Count -eq 1 -and @($nativeProof|Where-Object {[string]$_ -match 'PASS VOLVE_NATIVE_DNSQUERY_CONFIGURED_TCP'}).Count -eq 1)
    Write-Host ('CI NATIVE TCP DNS diagnostic: verified='+$nativeTCP+' exit='+$nativeExit)
    foreach($line in $nativeProof){Write-Host ([string]$line)}
    # Separate connection-reuse observation: both addresses, two distinct
    # challenges each on one socket. Do not retry or reconnect on EOF.
    # This is diagnostic only and cannot waive the configured-client gate.
    $reuseProof=@(& $probe '-test.run=^TestCIResidentTCPConnectionReuse$' '-test.v' '-test.timeout=30s' 2>&1)
    $reuseExit=$LASTEXITCODE
    $reuseMarkers=@($reuseProof|Where-Object {[string]$_ -match 'PASS VOLVE_TCP_REUSE_QUERY address=(127\.0\.0\.1|::1) sequence=[12]$'})
    $reuseVerified=($reuseExit -eq 0 -and $reuseMarkers.Count -eq 4 -and @($reuseProof|Where-Object {[string]$_ -match '^--- PASS: TestCIResidentTCPConnectionReuse '}).Count -eq 1)
    Write-Host ('CI TCP REUSE diagnostic: verified='+$reuseVerified+' exit='+$reuseExit+' verified_queries='+$reuseMarkers.Count)
    foreach($line in $reuseProof){Write-Host ([string]$line)}
    # Determine whether the OS's outgoing-interface selection can explain
    # the reproduced configured TCP failure, without altering DNS or routes.
    $interfaceProof=@()
    $interfaceExit=$null
    if($tcpKnownFailure){
        $loop4=@(Get-NetIPAddress -IPAddress '127.0.0.1' -AddressFamily IPv4 -ErrorAction Stop)
        $loop6=@(Get-NetIPAddress -IPAddress '::1' -AddressFamily IPv6 -ErrorAction Stop)
        if($loop4.Count -ne 1 -or $loop6.Count -ne 1){throw 'Loopback interface identity ambiguous'}
        $env:VOLVE_CI_PRIVATE_NIC_INDEX=[string]$nic[0].InterfaceIndex
        $env:VOLVE_CI_LOOPBACK_V4_INDEX=[string]$loop4[0].InterfaceIndex
        $env:VOLVE_CI_LOOPBACK_V6_INDEX=[string]$loop6[0].InterfaceIndex
        try{
            $observed=@(& $probe '-test.run=^TestCIResidentTCPInterfaceSelection$' '-test.v' '-test.timeout=40s' 2>&1)
            $interfaceExit=$LASTEXITCODE
            foreach($line in $observed){
                Write-Host ([string]$line)
                if([string]$line -match 'VOLVE_TCP_INTERFACE_OBSERVATION host='){$interfaceProof+=([string]$line).Trim()}
            }
            Write-Host ('CI TCP INTERFACE diagnostic: exit='+$interfaceExit+' observations='+$interfaceProof.Count)
        }finally{
            foreach($name in @('VOLVE_CI_PRIVATE_NIC_INDEX','VOLVE_CI_LOOPBACK_V4_INDEX','VOLVE_CI_LOOPBACK_V6_INDEX')){
                Remove-Item -LiteralPath ('Env:'+$name) -ErrorAction SilentlyContinue
            }
        }
        Assert-LoopbackAssignments
    }
    # Explicit-server probes are diagnostic ONLY. They do not establish
    # that the Windows-configured resolver chooses or reaches that server.
    # No retry, cache flush, adapter change or external network is involved.
    $explicitTCP=@()
    if($tcpKnownFailure){
        foreach($server in @('127.0.0.1','::1')){
            Assert-LoopbackAssignments
            $challenge=[guid]::NewGuid().ToString('N')+'.volve-motor-ci.test.'
            $entry=[ordered]@{server=$server;verified=$false;error_id=$null;outcome='not_verified'}
            try{
                $records=@(Resolve-DnsName -Name $challenge -Type A -Server $server -TcpOnly -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop |
                    Where-Object {$_.PSObject.Properties['IPAddress'] -and [string]$_.Type -eq 'A'})
                if($records.Count -eq 1 -and [string]$records[0].IPAddress -ceq '203.0.113.7' -and ([string]$records[0].Name).TrimEnd('.') -ceq $challenge.TrimEnd('.')){
                    $entry.verified=$true
                    $entry.outcome='expected_a_record'
                }else{$entry.outcome='unexpected_answer'}
            }catch{
                $entry.error_id=[string]$_.FullyQualifiedErrorId
                $entry.outcome='query_failed'
            }
            $explicitTCP+=@([pscustomobject]$entry)
            Write-Host ('CI EXPLICIT TCP diagnostic: '+($entry|ConvertTo-Json -Compress))
        }
    }
    Assert-LoopbackAssignments
    $again=@(Get-CimInstance Win32_Process -Filter ('ProcessId='+$pidNumber) -ErrorAction Stop)
    if($again.Count -ne 1 -or $again[0].CreationDate -ne $creation -or $again[0].ExecutablePath -ine $exe){throw 'Motor replaced during test'}
    if((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash -cne $MotorSHA -or (Get-FileHash -LiteralPath $catalog -Algorithm SHA256).Hash -cne $catalogPin){throw 'Motor/catalog changed during probe'}
    $report=[ordered]@{actual_system_motor=$true;motor_sha256=$MotorSHA;catalog_sha256=$catalogPin;independent_wire_probe_sha256=$WireProbeSHA;independent_wire_probe_verified=$true;dual_stack_transport_checks=$checks;configured_resolver_default=$true;configured_resolver_tcp=(-not $tcpKnownFailure);configured_tcp_known_failure=$tcpKnownFailure;native_tcp_diagnostic_verified=$nativeTCP;native_tcp_diagnostic_exit=$nativeExit;tcp_reuse_diagnostic_verified=$reuseVerified;tcp_reuse_diagnostic_exit=$reuseExit;tcp_reuse_verified_queries=$reuseMarkers.Count;tcp_interface_diagnostic_exit=$interfaceExit;tcp_interface_observations=$interfaceProof;explicit_tcp_diagnostic=$explicitTCP;configured_resolver_attempts=$resolverAttempts;blocked_domains_verified=$true;synthetic_upstream_only=$true}
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
