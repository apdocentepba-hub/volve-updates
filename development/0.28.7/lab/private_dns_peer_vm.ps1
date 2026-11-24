# VOLVE hosted CI only. Two disposable guests, one Hyper-V private switch.
# No public network, host NIC, NAT, recursive DNS or production installation.
# Dot-sourcing this helper must not alter the caller's StrictMode.
function Assert-VolvPrivatePeerTopology {
    param([guid]$ClientId,[guid]$PeerId,[guid]$SwitchId)
    Set-StrictMode -Version Latest
    if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted'){throw 'Hosted CI only'}
    if($ClientId -eq $PeerId -or $ClientId -eq [guid]::Empty -or $PeerId -eq [guid]::Empty){throw 'Invalid distinct guest identities'}
    $sw=Get-VMSwitch -Id $SwitchId -ErrorAction Stop
    if([string]$sw.SwitchType -cne 'Private' -or $sw.Name -cnotmatch '^VOLVE-CI-WINGUEST-[a-f0-9]{32}-PRIVATE$'){throw 'Unexpected private switch'}
    if(@(Get-VMNetworkAdapter -ManagementOS -ErrorAction Stop|Where-Object {$_.SwitchName -ceq $sw.Name}).Count -ne 0){throw 'Host attached to private switch'}
    $client=Get-VM -Id $ClientId -ErrorAction Stop
    $peer=Get-VM -Id $PeerId -ErrorAction Stop
    if($client.Name+'-PRIVATE' -cne $sw.Name -or $peer.Name -cne ($client.Name+'-PEER')){throw 'Unexpected guest names'}
    foreach($guest in @($client,$peer)){
        $nic=@($guest|Get-VMNetworkAdapter -ErrorAction Stop)
        if($nic.Count -ne 1 -or $nic[0].SwitchName -cne $sw.Name){throw 'Guest not confined to private switch'}
    }
    $attached=@(Get-VM -ErrorAction Stop|Get-VMNetworkAdapter -ErrorAction Stop|Where-Object {$_.SwitchName -ceq $sw.Name})
    if($attached.Count -ne 2 -or @($attached|Where-Object {$_.VMId -notin @($ClientId,$PeerId)}).Count -ne 0){throw 'Foreign attachment to private switch'}
    return $true
}

# The peer has its own fresh differencing disk created from the immutable
# prepared evaluation image BEFORE either guest is booted. No disk cloning
# of a running Windows installation and no second full VHD download.
function Start-VolvPrivateDNSPeer {
    param([object]$Peer,[object]$Client,[object]$Switch,[pscredential]$Credential,
          [string]$PeerExe,[string]$ExpectedSHA)
    Set-StrictMode -Version Latest
    $ErrorActionPreference='Stop'
    if(-not (Assert-VolvPrivatePeerTopology -ClientId $Client.Id -PeerId $Peer.Id -SwitchId $Switch.Id)){throw 'Private topology not verified'}
    if((Get-FileHash -LiteralPath $PeerExe -Algorithm SHA256).Hash -cne $ExpectedSHA){throw 'Peer executable changed'}
    if((Get-VM -Id $Peer.Id -ErrorAction Stop).State -ne 'Off'){throw 'Peer is not fresh and stopped'}
    Start-VM -VM $Peer -ErrorAction Stop
    $session=$null
    try{
        $until=[datetime]::UtcNow.AddMinutes(10)
        do{
            try{$session=New-PSSession -VMId $Peer.Id -Credential $Credential -ErrorAction Stop;break}
            catch{Start-Sleep -Seconds 5}
        }while([datetime]::UtcNow -lt $until)
        if($null -eq $session){throw 'Peer PowerShell Direct unavailable'}
        $root='C:\VOLVE-CI-PrivateDNSPeer'
        Invoke-Command -Session $session -ArgumentList $root -ErrorAction Stop -ScriptBlock {
            param($root)
            $ErrorActionPreference='Stop'
            $deadline=[datetime]::UtcNow.AddMinutes(6)
            do{
                $setup=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\Setup'
                $image=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State'
                $n=@(Get-NetAdapter -ErrorAction Stop)
                if($setup.SystemSetupInProgress -eq 0 -and $setup.OOBEInProgress -eq 0 -and $image.ImageState -ceq 'IMAGE_STATE_COMPLETE' -and $n.Count -eq 1 -and $n[0].Status -eq 'Up'){break}
                Start-Sleep -Seconds 5
            }while([datetime]::UtcNow -lt $deadline)
            if($setup.SystemSetupInProgress -ne 0 -or $setup.OOBEInProgress -ne 0 -or $image.ImageState -cne 'IMAGE_STATE_COMPLETE'){throw 'Peer setup incomplete'}
            $cs=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
            if(($cs.Manufacturer+' '+$cs.Model) -notmatch '(?i)virtual machine|hyper-v' -or $n.Count -ne 1 -or $n[0].Status -ne 'Up' -or $n[0].InterfaceDescription -notmatch '^Microsoft Hyper-V Network Adapter( #[0-9]+)?$'){throw 'Peer adapter identity mismatch'}
            if(@(Get-NetRoute -ErrorAction Stop|Where-Object {$_.DestinationPrefix -in @('0.0.0.0/0','::/0')}).Count -ne 0){throw 'Peer default route detected'}
            if(Test-Path -LiteralPath $root){throw 'Peer directory collision'}
            $idx=$n[0].InterfaceIndex
            Rename-NetAdapter -Name $n[0].Name -NewName 'VOLVE-CI-PRIVATE-DNS-PEER' -ErrorAction Stop
            Set-NetIPInterface -InterfaceIndex $idx -AddressFamily IPv4 -Dhcp Disabled -ErrorAction Stop
            New-NetIPAddress -InterfaceIndex $idx -IPAddress '192.0.2.53' -PrefixLength 24 -ErrorAction Stop|Out-Null
            New-NetIPAddress -InterfaceIndex $idx -IPAddress '192.0.2.54' -PrefixLength 24 -ErrorAction Stop|Out-Null
            if(@(Get-NetRoute -ErrorAction Stop|Where-Object {$_.DestinationPrefix -in @('0.0.0.0/0','::/0')}).Count -ne 0){throw 'Peer default route after setup'}
            New-Item -ItemType Directory -Path $root -ErrorAction Stop|Out-Null
            & icacls.exe $root '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'|Out-Null
            if($LASTEXITCODE -ne 0){throw 'Peer ACL setup failed'}
        }
        $dest=Join-Path $root 'VOLVE-CI-PrivateDNSPeer.exe'
        Copy-Item -LiteralPath $PeerExe -Destination $dest -ToSession $session -ErrorAction Stop
        Invoke-Command -Session $session -ArgumentList $root,$ExpectedSHA -ErrorAction Stop -ScriptBlock {
            param($root,$sha)
            $ErrorActionPreference='Stop'
            $exe=Join-Path $root 'VOLVE-CI-PrivateDNSPeer.exe'
            if((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash -cne $sha){throw 'Peer copy hash mismatch'}
            foreach($protocol in @('UDP','TCP')){
                New-NetFirewallRule -Name ('VOLVE-CI-PrivatePeer-'+$protocol) -DisplayName ('VOLVE CI private DNS '+$protocol) -Direction Inbound -Action Allow -Program $exe -Protocol $protocol -LocalPort 53 -LocalAddress @('192.0.2.53','192.0.2.54') -RemoteAddress '192.0.2.10' -InterfaceAlias 'VOLVE-CI-PRIVATE-DNS-PEER' -Profile Any -ErrorAction Stop|Out-Null
            }
            $env:GITHUB_ACTIONS='true'
            $env:RUNNER_ENVIRONMENT='github-hosted'
            $env:VOLVE_CI_PRIVATE_DNS_PEER='PRIVATE_GUEST_ONLY'
            $p=Start-Process -FilePath $exe -WorkingDirectory $root -RedirectStandardOutput (Join-Path $root 'peer.stdout') -RedirectStandardError (Join-Path $root 'peer.err') -PassThru -ErrorAction Stop
            $until=[datetime]::UtcNow.AddSeconds(30)
            $ready=$false
            $log=Join-Path $root 'peer.log'
            do{
                if($p.HasExited){throw 'Private DNS peer exited early'}
                if(Test-Path -LiteralPath $log -PathType Leaf){
                    $stream=$null;$reader=$null
                    try{
                        $stream=[IO.File]::Open($log,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
                        $reader=[IO.StreamReader]::new($stream)
                        $ready=@($reader.ReadToEnd().Split("`n")|ForEach-Object {$_.TrimEnd("`r")}|Where-Object {$_ -ceq 'VOLVE_PRIVATE_PEER_READY two_ipv4_addresses udp_tcp53 NO_FORWARDING'}).Count -eq 1
                    }catch [IO.IOException]{
                        $ready=$false
                    }finally{
                        if($null -ne $reader){$reader.Dispose()}elseif($null -ne $stream){$stream.Dispose()}
                    }
                    if($ready){break}
                }
                Start-Sleep -Seconds 1
            }while([datetime]::UtcNow -lt $until)
            $tcp=@(Get-NetTCPConnection -State Listen -LocalPort 53 -ErrorAction Stop|Where-Object {$_.OwningProcess -eq $p.Id})
            $udp=@(Get-NetUDPEndpoint -LocalPort 53 -ErrorAction Stop|Where-Object {$_.OwningProcess -eq $p.Id})
            foreach($address in @('192.0.2.53','192.0.2.54')){
                if(@($tcp|Where-Object {$_.LocalAddress -ceq $address}).Count -ne 1 -or @($udp|Where-Object {$_.LocalAddress -ceq $address}).Count -ne 1){throw 'Peer address listener mismatch'}
            }
            if($tcp.Count -ne 2 -or $udp.Count -ne 2){throw 'Unexpected additional peer DNS listeners'}
            if($p.HasExited -or -not $ready){throw 'Peer readiness not proven'}
        }
        return $session
    }catch{
        if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}
        throw
    }
}

# Independently re-attest the same continuously running peer. A stale
# readiness marker or another process on port 53 is not network evidence.
function Get-VolvPrivatePeerLiveIdentity {
    param([object]$Session,[string]$ExpectedSHA)
    if($ExpectedSHA -cnotmatch '^[A-F0-9]{64}$'){throw 'Missing exact peer executable pin'}
    Invoke-Command -Session $Session -ArgumentList $ExpectedSHA -ErrorAction Stop -ScriptBlock {
        param($sha)
        $ErrorActionPreference='Stop'
        Set-StrictMode -Version Latest
        $exe='C:\VOLVE-CI-PrivateDNSPeer\VOLVE-CI-PrivateDNSPeer.exe'
        if((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash -cne $sha){throw 'Peer executable no longer matches original hash'}
        $n=@(Get-NetAdapter -ErrorAction Stop)
        if($n.Count -ne 1 -or $n[0].Name -cne 'VOLVE-CI-PRIVATE-DNS-PEER' -or $n[0].Status -ne 'Up' -or $n[0].InterfaceDescription -notmatch '^Microsoft Hyper-V Network Adapter( #[0-9]+)?$'){throw 'Peer adapter changed'}
        if(@(Get-NetRoute -ErrorAction Stop|Where-Object {$_.DestinationPrefix -in @('0.0.0.0/0','::/0')}).Count -ne 0){throw 'Peer default route appeared'}
        $ips=@(Get-NetIPAddress -InterfaceIndex $n[0].InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop)
        if($ips.Count -ne 2 -or (($ips.IPAddress|Sort-Object) -join ',') -cne '192.0.2.53,192.0.2.54' -or @($ips|Where-Object {$_.PrefixLength -ne 24 -or $_.AddressState -ne 'Preferred'}).Count -ne 0){throw 'Peer IPv4 identity drift'}
        $p=@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.ExecutablePath -ieq $exe -or $_.Name -ieq 'VOLVE-CI-PrivateDNSPeer.exe'})
        if($p.Count -ne 1 -or $p[0].ExecutablePath -ine $exe){throw 'Peer process identity ambiguous'}
        $id=[uint32]$p[0].ProcessId
        $tcp=@(Get-NetTCPConnection -State Listen -ErrorAction Stop|Where-Object {$_.LocalPort -eq 53 -and $_.OwningProcess -eq $id})
        $udp=@(Get-NetUDPEndpoint -ErrorAction Stop|Where-Object {$_.LocalPort -eq 53 -and $_.OwningProcess -eq $id})
        if($tcp.Count -ne 2 -or $udp.Count -ne 2){throw 'Peer listener count changed'}
        foreach($ip in @('192.0.2.53','192.0.2.54')){
            if(@($tcp|Where-Object {$_.LocalAddress -ceq $ip}).Count -ne 1 -or @($udp|Where-Object {$_.LocalAddress -ceq $ip}).Count -ne 1){throw 'Peer listener identity changed'}
        }
        $again=@(Get-CimInstance Win32_Process -Filter ('ProcessId='+$id) -ErrorAction Stop)
        if($again.Count -ne 1 -or $again[0].CreationDate -ne $p[0].CreationDate -or $again[0].ExecutablePath -ine $exe){throw 'Peer process replaced during socket audit'}
        # Event 12 is a separately recorded kernel startup, not a live
        # wall-clock calculation. Hash the complete event without leaking XML.
        $bootEvent=Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='Microsoft-Windows-Kernel-General';Id=12} -MaxEvents 1 -ErrorAction Stop
        if($null -eq $bootEvent -or $bootEvent.RecordId -le 0){throw 'Peer kernel startup event unavailable'}
        $hasher=[Security.Cryptography.SHA256]::Create()
        try{$bootEventHash=([BitConverter]::ToString($hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($bootEvent.ToXml())))).Replace('-','')}
        finally{$hasher.Dispose()}
        # System uptime is independently reported in seconds. Missing counters
        # fail closed rather than attributing WMI clock drift to a safe cause.
        $perf=Get-CimInstance Win32_PerfFormattedData_PerfOS_System -ErrorAction Stop
        if($null -eq $perf.SystemUpTime -or [uint64]$perf.SystemUpTime -eq 0){throw 'Peer uptime unavailable'}
        # Cursor is independent of wall-clock time (which may move backward).
        $systemCursor='0'
        try{
            $latest=Get-WinEvent -LogName System -MaxEvents 1 -ErrorAction Stop
            if($latest.RecordId -gt 0){$systemCursor=[string]$latest.RecordId}
        }catch{}
        [pscustomobject]@{
            system_record_cursor=$systemCursor
            boot_event_record=[string]$bootEvent.RecordId
            boot_event_sha256=$bootEventHash
            uptime_seconds=[string]$perf.SystemUpTime
            process_id=$id
            created_ticks=$p[0].CreationDate.ToUniversalTime().Ticks.ToString()
            boot_ticks=(Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime.ToUniversalTime().Ticks.ToString()
            adapter_guid=$n[0].InterfaceGuid.ToString()
            executable_sha256=$sha
        }
    }
}
function Assert-VolvPrivatePeerIdentityEvidence {
    param([object]$PinnedIdentity,[object]$current)
    Set-StrictMode -Version Latest
    if($null -eq $PinnedIdentity -or $null -eq $current){throw 'Peer continuity unproven: missing evidence'}
    foreach($identity in @($PinnedIdentity,$current)){
        foreach($field in @('boot_event_record','boot_event_sha256','uptime_seconds','process_id','created_ticks','boot_ticks','adapter_guid','executable_sha256')){
            if($null -eq $identity.PSObject.Properties[$field] -or [string]::IsNullOrWhiteSpace([string]$identity.$field)){throw ('Peer continuity unproven: missing '+$field)}
        }
        foreach($field in @('boot_event_record','uptime_seconds','process_id','created_ticks','boot_ticks')){
            $parsed=[uint64]0
            if([string]$identity.$field -cnotmatch '^[1-9][0-9]*$' -or -not [uint64]::TryParse([string]$identity.$field,[ref]$parsed)){throw ('Peer continuity unproven: invalid '+$field)}
        }
        foreach($field in @('boot_event_sha256','executable_sha256')){
            if([string]$identity.$field -cnotmatch '^[A-F0-9]{64}$'){throw ('Peer continuity unproven: invalid '+$field)}
        }
        $adapter=[guid]::Empty
        if(-not [guid]::TryParse([string]$identity.adapter_guid,[ref]$adapter) -or $adapter -eq [guid]::Empty){throw 'Peer continuity unproven: invalid adapter GUID'}
    }
    # New independent evidence is mandatory, not an exemption for a WMI
    # timestamp mismatch. Retain the original exact boot_ticks gate until
    # the actual reason for drift is established in this disposable guest.
    if($null -eq $PinnedIdentity){throw 'Peer continuity unproven: missing pin'}
    foreach($field in @('boot_event_record','boot_event_sha256')){
        if([string]::IsNullOrEmpty([string]$PinnedIdentity.$field) -or [string]$current.$field -cne [string]$PinnedIdentity.$field){throw ('Peer continuity unproven: '+$field)}
    }
    if([string]$PinnedIdentity.uptime_seconds -cnotmatch '^[1-9][0-9]*$' -or [string]$current.uptime_seconds -cnotmatch '^[1-9][0-9]*$' -or [uint64]$current.uptime_seconds -lt [uint64]$PinnedIdentity.uptime_seconds){throw 'Peer continuity unproven: uptime'}
    if([string]$current.boot_ticks -cne [string]$PinnedIdentity.boot_ticks){
        Write-Host ('CI PEER BOOT CLOCK DRIFT: pinned='+$PinnedIdentity.boot_ticks+' current='+$current.boot_ticks+' kernel_event_record='+$current.boot_event_record+' kernel_event_unchanged=true uptime_before='+$PinnedIdentity.uptime_seconds+' uptime_now='+$current.uptime_seconds+'; original_gate=FAILED')
    }
    foreach($field in @('process_id','created_ticks','boot_ticks','adapter_guid','executable_sha256')){
        if($null -eq $PinnedIdentity -or [string]::IsNullOrEmpty([string]$PinnedIdentity.$field) -or [string]$current.$field -cne [string]$PinnedIdentity.$field){throw ('Peer continuity unproven: '+$field)}
    }
}
function Assert-VolvPrivatePeerSameIdentity {
    param([object]$Session,[string]$ExpectedSHA,[object]$PinnedIdentity)
    $current=Get-VolvPrivatePeerLiveIdentity -Session $Session -ExpectedSHA $ExpectedSHA
    # Diagnostic only: Microsoft documents Kernel-General event 1 for time
    # changes by W32Time and Hyper-V time synchronization. Compare event record
    # IDs, not wall-clock ranges. No clocks, services, or guest settings changed.
    if($null -ne $PinnedIdentity -and [string]$current.boot_ticks -cne [string]$PinnedIdentity.boot_ticks){
        try{
            $lo=[uint64]$PinnedIdentity.system_record_cursor
            $hi=[uint64]$current.system_record_cursor
            if($lo -eq 0 -or $hi -lt $lo){throw 'clock event cursor unavailable'}
            if($hi -gt $lo){
                $diag=Invoke-Command -Session $Session -ArgumentList $lo,$hi -ErrorAction Stop -ScriptBlock {
                    param([uint64]$lo,[uint64]$hi)
                    $ErrorActionPreference='Stop'
                    $xpath="*[System[Provider[@Name='Microsoft-Windows-Kernel-General'] and (EventID=1) and (EventRecordID > $lo) and (EventRecordID <= $hi)]]"
                    $ev=@(Get-WinEvent -LogName System -FilterXPath $xpath -MaxEvents 129 -ErrorAction Stop)
                    if($ev.Count -gt 128){throw 'clock event sample truncated'}
                    $parsed=0
                    $delta=[decimal]0
                    foreach($e in $ev){
                        $xml=[xml]$e.ToXml()
                        $fields=@($xml.Event.EventData.Data)
                        $old=@($fields|Where-Object {$_.Name -ceq 'OldTime'})
                        $new=@($fields|Where-Object {$_.Name -ceq 'NewTime'})
                        if($old.Count -ne 1 -or $new.Count -ne 1){continue}
                        try{
                            $o=[DateTimeOffset]::Parse([string]$old[0].'#text',[Globalization.CultureInfo]::InvariantCulture)
                            $n=[DateTimeOffset]::Parse([string]$new[0].'#text',[Globalization.CultureInfo]::InvariantCulture)
                            $delta+=([decimal]$n.UtcDateTime.Ticks-[decimal]$o.UtcDateTime.Ticks)
                            $parsed++
                        }catch{}
                    }
                    [pscustomobject]@{count=$ev.Count;parsed=$parsed;net_ticks=[string]$delta}
                }
                Write-Host ('CI PEER CLOCK EVENTS: count='+$diag.count+' parsed='+$diag.parsed+' net_ticks='+$diag.net_ticks+'; causal_attribution=UNPROVEN')
            }else{Write-Host 'CI PEER CLOCK EVENTS: unchanged system cursor; causal_attribution=UNPROVEN'}
        }catch{Write-Host 'CI PEER CLOCK EVENTS: unavailable or empty; causal_attribution=UNPROVEN'}
    }
    Assert-VolvPrivatePeerIdentityEvidence -PinnedIdentity $PinnedIdentity -current $current
}
function Assert-VolvPrivateDNSPeerChallenge {
    param([object]$ClientSession,[object]$PeerSession,[guid]$ClientId,[guid]$PeerId,[guid]$SwitchId,
          [string]$ProbePath,[string]$ProbeSHA,[string]$PeerSHA,[object]$PinnedPeerIdentity,[ValidateSet('Original','Fault','Restored')][string]$Phase,
          [ValidateSet('Default','TCP')][string]$Transport)
    Set-StrictMode -Version Latest
    $ErrorActionPreference='Stop'
    if(-not (Assert-VolvPrivatePeerTopology -ClientId $ClientId -PeerId $PeerId -SwitchId $SwitchId)){throw 'Private topology not verified'}
    Assert-VolvPrivatePeerSameIdentity -Session $PeerSession -ExpectedSHA $PeerSHA -PinnedIdentity $PinnedPeerIdentity
    $nonce=[guid]::NewGuid().ToString('N')
    $observation=Invoke-Command -Session $ClientSession -ArgumentList $ProbePath,$ProbeSHA,$nonce,$Phase,$Transport -ErrorAction Stop -ScriptBlock {
        param($path,$sha,$nonce,$phase,$transport)
        if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne $sha){throw 'Client probe hash mismatch'}
        $env:GITHUB_ACTIONS='true'
        $env:RUNNER_ENVIRONMENT='github-hosted'
        $env:VOLVE_CI_NESTED_GUEST_DNS='PRIVATE_GUEST_ONLY'
        & $path -Nonce $nonce -Phase $phase -Transport $transport
    }
    $wire=Invoke-Command -Session $PeerSession -ArgumentList $nonce,$Phase,$Transport -ErrorAction Stop -ScriptBlock {
        param($nonce,$phase,$transport)
        $log='C:\VOLVE-CI-PrivateDNSPeer\peer.log'
        $deadline=[datetime]::UtcNow.AddSeconds(3)
        do{
            $stream=$null;$reader=$null
            try{
                $stream=[IO.File]::Open($log,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
                $reader=[IO.StreamReader]::new($stream)
                $lines=@($reader.ReadToEnd().Split("`n")|ForEach-Object {$_.TrimEnd("`r")})
            }finally{
                if($null -ne $reader){$reader.Dispose()}elseif($null -ne $stream){$stream.Dispose()}
            }
            $received=@($lines|Where-Object {$_ -cmatch ('^VOLVE_PRIVATE_PEER_RECEIVED transport=(udp|tcp) nonce='+$nonce+'$')})
            $replies=@($lines|Where-Object {$_ -cmatch ('^VOLVE_PRIVATE_PEER_REPLY transport=(udp|tcp) nonce='+$nonce+'$')})
            $udp=@($replies|Where-Object {$_ -cmatch 'transport=udp'}).Count
            $tcp=@($replies|Where-Object {$_ -cmatch 'transport=tcp'}).Count
            if($phase -cne 'Fault' -and (($transport -ceq 'TCP' -and $tcp -gt 0) -or ($transport -ceq 'Default' -and $udp -gt 0))){break}
            Start-Sleep -Milliseconds 150
        }while([datetime]::UtcNow -lt $deadline)
        [pscustomobject]@{udp=$udp;tcp=$tcp;received=$received.Count;received_udp=@($received|Where-Object {$_ -cmatch 'transport=udp'}).Count;received_tcp=@($received|Where-Object {$_ -cmatch 'transport=tcp'}).Count}
    }
    if($observation.nonce -cne $nonce -or $observation.phase -cne $Phase -or $observation.transport -cne $Transport){throw 'Client challenge mismatch'}
    if($observation.direct_private_tcp_before_and_after -ne $true){throw 'Private peer liveness control absent'}
    if($Phase -ceq 'Fault'){
        if($observation.resolved -or $wire.received -ne 0 -or $wire.udp -ne 0 -or $wire.tcp -ne 0){throw 'Fault did not isolate configured DNS from peer'}
    }else{
        if(-not $observation.resolved){throw 'Client resolver failed'}
        if($Transport -ceq 'TCP' -and ($wire.tcp -lt 1 -or $wire.received_tcp -lt $wire.tcp)){throw 'No independently observed TCP DNS reply'}
        if($Transport -ceq 'Default' -and ($wire.udp -lt 1 -or $wire.received_udp -lt $wire.udp)){throw 'No independently observed UDP DNS reply'}
    }
    if(-not (Assert-VolvPrivatePeerTopology -ClientId $ClientId -PeerId $PeerId -SwitchId $SwitchId)){throw 'Private topology changed during probe'}
    Assert-VolvPrivatePeerSameIdentity -Session $PeerSession -ExpectedSHA $PeerSHA -PinnedIdentity $PinnedPeerIdentity
    [pscustomobject]@{peer_continuity_verified=$true;phase=$Phase;transport=$Transport;nonce=$nonce;resolved=$observation.resolved;resolution_error=$observation.resolution_error;peer_udp=$wire.udp;peer_tcp=$wire.tcp;peer_received=$wire.received;direct_private_tcp_before_and_after=$true;private_network_only=$true}
}
