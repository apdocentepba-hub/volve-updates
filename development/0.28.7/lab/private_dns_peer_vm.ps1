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

function Assert-VolvPrivateDNSPeerChallenge {
    param([object]$ClientSession,[object]$PeerSession,[guid]$ClientId,[guid]$PeerId,[guid]$SwitchId,
          [string]$ProbePath,[string]$ProbeSHA,[ValidateSet('Original','Fault','Restored')][string]$Phase,
          [ValidateSet('Default','TCP')][string]$Transport)
    Set-StrictMode -Version Latest
    $ErrorActionPreference='Stop'
    if(-not (Assert-VolvPrivatePeerTopology -ClientId $ClientId -PeerId $PeerId -SwitchId $SwitchId)){throw 'Private topology not verified'}
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
    [pscustomobject]@{phase=$Phase;transport=$Transport;nonce=$nonce;resolved=$observation.resolved;peer_udp=$wire.udp;peer_tcp=$wire.tcp;peer_received=$wire.received;direct_private_tcp_before_and_after=$true;private_network_only=$true}
}
