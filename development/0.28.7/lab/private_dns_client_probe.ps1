# VOLVE CI only: observe the actual Windows-configured resolver on the
# private guest. No adapter, cache, HOSTS, firewall, or task writes.
# Caller MUST independently pin the private Hyper-V switch and challenge
# nonce, then corroborate success/failure with the peer's wire-reply log.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{32}$')][string]$Nonce,
    [Parameter(Mandatory=$true)][ValidateSet('Original','Fault','Restored')][string]$Phase,
    [Parameter(Mandatory=$true)][ValidateSet('Default','TCP')][string]$Transport
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or
   $env:VOLVE_CI_NESTED_GUEST_DNS -cne 'PRIVATE_GUEST_ONLY'){throw 'Private guest CI only'}
$cs=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
if(($cs.Manufacturer+' '+$cs.Model) -notmatch '(?i)virtual machine|hyper-v'){throw 'Not a Hyper-V guest'}
$n=@(Get-NetAdapter -ErrorAction Stop)
if($n.Count -ne 1 -or $n[0].Name -cne 'VOLVE-CI-PRIVATE-DNS' -or $n[0].Status -ne 'Up' -or
    $n[0].InterfaceDescription -notmatch '^Microsoft Hyper-V Network Adapter( #[0-9]+)?$'){throw 'Unexpected private NIC'}
if(@(Get-NetRoute -ErrorAction Stop|Where-Object {$_.DestinationPrefix -in @('0.0.0.0/0','::/0')}).Count -ne 0){throw 'Default route present'}
if(Get-ScheduledTask -TaskName 'VOLVE-DNS-SERVER-0270' -ErrorAction SilentlyContinue){throw 'Installed motor present'}
$idx=[uint32]$n[0].InterfaceIndex
$ips=@(Get-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction Stop)
if($ips.Count -ne 1 -or $ips[0].IPAddress -cne '192.0.2.10' -or $ips[0].PrefixLength -ne 24){throw 'Private client IP mismatch'}
$dns=@(Get-DnsClientServerAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction Stop)
if($dns.Count -ne 1){throw 'Ambiguous IPv4 DNS client inventory'}
$expected=if($Phase -ceq 'Fault'){'127.0.0.1'}else{'192.0.2.53,192.0.2.54'}
if(($dns[0].ServerAddresses -join ',') -cne $expected){throw 'Configured DNS does not match selected phase'}
# Control observation: a failed DNS query must not be caused by loss
# of the private physical network, dead peer or blocked TCP port.
# No query is sent by these direct IP connections. They are not counted
# as successful name resolution, and do not modify the Windows resolver.
function Assert-PrivatePeerTCPReachable {
    foreach($address in @('192.0.2.53','192.0.2.54')){
        $client=[Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
        $pending=$null
        try{
            $client.Client.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Parse('192.0.2.10'),0))
            $pending=$client.BeginConnect([Net.IPAddress]::Parse($address),53,$null,$null)
            if(-not $pending.AsyncWaitHandle.WaitOne(2500,$false)){throw 'Private peer TCP control timed out'}
            $client.EndConnect($pending)
            if(-not $client.Connected -or $client.Client.RemoteEndPoint.Address.ToString() -cne $address -or
               $client.Client.LocalEndPoint.Address.ToString() -cne '192.0.2.10'){throw 'Private peer TCP control identity mismatch'}
        }finally{
            if($null -ne $pending){$pending.AsyncWaitHandle.Dispose()}
            $client.Dispose()
        }
    }
}
Assert-PrivatePeerTCPReachable
$name=$Nonce+'.volve-ci.test'
$arguments=@{Name=($name+'.');Type='A';DnsOnly=$true;NoHostsFile=$true;QuickTimeout=$true;ErrorAction='Stop'}
if($Transport -ceq 'TCP'){$arguments.TcpOnly=$true}
# Deliberately NO -Server. This must exercise the actual Windows
# resolver configuration, not an application bypass of a broken DNS.
$answers=@()
$errorId=$null
try{$answers=@(Resolve-DnsName @arguments)}
catch{
    $errorId=[string]$_.FullyQualifiedErrorId
    # Only the resolution failure is admissible. Command binding,
    # permissions and other local failures must never prove the fault.
    # Windows may report WSAECONNRESET (10054) on a DNS socket
    # directed to an absent localhost listener. Treat that as an admissible
    # negative observation only during the deliberate fault phase. Do not
    # match localized messages, arbitrary exceptions or all SocketExceptions.
    $knownResolution=$errorId -cmatch '^(DNS_ERROR_RCODE_NAME_ERROR|DNS_ERROR_RCODE_SERVER_FAILURE|DNS_ERROR_RCODE_REFUSED|DNS_ERROR_NO_DNS_SERVERS|DNS_ERROR_NO_PACKET|DNS_ERROR_RECORD_DOES_NOT_EXIST|DNS_INFO_NO_RECORDS|ERROR_TIMEOUT|WSAETIMEDOUT|WSAHOST_NOT_FOUND|WSATRY_AGAIN)(,|$)'
    $knownFaultReset=($Phase -ceq 'Fault' -and $errorId -cmatch '^(WSAECONNRESET|WSAECONNREFUSED|10054|10061)(,Microsoft\.DnsClient\.Commands\.ResolveDnsName|$)')
    # Exact native TCP observation in run 45475233420/job 138733829057:
    # 10057 (WSAENOTCONN). Accept only for this deliberately disconnected
    # DNS-over-TCP fault, still requiring no local listener, intact private
    # TCP controls, exact DNS assignment and no matching peer wire evidence.
    $knownTCPNotConnected=($Phase -ceq 'Fault' -and $Transport -ceq 'TCP' -and $errorId -cmatch '^(WSAENOTCONN|10057),Microsoft\.DnsClient\.Commands\.ResolveDnsName$')
    if(-not $knownResolution -and -not $knownFaultReset -and -not $knownTCPNotConnected){
        throw ('Unexpected resolver failure; error_id='+$errorId+'; exception_type='+$_.Exception.GetType().FullName)
    }
}
$addresses=@($answers|Where-Object {
    $_.PSObject.Properties['IPAddress'] -and
    $_.PSObject.Properties['Type'] -and [string]$_.Type -eq 'A'
})
$resolved=$false
if($null -eq $errorId){
    if($addresses.Count -ne 1 -or [string]$addresses[0].IPAddress -cne '192.0.2.53' -or
       ([string]$addresses[0].Name).TrimEnd('.') -cne $name){throw 'Unexpected DNS response; not an admissible fault or success'}
    $resolved=$true
}
if($Phase -ceq 'Fault'){
    if($resolved -or $null -eq $errorId){throw 'Fault did not prevent Windows resolution'}
    # The deliberate loopback fault has no DNS service, not merely a
    # server returning an unexpected response. Query the actual socket
    # inventory without suppressing inventory/permission failures.
    if(@(Get-NetUDPEndpoint -ErrorAction Stop|Where-Object {$_.LocalPort -eq 53}).Count -ne 0 -or
       @(Get-NetTCPConnection -State Listen -ErrorAction Stop|Where-Object {$_.LocalPort -eq 53}).Count -ne 0){throw 'Unexpected DNS53 listener during fault'}

}else{
    if(-not $resolved){throw ('Configured DNS failed to resolve private challenge: '+$errorId)}
}
Assert-PrivatePeerTCPReachable
# Read back the exact adapter identity and DNS list again, after the query.
$after=@(Get-NetAdapter -ErrorAction Stop)
$afterDNS=@(Get-DnsClientServerAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction Stop)
if($after.Count -ne 1 -or $after[0].InterfaceGuid -ne $n[0].InterfaceGuid -or
   $after[0].InterfaceIndex -ne $idx -or $afterDNS.Count -ne 1 -or
   ($afterDNS[0].ServerAddresses -join ',') -cne $expected){throw 'Adapter or DNS changed during challenge'}
[pscustomobject]@{
    phase=$Phase;transport=$Transport;nonce=$Nonce
    resolved=$resolved;resolution_error=$errorId
    direct_private_tcp_before_and_after=$true
    requires_independent_peer_log=$true
    internet_connectivity_proven=$false
}
