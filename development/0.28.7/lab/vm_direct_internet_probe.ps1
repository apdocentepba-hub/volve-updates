# VOLVE 0.28.7 - independent, direct TCP Internet health for a disposable
# persistent Windows VM reboot proof. No DNS resolver, adapter or hosts edits.
# This is NOT evidence of browser policy enforcement or publisher authorization.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

function Assert-VolvDirectInternetTCP {
    [CmdletBinding()]
    param(
        # Only deterministic unit tests may pass an injected dialer. The
        # production VM script calls this function without this parameter.
        [scriptblock]$TryEndpoint=$null
    )
    $destinations=@(
        [pscustomobject]@{IP='1.1.1.1';Port=443},
        [pscustomobject]@{IP='9.9.9.9';Port=443}
    )
    foreach($destination in $destinations){
        $success=$false
        if($null -ne $TryEndpoint){
            $result=& $TryEndpoint $destination.IP $destination.Port
            if($result -isnot [bool]){
                throw 'NOT VERIFIED: an injected TCP probe returned an ambiguous result'
            }
            $success=$result
        }else{
            $client=[Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
            $pending=$null
            try{
                # Bounded direct IP-literal TCP connection; DNS cannot make
                # a broken resolver look healthy by returning a cached answer.
                $pending=$client.BeginConnect([Net.IPAddress]::Parse($destination.IP),
                    [int]$destination.Port,$null,$null)
                if($pending.AsyncWaitHandle.WaitOne(2500,$false)){
                    $client.EndConnect($pending)
                    $success=$client.Connected
                }
            }catch{
                $success=$false
            }finally{
                if($null -ne $pending){$pending.AsyncWaitHandle.Dispose()}
                $client.Dispose()
            }
        }
        if($success){
            return [pscustomobject]@{
                Verified=$true
                Endpoint=($destination.IP+':'+$destination.Port)
                Transport='direct-ipv4-tcp'
            }
        }
    }
    throw 'NOT VERIFIED: neither independent direct TCP Internet endpoint is reachable'
}
