# Deterministic negative/positive tests for direct TCP proof.
# This file uses injected boolean dialers and never opens a real socket.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'vm_direct_internet_probe.ps1')

$script:calls=@()
$good=Assert-VolvDirectInternetTCP -TryEndpoint {
    param($ip,$port)
    $script:calls+=($ip+':'+$port)
    if($ip -eq '1.1.1.1'){return $false}
    if($ip -eq '9.9.9.9' -and $port -eq 443){return $true}
    return $false
}
if(-not $good.Verified -or $good.Endpoint -cne '9.9.9.9:443' -or
   $good.Transport -cne 'direct-ipv4-tcp' -or
   ($script:calls -join ',') -cne '1.1.1.1:443,9.9.9.9:443'){
    throw 'Healthy independent TCP fallback or endpoint allowlist failed'
}
$script:rejected=0
function MustReject([string]$label,[scriptblock]$dial){
    try {
        $null=Assert-VolvDirectInternetTCP -TryEndpoint $dial
        throw ('UNSAFE: '+$label+' was certified as Internet access')
    }catch {
        if($_.Exception.Message -notmatch '^NOT VERIFIED:'){throw}
        $script:rejected++
    }
}
MustReject 'both endpoints unreachable' {param($ip,$port) return $false}
MustReject 'ambiguous text result' {param($ip,$port) return 'success'}
MustReject 'missing response' {param($ip,$port) return $null}
if($script:rejected -ne 3){throw ('Expected 3 negative cases, got '+$script:rejected)}
Write-Host 'PASS: Internet health requires direct TCP reachability; 3 negative cases; no network operations'
