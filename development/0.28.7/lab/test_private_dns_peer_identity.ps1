# Pure synthetic contracts only: no guest, CIM, network, task or DNS operation.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'private_dns_peer_vm.ps1')
function New-PeerFixture {
    [pscustomobject]@{
        retained_process_pin='0123456789abcdef0123456789abcdef'
        retained_process_live=$true
        boot_event_record='123'
        boot_event_sha256=('A'*64)
        uptime_seconds='300'
        native_uptime_ms='300100'
        process_id='42'
        created_ticks='639311539709780640'
        boot_ticks='639311539144990360'
        adapter_guid='{D1DC3AD0-88A3-4F88-819F-4DFAC7D04032}'
        executable_sha256=('B'*64)
    }
}
$pinned=New-PeerFixture
$current=New-PeerFixture
Assert-VolvPrivatePeerIdentityEvidence -PinnedIdentity $pinned -current $current
$current.uptime_seconds='310'
$current.native_uptime_ms='310100'
Assert-VolvPrivatePeerIdentityEvidence -PinnedIdentity $pinned -current $current
foreach($jitter in @(5140,-5140,10000,-10000,71030,-71030)){
    $current=New-PeerFixture
    $current.uptime_seconds='310'
    $current.native_uptime_ms='310100'
    $current.boot_ticks=([decimal]$pinned.boot_ticks+$jitter).ToString([Globalization.CultureInfo]::InvariantCulture)
    Assert-VolvPrivatePeerIdentityEvidence -PinnedIdentity $pinned -current $current
}
$cases=@(
    @{field='boot_event_record';value='124'},
    @{field='boot_event_sha256';value=('C'*64)},
    @{field='uptime_seconds';value='299'},
    @{field='native_uptime_ms';value='300099'},
    @{field='native_uptime_ms';value='306101'},
    @{field='native_uptime_ms';value='0'},
    @{field='process_id';value='43'},
    @{field='created_ticks';value='639311539709780641'},
    @{field='boot_ticks';value='0'},
    @{field='retained_process_pin';value='1123456789abcdef0123456789abcdef'},
    @{field='retained_process_pin';value=('0'*32)},
    @{field='retained_process_live';value=$false},
    @{field='retained_process_live';value='true'},
    @{field='adapter_guid';value='{D1DC3AD0-88A3-4F88-819F-4DFAC7D04033}'},
    @{field='executable_sha256';value=('D'*64)},
    @{field='boot_event_record';value='0'},
    @{field='boot_event_sha256';value='invalid'},
    @{field='uptime_seconds';value='18446744073709551616'},
    @{field='process_id';value='-1'},
    @{field='adapter_guid';value='00000000-0000-0000-0000-000000000000'}
)
foreach($case in $cases){
    $current=New-PeerFixture
    $field=$case.field
    $current.$field=$case.value
    $rejected=$false
    try{Assert-VolvPrivatePeerIdentityEvidence -PinnedIdentity $pinned -current $current}
    catch{if($_.Exception.Message -notmatch '^Peer continuity unproven:'){throw};$rejected=$true}
    if(-not $rejected){throw ('Unsafe peer identity accepted: '+$field)}
}
foreach($field in $pinned.PSObject.Properties.Name){
    $missing=New-PeerFixture
    $missing.PSObject.Properties.Remove($field)
    $rejected=$false
    try{Assert-VolvPrivatePeerIdentityEvidence -PinnedIdentity $pinned -current $missing}
    catch{if($_.Exception.Message -notmatch '^Peer continuity unproven: missing '){throw};$rejected=$true}
    if(-not $rejected){throw ('Missing peer evidence accepted: '+$field)}
}
# A nonadvancing second counter is permissible only when both readings
# still agree within sampling precision. A decrement is always rejected.
foreach($case in @(
    @{delta=71030;native='310100';perf='310';pin='1123456789abcdef0123456789abcdef';live=$true},
    @{delta=71030;native='310100';perf='310';pin=$pinned.retained_process_pin;live=$false},
    @{delta=71030;native='299100';perf='310';pin=$pinned.retained_process_pin;live=$true},
    @{delta=71030;native='316100';perf='310';pin=$pinned.retained_process_pin;live=$true}
)){
    $current=New-PeerFixture
    $current.boot_ticks=([decimal]$pinned.boot_ticks+$case.delta).ToString([Globalization.CultureInfo]::InvariantCulture)
    $current.native_uptime_ms=$case.native
    $current.uptime_seconds=$case.perf
    $current.retained_process_pin=$case.pin
    $current.retained_process_live=$case.live
    $rejected=$false
    try{Assert-VolvPrivatePeerIdentityEvidence -PinnedIdentity $pinned -current $current}
    catch{if($_.Exception.Message -notmatch '^Peer continuity unproven:'){throw};$rejected=$true}
    if(-not $rejected){throw 'Unsafe peer replacement or inconsistent uptime accepted'}
}
Write-Host 'PASS: peer identity evidence 8 accepted + 35 rejected synthetic cases; original retained process handle required; WMI drift diagnostic only; NO REBOOT NO DNS'
