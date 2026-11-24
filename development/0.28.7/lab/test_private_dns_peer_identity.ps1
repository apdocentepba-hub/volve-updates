# Pure synthetic contracts only: no guest, CIM, network, task or DNS operation.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'private_dns_peer_vm.ps1')
function New-PeerFixture {
    [pscustomobject]@{
        boot_event_record='123'
        boot_event_sha256=('A'*64)
        uptime_seconds='300'
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
Assert-VolvPrivatePeerIdentityEvidence -PinnedIdentity $pinned -current $current
$cases=@(
    @{field='boot_event_record';value='124'},
    @{field='boot_event_sha256';value=('C'*64)},
    @{field='uptime_seconds';value='299'},
    @{field='process_id';value='43'},
    @{field='created_ticks';value='639311539709780641'},
    @{field='boot_ticks';value='639311539144990361'},
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
Write-Host 'PASS: peer identity evidence 2 accepted + 21 rejected synthetic cases; exact WMI gate retained; NO REBOOT NO DNS'
