# VOLVÉ DNS response parser contract: pure memory, no UDP, tasks or OS edits.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'vm_dns_reply_contract.ps1')

[byte[]]$request=@(
    0x43,0x21,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
    0x07,101,120,97,109,112,108,101,0x03,111,114,103,0x00,
    0x00,0x01,0x00,0x01
)
[byte[]]$goodNX=$request.Clone()
$goodNX[2]=0x81
$goodNX[3]=0x83
[byte[]]$goodAllow=$request.Clone()
$goodAllow[2]=0x81
$goodAllow[3]=0x80
foreach($case in @(
    @{packet=$goodNX;want=3},
    @{packet=$goodAllow;want=0}
)){
    $rcode=Assert-VolvVmDnsReply -Request $request -Reply $case.packet
    if($rcode -ne $case.want){throw 'Valid recursive DNS answer has wrong RCODE'}
}
$count=0
function Reject-DNS([byte[]]$packet,[string]$why){
    $rejected=$false
    try{$null=Assert-VolvVmDnsReply -Request $request -Reply $packet}
    catch{$rejected=$true}
    if(-not $rejected){throw ('DNS parser accepted '+$why)}
    $script:count++
}
[byte[]]$bad=$goodNX.Clone();$bad[0]=0
Reject-DNS $bad 'foreign transaction ID'
[byte[]]$bad=$goodNX.Clone();$bad[2]=0x01
Reject-DNS $bad 'nonresponse'
[byte[]]$bad=$goodNX.Clone();$bad[2]=0x89
Reject-DNS $bad 'nonstandard opcode'
[byte[]]$bad=$goodNX.Clone();$bad[2]=0x83
Reject-DNS $bad 'truncated TC reply'
[byte[]]$bad=$goodNX.Clone();$bad[2]=0x80
Reject-DNS $bad 'missing RD echo'
[byte[]]$bad=$goodNX.Clone();$bad[3]=0x93
Reject-DNS $bad 'reserved flags set'
[byte[]]$bad=$goodNX.Clone();$bad[4]=1
Reject-DNS $bad 'incorrect high question count'
[byte[]]$bad=$goodNX.Clone();$bad[5]=2
Reject-DNS $bad 'multiple questions'
[byte[]]$bad=$goodNX.Clone();$bad[14]=121
Reject-DNS $bad 'different requested domain'
[byte[]]$bad=$goodNX.Clone();$bad[$bad.Length-3]=28
Reject-DNS $bad 'different QTYPE'
[byte[]]$bad=$goodNX.Clone();$bad[$bad.Length-1]=2
Reject-DNS $bad 'different QCLASS'
[byte[]]$bad=$goodNX[0..($goodNX.Length-2)]
Reject-DNS $bad 'truncated question'
[byte[]]$bad=@()
Reject-DNS $bad 'empty reply'
if($count -ne 13){throw ('Expected 13 negative cases; saw '+$count)}
Write-Output 'PASS: 2 valid RD=1 DNS replies and 13 malformed/unrelated replies rejected without OS changes'
