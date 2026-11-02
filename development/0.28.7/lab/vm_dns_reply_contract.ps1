# VOLVÉ 0.28.7 — pure DNS answer contract for a persistent VM reboot test.
# The helper does NOT send packets, resolve names or mutate Windows. It
# validates the reply to one fixed, transaction-bound DNS question.
Set-StrictMode -Version Latest

function Assert-VolvVmDnsReply {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][byte[]]$Request,
        [Parameter(Mandatory=$true)][byte[]]$Reply
    )
    # 12-byte header + nonempty QNAME + root label + QTYPE + QCLASS.
    if($Request.Length -lt 18 -or $Reply.Length -lt $Request.Length){
        throw 'NOT VERIFIED: DNS reply truncated or request malformed'
    }
    if($Request[4] -ne 0 -or $Request[5] -ne 1 -or
       $Request[2] -ne 1 -or $Request[3] -ne 0){
        throw 'NOT VERIFIED: DNS request flags or question count not expected'
    }
    if($Reply[0] -ne $Request[0] -or $Reply[1] -ne $Request[1]){
        throw 'NOT VERIFIED: DNS transaction ID changed'
    }
    # QR=1; opcode=0; TC=0; response RD must match the original request.
    # An ordinary reply with RD=1 has first flag byte 0x81; DO NOT
    # reject its low bit as an opcode error (regression seen on real PC).
    if(($Reply[2] -band 0x80) -eq 0 -or
       ($Reply[2] -band 0x78) -ne 0 -or
       ($Reply[2] -band 0x02) -ne 0 -or
       ($Reply[2] -band 0x01) -ne ($Request[2] -band 0x01)){
        throw 'NOT VERIFIED: DNS response flags/opcode invalid'
    }
    # Z (reserved) flags must be zero, but RA/AA/AD/CD may vary by resolver.
    if(($Reply[3] -band 0x70) -ne 0 -or
       $Reply[4] -ne 0 -or $Reply[5] -ne 1){
        throw 'NOT VERIFIED: DNS response reserved flags/question count invalid'
    }
    # All original wire-format question bytes must match exactly, including
    # QNAME, QTYPE and QCLASS. Never trust only the transaction ID.
    for($i=12;$i -lt $Request.Length;$i++){
        if($Reply[$i] -ne $Request[$i]){
            throw 'NOT VERIFIED: DNS response answers a different question'
        }
    }
    return [int]($Reply[3] -band 0x0f)
}
