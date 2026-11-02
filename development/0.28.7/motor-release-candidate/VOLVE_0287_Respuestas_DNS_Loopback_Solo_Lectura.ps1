# VOLVE 0.28.7 — respuestas reales del motor DNS residente, SOLO LECTURA.
# Sin modificar la configuración DNS, tareas, archivos, procesos o firewall.
# Envía exactamente seis consultas DNS UDP a 127.0.0.1 / ::1, puerto 53.
# La consulta permitida puede ser reenviada a resolutores configurados.
# Esta prueba NO verifica recuperación tras reinicio ni autoriza migración.
[CmdletBinding()]
param([switch]$SelfTest)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$here=Split-Path -Parent $MyInvocation.MyCommand.Path
$ownerPath=Join-Path $here 'VOLVE_0287_Proceso_DNS53_Solo_Lectura.ps1'
if(-not (Test-Path -LiteralPath $ownerPath -PathType Leaf)){
    throw 'Falta el verificador local de identidad SYSTEM; no se hicieron consultas'
}
function Verify-Owner {
    $raw=@(& $ownerPath)
    $result=($raw -join [Environment]::NewLine).Trim()|ConvertFrom-Json -ErrorAction Stop
    if($result.schema -ne 1 -or
       $result.tool -ne 'volve-0287-dns53-process-ownership-readonly' -or
       $result.may_modify_windows -ne $false -or
       $result.migration_authorized -ne $false -or
       $result.dns53_identity_verified -ne $true){
        throw 'No se comprobó el proceso original SYSTEM en IPv4 e IPv6; no se consultó DNS'
    }
}
function Get-DnsRCodeFromReply([byte[]]$request,[byte[]]$reply) {
    # DNS high header byte: QR is bit 7, OPCODE occupies bits 6..3;
    # RD is bit 0, and a normal recursive reply echoes RD=1.
    # The previous probe mistakenly required bits 3..0 == 0 and
    # therefore rejected valid responses (e.g., 0x81, even NXDOMAIN).
    if($request.Length -lt 12 -or $reply.Length -lt $request.Length -or
       $reply[0] -ne $request[0] -or $reply[1] -ne $request[1] -or
       ($reply[2] -band 0x80) -eq 0 -or
       ($reply[2] -band 0x78) -ne 0 -or
       ($reply[2] -band 0x02) -ne 0 -or
       $reply[4] -ne 0 -or $reply[5] -ne 1){
        throw 'DNS_INVALID_RESPONSE_HEADER'
    }
    for($i=12;$i -lt $request.Length;$i++){
        if($reply[$i] -ne $request[$i]){throw 'DNS_INVALID_RESPONSE_QUESTION'}
    }
    return [int]($reply[3] -band 15)
}
if($SelfTest){
    [byte[]]$req=@(0,66,1,0,0,1,0,0,0,0,0,0)
    [byte[]]$nxdomain=@(0,66,129,131,0,1,0,0,0,0,0,0)
    [byte[]]$noerror=@(0,66,129,128,0,1,0,0,0,0,0,0)
    if((Get-DnsRCodeFromReply $req $nxdomain) -ne 3 -or
       (Get-DnsRCodeFromReply $req $noerror) -ne 0){
        throw 'Valid RD=1 DNS reply wrongly rejected'
    }
    [byte[]]$wrongId=@(0,67,129,131,0,1,0,0,0,0,0,0)
    [byte[]]$wrongOpcode=@(0,66,137,131,0,1,0,0,0,0,0,0)
    foreach($bad in @($wrongId,$wrongOpcode)){
        $rejected=$false
        try{$null=Get-DnsRCodeFromReply $req $bad}catch{$rejected=$true}
        if(-not $rejected){throw 'Unrelated or non-query DNS response accepted'}
    }
    Write-Output 'VOLVE_DNS_RD1_RESPONSE_PARSER_PASS'
    return
}
function Query-DNS([string]$Address,[string]$Name){
    $ip=[Net.IPAddress]::Parse($Address)
    $client=[Net.Sockets.UdpClient]::new($ip.AddressFamily)
    try{
        $client.Client.ReceiveTimeout=2300
        $client.Client.SendTimeout=2300
        $client.Connect($ip,53)
        $id=Get-Random -Minimum 1024 -Maximum 64000
        $bytes=[Collections.Generic.List[byte]]::new()
        foreach($b in @([byte]($id -shr 8),[byte]($id -band 255),
          [byte]1,[byte]0,[byte]0,[byte]1,[byte]0,[byte]0,[byte]0,[byte]0,[byte]0,[byte]0)){
            $bytes.Add($b)
        }
        foreach($label in $Name.Split('.')){
            $part=[Text.Encoding]::ASCII.GetBytes($label)
            if($part.Length -lt 1 -or $part.Length -gt 63){throw 'Etiqueta DNS no permitida'}
            $bytes.Add([byte]$part.Length)
            foreach($b in $part){$bytes.Add($b)}
        }
        foreach($b in @([byte]0,[byte]0,[byte]1,[byte]0,[byte]1)){$bytes.Add($b)}
        [byte[]]$query=$bytes.ToArray()
        $sent=$client.Send($query,$query.Length)
        if($sent -ne $query.Length){throw 'Consulta DNS incompleta'}
        $remote=[Net.IPEndPoint]::new(
          $(if($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6){[Net.IPAddress]::IPv6Any}else{[Net.IPAddress]::Any}),0)
        [byte[]]$reply=$client.Receive([ref]$remote)
        return Get-DnsRCodeFromReply $query $reply
    } finally {$client.Dispose()}
}
$report=[ordered]@{
    schema=1
    diagnostic_revision=2
    tool='volve-0287-local-dualstack-dns-functional-readonly'
    may_modify_windows=$false
    migration_authorized=$false
    network_scope='fixed-six-local-dns-queries-udp53; allowed-domains-may-forward'
    identity_verified_before=$false
    identity_verified_after=$false
    queries_attempted=0
    queries_succeeded=0
    blocked_nxdomain_observations=0
    allowed_noerror_observations=0
    dns_functional_observed=$false
    results=@()
    note='Prueba de respuestas locales, no porcentaje de bloqueo, firma editorial ni reinicio.'
}
try{
    Verify-Owner
    $report.identity_verified_before=$true
    foreach($addr in @('127.0.0.1','::1')){
        foreach($item in @(
            @{domain='stake.com';expect=3;kind='blocked'},
            @{domain='betwarrior.bet.ar';expect=3;kind='blocked'},
            @{domain='example.org';expect=0;kind='allowed'}
        )){
            $report.queries_attempted++
            $rcode=$null
            $status='not_verified'
            try{
                $rcode=Query-DNS $addr $item.domain
                $report.queries_succeeded++
                if($rcode -eq $item.expect){
                    $status='as_expected'
                    if($item.kind -eq 'blocked'){$report.blocked_nxdomain_observations++}
                    else {$report.allowed_noerror_observations++}
                } else {$status='unexpected_rcode'}
            } catch {
                # Fail closed, but separate real socket timeout from a
                # malformed DNS reply and from a PowerShell/runtime error.
                # Do not export path, process ID, or raw exception details.
                $socket=$_.Exception
                while($null -ne $socket -and -not ($socket -is [Net.Sockets.SocketException])){
                    $socket=$socket.InnerException
                }
                if($null -ne $socket){
                    $status=$(if($socket.SocketErrorCode -eq [Net.Sockets.SocketError]::TimedOut){'timeout'}else{'socket_error'})
                }elseif($_.Exception.Message -like 'DNS_INVALID_RESPONSE_*'){
                    $status='invalid_response'
                }else{
                    $status='probe_error'
                }
            }
            $report.results+=([ordered]@{
                address_family=$(if($addr -eq '::1'){'IPv6'}else{'IPv4'})
                domain=$item.domain
                rcode=$rcode
                status=$status
            })
        }
    }
    # A new identity probe also protects against a process replacement after
    # the six local reads. No DNS adapter setting is touched at any point.
    Verify-Owner
    $report.identity_verified_after=$true
    $report.dns_functional_observed=($report.queries_attempted -eq 6 -and
        $report.blocked_nxdomain_observations -eq 4 -and
        $report.allowed_noerror_observations -eq 2)
} catch {
    $report.note='No verificado: falló una comprobación de identidad o la lectura local. No autoriza cambios.'
}
$report|ConvertTo-Json -Depth 6
