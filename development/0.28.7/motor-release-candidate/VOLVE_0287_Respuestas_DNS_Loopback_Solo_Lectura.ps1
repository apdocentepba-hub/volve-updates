# VOLVE 0.28.7 — respuestas reales del motor DNS residente, SOLO LECTURA.
# Sin modificar la configuración DNS, tareas, archivos, procesos o firewall.
# Envía exactamente seis consultas DNS UDP a 127.0.0.1 / ::1, puerto 53.
# La consulta permitida puede ser reenviada a resolutores configurados.
# Esta prueba NO verifica recuperación tras reinicio ni autoriza migración.
[CmdletBinding()]
param()
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
        if($reply.Length -lt 12 -or
           $reply[0] -ne $query[0] -or $reply[1] -ne $query[1] -or
           ($reply[2] -band 128) -eq 0 -or
           ($reply[2] -band 15) -ne 0 -or
           $reply[4] -ne 0 -or $reply[5] -ne 1){
            throw 'Respuesta DNS sin coincidencia de consulta o encabezado'
        }
        return [int]($reply[3] -band 15)
    } finally {$client.Dispose()}
}
$report=[ordered]@{
    schema=1
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
                $status='timeout_or_invalid_response'
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
