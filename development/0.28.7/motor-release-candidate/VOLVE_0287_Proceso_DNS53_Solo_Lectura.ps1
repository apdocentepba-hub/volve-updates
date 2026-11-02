# VOLVÉ 0.28.7 — comprobación del PROCESO que atiende DNS53 (solo lectura).
# No cambia DNS, tareas, registro, archivos del motor ni procesos.
# No consulta dominios ni envía datos por red.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$current=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=[Security.Principal.WindowsPrincipal]::new($current)
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    throw 'Se requiere PowerShell como Administrador; no se modificó Windows.'
}
$root=Join-Path $env:ProgramData 'VOLVE-Browser-Filter'
$original=Join-Path $root 'VOLVE_DNS_Server_0270.exe'
$taskExact=$false
$taskStatus='not_verified'
try {
    $task=Get-ScheduledTask -TaskName 'VOLVE-DNS-SERVER-0270' -TaskPath '\' -ErrorAction Stop
    if(@($task).Count -ne 1){throw 'Ambiguous task'}
    $taskExact=($task.Principal.UserId -in @('SYSTEM','S-1-5-18') -and
        @($task.Actions).Count -eq 1 -and
        [string]::Equals(([string]$task.Actions[0].Execute).Trim('"'),$original,
          [StringComparison]::OrdinalIgnoreCase) -and
        [string]$task.Actions[0].Arguments -ceq '--dns-service')
    $taskStatus=[string]$task.State
} catch {
    $taskExact=$false
}
$count4=$null
$count6=$null
$sameOwner=$false
$originalProcess=$false
$systemToken=$false
$probe='not_verified'
try {
    $v4=@(Get-NetUDPEndpoint -LocalAddress '127.0.0.1' -LocalPort 53 -ErrorAction Stop)
    $v6=@(Get-NetUDPEndpoint -LocalAddress '::1' -LocalPort 53 -ErrorAction Stop)
    $count4=$v4.Count
    $count6=$v6.Count
    if($v4.Count -eq 1 -and $v6.Count -eq 1){
        $pid4=[int]$v4[0].OwningProcess
        $pid6=[int]$v6[0].OwningProcess
        $sameOwner=($pid4 -gt 0 -and $pid4 -eq $pid6)
        if($sameOwner){
            $process=@(Get-CimInstance Win32_Process -Filter ('ProcessId = '+$pid4) -ErrorAction Stop)
            if($process.Count -eq 1){
                $originalProcess=[string]::Equals([string]$process[0].ExecutablePath,
                  $original,[StringComparison]::OrdinalIgnoreCase)
                $sid=Invoke-CimMethod -InputObject $process[0] -MethodName GetOwnerSid -ErrorAction Stop
                $systemToken=($sid.ReturnValue -eq 0 -and $sid.Sid -eq 'S-1-5-18')
                $probe='observed'
            }
        }
    }
} catch {
    # Errors, access denials or transient socket transitions are UNKNOWN,
    # not evidence that no DNS service is installed.
    $probe='not_verified'
}
$ready=($taskExact -and $taskStatus -eq 'Running' -and
    $count4 -eq 1 -and $count6 -eq 1 -and
    $sameOwner -and $originalProcess -and $systemToken -and
    $probe -eq 'observed')
$report=[ordered]@{
    schema=1
    tool='volve-0287-dns53-process-ownership-readonly'
    may_modify_windows=$false
    network_queries_sent=$false
    migration_authorized=$false
    task_exact_system_action=$taskExact
    task_state=$taskStatus
    loopback_ipv4_udp53_count=$count4
    loopback_ipv6_udp53_count=$count6
    same_process_owns_both=$sameOwner
    process_is_exact_original_exe=$originalProcess
    process_is_local_system=$systemToken
    observation_state=$probe
    dns53_identity_verified=$ready
    note='Identidad de proceso únicamente. No acredita respuesta DNS, bloqueo, Internet, firma editorial ni permiso de actualización.'
}
$report|ConvertTo-Json -Depth 5
