# VOLVE 0.28.7 - Identidad del motor legado (SOLO LECTURA)
# No repara, instala, arranca, detiene ni modifica tareas, DNS ni archivos.
# Solo presenta datos de componentes de VOLVE conocidos, sin rutas privadas ni datos de red del usuario.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-ExactVOLVETask([string]$Name) {
    try {
        $task = Get-ScheduledTask -TaskPath '\' -TaskName $Name -ErrorAction Stop
        if (@($task).Count -ne 1) { return @{status='ambiguous'; task=$null} }
        return @{status='found';task=$task}
    } catch {
        # Missing/denied are both treated as unverified; never report 'not installed'.
        return @{status='not_verified';task=$null}
    }
}
function Get-ExactSafeFile([string]$Path) {
    $result = [ordered]@{exists=$false;regular=$false;sha256=$null;size=$null}
    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($item.PSIsContainer) { return $result }
        $result.exists = $true
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $result }
        if ($item.Length -lt 1024 -or $item.Length -gt 83886080) { return $result }
        $result.regular = $true
        $result.sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        $result.size = [int64]$item.Length
        return $result
    } catch { return $result }
}
function Get-ListenerCount([string]$Addr) {
    try { return [int]@(Get-NetUDPEndpoint -LocalAddress $Addr -LocalPort 53 -ErrorAction Stop).Count }
    catch { return $null }  # Unknown is not zero.
}

$current = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($current)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'VOLVE: se requiere PowerShell como administrador para el diagnóstico de solo lectura. No se modificó Windows.'
}
$root = Join-Path $env:ProgramData 'VOLVE-Browser-Filter'
$old = Join-Path $root 'VOLVE_DNS_Server_0270.exe'
$taskResult = Get-ExactVOLVETask 'VOLVE-DNS-SERVER-0270'
$rescueResult = Get-ExactVOLVETask 'VOLVE-DNS-RESCUE-0270'
$catalogResult = Get-ExactVOLVETask 'VOLVE-CATALOGO-0230'
$oldFile = Get-ExactSafeFile $old
$actionPinned = $false
$systemPinned = $false
$actionCount = 0
$taskState = $null
if ($taskResult.status -eq 'found') {
    $t = $taskResult.task
    $taskState = [string]$t.State
    $actionCount = @($t.Actions).Count
    $systemPinned = ([string]$t.Principal.UserId -in @('SYSTEM','S-1-5-18'))
    if ($actionCount -eq 1) {
        $a = $t.Actions[0]
        $actionPinned = ([string]::Equals(([string]$a.Execute).Trim('"'),$old,[StringComparison]::OrdinalIgnoreCase) -and
                         [string]$a.Arguments -ceq '--dns-service')
    }
}
$catalogLast = $null
$catalogResultCode = $null
if ($catalogResult.status -eq 'found') {
    try {
        $info = Get-ScheduledTaskInfo -TaskName 'VOLVE-CATALOGO-0230' -TaskPath '\' -ErrorAction Stop
        $catalogLast = $info.LastRunTime.ToString('o')
        $catalogResultCode = [int]$info.LastTaskResult
    } catch { }
}
$ipv4 = Get-ListenerCount '127.0.0.1'
$ipv6 = Get-ListenerCount '::1'
$result = [ordered]@{
    schema = 1
    tool = 'volve-0287-legacy-engine-review-readonly'
    may_modify_windows = $false
    migration_authorized = $false
    legacy_task_status = $taskResult.status
    legacy_task_state = $taskState
    legacy_task_system = $systemPinned
    legacy_task_action_count = $actionCount
    legacy_task_exact_action = $actionPinned
    old_engine_file = $oldFile
    rescue_task_status = $rescueResult.status
    catalog_task_status = $catalogResult.status
    catalog_last_run = $catalogLast
    catalog_last_result = $catalogResultCode
    udp53_loopback_ipv4_listener_count = $ipv4
    udp53_loopback_ipv6_listener_count = $ipv6
    identity_review_possible = ($taskResult.status -eq 'found' -and $systemPinned -and $actionPinned -and $oldFile.regular)
    note = 'No modifica Windows. Un hash local no equivale a autorización editorial, identidad del proceso activo ni recuperación productiva.'
}
$result | ConvertTo-Json -Depth 5
