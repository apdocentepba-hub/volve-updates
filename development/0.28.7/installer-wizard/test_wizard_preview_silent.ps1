# VOLVE 0.28.7 - real Windows E2E: the preview must stay strictly inert,
# even when invoked silently (/S bypasses the interactive consent pages).
# This check runs ONLY on an ephemeral GitHub-hosted Windows VM.
param(
    [Parameter(Mandatory=$true)][string]$WizardExe
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted'){
    throw 'REFUSED: wizard silent smoke test requires a disposable GitHub-hosted Windows VM'
}
$vm=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
if(($vm.Manufacturer+' '+$vm.Model) -notmatch '(?i:virtual machine|vmware|kvm|hyper-v|qemu|virtualbox)'){
    throw 'REFUSED: Windows environment is not positively identified as virtual'
}
$exe=(Resolve-Path -LiteralPath $WizardExe -ErrorAction Stop).Path
if((Split-Path -Leaf $exe) -cne 'VOLVE_Asistente_VistaPrevia_0287.exe'){
    throw 'REFUSED: executable is not the exact non-protective wizard preview'
}

function Get-VolvPreviewSnapshot {
    $hostsPath=Join-Path $env:WINDIR 'System32\drivers\etc\hosts'
    $hostsHash=(Get-FileHash -LiteralPath $hostsPath -Algorithm SHA256 -ErrorAction Stop).Hash
    $dns=@(Get-DnsClientServerAddress -ErrorAction Stop |
        Sort-Object InterfaceIndex,AddressFamily |
        ForEach-Object {([string]$_.InterfaceIndex)+'|'+([string]$_.AddressFamily)+'|'+
            ([string]::Join(',', [string[]]@($_.ServerAddresses)))})
    $tasks=@(Get-ScheduledTask -ErrorAction Stop |
        Where-Object {$_.TaskName -match '(?i)^VOLVE[_\.-]'} |
        Sort-Object TaskPath,TaskName |
        ForEach-Object {
            $xml=Export-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath -ErrorAction Stop
            $sha=[Security.Cryptography.SHA256]::Create()
            try {
                $bytes=[Text.Encoding]::UTF8.GetBytes([string]$xml)
                $hash=[BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','')
            } finally {$sha.Dispose()}
            [string]$_.TaskPath+[string]$_.TaskName+'|'+$hash
        })
    $roots=@(
        (Join-Path $env:LOCALAPPDATA 'VOLVE-Preview'),
        (Join-Path $env:LOCALAPPDATA 'VOLVE'),
        (Join-Path $env:ProgramData 'VOLVE'),
        (Join-Path $env:ProgramFiles 'VOLVE')
    )
    $folders=@($roots | ForEach-Object {
        [string]$_+'|'+[string](Test-Path -LiteralPath $_)
    })
    $policies=@()
    $keys=@(
        'HKLM:\SOFTWARE\Policies\Google\Chrome',
        'HKCU:\SOFTWARE\Policies\Google\Chrome',
        'HKLM:\SOFTWARE\Policies\Microsoft\Edge',
        'HKCU:\SOFTWARE\Policies\Microsoft\Edge',
        'HKLM:\SOFTWARE\Policies\Mozilla\Firefox',
        'HKCU:\SOFTWARE\Policies\Mozilla\Firefox',
        'HKLM:\SOFTWARE\VOLVE',
        'HKCU:\SOFTWARE\VOLVE'
    )
    foreach($key in $keys){
        $item=Get-Item -LiteralPath $key -ErrorAction SilentlyContinue
        if($null -eq $item){$policies+=($key+'|ABSENT');continue}
        $all=@($item)+@(Get-ChildItem -LiteralPath $key -Recurse -ErrorAction Stop)
        foreach($sub in $all){
            $policies+=($sub.Name+'|KEY')
            foreach($name in @($sub.GetValueNames() | Sort-Object)){
                $kind=[string]$sub.GetValueKind($name)
                $value=$sub.GetValue($name,$null,'DoNotExpandEnvironmentNames')
                $serialized=ConvertTo-Json -InputObject $value -Depth 6 -Compress
                $policies+=($sub.Name+'|'+$name+'|'+$kind+'|'+$serialized)
            }
        }
    }
    return [pscustomobject]@{
        hosts=$hostsHash
        dns=[string[]]$dns
        tasks=[string[]]$tasks
        folders=[string[]]$folders
        registry=[string[]]$policies
    }
}

$before=Get-VolvPreviewSnapshot
$process=Start-Process -FilePath $exe -ArgumentList '/S' -WindowStyle Hidden -PassThru -ErrorAction Stop
try {
    if(-not $process.WaitForExit(40000)){
        throw 'Wizard preview did not finish silently within the bounded test window'
    }
    if($process.ExitCode -ne 0){
        throw ('Inert NSIS preview exited with code '+$process.ExitCode)
    }
} finally {
    if(-not $process.HasExited){
        Stop-Process -Id $process.Id -Force -ErrorAction Stop
        $process.WaitForExit(5000) | Out-Null
    }
    $process.Dispose()
}
$after=Get-VolvPreviewSnapshot
foreach($field in @('hosts','dns','tasks','folders','registry')){
    $b=ConvertTo-Json -InputObject $before.$field -Depth 10 -Compress
    $a=ConvertTo-Json -InputObject $after.$field -Depth 10 -Compress
    if($b -cne $a){
        # Do NOT log raw DNS, Scheduler XML, browser policies or file paths.
        throw ('REFUSED: silent wizard preview changed protected Windows surface '+$field)
    }
}
Write-Host 'PASS: real NSIS preview executed silently (/S) on Windows and exited cleanly'
Write-Host 'PASS: HOSTS, dual-stack DNS, VOLVE tasks, protected folders and browser policy registry unchanged'
Write-Host 'PASS: silent preview DID NOT install, activate protection or bypass release gates'
