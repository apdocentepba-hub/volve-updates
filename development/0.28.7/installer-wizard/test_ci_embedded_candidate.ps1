# CI-only lab: compile ONE NSIS EXE containing the verified signed bundle.
# No DNS/hosts/registry/task modifications or production installation.
param([Parameter(Mandatory=$true)][string]$GoodBundle,
      [Parameter(Mandatory=$true)][string]$TamperedBundle)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted'){
 throw 'REFUSED: embedded candidate only in disposable Windows GitHub CI'
}
$machine=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
if(($machine.Manufacturer+' '+$machine.Model) -notmatch '(?i:virtual machine|hyper-v|vmware|kvm|qemu|virtualbox)'){
 throw 'REFUSED: not a verified Windows virtual machine'
}
if($env:GITHUB_RUN_ID -cnotmatch '^[0-9]{6,20}$'){throw 'REFUSED: invalid test ID'}
$good=(Resolve-Path -LiteralPath $GoodBundle -ErrorAction Stop).Path
$bad=(Resolve-Path -LiteralPath $TamperedBundle -ErrorAction Stop).Path
if((Split-Path -Leaf $good) -cne 'VOLVE-CI-Signed-Container.exe' -or
   (Split-Path -Leaf $bad) -cne 'VOLVE-CI-Tampered-Container.exe'){
 throw 'REFUSED: not the expected signed/tampered CI fixtures'
}
$compiler=@('C:\Program Files (x86)\NSIS\makensis.exe','C:\Program Files\NSIS\makensis.exe') |
 Where-Object {Test-Path -LiteralPath $_ -PathType Leaf} | Select-Object -First 1
if(-not $compiler){throw 'REFUSED: NSIS compiler unavailable'}
$sourceRoot=Split-Path -Parent $MyInvocation.MyCommand.Path
$preview=Join-Path $sourceRoot 'VOLVE_Asistente_0287_PREVIEW.nsi'
$terms=Join-Path $sourceRoot 'TERMINOS_PREVIEW_0287.txt'
if(-not (Test-Path -LiteralPath $preview -PathType Leaf) -or -not (Test-Path -LiteralPath $terms -PathType Leaf)){
 throw 'REFUSED: preview source or consent terms missing'
}
$original=Get-Content -LiteralPath $preview -Raw -Encoding UTF8
$pattern='(?s)Section "Vista previa sin instalación" SecPreview.*?SectionEnd'
$match=[regex]::Match($original,$pattern)
if(-not $match.Success -or [regex]::Matches($original,$pattern).Count -ne 1 -or
   -not $original.Contains('RequestExecutionLevel user') -or
   -not $original.Contains('OutFile "VOLVE_Asistente_VistaPrevia_0287.exe"')){
 throw 'REFUSED: original inactive wizard structure was modified'
}
$work=Join-Path $env:RUNNER_TEMP ('VOLVE-CI-NSIS-OneEXE-'+$env:GITHUB_RUN_ID)
if(Test-Path -LiteralPath $work){throw 'REFUSED: duplicate CI candidate staging path'}
New-Item -ItemType Directory -Path $work -ErrorAction Stop | Out-Null
Copy-Item -LiteralPath $terms -Destination (Join-Path $work 'TERMINOS_PREVIEW_0287.txt') -ErrorAction Stop
$sectionTemplate=@'
Section "CI-only embedded signed bundle verification (NO INSTALL)" SecPreview
 SetOutPath "$TEMP\VOLVE-CI-Embedded-__RUN_ID__"
 File /oname=VOLVE-CI-Signed-Container.exe "__BUNDLE_PATH__"
 ExecWait '"$OUTDIR\VOLVE-CI-Signed-Container.exe" --verify-bundle' $R0
 Delete "$OUTDIR\VOLVE-CI-Signed-Container.exe"
 RMDir "$OUTDIR"
 StrCmp $R0 0 signed_ok
 DetailPrint "REFUSED: embedded bundle is invalid"
 SetErrorLevel 14
 Quit
signed_ok:
 DetailPrint "Signed CI bundle verified. NO INSTALL NO DNS NO TASKS"
SectionEnd
'@
function Build-VolvCandidate([string]$payload,[string]$output){
 if($payload.Contains('"') -or $payload.Contains('$')){throw 'REFUSED: invalid payload path'}
 $section=$sectionTemplate.Replace('__RUN_ID__',$env:GITHUB_RUN_ID).Replace('__BUNDLE_PATH__',$payload)
 $candidate=$original.Substring(0,$match.Index)+$section+$original.Substring($match.Index+$match.Length)
 $candidate=$candidate.Replace('OutFile "VOLVE_Asistente_VistaPrevia_0287.exe"','OutFile "'+$output+'"')
 if([regex]::Matches($candidate,'(?im)^\s*File\s+/oname=').Count -ne 1 -or
    [regex]::Matches($candidate,'(?im)^\s*ExecWait\s').Count -ne 1){throw 'REFUSED: unexpected NSIS file or execution directives'}
 $nsi=Join-Path $work ($output+'.nsi')
 [IO.File]::WriteAllText($nsi,$candidate,[Text.UTF8Encoding]::new($true))
 Push-Location $work
 try{
  & $compiler '/V3' (Split-Path -Leaf $nsi)
  if($LASTEXITCODE -ne 0){throw ('NSIS compilation failed '+$output)}
 }finally{Pop-Location}
 $exe=Join-Path $work $output
 if(-not (Test-Path -LiteralPath $exe -PathType Leaf) -or
    (Get-Item -LiteralPath $exe).Length -lt 100000){throw 'Compiled embedded candidate incomplete'}
 return $exe
}
function Run-VolvCandidate([string]$exe){
 $process=Start-Process -FilePath $exe -ArgumentList '/S' -WindowStyle Hidden -PassThru -ErrorAction Stop
 try{
  if(-not $process.WaitForExit(45000)){throw 'Candidate exceeded 45s lab limit'}
  return [int]$process.ExitCode
 }finally{
  if(-not $process.HasExited){
   Stop-Process -Id $process.Id -Force -ErrorAction Stop
   $process.WaitForExit(5000) | Out-Null
  }
  $process.Dispose()
 }
}
function Get-VolvProtectedSnapshot{
 $dns=Get-DnsClientServerAddress -ErrorAction Stop | Sort-Object InterfaceIndex,AddressFamily |
  Select-Object InterfaceIndex,AddressFamily,ServerAddresses | ConvertTo-Json -Depth 7 -Compress
 $hosts=(Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $env:WINDIR 'System32\drivers\etc\hosts')).Hash
 $tasks=@(Get-ScheduledTask -ErrorAction Stop | Where-Object {$_.TaskName -match '^(?i:VOLVE[-_\.])'} |
  Sort-Object TaskPath,TaskName | ForEach-Object {$_.TaskPath+$_.TaskName}) -join '|'
 return [pscustomobject]@{dns=$dns;hosts=$hosts;tasks=$tasks}
}
$before=Get-VolvProtectedSnapshot
$goodCandidate=Build-VolvCandidate -payload $good -output 'VOLVE-CI-Embedded-Valid-NO-INSTALL.exe'
$badCandidate=Build-VolvCandidate -payload $bad -output 'VOLVE-CI-Embedded-Tampered-NO-INSTALL.exe'
$goodExit=Run-VolvCandidate -exe $goodCandidate
if($goodExit -ne 0){throw ('Valid embedded signed bundle failed: '+$goodExit)}
$badExit=Run-VolvCandidate -exe $badCandidate
if($badExit -ne 14){throw ('Tampered embedded signed bundle did not fail closed: '+$badExit)}
if(Test-Path -LiteralPath (Join-Path $env:TEMP ('VOLVE-CI-Embedded-'+$env:GITHUB_RUN_ID))){
 throw 'Temporary embedded bundle was not removed after verification'
}
$after=Get-VolvProtectedSnapshot
foreach($key in @('dns','hosts','tasks')){
 if([string]$before.$key -cne [string]$after.$key){throw ('CI candidate changed protected Windows '+$key)}
}
$receipt=[ordered]@{
 schema='VOLVE-0287-ONE-EMBEDDED-EXE-CI-V1'
 valid_bundle_verification_passed=$true
 altered_bundle_rejected=$true
 temporary_payload_cleaned=$true
 no_protected_windows_changes=$true
 installer_active=$false
 reboot_verified=$false
 release_signed=$false
 can_install=$false
 can_change_dns=$false
 can_change_tasks=$false
 candidate_sha256=(Get-FileHash -LiteralPath $goodCandidate -Algorithm SHA256).Hash.ToLowerInvariant()
}
$receipt | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $env:RUNNER_TEMP 'VOLVE_CI_ONE_EMBEDDED_EXE_NO_INSTALL.json') -Encoding UTF8
Write-Host 'PASS VOLVE_CI_NSIS_SINGLE_EXE_EMBEDDED_SIGNED_BUNDLE_VERIFIED_TAMPER_REFUSED'
Write-Host 'PASS VOLVE_CI_NSIS_SINGLE_EXE_NO_INSTALL_NO_DNS_NO_TASKS_NO_RELEASE'
