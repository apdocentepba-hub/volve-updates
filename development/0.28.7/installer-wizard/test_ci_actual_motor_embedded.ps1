# Disposable hosted Windows CI only: put the ACTUAL compiled VOLVE DNS motor
# and the previously verified signed seven-part bundle into ONE NSIS EXE.
# Test real PE signing and exact SHA after NSIS extraction (including tamper).
# This is NOT an installer and never starts the motor or changes Windows DNS.
param(
 [Parameter(Mandatory=$true)][string]$GoodBundle,
 [Parameter(Mandatory=$true)][string]$MotorSourceRoot
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or
   $env:GITHUB_RUN_ID -cnotmatch '^[0-9]{6,20}$'){
 throw 'REFUSED: real-motor NSIS handoff is hosted GitHub CI only'
}
$vm=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
if(($vm.Manufacturer+' '+$vm.Model) -notmatch '(?i:virtual machine|hyper-v|vmware|kvm|qemu|virtualbox)'){
 throw 'REFUSED: not a disposable virtualized Windows host'
}
if(-not (Test-Path -LiteralPath $GoodBundle -PathType Leaf) -or
   (Split-Path -Leaf $GoodBundle) -cne 'VOLVE-CI-Signed-Container.exe'){
 throw 'REFUSED: previously verified signed bundle is unavailable'
}
$source=(Resolve-Path -LiteralPath $MotorSourceRoot -ErrorAction Stop).Path
if((Split-Path -Leaf $source) -cne 'codigo' -or
   -not (Test-Path -LiteralPath (Join-Path $source 'go.mod') -PathType Leaf)){
 throw 'REFUSED: expected reconstructed original motor source not found'
}
$compiler=@('C:\Program Files (x86)\NSIS\makensis.exe','C:\Program Files\NSIS\makensis.exe') |
 Where-Object {Test-Path -LiteralPath $_ -PathType Leaf} | Select-Object -First 1
if(-not $compiler){throw 'REFUSED: NSIS compiler unavailable'}
$thumb=[string]$env:VOLVE_CI_CERT_THUMBPRINT
if($thumb -cnotmatch '^[A-Fa-f0-9]{40}$'){throw 'REFUSED: ephemeral CI test signer missing'}
if(-not (Test-Path -LiteralPath (Join-Path $env:WINDIR 'SysWOW64\WindowsPowerShell\v1.0\powershell.exe') -PathType Leaf)){
 throw 'REFUSED: expected x64 Windows with 32-bit NSIS and Sysnative redirection unavailable'
}
$cert=Get-Item -LiteralPath ('Cert:\CurrentUser\My\'+$thumb) -ErrorAction Stop
if(-not $cert.HasPrivateKey){throw 'REFUSED: ephemeral CI signing key unavailable'}
$scriptRoot=Split-Path -Parent $MyInvocation.MyCommand.Path
$preview=Join-Path $scriptRoot 'VOLVE_Asistente_0287_PREVIEW.nsi'
$terms=Join-Path $scriptRoot 'TERMINOS_PREVIEW_0287.txt'
$original=Get-Content -LiteralPath $preview -Raw -Encoding UTF8
$pattern='(?s)Section "Vista previa sin instalación" SecPreview.*?SectionEnd'
$match=[regex]::Match($original,$pattern)
if(-not $match.Success -or [regex]::Matches($original,$pattern).Count -ne 1 -or
   -not $original.Contains('RequestExecutionLevel user') -or
   -not $original.Contains('OutFile "VOLVE_Asistente_VistaPrevia_0287.exe"') -or
   -not (Test-Path -LiteralPath $terms -PathType Leaf)){
 throw 'REFUSED: original non-elevated inactive assistant changed'
}
$work=Join-Path $env:RUNNER_TEMP ('VOLVE-CI-ActualMotor-Bundle-'+$env:GITHUB_RUN_ID)
$stages=@('valid','motor-tampered') | ForEach-Object {
 Join-Path $env:TEMP ('VOLVE-CI-ActualMotor-'+$env:GITHUB_RUN_ID+'-'+$_)
}
if((Test-Path -LiteralPath $work) -or @($stages|Where-Object {Test-Path -LiteralPath $_}).Count -gt 0){
 throw 'REFUSED: staging directories must not exist before test'
}
function Get-VolvCISafetyBaseline {
 $dns=Get-DnsClientServerAddress -ErrorAction Stop | Sort-Object InterfaceIndex,AddressFamily |
  Select-Object InterfaceIndex,AddressFamily,ServerAddresses | ConvertTo-Json -Depth 7 -Compress
 $hosts=(Get-FileHash -LiteralPath (Join-Path $env:WINDIR 'System32\drivers\etc\hosts') -Algorithm SHA256).Hash
 $tasks=@(Get-ScheduledTask -ErrorAction Stop | Where-Object {$_.TaskName -match '^(?i:VOLVE[-_\.])'} |
  Sort-Object TaskPath,TaskName | ForEach-Object {$_.TaskPath+$_.TaskName}) -join '|'
 return [pscustomobject]@{dns=$dns;hosts=$hosts;tasks=$tasks}
}
$baseline=Get-VolvCISafetyBaseline
New-Item -ItemType Directory -Path $work -ErrorAction Stop | Out-Null
try {
 $rawMotor=Join-Path $work 'VOLVE-CI-Real-Motor-unsigned.exe'
 Push-Location $source
 try {
  & go build -mod=mod -trimpath -o $rawMotor .
  if($LASTEXITCODE -ne 0){throw 'Actual native VOLVE DNS motor did not compile'}
 } finally {Pop-Location}
 $data=[IO.File]::ReadAllBytes($rawMotor)
 if($data.Length -lt 1048576 -or $data[0] -ne 77 -or $data[1] -ne 90){
  throw 'Compiled real motor is not a Windows PE'
 }
 $signedMotor=Join-Path $work 'VOLVE-CI-Real-Motor-0287.exe'
 Copy-Item -LiteralPath $rawMotor -Destination $signedMotor -ErrorAction Stop
 $signed=Set-AuthenticodeSignature -FilePath $signedMotor -Certificate $cert -HashAlgorithm SHA256 -IncludeChain All
 $verified=Get-AuthenticodeSignature -LiteralPath $signedMotor -ErrorAction Stop
 if($signed.Status -ne 'Valid' -or $verified.Status -ne 'Valid' -or
    $verified.SignerCertificate.Thumbprint -cne $thumb){
  throw 'Actual motor was not signed by the approved ephemeral CI test certificate'
 }
 $hash=(Get-FileHash -LiteralPath $signedMotor -Algorithm SHA256).Hash
 if($hash -cnotmatch '^[A-F0-9]{64}$'){throw 'Signed motor fingerprint missing'}
 $tampered=Join-Path $work 'VOLVE-CI-Real-Motor-tampered.exe'
 $bytes=[IO.File]::ReadAllBytes($signedMotor)
 $bytes[$bytes.Length-57]=$bytes[$bytes.Length-57] -bxor 1
 [IO.File]::WriteAllBytes($tampered,$bytes)
 if((Get-FileHash -LiteralPath $tampered -Algorithm SHA256).Hash -ceq $hash){
  throw 'Negative fixture was not modified'
 }
 # The verifier is embedded by NSIS. Its pinned publisher and SHA are
 # compiled into the CI-only package, not read from the staged motor.
 $verifySource=@'
$ErrorActionPreference='Stop'
$receipt=Join-Path $PSScriptRoot 'VOLVE-CI-Verify-Receipt.txt'
function Stop-CIVerify([string]$Reason){
 [IO.File]::WriteAllText($receipt,$Reason,[Text.Encoding]::ASCII)
 exit 27
}
$file=Join-Path $PSScriptRoot 'VOLVE-CI-Real-Motor-0287.exe'
if(-not (Test-Path -LiteralPath $file -PathType Leaf)){Stop-CIVerify 'missing-motor'}
# The NSIS child inherits a different environment than the GitHub Actions
# shell. Load exact Windows PowerShell built-in modules independently of
# PSModulePath auto-loading. This NEVER changes certificate/hash requirements.
try{
 $builtinRoot=Join-Path $PSHOME 'Modules'
 $securityModule=Join-Path $builtinRoot 'Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1'
 $utilityModule=Join-Path $builtinRoot 'Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1'
 Import-Module -Name $securityModule -ErrorAction Stop
 Import-Module -Name $utilityModule -ErrorAction Stop
 $null=Get-Command -Name Get-AuthenticodeSignature -ErrorAction Stop
 $null=Get-Command -Name Get-FileHash -ErrorAction Stop
}catch{
 try{[IO.File]::WriteAllText($receipt,'exception-command-init',[Text.Encoding]::ASCII)}catch{}
 exit 27
}
# Fresh NSIS extraction + Defender scanning may transiently lock the new PE.
# Retry ONLY thrown IO/signature-read errors. Any actual mismatched pin or
# signature is rejected immediately and never converted to success.
Start-Sleep -Milliseconds 1200
for($attempt=0;$attempt -lt 3;$attempt++){
 try {
  $signature=Get-AuthenticodeSignature -LiteralPath $file -ErrorAction Stop
  if($signature.Status -ne 'Valid'){Stop-CIVerify 'auth-status'}
  if($null -eq $signature.SignerCertificate){Stop-CIVerify 'missing-cert'}
  if($signature.SignerCertificate.Thumbprint -cne '__THUMBPRINT__'){Stop-CIVerify 'wrong-cert'}
  $digest=(Get-FileHash -LiteralPath $file -Algorithm SHA256 -ErrorAction Stop).Hash
  if($digest -cne '__MOTOR_SHA256__'){Stop-CIVerify 'wrong-hash'}
  [IO.File]::WriteAllText($receipt,'pass',[Text.Encoding]::ASCII)
  exit 0
 }catch{
  if($attempt -eq 2){
   $kind=$_.Exception.GetType().Name
   if($kind -notmatch '^[A-Za-z]{3,64}$'){$kind='Unknown'}
   $cmd=[string]$_.Exception.CommandName
   $safeCmd='unknown'
   if($cmd -ceq 'Get-AuthenticodeSignature'){$safeCmd='auth'}
   if($cmd -ceq 'Get-FileHash'){$safeCmd='hash'}
   try{[IO.File]::WriteAllText($receipt,'exception-'+$kind+'-'+$safeCmd,[Text.Encoding]::ASCII)}catch{}
   exit 27
  }
  Start-Sleep -Milliseconds 550
 }
}
Stop-CIVerify 'exception'
'@
 $verifySource=$verifySource.Replace('__THUMBPRINT__',$thumb).Replace('__MOTOR_SHA256__',$hash)
 $verifier=Join-Path $work 'VOLVE-CI-Verify-Motor.ps1'
 [IO.File]::WriteAllText($verifier,$verifySource,[Text.UTF8Encoding]::new($false))
 Copy-Item -LiteralPath $terms -Destination (Join-Path $work 'TERMINOS_PREVIEW_0287.txt') -ErrorAction Stop
 $section=@'
Section "CI-only stage signed real motor and bundle (NO INSTALL)" SecPreview
 StrCpy $R1 "$TEMP\VOLVE-CI-ActualMotor-__RUN_ID__-__CASE__"
 SetOutPath "$R1"
 File /oname=VOLVE-CI-Signed-Container.exe "__SIGNED_BUNDLE__"
 File /oname=VOLVE-CI-Real-Motor-0287.exe "__MOTOR__"
 File /oname=VOLVE-CI-Verify-Motor.ps1 "__VERIFY__"
 ExecWait '"$R1\VOLVE-CI-Signed-Container.exe" --verify-bundle' $R0
 StrCmp $R0 0 ci_bundle_ok
 SetErrorLevel 14
 Quit
ci_bundle_ok:
 ; NSIS is a 32-bit process on this x64 CI guest. Sysnative resolves
 ; the 64-bit Windows PowerShell that the CI trust gate checked earlier.
 ExecWait '"$WINDIR\Sysnative\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$R1\VOLVE-CI-Verify-Motor.ps1"' $R0
 ; Preserve ONLY the numeric verifier exit status in the disposable stage.
 FileOpen $R2 "$R1\VOLVE-CI-Checker-ExitCode.txt" w
 FileWrite $R2 "$R0"
 FileClose $R2
 StrCmp $R0 0 ci_motor_ok
 SetErrorLevel 27
 Quit
ci_motor_ok:
 DetailPrint "CI: signed real motor and seven-part bundle verified. NO INSTALL."
SectionEnd
'@
 function Build-VolvCICandidate([string]$case,[string]$motorPath){
  if($case -cnotin @('valid','motor-tampered')){throw 'Unknown test case'}
  foreach($p in @($motorPath,$GoodBundle,$verifier)){
   if($p.Contains('"') -or $p.Contains('$')){throw 'REFUSED: invalid NSIS embedded path'}
  }
  $replacement=$section.Replace('__RUN_ID__',$env:GITHUB_RUN_ID).Replace('__CASE__',$case).
    Replace('__SIGNED_BUNDLE__',$GoodBundle).Replace('__MOTOR__',$motorPath).Replace('__VERIFY__',$verifier)
  $candidate=$original.Substring(0,$match.Index)+$replacement+
    $original.Substring($match.Index+$match.Length)
  $out='VOLVE-CI-ActualMotor-'+$case+'-NO-INSTALL.exe'
  $candidate=$candidate.Replace('OutFile "VOLVE_Asistente_VistaPrevia_0287.exe"','OutFile "'+$out+'"')
  if([regex]::Matches($candidate,'(?im)^\s*File\s+/oname=').Count -ne 3 -or
     [regex]::Matches($candidate,'(?im)^\s*ExecWait\s').Count -ne 2 -or
     -not $candidate.Contains('RequestExecutionLevel user')){
   throw 'REFUSED: unexpected NSIS install directives'
  }
  $nsi=Join-Path $work ($case+'.nsi')
  [IO.File]::WriteAllText($nsi,$candidate,[Text.UTF8Encoding]::new($true))
  Push-Location $work
  try {
   & $compiler '/V3' (Split-Path -Leaf $nsi) | Out-Null
   if($LASTEXITCODE -ne 0){throw 'NSIS compile rejected '+$case}
  }finally {Pop-Location}
  $result=Join-Path $work $out
  if(-not (Test-Path -LiteralPath $result -PathType Leaf)){throw 'NSIS EXE missing'}
  return $result
 }
 function Run-VolvCICandidate([string]$exe){
  $proc=Start-Process -FilePath $exe -ArgumentList '/S' -WindowStyle Hidden -PassThru -ErrorAction Stop
  try {
   if(-not $proc.WaitForExit(60000)){throw 'NSIS stage exceeded 60 seconds'}
   return [int]$proc.ExitCode
  }finally{
   if(-not $proc.HasExited){
    Stop-Process -Id $proc.Id -Force -ErrorAction Stop
    $proc.WaitForExit(5000) | Out-Null
   }
   $proc.Dispose()
  }
 }
 # Windows PowerShell 5.1 is the process launched by NSIS. Validate
 # its own exact trust decision BEFORE compiling the wrapper.
 $winPS=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
 & $winPS '-NoProfile' '-NonInteractive' '-ExecutionPolicy' 'Bypass' '-File' $verifier
 $preNSISVerifierExit=$LASTEXITCODE
 if($preNSISVerifierExit -ne 0){
  $authFromWindows=Get-AuthenticodeSignature -LiteralPath $signedMotor -ErrorAction Stop
  Write-Host ('CI MOTOR PREFLIGHT: windowsPowerShellVerifier=REFUSED; signatureStatus='+$authFromWindows.Status)
  throw 'Windows PowerShell verifier rejected signed motor before NSIS staging'
 }
 $goodCandidate=Build-VolvCICandidate 'valid' $signedMotor
 $goodExit=Run-VolvCICandidate $goodCandidate
 if($goodExit -ne 0){
  $stage=$stages[0]
  $stageExists=Test-Path -LiteralPath $stage -PathType Container
  $motorExists=$stageExists -and (Test-Path -LiteralPath (Join-Path $stage 'VOLVE-CI-Real-Motor-0287.exe') -PathType Leaf)
  $bundleExists=$stageExists -and (Test-Path -LiteralPath (Join-Path $stage 'VOLVE-CI-Signed-Container.exe') -PathType Leaf)
  $verifierExists=$stageExists -and (Test-Path -LiteralPath (Join-Path $stage 'VOLVE-CI-Verify-Motor.ps1') -PathType Leaf)
  $stageSigner='unavailable'
  $stageHashEquals=$false
  if($motorExists){
   $stageSigner=[string](Get-AuthenticodeSignature -LiteralPath (Join-Path $stage 'VOLVE-CI-Real-Motor-0287.exe')).Status
   $stageHashEquals=((Get-FileHash -LiteralPath (Join-Path $stage 'VOLVE-CI-Real-Motor-0287.exe') -Algorithm SHA256).Hash -ceq $hash)
  }
  $verifyReason='missing'
  $reasonPath=Join-Path $stage 'VOLVE-CI-Verify-Receipt.txt'
  if(Test-Path -LiteralPath $reasonPath -PathType Leaf){
   $verifyReason=(Get-Content -LiteralPath $reasonPath -Raw).Trim()
   if(($verifyReason -cnotin @('missing-motor','auth-status','missing-cert','wrong-cert','wrong-hash','pass','exception','exception-command-init')) -and ($verifyReason -cnotmatch '^exception-[A-Za-z]{3,64}(-[a-z]{3,8})?$')){$verifyReason='invalid'}
  }
  $rawChild='missing'
  $childReceipt=Join-Path $stage 'VOLVE-CI-Checker-ExitCode.txt'
  if(Test-Path -LiteralPath $childReceipt -PathType Leaf){
    $rawChild=(Get-Content -LiteralPath $childReceipt -Raw).Trim()
    if($rawChild -notmatch '^[0-9]{1,4}$'){$rawChild='invalid'}
  }
  $stagedWin64=-1;$stagedWin32=-1;$stagedSignerMatch=$false
  if($verifierExists -and $motorExists){
    $stagedVerifier=Join-Path $stage 'VOLVE-CI-Verify-Motor.ps1'
    & $winPS '-NoProfile' '-NonInteractive' '-ExecutionPolicy' 'Bypass' '-File' $stagedVerifier
    $stagedWin64=$LASTEXITCODE
    $winPS32=Join-Path $env:WINDIR 'SysWOW64\WindowsPowerShell\v1.0\powershell.exe'
    & $winPS32 '-NoProfile' '-NonInteractive' '-ExecutionPolicy' 'Bypass' '-File' $stagedVerifier
    $stagedWin32=$LASTEXITCODE
    $stagedSignerMatch=([string](Get-AuthenticodeSignature -LiteralPath (Join-Path $stage 'VOLVE-CI-Real-Motor-0287.exe')).SignerCertificate.Thumbprint -ceq $thumb)
  }
  Write-Host ("CI MOTOR STAGE DIAGNOSTIC: nsisExit=$goodExit; childExit=$rawChild; verifyReason=$verifyReason; stageExists=$stageExists; motorExists=$motorExists; bundleExists=$bundleExists; verifierExists=$verifierExists; signatureStatus=$stageSigner; certPinMatch=$stagedSignerMatch; exactHash=$stageHashEquals; win64ManualExit=$stagedWin64; win32ManualExit=$stagedWin32")
  throw 'Actual signed motor/bundle NSIS stage refused valid inputs'
 }
 $goodStage=$stages[0]
 $names=@(Get-ChildItem -LiteralPath $goodStage -File -ErrorAction Stop|Select-Object -ExpandProperty Name|Sort-Object)
 $expected=@('VOLVE-CI-Checker-ExitCode.txt','VOLVE-CI-Real-Motor-0287.exe','VOLVE-CI-Signed-Container.exe','VOLVE-CI-Verify-Motor.ps1','VOLVE-CI-Verify-Receipt.txt')|Sort-Object
 if(($names -join '|') -cne ($expected -join '|')){throw 'Embedded NSIS package staged unexpected files'}
 if((Get-FileHash -LiteralPath (Join-Path $goodStage 'VOLVE-CI-Real-Motor-0287.exe') -Algorithm SHA256).Hash -cne $hash){
  throw 'Actual motor modified by NSIS staging'
 }
 if((Get-Content -LiteralPath (Join-Path $goodStage 'VOLVE-CI-Verify-Receipt.txt') -Raw).Trim() -cne 'pass'){
  throw 'Embedded motor verifier did not attest real motor'
 }
 $badCandidate=Build-VolvCICandidate 'motor-tampered' $tampered
 if((Run-VolvCICandidate $badCandidate) -ne 27){
  throw 'CRITICAL: tampered actual DNS motor was not rejected by embedded signed+SHA gate'
 }
 Write-Host 'PASS: ONE_NSIS_EXE_STAGES_ACTUAL_WINDOWS_DNS_MOTOR_AND_SIGNED_7_PART_BUNDLE'
 Write-Host 'PASS: MOTOR_AUTHENTICODE_AND_EXACT_SHA256_VERIFIED; TAMPERED_REAL_MOTOR_REFUSED'
}finally{
 foreach($path in $stages){
  if(Test-Path -LiteralPath $path){Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop}
 }
 if(Test-Path -LiteralPath $work){Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction Stop}
 $after=Get-VolvCISafetyBaseline
 foreach($key in @('dns','hosts','tasks')){
  if([string]$baseline.$key -cne [string]$after.$key){
   throw ('FATAL: CI-only embedded motor altered protected Windows '+$key)
  }
 }
 Write-Host 'PASS: ACTUAL_MOTOR_BUNDLE_LAB_LEAVES_WINDOWS_DNS_HOSTS_TASKS_UNCHANGED; NO_RELEASE'
}
