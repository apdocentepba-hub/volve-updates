//go:build windows

package motorupdate

// This module observes only the existence and anonymous numeric entry counts
// of the browser policy keys used by legacy VOLVE 0.28.6. It never reads any
// browsing history and deliberately never returns URL/filter values.
// A registry entry is NOT evidence that a browser applied or enforced it.
// In particular, motor DNS protection is a separate mechanism.
import (
 "bytes"
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "os/exec"
 "path/filepath"
)

const WindowsVOLVEBrowserPolicyQuery = `$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';
$policies=@(
 @{Name='chrome';Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome\URLBlocklist'},
 @{Name='edge';Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge\URLBlocklist'},
 @{Name='firefox';Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox\WebsiteFilter\Block'}
);
$items=@(foreach($spec in $policies){
 $exists=Test-Path -LiteralPath $spec.Path -PathType Container -ErrorAction Stop;
 $numbered=0;$invalid=0;$unexpected=0;
 $stream=[IO.MemoryStream]::new();
 $writer=[IO.BinaryWriter]::new($stream,[Text.Encoding]::UTF8);
 try {
  # Length-prefixed canonical fingerprint; raw policy values never leave
  # this PowerShell process and are never serialized to the JSON report.
  $writer.Write([string]$spec.Name);$writer.Write([bool]$exists);
  if($exists){
   $key=Get-Item -LiteralPath $spec.Path -ErrorAction Stop;
   try {
    [string[]]$names=@($key.GetValueNames());
    [Array]::Sort($names,[StringComparer]::Ordinal);
    $writer.Write([int]$names.Length);
    foreach($name in $names){
     $kind=[string]$key.GetValueKind($name);
     $value=$key.GetValue($name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames);
     $canonical=ConvertTo-Json -InputObject $value -Compress -Depth 8;
     $writer.Write([string]$name);$writer.Write($kind);$writer.Write([string]$canonical);
     if($name -cmatch '^(?:[1-9][0-9]{0,2}|1000)
ConvertTo-Json -InputObject $items -Compress -Depth 4`

type WindowsBrowserPolicyInspect func(context.Context,string)([]byte,error)

func DefaultWindowsBrowserPolicyInspect(ctx context.Context,query string)([]byte,error){
 if query!=WindowsVOLVEBrowserPolicyQuery{
  return nil,errors.New("only fixed read-only VOLVE browser registry inventory is permitted")
 }
 if err:=ctx.Err();err!=nil{return nil,err}
 root:=os.Getenv("SystemRoot")
 if !filepath.IsAbs(root){return nil,errors.New("Windows SystemRoot unavailable")}
 powershell:=filepath.Join(root,"System32","WindowsPowerShell","v1.0","powershell.exe")
 out,err:=exec.CommandContext(ctx,powershell,"-NoLogo","-NoProfile","-NonInteractive","-Command",query).Output()
 if err!=nil{return nil,fmt.Errorf("read-only browser policy registry observation failed: %w",err)}
 return out,nil
}

type WindowsBrowserPolicyRecord struct{
 Name string `json:"Name"`
 Present bool `json:"Present"`
 NumberedEntries int `json:"NumberedEntries"`
 InvalidEntries int `json:"InvalidEntries"`
 UnexpectedEntries int `json:"UnexpectedEntries"`
 ContentSHA256 string `json:"ContentSHA256"`
}

type WindowsBrowserPolicyEvidence struct{
 Schema int `json:"schema"`
 Component string `json:"component"`
 Records []WindowsBrowserPolicyRecord `json:"records"`
 TotalNumberedEntries int `json:"total_numbered_entries"`
 BrowserEnforcementVerified bool `json:"browser_enforcement_verified"`
 DNSMotorVerified bool `json:"dns_motor_verified"`
 NoRegistryValuesCollected bool `json:"no_registry_values_collected"`
}

// InspectWindowsBrowserPoliciesReadOnly is an independent, potentially partial
// view of the previous CENTRO's registry-policy controls. Fail closed on
// malformed/injected data. All 3 policy keys must be independently queried;
// empty values and unrecognized slots are reported as anomalies, never hidden.
func InspectWindowsBrowserPoliciesReadOnly(ctx context.Context,inspect WindowsBrowserPolicyInspect)(WindowsBrowserPolicyEvidence,error){
 var empty WindowsBrowserPolicyEvidence
 if err:=ctx.Err();err!=nil{return empty,err}
 if inspect==nil{return empty,errors.New("Windows browser registry reader unavailable")}
 raw,err:=inspect(ctx,WindowsVOLVEBrowserPolicyQuery)
 if err!=nil{return empty,err}
 if len(raw)<2||len(raw)>8192{return empty,errors.New("browser registry evidence empty or oversized")}
 dec:=json.NewDecoder(bytes.NewReader(raw));dec.DisallowUnknownFields()
 var records []WindowsBrowserPolicyRecord
 if err:=dec.Decode(&records);err!=nil{return empty,fmt.Errorf("invalid browser policy evidence: %w",err)}
 var trailing any
 if err:=dec.Decode(&trailing);err!=io.EOF{return empty,errors.New("unexpected trailing browser policy evidence")}
 if len(records)!=3{return empty,errors.New("three independent browser registries required")}
 want:=map[string]bool{"chrome":true,"edge":true,"firefox":true}
 total:=0
 for _,record:=range records{
  if !want[record.Name] {return empty,errors.New("duplicate or unexpected browser registry key")}
  delete(want,record.Name)
  if !hexRe.MatchString(strings.ToLower(record.ContentSHA256)) {
   return empty,errors.New("browser policy content fingerprint missing or malformed")
  }
  for _,count:=range []int{record.NumberedEntries,record.InvalidEntries,record.UnexpectedEntries}{
   if count<0||count>1000{return empty,errors.New("impossible browser registry policy count")}
  }
  if !record.Present && (record.NumberedEntries!=0||record.InvalidEntries!=0||record.UnexpectedEntries!=0){
   return empty,errors.New("missing browser registry cannot contain policy entries")
  }
  if record.NumberedEntries+record.InvalidEntries>1000{
   return empty,errors.New("too many numbered browser registry entries")
  }
  total+=record.NumberedEntries
 }
 if err:=ctx.Err();err!=nil{return empty,err}
 return WindowsBrowserPolicyEvidence{
  Schema:1,Component:"browser-policy-registry-read-only",Records:records,
  TotalNumberedEntries:total,BrowserEnforcementVerified:false,
  DNSMotorVerified:false,NoRegistryValuesCollected:true,
 },nil
}
){
      if($value -is [string] -and $value.Length -gt 0 -and $value.Length -le 2048){$numbered++}
      else{$invalid++}
     } else{$unexpected++}
    }
   } finally { $key.Close() }
  } else {$writer.Write([int]0)}
  $writer.Flush();
  $sha=[Security.Cryptography.SHA256]::Create();
  try {$digest=[BitConverter]::ToString($sha.ComputeHash($stream.ToArray())).Replace('-','').ToLowerInvariant()}
  finally {$sha.Dispose()}
 } finally {$writer.Dispose();$stream.Dispose()}
 [pscustomobject]@{
  Name=[string]$spec.Name;Present=[bool]$exists;
  NumberedEntries=[int]$numbered;InvalidEntries=[int]$invalid;
  UnexpectedEntries=[int]$unexpected;ContentSHA256=[string]$digest
 }
});
ConvertTo-Json -InputObject $items -Compress -Depth 4`

type WindowsBrowserPolicyInspect func(context.Context,string)([]byte,error)

func DefaultWindowsBrowserPolicyInspect(ctx context.Context,query string)([]byte,error){
 if query!=WindowsVOLVEBrowserPolicyQuery{
  return nil,errors.New("only fixed read-only VOLVE browser registry inventory is permitted")
 }
 if err:=ctx.Err();err!=nil{return nil,err}
 root:=os.Getenv("SystemRoot")
 if !filepath.IsAbs(root){return nil,errors.New("Windows SystemRoot unavailable")}
 powershell:=filepath.Join(root,"System32","WindowsPowerShell","v1.0","powershell.exe")
 out,err:=exec.CommandContext(ctx,powershell,"-NoLogo","-NoProfile","-NonInteractive","-Command",query).Output()
 if err!=nil{return nil,fmt.Errorf("read-only browser policy registry observation failed: %w",err)}
 return out,nil
}

type WindowsBrowserPolicyRecord struct{
 Name string `json:"Name"`
 Present bool `json:"Present"`
 NumberedEntries int `json:"NumberedEntries"`
 InvalidEntries int `json:"InvalidEntries"`
 UnexpectedEntries int `json:"UnexpectedEntries"`
}

type WindowsBrowserPolicyEvidence struct{
 Schema int `json:"schema"`
 Component string `json:"component"`
 Records []WindowsBrowserPolicyRecord `json:"records"`
 TotalNumberedEntries int `json:"total_numbered_entries"`
 BrowserEnforcementVerified bool `json:"browser_enforcement_verified"`
 DNSMotorVerified bool `json:"dns_motor_verified"`
 NoRegistryValuesCollected bool `json:"no_registry_values_collected"`
}

// InspectWindowsBrowserPoliciesReadOnly is an independent, potentially partial
// view of the previous CENTRO's registry-policy controls. Fail closed on
// malformed/injected data. All 3 policy keys must be independently queried;
// empty values and unrecognized slots are reported as anomalies, never hidden.
func InspectWindowsBrowserPoliciesReadOnly(ctx context.Context,inspect WindowsBrowserPolicyInspect)(WindowsBrowserPolicyEvidence,error){
 var empty WindowsBrowserPolicyEvidence
 if err:=ctx.Err();err!=nil{return empty,err}
 if inspect==nil{return empty,errors.New("Windows browser registry reader unavailable")}
 raw,err:=inspect(ctx,WindowsVOLVEBrowserPolicyQuery)
 if err!=nil{return empty,err}
 if len(raw)<2||len(raw)>8192{return empty,errors.New("browser registry evidence empty or oversized")}
 dec:=json.NewDecoder(bytes.NewReader(raw));dec.DisallowUnknownFields()
 var records []WindowsBrowserPolicyRecord
 if err:=dec.Decode(&records);err!=nil{return empty,fmt.Errorf("invalid browser policy evidence: %w",err)}
 var trailing any
 if err:=dec.Decode(&trailing);err!=io.EOF{return empty,errors.New("unexpected trailing browser policy evidence")}
 if len(records)!=3{return empty,errors.New("three independent browser registries required")}
 want:=map[string]bool{"chrome":true,"edge":true,"firefox":true}
 total:=0
 for _,record:=range records{
  if !want[record.Name] {return empty,errors.New("duplicate or unexpected browser registry key")}
  delete(want,record.Name)
  for _,count:=range []int{record.NumberedEntries,record.InvalidEntries,record.UnexpectedEntries}{
   if count<0||count>1000{return empty,errors.New("impossible browser registry policy count")}
  }
  if !record.Present && (record.NumberedEntries!=0||record.InvalidEntries!=0||record.UnexpectedEntries!=0){
   return empty,errors.New("missing browser registry cannot contain policy entries")
  }
  if record.NumberedEntries+record.InvalidEntries>1000{
   return empty,errors.New("too many numbered browser registry entries")
  }
  total+=record.NumberedEntries
 }
 if err:=ctx.Err();err!=nil{return empty,err}
 return WindowsBrowserPolicyEvidence{
  Schema:1,Component:"browser-policy-registry-read-only",Records:records,
  TotalNumberedEntries:total,BrowserEnforcementVerified:false,
  DNSMotorVerified:false,NoRegistryValuesCollected:true,
 },nil
}
