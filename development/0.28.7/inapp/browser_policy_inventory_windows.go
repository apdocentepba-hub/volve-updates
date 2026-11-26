//go:build windows

package motorupdate

// This module fingerprints browser policy registry content locally. It never
// reads browsing history and never exports URL/filter values; only counts and
// SHA-256 fingerprints leave the PowerShell process.
// A registry entry or a stable fingerprint is NOT proof of browser enforcement.
// Motor DNS protection is a separate mechanism.
import (
 "bytes"
 "context"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "os/exec"
 "path/filepath"
 "sort"
 "strings"
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
  # Length-prefixed canonical fingerprint. Raw policy values remain in this
  # process only; they are never serialized into the JSON evidence.
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
     if($name -cmatch '^(?:[1-9][0-9]{0,2}|1000)$'){
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
 ContentSHA256 string `json:"ContentSHA256"`
}

type WindowsBrowserPolicyEvidence struct{
 Schema int `json:"schema"`
 Component string `json:"component"`
 Records []WindowsBrowserPolicyRecord `json:"records"`
 TotalNumberedEntries int `json:"total_numbered_entries"`
 BrowserEnforcementVerified bool `json:"browser_enforcement_verified"`
 DNSMotorVerified bool `json:"dns_motor_verified"`
 NoRegistryValuesExported bool `json:"no_registry_values_exported"`
}

// InspectWindowsBrowserPoliciesReadOnly fails closed on incomplete or
// malformed registry evidence. Each of the three policy locations must be
// inspected; values are represented only by local SHA-256 fingerprints.
func InspectWindowsBrowserPoliciesReadOnly(ctx context.Context,inspect WindowsBrowserPolicyInspect)(WindowsBrowserPolicyEvidence,error){
 var empty WindowsBrowserPolicyEvidence
 if ctx==nil{return empty,errors.New("Windows browser inspection context required")}
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
  if !want[record.Name]{return empty,errors.New("duplicate or unexpected browser registry key")}
  delete(want,record.Name)
  if !hexRe.MatchString(strings.ToLower(record.ContentSHA256)){
   return empty,errors.New("browser policy content fingerprint missing or malformed")
  }
  for _,count:=range []int{record.NumberedEntries,record.InvalidEntries,record.UnexpectedEntries}{
   if count<0||count>1000{return empty,errors.New("impossible browser registry policy count")}
  }
  if !record.Present&&(record.NumberedEntries!=0||record.InvalidEntries!=0||record.UnexpectedEntries!=0){
   return empty,errors.New("missing browser registry cannot contain policy entries")
  }
  if record.NumberedEntries+record.InvalidEntries>1000{
   return empty,errors.New("too many numbered browser registry entries")
  }
  total+=record.NumberedEntries
 }
 if len(want)!=0{return empty,errors.New("one or more browser registry locations were not inspected")}
 if err:=ctx.Err();err!=nil{return empty,err}
 return WindowsBrowserPolicyEvidence{
  Schema:1,Component:"browser-policy-registry-read-only",Records:records,
  TotalNumberedEntries:total,BrowserEnforcementVerified:false,
  DNSMotorVerified:false,NoRegistryValuesExported:true,
 },nil
}

// This local-only backup representation preserves exactly the bytes used by
// the existing fingerprint, including policy names, presence, registry value
// names, kinds and JSON values. It covers only the three existing HKLM keys,
// not HKCU, other registry views, descendant keys or full browser settings.
// It does not write registry values, persist data, or authorize restoration.
const browserOriginalPayloadLimit = 8 << 20

type browserOriginalCaptureRow struct {
 WindowsBrowserPolicyRecord
 PayloadBase64 string
}

// This query is derived only from the fixed, audited read-only inventory.
// The additional data stays in the calling process, never in public evidence.
func browserOriginalCaptureQuery()string{
 q:=strings.Replace(WindowsVOLVEBrowserPolicyQuery,
  "$writer.Flush();","$writer.Flush();if($stream.Length -gt 8388608){throw 'Policy backup exceeds local limit'};$backup=[Convert]::ToBase64String($stream.ToArray());",1)
 q=strings.Replace(q,"ContentSHA256=[string]$digest","ContentSHA256=[string]$digest;PayloadBase64=[string]$backup",1)
 return q
}

func readOriginalBrowserPolicyLocal(ctx context.Context)([]byte,error){
 if ctx==nil{return nil,errors.New("browser backup context required")}
 if err:=ctx.Err();err!=nil{return nil,err}
 root:=os.Getenv("SystemRoot")
 if !filepath.IsAbs(root)||strings.HasPrefix(root,`\\`){return nil,errors.New("local Windows SystemRoot unavailable")}
 ps:=filepath.Join(root,"System32","WindowsPowerShell","v1.0","powershell.exe")
 q:=browserOriginalCaptureQuery()
 if !strings.Contains(q,"PayloadBase64=[string]$backup"){return nil,errors.New("fixed backup query unavailable")}
 out,err:=exec.CommandContext(ctx,ps,"-NoLogo","-NoProfile","-NonInteractive","-Command",q).Output()
 if err!=nil{return nil,errors.New("local read-only browser policy capture failed")}
 return out,nil
}

// The independent baseline must come from a prior read-only inspection.
// Never generate a new trusted pin from the private backup payload.
func captureOriginalBrowserPolicyBytes(ctx context.Context,baseline WindowsBrowserPolicyEvidence,
 readLocal func(context.Context)([]byte,error))(map[string][]byte,error){
 if ctx==nil||readLocal==nil{return nil,errors.New("browser backup requires local reader and context")}
 if err:=ctx.Err();err!=nil{return nil,err}
 if baseline.Schema!=1||baseline.Component!="browser-policy-registry-read-only"||
  !baseline.NoRegistryValuesExported||baseline.BrowserEnforcementVerified||baseline.DNSMotorVerified{
  return nil,errors.New("independent browser policy baseline required")
 }
 // Validate the public record structure again; caller-provided duplicate
 // names, impossible counts and missing digests must not become trusted pins.
 public,err:=json.Marshal(baseline.Records)
 if err!=nil{return nil,errors.New("invalid browser baseline")}
 validated,err:=InspectWindowsBrowserPoliciesReadOnly(ctx,func(context.Context,string)([]byte,error){return public,nil})
 if err!=nil||validated.TotalNumberedEntries!=baseline.TotalNumberedEntries{return nil,errors.New("invalid independent browser policy baseline")}
 expected:=map[string]WindowsBrowserPolicyRecord{}
 for _,p:=range validated.Records{expected[p.Name]=p}
 raw,err:=readLocal(ctx)
 if err!=nil{return nil,errors.New("local browser policy backup unavailable")}
 if len(raw)<2||len(raw)>4*browserOriginalPayloadLimit+65536{return nil,errors.New("local browser policy backup exceeds limit")}
 dec:=json.NewDecoder(bytes.NewReader(raw));dec.DisallowUnknownFields()
 var rows []browserOriginalCaptureRow
 if err:=dec.Decode(&rows);err!=nil{return nil,errors.New("invalid local browser policy backup")}
 var trailing any
 if err:=dec.Decode(&trailing);err!=io.EOF||len(rows)!=3{return nil,errors.New("incomplete local browser policy backup")}
 result:=make(map[string][]byte,3)
 for _,row:=range rows{
  p,ok:=expected[row.Name]
  if !ok{return nil,errors.New("duplicate or unknown policy backup")}
  delete(expected,row.Name)
  observed:=row.WindowsBrowserPolicyRecord
  if !strings.EqualFold(observed.ContentSHA256,p.ContentSHA256){return nil,errors.New("browser policy changed since independent observation")}
  observed.ContentSHA256=p.ContentSHA256
  if observed!=p{return nil,errors.New("browser policy metadata changed since independent observation")}
  data,err:=base64.StdEncoding.Strict().DecodeString(row.PayloadBase64)
  if err!=nil||len(data)==0||len(data)>browserOriginalPayloadLimit{return nil,errors.New("invalid local browser policy bytes")}
  sum:=sha256.Sum256(data)
  if !strings.EqualFold(hex.EncodeToString(sum[:]),p.ContentSHA256){return nil,errors.New("browser policy backup integrity mismatch")}
  result[row.Name]=data
 }
 if len(expected)!=0{return nil,errors.New("missing original browser policy payload")}
 if err:=ctx.Err();err!=nil{return nil,err}
 return result,nil
}

// Create-only local staging; no registry mutation or restoration permit.
// The trusted baseline is external to the archive. A separate native
// adapter and transaction authorization are required before real use.
const browserOriginalArchiveDir="browser-original-backup-v1"
const browserOriginalArchiveFile="original-browser-policies.json"
const browserOriginalArchiveLimit=4*browserOriginalPayloadLimit+65536

func browserOriginalArchivePaths(parent string)(string,string,error){
 if !filepath.IsAbs(parent)||filepath.Clean(parent)!=parent||
  filepath.Base(parent)!="original-protection-recovery"||strings.HasPrefix(parent,`\\`){
  return "","",errors.New("dedicated local original-protection recovery parent required")
 }
 dir:=filepath.Join(parent,browserOriginalArchiveDir)
 return dir,filepath.Join(dir,browserOriginalArchiveFile),nil
}

func storeBrowserOriginalArchiveUnarmed(ctx context.Context,parent string,baseline WindowsBrowserPolicyEvidence,
 data map[string][]byte,seal,check func(string)error)error{
 if ctx==nil||seal==nil||check==nil{return errors.New("browser archive requires context and trusted ACL callbacks")}
 if err:=ctx.Err();err!=nil{return err}
 if len(data)!=3||len(baseline.Records)!=3{return errors.New("three original browser payloads required")}
 rows:=make([]browserOriginalCaptureRow,0,3)
 for _,p:=range baseline.Records{
  value:=data[p.Name]
  if len(value)==0||len(value)>browserOriginalPayloadLimit{return errors.New("browser payload size invalid")}
  rows=append(rows,browserOriginalCaptureRow{WindowsBrowserPolicyRecord:p,PayloadBase64:base64.StdEncoding.EncodeToString(value)})
 }
 raw,err:=json.Marshal(rows)
 if err!=nil||len(raw)>browserOriginalArchiveLimit{return errors.New("browser archive encoding refused")}
 if _,err:=captureOriginalBrowserPolicyBytes(ctx,baseline,func(context.Context)([]byte,error){return raw,nil});err!=nil{return err}
 dir,file,err:=browserOriginalArchivePaths(parent);if err!=nil{return err}
 if err:=verifyOriginalHostsBackupNode(parent,true,check);err!=nil{return err}
 if err:=os.Mkdir(dir,0700);err!=nil{return errors.New("browser archive stage must be new")}
 if err:=seal(dir);err!=nil{return err}
 if err:=verifyOriginalHostsBackupNode(dir,true,check);err!=nil{return err}
 if err:=verifyOriginalHostsBackupNode(parent,true,check);err!=nil{return err}
 if err:=ctx.Err();err!=nil{return err}
 f,err:=os.OpenFile(file,os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600)
 if err!=nil{return err}
 n,writeErr:=f.Write(raw)
 if writeErr==nil&&n!=len(raw){writeErr=io.ErrShortWrite}
 if writeErr==nil{writeErr=f.Sync()}
 closeErr:=f.Close()
 if writeErr!=nil{return writeErr}
 if closeErr!=nil{return closeErr}
 if err:=seal(file);err!=nil{return err}
 _,err=readBrowserOriginalArchiveUnarmed(ctx,parent,baseline,check)
 return err
}

func readBrowserOriginalArchiveUnarmed(ctx context.Context,parent string,baseline WindowsBrowserPolicyEvidence,
 check func(string)error)(map[string][]byte,error){
 if ctx==nil||check==nil{return nil,errors.New("browser archive requires context and ACL verifier")}
 if err:=ctx.Err();err!=nil{return nil,err}
 dir,file,err:=browserOriginalArchivePaths(parent);if err!=nil{return nil,err}
 verify:=func()error{
  if err:=verifyOriginalHostsBackupNode(parent,true,check);err!=nil{return err}
  if err:=verifyOriginalHostsBackupNode(dir,true,check);err!=nil{return err}
  if err:=verifyOriginalHostsBackupNode(file,false,check);err!=nil{return err}
  nodes,err:=os.ReadDir(dir)
  if err!=nil{return err}
  if len(nodes)!=1||nodes[0].Name()!=browserOriginalArchiveFile{return errors.New("ambiguous browser archive directory")}
  return nil
 }
 if err:=verify();err!=nil{return nil,err}
 before,err:=os.Lstat(file);if err!=nil{return nil,err}
 if !before.Mode().IsRegular()||before.Size()<2||before.Size()>browserOriginalArchiveLimit{return nil,errors.New("browser archive file invalid")}
 f,err:=os.Open(file);if err!=nil{return nil,err}
 opened,err:=f.Stat()
 if err!=nil||!os.SameFile(before,opened){f.Close();return nil,errors.New("browser archive changed before opening")}
 raw,readErr:=io.ReadAll(io.LimitReader(f,browserOriginalArchiveLimit+1))
 end,statErr:=f.Stat()
 closeErr:=f.Close()
 if readErr!=nil||statErr!=nil||closeErr!=nil{return nil,errors.New("browser archive read failed")}
 after,err:=os.Lstat(file);if err!=nil{return nil,err}
 if len(raw)>browserOriginalArchiveLimit||!after.Mode().IsRegular()||!os.SameFile(before,after)||
  !os.SameFile(opened,end)||before.Size()!=end.Size()||before.Size()!=after.Size()||
  before.Size()!=int64(len(raw))||!before.ModTime().Equal(end.ModTime())||!before.ModTime().Equal(after.ModTime()){
  return nil,errors.New("browser archive changed during read")
 }
 if err:=verify();err!=nil{return nil,err}
 return captureOriginalBrowserPolicyBytes(ctx,baseline,func(context.Context)([]byte,error){return raw,nil})
}

// A partial backup receipt intentionally excludes raw hosts and registry values.
// A verified pair is NOT a complete restore snapshot: catalog, DNS, policy
// coverage, transaction binding, and an authenticated recovery controller
// are separate requirements. No install or restore authorization is issued.
type originalProtectionPairReceipt struct {
 HostsVerified bool
 BrowserKeysVerified int
 CatalogBackupVerified bool
 DNSBackupVerified bool
 CompleteRecoverySnapshot bool
 InstallAuthorized bool
 RestoreAuthorized bool
}

func verifyOriginalProtectionPairUnarmed(ctx context.Context,parent string,
 baseline ProtectionSnapshot,browser WindowsBrowserPolicyEvidence,
 check func(string)error)(originalProtectionPairReceipt,error){
 var denied originalProtectionPairReceipt
 if ctx==nil||check==nil{return denied,errors.New("paired backup verification requires context and trusted ACL verifier")}
 if err:=ctx.Err();err!=nil{return denied,err}
 if !validProtectionSnapshot(baseline){return denied,errors.New("independent protection baseline incomplete")}
 // Bind both archives to the SAME original protection census rather than
 // trusting a browser record from an unrelated operation.
 public,err:=json.Marshal(browser.Records)
 if err!=nil{return denied,errors.New("browser baseline encoding refused")}
 validated,err:=InspectWindowsBrowserPoliciesReadOnly(ctx,func(context.Context,string)([]byte,error){return public,nil})
 if err!=nil||validated.TotalNumberedEntries!=browser.TotalNumberedEntries||
  browser.Schema!=1||browser.Component!="browser-policy-registry-read-only"||
  !browser.NoRegistryValuesExported||browser.BrowserEnforcementVerified||browser.DNSMotorVerified{
  return denied,errors.New("independent browser baseline invalid")
 }
 pins:=map[string]string{"chrome":baseline.ChromePoliciesSHA256,"edge":baseline.EdgePoliciesSHA256,"firefox":baseline.FirefoxPoliciesSHA256}
 for _,record:=range validated.Records{
  if !strings.EqualFold(record.ContentSHA256,pins[record.Name]){return denied,errors.New("browser backup belongs to a different protection baseline")}
 }
 hostsPin:=WindowsHostsFileEvidence{SHA256:baseline.HostsSHA256,BlockedRuleCount:baseline.HostsBlockedRuleCount}
 if _,err:=readOriginalWindowsHostsBackupUnarmed(ctx,parent,hostsPin,check);err!=nil{return denied,fmt.Errorf("original hosts backup not verified: %w",err)}
 policies,err:=readBrowserOriginalArchiveUnarmed(ctx,parent,browser,check)
 if err!=nil||len(policies)!=3{return denied,errors.New("three original browser archives not verified")}
 // Independently check the hosts archive again after browser I/O. This is
 // not an atomic filesystem snapshot; the future controller must keep its
 // authenticated transaction lock and validate live state before mutation.
 if _,err:=readOriginalWindowsHostsBackupUnarmed(ctx,parent,hostsPin,check);err!=nil{return denied,errors.New("original hosts backup changed while verifying pair")}
 if err:=ctx.Err();err!=nil{return denied,err}
 return originalProtectionPairReceipt{HostsVerified:true,BrowserKeysVerified:3},nil
}

// Compare original records from the independently pinned, verified journal
// to the stable Windows assignment provenance fingerprint. Automatic states
// use [] in the provenance encoding, not the journal's nil server slice.
// Preserve exact static server ordering and address spelling.
func originalDNSRecordsMatchProtectionBaseline(records []DNSRestoreRecord,baseline ProtectionSnapshot)error{
 if !validProtectionSnapshot(baseline){return errors.New("independent protection baseline incomplete")}
 if err:=validateDNSRecoveryRecords(records);err!=nil{return err}
 states:=make([]DNSServerState,0,len(records))
 for _,record:=range records{
  s:=record.Original
  s.InterfaceGUID=strings.ToLower(s.InterfaceGUID)
  s.Servers=append([]string{},s.Servers...)
  states=append(states,s)
 }
 sort.Slice(states,func(i,j int)bool{
  return states[i].InterfaceGUID+string(states[i].Family)<states[j].InterfaceGUID+string(states[j].Family)
 })
 raw,err:=json.Marshal(states)
 if err!=nil{return errors.New("original DNS provenance encoding failed")}
 sum:=sha256.Sum256(raw)
 if !strings.EqualFold(hex.EncodeToString(sum[:]),baseline.DNSAdaptersSHA256){
  return errors.New("original DNS journal belongs to a different protection baseline")
 }
 return nil
}

// Verify three local backups under one transaction directory. The caller
// must authenticate the independent pins and hold the relevant lock; this
// observation alone is not atomic, signed, or a restore/activation permit.
// Catalog and full browser-policy coverage remain outstanding.
func verifyOriginalProtectionTripleUnarmed(ctx context.Context,protectionParent,dnsParent string,
 baseline ProtectionSnapshot,browser WindowsBrowserPolicyEvidence,dnsJournalPin string,
 check func(string)error)(originalProtectionPairReceipt,error){
 var denied originalProtectionPairReceipt
 if ctx==nil||check==nil{return denied,errors.New("triple verification requires context and trusted ACL verifier")}
 if err:=ctx.Err();err!=nil{return denied,err}
 if !filepath.IsAbs(dnsParent)||filepath.Clean(dnsParent)!=dnsParent||
  filepath.Base(dnsParent)!="legacy-engine-recovery"||
  !strings.EqualFold(filepath.Dir(dnsParent),filepath.Dir(protectionParent)){
  return denied,errors.New("recovery parents must belong to the same local transaction directory")
 }
 if !protectionDigest.MatchString(strings.ToLower(dnsJournalPin)){return denied,errors.New("independent DNS journal pin required")}
 receipt,err:=verifyOriginalProtectionPairUnarmed(ctx,protectionParent,baseline,browser,check)
 if err!=nil{return denied,err}
 records,err:=ReadStagedDNSOriginalBackupUnarmed(ctx,dnsParent,dnsJournalPin,check)
 if err!=nil{return denied,errors.New("original DNS backup not verified")}
 if err:=originalDNSRecordsMatchProtectionBaseline(records,baseline);err!=nil{return denied,err}
 if err:=ctx.Err();err!=nil{return denied,err}
 receipt.DNSBackupVerified=true
 return receipt,nil
}
