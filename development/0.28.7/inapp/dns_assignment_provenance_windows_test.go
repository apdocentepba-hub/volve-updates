//go:build windows

package motorupdate

import (
 "context"
 "encoding/json"
 "errors"
 "os"
 "os/exec"
 "path/filepath"
 "time"
 "strings"
 "testing"
)

const testDNSGUID="{01234567-89ab-cdef-0123-456789abcdef}"

func protectionSnapshotDNSJSON()[]byte{
 return []byte(`[{"InterfaceGUID":"`+testDNSGUID+`","InterfaceIndex":7,"Family":"IPv4","RegistryKeyPresent":true,"NameServerPresent":true,"NameServerKind":"String","NameServerNonEmpty":true,"ProfileNameServerNonEmpty":false,"Mode":"static","Servers":["1.1.1.1","8.8.8.8"],"EffectiveServers":["1.1.1.1","8.8.8.8"]},`+
  `{"InterfaceGUID":"`+testDNSGUID+`","InterfaceIndex":7,"Family":"IPv6","RegistryKeyPresent":true,"NameServerPresent":false,"NameServerKind":"Missing","NameServerNonEmpty":false,"ProfileNameServerNonEmpty":false,"Mode":"automatic","Servers":[],"EffectiveServers":["2606:4700:4700::1111"]}]`)
}

func TestWindowsDNSAssignmentProvenanceSeparatesStaticAndAutomatic(t *testing.T){
 calls:=0
 evidence,err:=InspectWindowsDNSAssignmentProvenanceReadOnly(context.Background(),func(_ context.Context,query string)([]byte,error){
  calls++
  if query!=windowsDNSAssignmentSourceQuery{t.Fatal("unexpected or mutable DNS command")}
  return protectionSnapshotDNSJSON(),nil
 })
 if err!=nil{t.Fatal(err)}
 if calls!=1||evidence.Schema!=1||evidence.Component!="windows-dns-assignment-provenance-read-only"||
  evidence.AdapterCount!=1||evidence.StaticFamilyCount!=1||evidence.AutomaticFamilyCount!=1||
  len(evidence.States)!=2||len(evidence.SHA256)!=64{
  t.Fatalf("DNS assignment evidence incomplete: %+v",evidence)
 }
 if evidence.States[0].Family!=DNSIPv4||evidence.States[0].Mode!=DNSStatic||
  !sameDNSAddresses(evidence.States[0].Servers,[]string{"1.1.1.1","8.8.8.8"})||
  evidence.States[1].Family!=DNSIPv6||evidence.States[1].Mode!=DNSAutomatic||
  len(evidence.States[1].Servers)!=0{
  t.Fatalf("static/automatic provenance was misclassified: %+v",evidence.States)
 }
}

func TestWindowsDNSAssignmentProvenanceRejectsUnknownOrConflictingSource(t *testing.T){
 base:=string(protectionSnapshotDNSJSON())
 cases:=[]struct{name,replace string}{
  {"profile-specific",`"ProfileNameServerNonEmpty":false`},
  {"unsupported-type",`"NameServerKind":"UnsupportedValueType"`},
  {"static-effective-mismatch",`"EffectiveServers":["9.9.9.9","8.8.8.8"]`},
  {"wrong-family-ip",`"Servers":["2001:4860:4860::8888"]`},
  {"missing-static-value",`"NameServerNonEmpty":false`},
  {"wrong-mode",`"Mode":"dhcp"`},
  {"bad-interface-guid",`"InterfaceGUID":"not-a-guid"`},
 }
 for _,tc:=range cases{t.Run(tc.name,func(t *testing.T){
  raw:=base
  switch tc.name{
  case "profile-specific":raw=strings.Replace(raw,`"ProfileNameServerNonEmpty":false`,`"ProfileNameServerNonEmpty":true`,1)
  case "unsupported-type":raw=strings.Replace(raw,`"NameServerKind":"String"`,tc.replace,1)
  case "static-effective-mismatch":raw=strings.Replace(raw,`"EffectiveServers":["1.1.1.1","8.8.8.8"]`,tc.replace,1)
  case "wrong-family-ip":raw=strings.Replace(raw,`"Servers":["1.1.1.1","8.8.8.8"]`,tc.replace,1)
  case "missing-static-value":raw=strings.Replace(raw,`"NameServerNonEmpty":true`,tc.replace,1)
  case "wrong-mode":raw=strings.Replace(raw,`"Mode":"static"`,tc.replace,1)
  case "bad-interface-guid":raw=strings.Replace(raw,`"InterfaceGUID":"`+testDNSGUID+`"`,tc.replace,1)
  }
  if _,err:=InspectWindowsDNSAssignmentProvenanceReadOnly(context.Background(),func(context.Context,string)([]byte,error){return []byte(raw),nil});err==nil{
   t.Fatal("contradictory or untrusted DNS source accepted")
  }
 })}
}

func TestWindowsDNSAssignmentProvenanceRejectsDuplicateOrIncompleteFamilies(t *testing.T){
 base:=string(protectionSnapshotDNSJSON())
 duplicate:=strings.Replace(base,`{"InterfaceGUID":"`+testDNSGUID+`","InterfaceIndex":7,"Family":"IPv6"`,`{"InterfaceGUID":"`+testDNSGUID+`","InterfaceIndex":7,"Family":"IPv4"`,1)
 missingIPv6:=strings.Replace(base,`,{"InterfaceGUID":"`+testDNSGUID+`","InterfaceIndex":7,"Family":"IPv6","RegistryKeyPresent":true,"NameServerPresent":false,"NameServerKind":"Missing","NameServerNonEmpty":false,"ProfileNameServerNonEmpty":false,"Mode":"automatic","Servers":[],"EffectiveServers":["2606:4700:4700::1111"]}`,`]`,1)
 for name,raw:=range map[string]string{"duplicate-family":duplicate,"missing-ipv6":missingIPv6}{
  t.Run(name,func(t *testing.T){
   if _,err:=InspectWindowsDNSAssignmentProvenanceReadOnly(context.Background(),func(context.Context,string)([]byte,error){return []byte(raw),nil});err==nil{
    t.Fatal("duplicate or incomplete adapter-family inventory accepted")
   }
  })
 }
}

func TestWindowsDNSAssignmentFingerprintIgnoresAutomaticLeaseAddressButPreservesStaticOrder(t *testing.T){
 one,err:=InspectWindowsDNSAssignmentProvenanceReadOnly(context.Background(),func(context.Context,string)([]byte,error){return protectionSnapshotDNSJSON(),nil})
 if err!=nil{t.Fatal(err)}
 raw:=strings.Replace(string(protectionSnapshotDNSJSON()),"2606:4700:4700::1111","2001:4860:4860::8888",1)
 two,err:=InspectWindowsDNSAssignmentProvenanceReadOnly(context.Background(),func(context.Context,string)([]byte,error){return []byte(raw),nil})
 if err!=nil{t.Fatal(err)}
 if one.SHA256!=two.SHA256{t.Fatal("automatic DHCP/RA lease address changed the configured-source fingerprint")}
 raw=string(protectionSnapshotDNSJSON())
 raw=strings.Replace(raw,`"Servers":["1.1.1.1","8.8.8.8"]`,`"Servers":["8.8.8.8","1.1.1.1"]`,1)
 raw=strings.Replace(raw,`"EffectiveServers":["1.1.1.1","8.8.8.8"]`,`"EffectiveServers":["8.8.8.8","1.1.1.1"]`,1)
 three,err:=InspectWindowsDNSAssignmentProvenanceReadOnly(context.Background(),func(context.Context,string)([]byte,error){return []byte(raw),nil})
 if err!=nil{t.Fatal(err)}
 if one.SHA256==three.SHA256{t.Fatal("static DNS server order change was omitted from source fingerprint")}
}

func TestWindowsDNSAssignmentProvenanceRejectsCancellationAndMutableQueries(t *testing.T){
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 calls:=0
 _,err:=InspectWindowsDNSAssignmentProvenanceReadOnly(ctx,func(context.Context,string)([]byte,error){calls++;return nil,nil})
 if !errors.Is(err,context.Canceled)||calls!=0{t.Fatalf("cancelled DNS inventory ran: calls=%d err=%v",calls,err)}
 if _,err:=DefaultWindowsReadOnlyPowerShell(context.Background(),"Set-DnsClientServerAddress -ResetServerAddresses");err==nil{
  t.Fatal("mutable PowerShell DNS command accepted by read-only runner")
 }
}

func TestWindowsDNSAssignmentProvenanceNativeWindowsReadOnly(t *testing.T){
 if testing.Short(){t.Skip("requires native Windows CI host")}
 evidence,err:=InspectWindowsDNSAssignmentProvenanceReadOnly(context.Background(),DefaultWindowsReadOnlyPowerShell)
 if err!=nil{
  safeRefusal:=strings.Contains(err.Error(),"DNS servers exist on an interface without a unique adapter GUID")||
   strings.Contains(err.Error(),"DNS interface index maps to conflicting adapter GUIDs")||
   strings.Contains(err.Error(),"DNS assignment registry key missing")||
   strings.Contains(err.Error(),"Unknown DNS client address family")
  if safeRefusal{
   t.Logf("SAFE REFUSAL native Windows DNS assignment census: %v; install remains prohibited",err)
   return
  }
  t.Fatal(err)
 }
 if evidence.AdapterCount==0||evidence.StaticFamilyCount+evidence.AutomaticFamilyCount!=len(evidence.States)||
  len(evidence.SHA256)!=64{
  t.Fatalf("native Windows DNS provenance incomplete: %+v",evidence)
 }
 t.Logf("READ ONLY native Windows DNS provenance: adapters=%d static_families=%d automatic_families=%d",
  evidence.AdapterCount,evidence.StaticFamilyCount,evidence.AutomaticFamilyCount)
}


func TestWindowsDNSAssignmentProvenanceRejectsMissingNullAndAliasedEvidence(t *testing.T){
 base:=string(protectionSnapshotDNSJSON())
 fields:=[]struct{key,value string}{
  {"InterfaceGUID",`"{01234567-89ab-cdef-0123-456789abcdef}"`},
  {"InterfaceIndex",`7`},
  {"Family",`"IPv4"`},
  {"RegistryKeyPresent",`true`},
  {"NameServerPresent",`true`},
  {"NameServerKind",`"String"`},
  {"NameServerNonEmpty",`true`},
  {"ProfileNameServerNonEmpty",`false`},
  {"Mode",`"static"`},
  {"Servers",`["1.1.1.1","8.8.8.8"]`},
  {"EffectiveServers",`["1.1.1.1","8.8.8.8"]`},
 }
 for _,field:=range fields{
  key:=`"`+field.key+`"`
  pair:=key+":"+field.value
  if !strings.Contains(base,pair){t.Fatalf("fixture missing %s",field.key)}
  missing:=strings.Replace(base,pair+",","",1)
  if missing==base{missing=strings.Replace(base,","+pair,"",1)}
  variants:=map[string]string{
   "missing":missing,
   "null":strings.Replace(base,pair,key+":null",1),
   "duplicate":strings.Replace(base,pair,pair+","+pair,1),
   "case-alias":strings.Replace(base,pair,`"`+strings.ToLower(field.key)+`":`+field.value,1),
  }
  for name,raw:=range variants{
   t.Run(field.key+"/"+name,func(t *testing.T){
    if raw==base{t.Fatal("mutation did not change fixture")}
    if evidence,err:=InspectWindowsDNSAssignmentProvenanceReadOnly(context.Background(),func(context.Context,string)([]byte,error){return []byte(raw),nil});err==nil||len(evidence.States)!=0||evidence.SHA256!=""{
     t.Fatal("incomplete/ambiguous DNS provenance admitted")
    }
   })
  }
 }
 for _,raw:=range []string{
  strings.Replace(base,`"Servers":["1.1.1.1","8.8.8.8"]`,`"Servers":[null,"8.8.8.8"]`,1),
  strings.Replace(base,`"EffectiveServers":["2606:4700:4700::1111"]`,`"EffectiveServers":[null]`,1),
  strings.Replace(base,`"ProfileNameServerNonEmpty":false`,`"ProfileNameServerNonEmpty":false,"Unexpected":false`,1),
 }{
  if _,err:=InspectWindowsDNSAssignmentProvenanceReadOnly(context.Background(),func(context.Context,string)([]byte,error){return []byte(raw),nil});err==nil{t.Fatal("invalid DNS record accepted")}
 }
}


// Execute the exact PowerShell predicate, not a second Go implementation.
// No Windows DNS, adapter, registry, or task operation is issued.
func TestWindowsDNSUnmappedLoopbackPlaceholderGuard(t *testing.T){
 script:=windowsDNSLoopbackPlaceholderGuard+`
$ErrorActionPreference='Stop'
$exact=@('fec0:0:0:ffff::1','fec0:0:0:ffff::2','fec0:0:0:ffff::3')
function Assert-Guard([bool]$expected,[string]$family,[uint32]$index,[object[]]$servers,[uint32[]]$loopIndexes,[int]$mapped){
 $actual=Test-VolvUnmappedLoopbackPlaceholders -family $family -index $index -servers $servers -loopbackIPv6Indexes $loopIndexes -mappedGUIDCount $mapped
 if($actual -ne $expected){throw 'Unexpected loopback placeholder classification'}
}
Assert-Guard $true 'IPv6' 1 $exact @(1) 0
Assert-Guard $true 'IPv6' 27 $exact @(27) 0
Assert-Guard $false 'IPv6' 1 $exact @(1) 1
Assert-Guard $false 'IPv6' 1 $exact @(1) 2
Assert-Guard $false 'IPv4' 1 $exact @(1) 0
Assert-Guard $false 'IPv6' 1 $exact @(2) 0
Assert-Guard $false 'IPv6' 1 $exact @(1,2) 0
Assert-Guard $false 'IPv6' 1 $exact @(1,1) 0
Assert-Guard $false 'IPv6' 1 $exact @() 0
Assert-Guard $false 'IPv6' 0 $exact @(0) 0
Assert-Guard $false 'IPv6' 1 @('fec0:0:0:ffff::1') @(1) 0
Assert-Guard $false 'IPv6' 1 @('fec0:0:0:ffff::1','fec0:0:0:ffff::2','::1') @(1) 0
Assert-Guard $false 'IPv6' 1 @('fec0:0:0:ffff::1','fec0:0:0:ffff::2','2001:4860:4860::8888') @(1) 0
Assert-Guard $false 'IPv6' 1 @('fec0:0:0:ffff::1','fec0:0:0:ffff::1','fec0:0:0:ffff::3') @(1) 0
Write-Output 'VOLVE_LOOPBACK_PLACEHOLDER_GUARD_14_PASS'
`
 path:=filepath.Join(t.TempDir(),"loopback-guard.ps1")
 if err:=os.WriteFile(path,[]byte(script),0600);err!=nil{t.Fatal(err)}
 root:=os.Getenv("SystemRoot")
 if !filepath.IsAbs(root){t.Fatal("Windows system root unavailable")}
 ps:=filepath.Join(root,"System32","WindowsPowerShell","v1.0","powershell.exe")
 ctx,cancel:=context.WithTimeout(context.Background(),30*time.Second);defer cancel()
 raw,err:=exec.CommandContext(ctx,ps,"-NoLogo","-NoProfile","-NonInteractive","-File",path).CombinedOutput()
 if err!=nil||strings.TrimSpace(string(raw))!="VOLVE_LOOPBACK_PLACEHOLDER_GUARD_14_PASS"{t.Fatalf("native loopback guard test failed: %v %s",err,raw)}
}

func TestWindowsDNSOverrideCensusStrictEvidence(t *testing.T){
 base:=`{"schema":1,"component":"windows-dns-override-census-v1","local_nrpt_rules":0,"effective_nrpt_policies":0,"doh_cmdlet_available":true,"known_doh_servers":3,"dns_group_policy_key_present":false,"dns_group_policy_values":0,"dns_group_policy_subkeys":0,"local_nrpt_sha256":"`+strings.Repeat("a",64)+`","effective_nrpt_sha256":"`+strings.Repeat("b",64)+`","known_doh_sha256":"`+strings.Repeat("c",64)+`","dns_group_policy_sha256":"`+strings.Repeat("d",64)+`"}`
 read:=func(raw string)(WindowsDNSOverrideCensus,error){
  return InspectWindowsDNSOverrideCensusReadOnly(context.Background(),func(_ context.Context,q string)([]byte,error){
   if q!=windowsDNSOverrideCensusQuery{t.Fatal("unexpected query")}
   return []byte(raw),nil
  })
 }
 got,err:=read(base)
 if err!=nil||!got.DoHCmdletAvailable||got.KnownDoHServers!=3{t.Fatal("valid census refused",err)}
 changed,err:=read(strings.Replace(base,strings.Repeat("c",64),strings.Repeat("e",64),1))
 if err!=nil||changed==got||changed.KnownDoHServers!=got.KnownDoHServers{t.Fatal("same-count content drift not detected",err)}
 encoded,err:=json.Marshal(got)
 if err!=nil||strings.Contains(string(encoded),"sha256")||strings.Contains(string(encoded),strings.Repeat("c",64)){t.Fatal("private fingerprint exported",err)}
 unavailable:=strings.Replace(strings.Replace(base,`"doh_cmdlet_available":true`,`"doh_cmdlet_available":false`,1),`"known_doh_servers":3`,`"known_doh_servers":0`,1)
 got,err=read(unavailable)
 if err!=nil||got.DoHCmdletAvailable{t.Fatal("unavailable cmdlet misclassified",err)}
 for name,raw:=range map[string]string{
  "missing":strings.Replace(base,`"local_nrpt_rules":0,`,"",1),
  "null":strings.Replace(base,`"local_nrpt_rules":0`,`"local_nrpt_rules":null`,1),
  "duplicate":strings.Replace(base,`"schema":1`,`"schema":1,"schema":1`,1),
  "foreign":strings.Replace(base,"windows-dns-override-census-v1","other",1),
  "negative":strings.Replace(base,`"local_nrpt_rules":0`,`"local_nrpt_rules":-1`,1),
  "oversized":strings.Replace(base,`"local_nrpt_rules":0`,`"local_nrpt_rules":65537`,1),
  "contradictory-doh":strings.Replace(base,`"doh_cmdlet_available":true`,`"doh_cmdlet_available":false`,1),
  "contradictory-policy":strings.Replace(base,`"dns_group_policy_values":0`,`"dns_group_policy_values":1`,1),
  "invalid-digest":strings.Replace(base,strings.Repeat("c",64),strings.Repeat("0",64),1),
  "extra-private":strings.Replace(base,`"schema":1`,`"schema":1,"private_namespace":"fixture.test"`,1),
 }{t.Run(name,func(t *testing.T){got,err:=read(raw);if err==nil||got!=(WindowsDNSOverrideCensus{}){t.Fatal("invalid census accepted")}})}
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 got,err=InspectWindowsDNSOverrideCensusReadOnly(ctx,func(context.Context,string)([]byte,error){t.Fatal("cancelled query executed");return nil,nil})
 if err==nil||got!=(WindowsDNSOverrideCensus{}){t.Fatal("cancelled census accepted")}
 t.Log("PASS VOLVE_DNS_OVERRIDE_CENSUS_REJECTS_INCOMPLETE_AND_CONTRADICTORY_EVIDENCE")
}

func TestWindowsDNSOverrideCensusNativeReadOnly(t *testing.T){
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{t.Skip("disposable hosted Windows only")}
 ctx,cancel:=context.WithTimeout(context.Background(),90*time.Second);defer cancel()
 before,err:=InspectWindowsDNSOverrideCensusReadOnly(ctx,DefaultWindowsReadOnlyPowerShell)
 if err!=nil{t.Fatal(err)}
 after,err:=InspectWindowsDNSOverrideCensusReadOnly(ctx,DefaultWindowsReadOnlyPowerShell)
 if err!=nil||before!=after{t.Fatal("native policy census unstable",err)}
 if err:=ctx.Err();err!=nil{t.Fatal(err)}
 t.Logf("Native counts only: local NRPT=%d effective NRPT=%d DoH cmdlet=%t known DoH=%d group policy present=%t",before.LocalNRPTRules,before.EffectiveNRPTPolicies,before.DoHCmdletAvailable,before.KnownDoHServers,before.GroupPolicyKeyPresent)
 t.Log("PASS VOLVE_NATIVE_DNS_OVERRIDE_CENSUS_COUNTS_ONLY_NO_INSTALL")
}


// Run the same PowerShell canonicalization helpers with inert fixture values;
// no real NRPT/DoH or registry setting is modified.
func TestWindowsDNSOverrideFingerprintSyntheticContent(t *testing.T){
 script:=windowsDNSOverrideFingerprintHelpers+`
$ErrorActionPreference='Stop'
$a=Get-VolvHash 'fixture' @('one','two')
$b=Get-VolvHash 'fixture' @('two','one')
$c=Get-VolvHash 'fixture' @('one','Three')
$d=Get-VolvHash 'other' @('one','two')
$e=Get-VolvHash 'fixture' @('one','two','two')
if($a -cne $b -or $a -ceq $c -or $a -ceq $d -or $a -ceq $e){throw 'Fingerprint canonicalization failed'}
$r1=ConvertTo-Json -InputObject (Get-VolvTypedValue ([int]7)) -Compress
$r2=ConvertTo-Json -InputObject (Get-VolvTypedValue ([string]'7')) -Compress
if($r1 -ceq $r2){throw 'Type distinction lost'}
Write-Output 'VOLVE_DNS_OVERRIDE_FINGERPRINT_SYNTHETIC_PASS'
`
 path:=filepath.Join(t.TempDir(),"override-fingerprint.ps1")
 if err:=os.WriteFile(path,[]byte(script),0600);err!=nil{t.Fatal(err)}
 ps:=filepath.Join(os.Getenv("SystemRoot"),"System32","WindowsPowerShell","v1.0","powershell.exe")
 if !filepath.IsAbs(ps){t.Fatal("Windows PowerShell unavailable")}
 ctx,cancel:=context.WithTimeout(context.Background(),30*time.Second);defer cancel()
 raw,err:=exec.CommandContext(ctx,ps,"-NoLogo","-NoProfile","-NonInteractive","-File",path).CombinedOutput()
 if err!=nil||strings.TrimSpace(string(raw))!="VOLVE_DNS_OVERRIDE_FINGERPRINT_SYNTHETIC_PASS"{t.Fatalf("fingerprint fixture failed: %v",err)}
 t.Log("PASS VOLVE_DNS_OVERRIDE_FINGERPRINT_SYNTHETIC_CONTENT_DRIFT")
}
