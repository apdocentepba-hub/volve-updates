//go:build windows

package motorupdate

import (
 "context"
 "errors"
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
