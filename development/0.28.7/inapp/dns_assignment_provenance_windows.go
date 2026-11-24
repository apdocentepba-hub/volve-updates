//go:build windows

package motorupdate

// Read-only provenance for each adapter's configured DNS assignment mode.
// NameServer is the per-interface static override; an absent/empty value is
// classified as automatic (DHCP/RA), never as a hard-coded DHCP server list.
// ProfileNameServer and unsupported registry types fail closed.
import (
 "bytes"
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "net"
 "sort"
 "strings"
)

// The real Server 2022 guest exposes an unmapped software loopback IPv6
// row with exactly the three legacy resolver placeholders. They are not a
// configurable adapter target. Only that positively identified row is
// outside the signed adapter restoration set. An arbitrary unmapped DNS
// server, mapped adapter, duplicate loopback identity or partial placeholder
// list is NEVER eligible for this exception.
const windowsDNSLoopbackPlaceholderGuard = `
function Test-VolvUnmappedLoopbackPlaceholders([string]$family,[uint32]$index,[object[]]$servers,[uint32[]]$loopbackIPv6Indexes,[int]$mappedGUIDCount){
 if($mappedGUIDCount -ne 0 -or $family -cne 'IPv6' -or $index -eq 0){return $false}
 if(@($loopbackIPv6Indexes).Count -ne 1 -or $loopbackIPv6Indexes[0] -ne $index){return $false}
 if(@($servers).Count -ne 3){return $false}
 return ([string]$servers[0] -ieq 'fec0:0:0:ffff::1' -and [string]$servers[1] -ieq 'fec0:0:0:ffff::2' -and [string]$servers[2] -ieq 'fec0:0:0:ffff::3')
}
`

const windowsDNSAssignmentSourceQuery = `$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';` + windowsDNSLoopbackPlaceholderGuard + `
$loopbackIPv6Indexes=@(foreach($n in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()){
 if($n.NetworkInterfaceType -ne [Net.NetworkInformation.NetworkInterfaceType]::Loopback){continue}
 if($n.Supports([Net.NetworkInformation.NetworkInterfaceComponent]::IPv6)){
  [uint32]$n.GetIPProperties().GetIPv6Properties().Index
 }
});
$adapters=@(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {$_.InterfaceGuid -and $_.InterfaceIndex -gt 0});
$dnsRows=@(Get-DnsClientServerAddress -ErrorAction Stop);
$items=@(foreach($d in $dnsRows){
 $family=switch([string]$d.AddressFamily){
  '2' {'IPv4'} '23' {'IPv6'} 'IPv4' {'IPv4'} 'IPv6' {'IPv6'}
  'InterNetwork' {'IPv4'} 'InterNetworkV6' {'IPv6'}
  default {throw 'Unknown DNS client address family'}
 };
 $adapterGUIDs=@($adapters | Where-Object {[uint32]$_.InterfaceIndex -eq [uint32]$d.InterfaceIndex} | ForEach-Object {[string]$_.InterfaceGuid} | Sort-Object -Unique);
 if($adapterGUIDs.Count -eq 0){
  $unmappedServers=@($d.ServerAddresses)
  if($unmappedServers.Count -eq 0){continue}
  if(Test-VolvUnmappedLoopbackPlaceholders -family $family -index ([uint32]$d.InterfaceIndex) -servers $unmappedServers -loopbackIPv6Indexes $loopbackIPv6Indexes -mappedGUIDCount $adapterGUIDs.Count){continue}
  throw 'DNS servers exist on an interface without a unique adapter GUID'
 };
 if($adapterGUIDs.Count -ne 1){throw 'DNS interface index maps to conflicting adapter GUIDs'};
 $guid='{'+([string]$adapterGUIDs[0]).Trim('{}')+'}';
 $service=if($family -eq 'IPv4'){'Tcpip'}else{'Tcpip6'};
 $path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\'+$service+'\Parameters\Interfaces\'+$guid;
 if(-not (Test-Path -LiteralPath $path -PathType Container -ErrorAction Stop)){throw 'DNS assignment registry key missing'};
 $key=Get-Item -LiteralPath $path -ErrorAction Stop;
 try {
  $names=@($key.GetValueNames());
  $present=$names -contains 'NameServer';
  $kind='Missing';$nonEmpty=$false;$servers=@();
  if($present){
   $kind=[string]$key.GetValueKind('NameServer');
   $value=$key.GetValue('NameServer',$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames);
   if($value -is [string]){
    $nonEmpty=$value.Trim().Length -gt 0;
    if($nonEmpty){$servers=@($value -split '[,;\s]+' | Where-Object {$_})}
   } elseif($null -ne $value){$kind='UnsupportedValueType'}
  }
  $profilePresent=$names -contains 'ProfileNameServer';$profileNonEmpty=$false;
  if($profilePresent){
   $profileValue=$key.GetValue('ProfileNameServer',$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames);
   if($profileValue -is [string]){$profileNonEmpty=$profileValue.Trim().Length -gt 0}
   elseif($null -ne $profileValue){$profileNonEmpty=$true}
  }
  $effective=@($d.ServerAddresses | ForEach-Object {[string]$_});
  [pscustomobject]@{
   InterfaceGUID=$guid;InterfaceIndex=[uint32]$d.InterfaceIndex;
   Family=[string]$family;RegistryKeyPresent=$true;
   NameServerPresent=[bool]$present;NameServerKind=[string]$kind;
   NameServerNonEmpty=[bool]$nonEmpty;ProfileNameServerNonEmpty=[bool]$profileNonEmpty;
   Mode=$(if($nonEmpty){'static'}else{'automatic'});
   Servers=@($servers);EffectiveServers=@($effective)
  }
 } finally {$key.Close()}
});
ConvertTo-Json -InputObject $items -Compress -Depth 5`

type windowsDNSAssignmentRecord struct {
 InterfaceGUID string `json:"InterfaceGUID"`
 InterfaceIndex uint32 `json:"InterfaceIndex"`
 Family string `json:"Family"`
 RegistryKeyPresent bool `json:"RegistryKeyPresent"`
 NameServerPresent bool `json:"NameServerPresent"`
 NameServerKind string `json:"NameServerKind"`
 NameServerNonEmpty bool `json:"NameServerNonEmpty"`
 ProfileNameServerNonEmpty bool `json:"ProfileNameServerNonEmpty"`
 Mode string `json:"Mode"`
 Servers []string `json:"Servers"`
 EffectiveServers []string `json:"EffectiveServers"`
}

type WindowsDNSAssignmentProvenance struct {
 Schema int
 Component string
 // Contains local interface GUIDs and static DNS addresses; never serialize
 // this field into the user-facing diagnostic report.
 States []DNSServerState `json:"-"`
 SHA256 string
 AdapterCount int
 StaticFamilyCount int
 AutomaticFamilyCount int
}

// InspectWindowsDNSAssignmentProvenanceReadOnly independently verifies the
// registry assignment source and effective DNS list for every interface and
// address family. It never changes registry, adapter, DNS or task state.
func InspectWindowsDNSAssignmentProvenanceReadOnly(
 ctx context.Context,inspect WindowsReadOnlyPowerShell,
)(WindowsDNSAssignmentProvenance,error){
 var empty WindowsDNSAssignmentProvenance
 if ctx==nil{return empty,errors.New("DNS provenance context required")}
 if err:=ctx.Err();err!=nil{return empty,err}
 if inspect==nil{return empty,errors.New("read-only DNS provenance inspector required")}
 raw,err:=inspect(ctx,windowsDNSAssignmentSourceQuery)
 if err!=nil{return empty,fmt.Errorf("Windows DNS assignment source unavailable: %w",err)}
 if len(raw)<2||len(raw)>1<<20{return empty,errors.New("Windows DNS assignment inventory empty or oversized")}
 dec:=json.NewDecoder(bytes.NewReader(raw));dec.DisallowUnknownFields()
 var rows []json.RawMessage
 if err:=dec.Decode(&rows);err!=nil{return empty,fmt.Errorf("invalid Windows DNS assignment JSON: %w",err)}
 var trailing any
 if err:=dec.Decode(&trailing);err!=io.EOF{return empty,errors.New("unexpected trailing DNS assignment JSON")}
 if len(rows)==0||len(rows)>2048{return empty,errors.New("DNS assignment inventory has impossible interface count")}
 records:=make([]windowsDNSAssignmentRecord,0,len(rows))
 for _,row:=range rows{
  record,err:=decodeCompleteWindowsDNSAssignmentRecord(row)
  if err!=nil{return empty,fmt.Errorf("incomplete or ambiguous Windows DNS assignment evidence: %w",err)}
  records=append(records,record)
 }
 states:=make([]DNSServerState,0,len(records))
 seen:=map[string]bool{}
 guidIndexes:=map[string]uint32{}
 indexGUIDs:=map[uint32]string{}
 families:=map[string]map[DNSAddressFamily]bool{}
 staticCount,automaticCount:=0,0
 for _,r:=range records{
  if strings.TrimSpace(r.InterfaceGUID)!=r.InterfaceGUID||len(r.InterfaceGUID)!=38||
   r.InterfaceGUID[0]!='{'||r.InterfaceGUID[37]!='}'{
   return empty,errors.New("adapter GUID is not a canonical braced Windows GUID")
  }
  guid:=strings.ToLower(r.InterfaceGUID)
  family:=DNSAddressFamily(r.Family)
  if r.InterfaceIndex==0||!r.RegistryKeyPresent||r.ProfileNameServerNonEmpty{
   return empty,errors.New("DNS interface identity or unsupported profile-specific source")
  }
  if family!=DNSIPv4&&family!=DNSIPv6{return empty,errors.New("unsupported DNS assignment family")}
  key:=guid+string(family)
  if seen[key]{return empty,errors.New("duplicate adapter/family DNS assignment record")}
  seen[key]=true
  if prior,ok:=guidIndexes[guid];ok&&prior!=r.InterfaceIndex{return empty,errors.New("one adapter GUID maps to multiple interface indexes")}
  if prior,ok:=indexGUIDs[r.InterfaceIndex];ok&&prior!=guid{return empty,errors.New("one interface index maps to multiple adapter GUIDs")}
  guidIndexes[guid]=r.InterfaceIndex;indexGUIDs[r.InterfaceIndex]=guid
  if families[guid]==nil{families[guid]=map[DNSAddressFamily]bool{}}
  families[guid][family]=true
  for _,ipText:=range r.EffectiveServers{
   ip:=net.ParseIP(ipText)
   if ip==nil||strings.TrimSpace(ipText)!=ipText||
    (family==DNSIPv4&&ip.To4()==nil)||(family==DNSIPv6&&ip.To4()!=nil){
    return empty,errors.New("effective DNS server is invalid or in the wrong address family")
   }
  }
  mode:=DNSConfigurationMode(r.Mode)
  state:=DNSServerState{InterfaceGUID:guid,Family:family,Mode:mode,Servers:[]string{}}
  switch mode{
  case DNSStatic:
   if !r.NameServerPresent||r.NameServerKind!="String"||!r.NameServerNonEmpty||len(r.Servers)==0{
    return empty,errors.New("static DNS source lacks a supported NameServer REG_SZ value")
   }
   state.Servers=append([]string(nil),r.Servers...)
   if err:=validDNSState(state);err!=nil{return empty,fmt.Errorf("invalid static DNS assignment: %w",err)}
   if !sameDNSAddresses(state.Servers,r.EffectiveServers){
    return empty,errors.New("static NameServer registry list does not match effective Windows DNS servers")
   }
   staticCount++
  case DNSAutomatic:
   if r.NameServerNonEmpty||len(r.Servers)!=0||
    (r.NameServerPresent&&r.NameServerKind!="String")||
    (!r.NameServerPresent&&r.NameServerKind!="Missing"){
    return empty,errors.New("automatic DNS assignment has contradictory static registry evidence")
   }
   if err:=validDNSState(state);err!=nil{return empty,err}
   automaticCount++
  default:
   return empty,errors.New("unknown Windows DNS assignment mode")
  }
  states=append(states,state)
 }
 for guid,present:=range families{
  if !present[DNSIPv4]||!present[DNSIPv6]{
   return empty,fmt.Errorf("adapter %s lacks an independently inspected IPv4 or IPv6 DNS source",guid)
  }
 }
 sort.Slice(states,func(i,j int)bool{
  a,b:=states[i],states[j]
  return strings.ToLower(a.InterfaceGUID)+string(a.Family)<strings.ToLower(b.InterfaceGUID)+string(b.Family)
 })
 canonical,err:=json.Marshal(states)
 if err!=nil{return empty,fmt.Errorf("canonical DNS assignment encoding failed: %w",err)}
 sum:=sha256.Sum256(canonical)
 if err:=ctx.Err();err!=nil{return empty,err}
 return WindowsDNSAssignmentProvenance{
  Schema:1,Component:"windows-dns-assignment-provenance-read-only",
  States:states,SHA256:hex.EncodeToString(sum[:]),
  AdapterCount:len(families),StaticFamilyCount:staticCount,
  AutomaticFamilyCount:automaticCount,
 },nil
}


// Every provenance field must be explicitly observed. Go's ordinary struct
// decoder silently converts missing/null booleans to false, accepts case
// aliases and overwrites duplicate keys. That could mistake missing registry
// evidence for an automatic DNS assignment. Reject ambiguity before any
// restoration plan is built.
func decodeCompleteWindowsDNSAssignmentRecord(raw []byte)(windowsDNSAssignmentRecord,error){
 var record windowsDNSAssignmentRecord
 required:=map[string]bool{
  "InterfaceGUID":false,"InterfaceIndex":false,"Family":false,
  "RegistryKeyPresent":false,"NameServerPresent":false,"NameServerKind":false,
  "NameServerNonEmpty":false,"ProfileNameServerNonEmpty":false,"Mode":false,
  "Servers":false,"EffectiveServers":false,
 }
 dec:=json.NewDecoder(bytes.NewReader(raw))
 first,err:=dec.Token()
 if err!=nil||first!=json.Delim('{'){return record,errors.New("DNS row is not an object")}
 for dec.More(){
  token,err:=dec.Token()
  if err!=nil{return record,err}
  key,ok:=token.(string)
  seen,known:=required[key]
  if !ok||!known||seen{return record,errors.New("unknown or duplicate DNS field")}
  var value json.RawMessage
  if err:=dec.Decode(&value);err!=nil{return record,err}
  if bytes.Equal(bytes.TrimSpace(value),[]byte("null")){return record,errors.New("null DNS field")}
  // The Windows query emits arrays even when no static or effective servers
  // exist. Reject null entries, which Go otherwise decodes as empty strings.
  if key=="Servers"||key=="EffectiveServers"{
   var entries []json.RawMessage
   if err:=json.Unmarshal(value,&entries);err!=nil||entries==nil{return record,errors.New("DNS server list is not an array")}
   for _,entry:=range entries{
    if bytes.Equal(bytes.TrimSpace(entry),[]byte("null")){return record,errors.New("null DNS server")}
   }
  }
  required[key]=true
 }
 last,err:=dec.Token()
 if err!=nil||last!=json.Delim('}'){return record,errors.New("incomplete DNS row")}
 if _,err:=dec.Token();err!=io.EOF{return record,errors.New("trailing DNS row content")}
 for _,seen:=range required{if !seen{return record,errors.New("missing required DNS field")}}
 if err:=json.Unmarshal(raw,&record);err!=nil{return record,err}
 return record,nil
}
