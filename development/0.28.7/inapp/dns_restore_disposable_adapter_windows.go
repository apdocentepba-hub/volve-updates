//go:build windows

package motorupdate

// Strict READ-ONLY eligibility gate for a sacrificial Windows DNS adapter.
// The ordinary Windows runner is NOT a disposable adapter. Any missing or
// ambiguous fact fails closed; no host adapter may be mutated by this file.
import (
 "bytes"
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "net"
 "os/exec"
 "regexp"
 "strconv"
 "strings"
)

var windowsDisposableDNSAlias=regexp.MustCompile(`^VOLVE-CI-DNS-LAB-[0-9]{12,20}$`)
var windowsDisposableHyperVDescription=regexp.MustCompile(`^Hyper-V Virtual Ethernet Adapter( #[1-9][0-9]*)?$`)

type WindowsDisposableDNSAdapter struct {
 InterfaceGUID string
 InterfaceIndex uint32
 Alias string
 Description string
}

type windowsDisposableAdapterObservation struct {
 InterfaceGuid string `json:"InterfaceGuid"`
 InterfaceIndex uint32 `json:"InterfaceIndex"`
 Name string `json:"Name"`
 InterfaceDescription string `json:"InterfaceDescription"`
 HardwareInterface bool `json:"HardwareInterface"`
 NetworkCategory string `json:"NetworkCategory"`
 Routes []string `json:"Routes"`
 IPAddresses []string `json:"IPAddresses"`
 DNSIPv4 []string `json:"DNSIPv4"`
 DNSIPv6 []string `json:"DNSIPv6"`
}

// All queries are generated internally and never interpolated with user
// input. No Set-, Add-, Remove- or netsh command is present in the query.
const windowsDisposableDNSInventoryQuery = `$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';
$items=@(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object { $_.Name -match '^VOLVE-CI-DNS-LAB-[0-9]{12,20}$' } | ForEach-Object {
 $a=$_; $i=[uint32]$a.InterfaceIndex;
 $routes=@(Get-NetRoute -InterfaceIndex $i -ErrorAction Stop | ForEach-Object { [string]$_.DestinationPrefix });
 $ips=@(Get-NetIPAddress -InterfaceIndex $i -ErrorAction Stop | ForEach-Object { [string]$_.IPAddress });
 $dns4=@(Get-DnsClientServerAddress -InterfaceIndex $i -AddressFamily IPv4 -ErrorAction Stop | ForEach-Object { $_.ServerAddresses } );
 $dns6=@(Get-DnsClientServerAddress -InterfaceIndex $i -AddressFamily IPv6 -ErrorAction Stop | ForEach-Object { $_.ServerAddresses } );
 $nc=@(Get-NetConnectionProfile -InterfaceIndex $i -ErrorAction SilentlyContinue | Select-Object -ExpandProperty NetworkCategory);
 [pscustomobject]@{
  InterfaceGuid=[string]$a.InterfaceGuid; InterfaceIndex=$i; Name=[string]$a.Name;
  InterfaceDescription=[string]$a.InterfaceDescription;HardwareInterface=[bool]$a.HardwareInterface;
  NetworkCategory=[string]$nc; Routes=@($routes); IPAddresses=@($ips);
  DNSIPv4=@($dns4);DNSIPv6=@($dns6)
 }
});ConvertTo-Json -InputObject $items -Compress -Depth 6`

type WindowsDisposableDNSInspect func(context.Context,string)([]byte,error)

func DefaultWindowsDisposableDNSInspect(ctx context.Context,query string)([]byte,error){
 if query!=windowsDisposableDNSInventoryQuery{return nil,errors.New("only read-only sacrificial adapter inventory is permitted")}
 if err:=ctx.Err();err!=nil{return nil,err}
 out,err:=exec.CommandContext(ctx,"powershell.exe","-NoProfile","-NonInteractive","-Command",query).Output()
 if err!=nil{return nil,fmt.Errorf("disposable adapter read-only inventory failed: %w",err)}
 return out,nil
}

func windowsLabLinkLocalOnly(s string,index uint32)bool{
 // Windows returns scoped IPv6 link-local addresses as fe80::...%<index>.
 // Accept ONLY the exact numeric zone of the pinned disposable adapter.
 if zone:=strings.IndexByte(s,'%');zone>=0 {
  if s[zone+1:]!=strconv.FormatUint(uint64(index),10){return false}
  s=s[:zone]
 }
 ip:=net.ParseIP(s)
 if ip==nil{return false}
 if ip.To4()!=nil{
  _,subnet,_:=net.ParseCIDR("169.254.0.0/16")
  return subnet.Contains(ip)
 }
 return ip.IsLinkLocalUnicast()
}

func windowsLabNonRoutingPrefix(s string)bool{
 // Only the OS-generated local broadcast/multicast routes are accepted.
 // Any default gateway, LAN prefix, host route or foreign subnet fails.
 if s=="224.0.0.0/4"||s=="255.255.255.255/32"||s=="ff00::/8"{
  return true
 }
 _,ipnet,err:=net.ParseCIDR(s)
 if err!=nil{return false}
 // Entire advertised route must be link-local, not a wider prefix that
 // happens to overlap it. A /0 or real LAN route is never disposable.
 if ipnet.IP.To4()!=nil{
  _,link,_:=net.ParseCIDR("169.254.0.0/16")
  ones,bits:=ipnet.Mask.Size()
  return bits==32&&ones>=16&&link.Contains(ipnet.IP)
 }
 _,link,_:=net.ParseCIDR("fe80::/10")
 ones,bits:=ipnet.Mask.Size()
 return bits==128&&ones>=10&&link.Contains(ipnet.IP)
}

// VerifyWindowsDisposableDNSAdapterReadOnly is the initial-state safety gate.
// It accepts only OS-generated, disconnected DNS placeholders.
func VerifyWindowsDisposableDNSAdapterReadOnly(
 ctx context.Context,alias,expectedGUID string,inspect WindowsDisposableDNSInspect,
)(WindowsDisposableDNSAdapter,error){
 return inspectWindowsDisposableDNSAdapterAtState(ctx,alias,expectedGUID,inspect,nil,nil,false)
}

// VerifyWindowsDisposableDNSAdapterWithLocalDNSReadOnly is restricted to the
// exact localhost configuration after a deliberately isolated VOLVE trial.
// Unlike the initial gate, it NEVER approves the automatic IPv6 placeholders.
func VerifyWindowsDisposableDNSAdapterWithLocalDNSReadOnly(
 ctx context.Context,alias,expectedGUID string,inspect WindowsDisposableDNSInspect,
)(WindowsDisposableDNSAdapter,error){
 return inspectWindowsDisposableDNSAdapterAtState(ctx,alias,expectedGUID,inspect,
  []string{"127.0.0.1"},[]string{"::1"},true)
}

func inspectWindowsDisposableDNSAdapterAtState(
 ctx context.Context,alias,expectedGUID string,inspect WindowsDisposableDNSInspect,
 pinnedV4,pinnedV6 []string,requirePinned bool,
)(WindowsDisposableDNSAdapter,error){
 var zero WindowsDisposableDNSAdapter
 if err:=ctx.Err();err!=nil{return zero,err}
 if inspect==nil||!windowsDisposableDNSAlias.MatchString(alias){
  return zero,errors.New("disposable DNS adapter requires unique CI alias and read-only inspector")
 }
 if err:=validDNSState(DNSServerState{InterfaceGUID:expectedGUID,Family:DNSIPv4,Mode:DNSAutomatic});err!=nil{
  return zero,fmt.Errorf("disposable DNS adapter expected GUID invalid: %w",err)
 }
 raw,err:=inspect(ctx,windowsDisposableDNSInventoryQuery)
 if err!=nil{return zero,err}
 if len(raw)<2||len(raw)>1<<20{return zero,errors.New("disposable adapter inventory missing or too large")}
 dec:=json.NewDecoder(bytes.NewReader(raw));dec.DisallowUnknownFields()
 var items []windowsDisposableAdapterObservation
 if err:=dec.Decode(&items);err!=nil{return zero,fmt.Errorf("disposable adapter inventory malformed: %w",err)}
 if len(items)>1024{return zero,errors.New("too many Windows adapters to establish trusted inventory")}
 var extra any
 if err:=dec.Decode(&extra);err!=io.EOF {
  return zero,errors.New("trailing or invalid disposable adapter inventory")
 }
 count:=0
 var selected windowsDisposableAdapterObservation
 for _,item:=range items {
  if item.Name!=alias{continue}
  count++
  selected=item
 }
 if count!=1{return zero,fmt.Errorf("disposable DNS alias must identify exactly one adapter, found %d",count)}
 normalized:="{"+strings.ToLower(strings.Trim(selected.InterfaceGuid,"{}"))+"}"
 if !strings.EqualFold(normalized,expectedGUID)||selected.InterfaceIndex==0 {
  return zero,errors.New("disposable DNS adapter GUID or index did not match pinned identity")
 }
 if selected.HardwareInterface ||
    (selected.InterfaceDescription!="Microsoft KM-TEST Loopback Adapter" &&
     !windowsDisposableHyperVDescription.MatchString(selected.InterfaceDescription)){
  return zero,errors.New("disposable DNS adapter is physical or not an allowlisted virtual device")
 }
 if selected.NetworkCategory=="DomainAuthenticated"||selected.NetworkCategory=="Private"{
  return zero,errors.New("disposable DNS adapter is attached to a trusted live network")
 }
 // Windows may attach exactly these three built-in IPv6 DNS fallback
 // placeholders to a newly created disconnected Hyper-V internal vNIC.
 // They are not evidence of a manually configured DNS resolver.
 // Reject EVERY other pre-existing DNS value, including any IPv4 server.
 ipv6Fallback:=[]string{"fec0:0:0:ffff::1","fec0:0:0:ffff::2","fec0:0:0:ffff::3"}
 if requirePinned {
  if !sameDNSAddresses(selected.DNSIPv4,pinnedV4) ||
     !sameDNSAddresses(selected.DNSIPv6,pinnedV6){
   return zero,errors.New("disposable recovery adapter does not have exact localhost DNS")
  }
 }else if len(selected.DNSIPv4)!=0 ||
    (len(selected.DNSIPv6)!=0 && !sameDNSAddresses(selected.DNSIPv6,ipv6Fallback)){
  return zero,errors.New("disposable DNS adapter has unknown configured DNS servers")
 }
 for _,addr:=range selected.IPAddresses {
  if !windowsLabLinkLocalOnly(addr,selected.InterfaceIndex){return zero,errors.New("disposable DNS adapter has non-linklocal IP")}
 }
 for _,route:=range selected.Routes {
  if !windowsLabNonRoutingPrefix(route){return zero,errors.New("disposable DNS adapter has routable network route")}
 }
 // Re-check that GUID still maps to the same index immediately before use.
 // A future mutator MUST repeat this exact full preflight under its OS lock.
 return WindowsDisposableDNSAdapter{InterfaceGUID:normalized,
  InterfaceIndex:selected.InterfaceIndex,Alias:alias,
  Description:selected.InterfaceDescription},nil
}
