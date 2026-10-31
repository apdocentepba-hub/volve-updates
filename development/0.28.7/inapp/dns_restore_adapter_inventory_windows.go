//go:build windows

package motorupdate

// Windows DNS restore identity gate. This module never changes adapters:
// it reads a live Windows adapter inventory, binds the immutable interface
// GUID to the current numeric InterfaceIndex and independently reads the
// EFFECTIVE DNS servers. DHCP/static source must still be proven by a
// separate protected installation journal and privileged source inspector.
import (
 "bytes"
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "net"
 "os/exec"
 "strings"
)

type WindowsAdapterBinding struct {
 InterfaceGUID string
 InterfaceIndex uint32
}

type windowsAdapterRecord struct {
 InterfaceGuid string `json:"InterfaceGuid"`
 InterfaceIndex uint32 `json:"InterfaceIndex"`
}
type windowsEffectiveDNSRecord struct {
 InterfaceIndex uint32 `json:"InterfaceIndex"`
 Family string `json:"Family"`
 Servers []string `json:"Servers"`
}

type WindowsReadOnlyPowerShell func(context.Context,string)([]byte,error)

const windowsAdapterInventoryQuery = `$ErrorActionPreference='Stop'; $items=@(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object { $_.InterfaceGuid -and $_.InterfaceIndex -gt 0 } | Select-Object InterfaceGuid,InterfaceIndex); ConvertTo-Json -InputObject $items -Depth 3 -Compress`
const windowsEffectiveDNSQuery = `$ErrorActionPreference='Stop'; $items=@(Get-DnsClientServerAddress -ErrorAction Stop | ForEach-Object { [pscustomobject]@{InterfaceIndex=[uint32]$_.InterfaceIndex;Family=$( switch ([string]$_.AddressFamily) { '2' {'IPv4'} '23' {'IPv6'} 'IPv4' {'IPv4'} 'IPv6' {'IPv6'} 'InterNetwork' {'IPv4'} 'InterNetworkV6' {'IPv6'} default {'Unknown'} } );Servers=@($_.ServerAddresses)} }); ConvertTo-Json -InputObject $items -Depth 4 -Compress`

func DefaultWindowsReadOnlyPowerShell(ctx context.Context,script string)([]byte,error){
 if script!=windowsAdapterInventoryQuery && script!=windowsEffectiveDNSQuery {
  return nil,errors.New("unrecognized read-only Windows inventory request")
 }
 cmd:=exec.CommandContext(ctx,"powershell.exe","-NoProfile","-NonInteractive","-Command",script)
 out,err:=cmd.Output()
 if err!=nil{return nil,fmt.Errorf("Windows read-only inventory failed: %w",err)}
 return out,nil
}
func parseWindowsAdapterInventory(raw []byte)([]WindowsAdapterBinding,error){
 if len(raw)==0||len(raw)>1<<20{return nil,errors.New("Windows adapter inventory absent or oversized")}
 var parsed []windowsAdapterRecord
 if err:=json.Unmarshal(bytes.TrimSpace(raw),&parsed);err!=nil{return nil,fmt.Errorf("invalid adapter JSON array: %w",err)}
 if len(parsed)==0{return nil,errors.New("no Windows network adapters with valid identity")}
 // Get-NetAdapter -IncludeHidden can expose duplicate virtual entries on
 // GitHub-hosted Windows. Never treat duplicate interface IDs as independent
 // targets. Exclude every conflicting GUID or index instead of trusting a
 // random first match; a caller asking for an ambiguous target will fail.
 seenGUID:=map[string]uint32{}
 seenIndex:=map[uint32]string{}
 badGUID:=map[string]bool{}
 badIndex:=map[uint32]bool{}
 candidates:=make([]WindowsAdapterBinding,0,len(parsed))
 for _,r:=range parsed{
  norm:="{"+strings.ToLower(strings.Trim(r.InterfaceGuid,"{}"))+"}"
  if err:=validDNSState(DNSServerState{InterfaceGUID:norm,Family:DNSIPv4,Mode:DNSAutomatic});err!=nil {
   return nil,fmt.Errorf("invalid live adapter GUID: %w",err)
  }
  if r.InterfaceIndex==0{return nil,errors.New("Windows interface index cannot be zero")}
  if prior,exists:=seenGUID[norm];exists && prior!=r.InterfaceIndex {
   badGUID[norm]=true
   badIndex[prior]=true
   badIndex[r.InterfaceIndex]=true
  }
  if prior,exists:=seenIndex[r.InterfaceIndex];exists && prior!=norm {
   badIndex[r.InterfaceIndex]=true
   badGUID[prior]=true
   badGUID[norm]=true
  }
  if _,exists:=seenGUID[norm];!exists{seenGUID[norm]=r.InterfaceIndex}
  if _,exists:=seenIndex[r.InterfaceIndex];!exists{seenIndex[r.InterfaceIndex]=norm}
  candidates=append(candidates,WindowsAdapterBinding{InterfaceGUID:norm,InterfaceIndex:r.InterfaceIndex})
 }
 out:=make([]WindowsAdapterBinding,0,len(candidates))
 retained:=map[string]bool{}
 for _,a:=range candidates{
  if badGUID[a.InterfaceGUID]||badIndex[a.InterfaceIndex]||retained[a.InterfaceGUID]{continue}
  retained[a.InterfaceGUID]=true
  out=append(out,a)
 }
 if len(out)==0{return nil,errors.New("no uniquely identifiable Windows adapter in live inventory")}
 return out,nil
}

// FindWindowsAdapterIndex binds exact interface GUID to the current interface
// index. Never use a human-readable adapter name or previously cached index.
func FindWindowsAdapterIndex(ctx context.Context,guid string,run WindowsReadOnlyPowerShell)(uint32,error){
 if run==nil{return 0,errors.New("no trusted read-only Windows inspector")}
 norm:="{"+strings.ToLower(strings.Trim(guid,"{}"))+"}"
 if err:=validDNSState(DNSServerState{InterfaceGUID:norm,Family:DNSIPv4,Mode:DNSAutomatic});err!=nil {
  return 0,fmt.Errorf("invalid requested interface GUID: %w",err)
 }
 if err:=ctx.Err();err!=nil{return 0,err}
 raw,err:=run(ctx,windowsAdapterInventoryQuery)
 if err!=nil{return 0,err}
 adapters,err:=parseWindowsAdapterInventory(raw)
 if err!=nil{return 0,err}
 for _,a:=range adapters{
  if a.InterfaceGUID==norm{return a.InterfaceIndex,nil}
 }
 return 0,errors.New("adapter GUID disappeared from current inventory")
}

func parseEffectiveDNS(raw []byte,index uint32,family DNSAddressFamily)([]string,error){
 if len(raw)==0||len(raw)>1<<20{return nil,errors.New("effective Windows DNS inventory absent or oversized")}
 var parsed []windowsEffectiveDNSRecord
 if err:=json.Unmarshal(bytes.TrimSpace(raw),&parsed);err!=nil{return nil,fmt.Errorf("invalid effective DNS JSON: %w",err)}
 seen:=0
 var servers []string
 for _,r:=range parsed{
  if r.InterfaceIndex!=index || r.Family!=string(family){continue}
  seen++
  servers=append([]string(nil),r.Servers...)
 }
 if seen!=1{return nil,fmt.Errorf("expected exactly one DNS family record for adapter, got %d",seen)}
 for _,s:=range servers{
  if s==""||strings.TrimSpace(s)!=s||net.ParseIP(s)==nil {
   return nil,errors.New("malformed DNS server in actual adapter inventory")
  }
 }
 return servers,nil
}

// PreflightWindowsVOLVEDNSRestore checks that current Windows effective DNS
// still targets localhost exclusively, and prepares family-scoped netsh
// arguments bound to the live GUID->index mapping. This is READ-ONLY.
// A production caller MUST recheck both snapshots under its exclusive lock
// immediately before executing an authenticated rollback.
func PreflightWindowsVOLVEDNSRestore(ctx context.Context,r DNSRestoreRecord,run WindowsReadOnlyPowerShell)([]WindowsDNSCommand,error){
 if run==nil{return nil,errors.New("no Windows DNS inventory runner")}
 if err:=validDNSState(r.Original);err!=nil{return nil,err}
 if err:=validDNSState(r.Expected);err!=nil{return nil,err}
 if !strings.EqualFold(r.Original.InterfaceGUID,r.Expected.InterfaceGUID) ||
  r.Original.Family!=r.Expected.Family || r.Expected.Mode!=DNSStatic ||
  len(r.Expected.Servers)!=1 {return nil,errors.New("inconsistent restore journal")}
 expected:="127.0.0.1"
 if r.Expected.Family==DNSIPv6{expected="::1"}
 if !net.ParseIP(r.Expected.Servers[0]).Equal(net.ParseIP(expected)){
  return nil,errors.New("only VOLVE localhost DNS may be recovered")
 }
 index,err:=FindWindowsAdapterIndex(ctx,r.Original.InterfaceGUID,run)
 if err!=nil{return nil,err}
 raw,err:=run(ctx,windowsEffectiveDNSQuery)
 if err!=nil{return nil,err}
 current,err:=parseEffectiveDNS(raw,index,r.Expected.Family)
 if err!=nil{return nil,err}
 if len(current)!=1||!net.ParseIP(current[0]).Equal(net.ParseIP(expected)){
  return nil,errors.New("Windows adapter no longer targets VOLVE localhost; refusing restore plan")
 }
 // This repeats the identity inspection after reading effective DNS to catch
 // simple adapter replacement races. The executor MUST repeat again at apply.
 verifiedIndex,err:=FindWindowsAdapterIndex(ctx,r.Original.InterfaceGUID,run)
 if err!=nil||verifiedIndex!=index{return nil,errors.New("live Windows adapter changed during DNS restore preflight")}
 return PlanWindowsDNSRestore(r.Original,index)
}
