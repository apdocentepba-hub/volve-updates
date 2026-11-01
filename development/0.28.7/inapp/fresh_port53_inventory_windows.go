//go:build windows

package motorupdate

// Independent read-only Windows TCP/UDP port 53 ownership check. This scan
// cannot stop a service, bind a port or change any DNS adapter.
import (
 "bytes"
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "net/netip"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
)

// Filter locally after querying complete TCP listeners and UDP endpoints.
// A missing command or access error fails the inventory; SilentlyContinue
// would risk mistaking a failed enumeration for an unused DNS port.
const WindowsFreshPort53Query = `$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';
$items=@(
  Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { [uint32]$_.LocalPort -eq 53 } | ForEach-Object {
    [pscustomobject]@{Transport='TCP';Address=[string]$_.LocalAddress;Port=[uint32]$_.LocalPort;PID=[uint32]$_.OwningProcess}
  }
  Get-NetUDPEndpoint -ErrorAction Stop | Where-Object { [uint32]$_.LocalPort -eq 53 } | ForEach-Object {
    [pscustomobject]@{Transport='UDP';Address=[string]$_.LocalAddress;Port=[uint32]$_.LocalPort;PID=[uint32]$_.OwningProcess}
  }
);ConvertTo-Json -InputObject $items -Compress -Depth 4`

type WindowsFreshPort53Inspect func(context.Context, string) ([]byte,error)

func DefaultWindowsFreshPort53Inspect(ctx context.Context,query string)([]byte,error){
 if query!=WindowsFreshPort53Query{return nil,errors.New("only fixed Windows port 53 read-only inventory allowed")}
 if err:=ctx.Err();err!=nil{return nil,err}
 root:=os.Getenv("SystemRoot")
 if !filepath.IsAbs(root){return nil,errors.New("Windows system root unavailable")}
 ps:=filepath.Join(root,"System32","WindowsPowerShell","v1.0","powershell.exe")
 output,err:=exec.CommandContext(ctx,ps,"-NoLogo","-NoProfile","-NonInteractive","-Command",query).Output()
 if err!=nil{return nil,fmt.Errorf("cannot query Windows TCP/UDP port 53 owners: %w",err)}
 return output,nil
}

type windowsFreshPort53Row struct {
 Transport string `json:"Transport"`
 Address string `json:"Address"`
 Port uint32 `json:"Port"`
 PID uint32 `json:"PID"`
}

type WindowsFreshPort53Inventory struct {
 UDP53IPv4OwnerCount int
 UDP53IPv6OwnerCount int
 TCP53IPv4OwnerCount int
 TCP53IPv6OwnerCount int
 EndpointCount int
}

// InspectWindowsFreshPort53ReadOnly reports EVERY 53 endpoint (even a PID 0
// system owner). For :: wildcard binds, conservatively count both IPv6 and
// possible IPv4 use because v6-only socket configuration is not observable
// from endpoint listing alone. No occupancy at scan time does NOT guarantee
// the port will remain free at install time; recheck under privileged lock.
func InspectWindowsFreshPort53ReadOnly(ctx context.Context,inspect WindowsFreshPort53Inspect)(WindowsFreshPort53Inventory,error){
 var zero WindowsFreshPort53Inventory
 if err:=ctx.Err();err!=nil{return zero,err}
 if inspect==nil{return zero,errors.New("Windows port 53 inspector unavailable")}
 raw,err:=inspect(ctx,WindowsFreshPort53Query)
 if err!=nil{return zero,err}
 if len(raw)<2||len(raw)>1<<20{return zero,errors.New("port 53 evidence missing or oversized")}
 decoder:=json.NewDecoder(bytes.NewReader(raw))
 decoder.DisallowUnknownFields()
 var rows []windowsFreshPort53Row
 if err:=decoder.Decode(&rows);err!=nil{return zero,fmt.Errorf("invalid Windows port 53 inventory: %w",err)}
 var extra any
 if err:=decoder.Decode(&extra);err!=io.EOF{return zero,errors.New("trailing Windows port 53 evidence")}
 if rows==nil||len(rows)>512{return zero,errors.New("missing or oversized Windows port 53 endpoint array")}
 result:=WindowsFreshPort53Inventory{EndpointCount:len(rows)}
 seen:=make(map[string]bool,len(rows))
 for _,row:=range rows{
  if err:=ctx.Err();err!=nil{return zero,err}
  if (row.Transport!="UDP"&&row.Transport!="TCP")||row.Port!=53||row.Address==""||
   strings.TrimSpace(row.Address)!=row.Address{
   return zero,errors.New("unknown transport, port or address in Windows 53 evidence")
  }
  ip,err:=netip.ParseAddr(row.Address)
  if err!=nil||!ip.IsValid(){return zero,errors.New("invalid IP address in Windows port 53 evidence")}
  key:=fmt.Sprintf("%s:%s:53:%d",row.Transport,ip.String(),row.PID)
  if seen[key]{return zero,errors.New("duplicate Windows port 53 endpoint identity")}
  seen[key]=true
  hasIPv4:=ip.Is4()||ip.Is4In6()||ip.Is6()&&ip.IsUnspecified()
  hasIPv6:=ip.Is6()
  if row.Transport=="UDP"{
   if hasIPv4{result.UDP53IPv4OwnerCount++}
   if hasIPv6{result.UDP53IPv6OwnerCount++}
  }else{
   if hasIPv4{result.TCP53IPv4OwnerCount++}
   if hasIPv6{result.TCP53IPv6OwnerCount++}
  }
 }
 return result,nil
}
