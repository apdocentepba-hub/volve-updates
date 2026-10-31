package motorupdate

// The Windows command planner keeps IPv4 and IPv6 DNS settings independent.
// Set-DnsClientServerAddress -ResetServerAddresses does not expose an
// AddressFamily parameter; blindly resetting it can affect both protocols.
// netsh interface ipv4/ipv6 set/add dnsservers has distinct family scopes.
// This file only builds validated argument vectors; it never runs netsh.
import (
 "errors"
 "fmt"
 "strconv"
)

type WindowsDNSCommand struct {
 Program string
 Args []string
}

// PlanWindowsDNSRestore builds exact, shell-free argument vectors for a
// separately attested adapter GUID resolved to a Windows InterfaceIndex.
// The privileged caller must recheck the index->GUID binding before each
// command and independently verify DNS state afterward.
func PlanWindowsDNSRestore(original DNSServerState,index uint32)([]WindowsDNSCommand,error){
 if err:=validDNSState(original);err!=nil{return nil,err}
 if index==0{return nil,errors.New("interface index cannot be zero")}
 family:="ipv4"
 if original.Family==DNSIPv6{family="ipv6"}
 label:="name="+strconv.FormatUint(uint64(index),10)
 base:=[]string{"interface",family}
 if original.Mode==DNSAutomatic {
  return []WindowsDNSCommand{{Program:"netsh.exe",Args:append(append([]string{},base...),"set","dnsservers",label,"source=dhcp")}},nil
 }
 result:=make([]WindowsDNSCommand,0,len(original.Servers))
 for i,server:=range original.Servers {
  // IPs were checked by validDNSState, so none can become command options.
  args:=append([]string{},base...)
  if i==0 {
   args=append(args,"set","dnsservers",label,"source=static","address="+server,"validate=no")
  } else {
   args=append(args,"add","dnsservers",label,"address="+server,"index="+strconv.Itoa(i+1),"validate=no")
  }
  result=append(result,WindowsDNSCommand{Program:"netsh.exe",Args:args})
 }
 if len(result)==0{return nil,fmt.Errorf("no restore commands for %s",family)}
 return result,nil
}
