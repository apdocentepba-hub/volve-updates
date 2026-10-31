//go:build windows

package motorupdate

import (
 "context"
 "encoding/json"
 "errors"
 "os"
 "reflect"
 "strings"
 "testing"
 "time"
)

const labAdapterAlias = "VOLVE-CI-DNS-LAB-1793423456789"
const labAdapterGUID = "{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}"

func disposableAdapterFixture() windowsDisposableAdapterObservation {
 return windowsDisposableAdapterObservation{
  InterfaceGuid:"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
  InterfaceIndex:71,Name:labAdapterAlias,
  InterfaceDescription:"Microsoft KM-TEST Loopback Adapter",HardwareInterface:false,
  NetworkCategory:"Public",
  Routes:[]string{"169.254.0.0/16","fe80::/64"},
  IPAddresses:[]string{"169.254.5.7","fe80::1234"},
  DNSIPv4:[]string{},DNSIPv6:[]string{},
 }
}
func disposableAdapterInspector(items []windowsDisposableAdapterObservation) WindowsDisposableDNSInspect {
 return func(ctx context.Context,query string)([]byte,error){
  if err:=ctx.Err();err!=nil{return nil,err}
  if query!=windowsDisposableDNSInventoryQuery{
   return nil,errors.New("untrusted PowerShell command")
  }
  return json.Marshal(items)
 }
}

func TestDisposableDNSAdapterUniqueNonroutingVirtualOnly(t *testing.T){
 good:=disposableAdapterFixture()
 got,err:=VerifyWindowsDisposableDNSAdapterReadOnly(
  context.Background(),labAdapterAlias,labAdapterGUID,
  disposableAdapterInspector([]windowsDisposableAdapterObservation{good}))
 if err!=nil{t.Fatal(err)}
 expected:=WindowsDisposableDNSAdapter{
  InterfaceGUID:labAdapterGUID,InterfaceIndex:71,
  Alias:labAdapterAlias,Description:"Microsoft KM-TEST Loopback Adapter",
 }
 if !reflect.DeepEqual(got,expected){t.Fatalf("disposable adapter proof mismatch: got %+v",got)}
}
func TestDisposableDNSAdapterRejectsOrdinaryOrConnectedNIC(t *testing.T){
 for _,tc:=range []struct{
  name string
  change func(*windowsDisposableAdapterObservation)
 }{
  {"physical",func(x *windowsDisposableAdapterObservation){x.HardwareInterface=true}},
  {"ethernet",func(x *windowsDisposableAdapterObservation){x.InterfaceDescription="Intel(R) Ethernet"}},
  {"connected LAN",func(x *windowsDisposableAdapterObservation){x.NetworkCategory="Private"}},
  {"domain network",func(x *windowsDisposableAdapterObservation){x.NetworkCategory="DomainAuthenticated"}},
  {"default IPv4 route",func(x *windowsDisposableAdapterObservation){x.Routes=[]string{"0.0.0.0/0"}}},
  {"default IPv6 route",func(x *windowsDisposableAdapterObservation){x.Routes=[]string{"::/0"}}},
  {"private LAN route",func(x *windowsDisposableAdapterObservation){x.Routes=[]string{"192.168.0.0/16"}}},
  {"routable IPv4",func(x *windowsDisposableAdapterObservation){x.IPAddresses=[]string{"10.0.0.2"}}},
  {"global IPv6",func(x *windowsDisposableAdapterObservation){x.IPAddresses=[]string{"2001:db8::10"}}},
  {"existing DNS v4",func(x *windowsDisposableAdapterObservation){x.DNSIPv4=[]string{"1.1.1.1"}}},
  {"existing DNS v6",func(x *windowsDisposableAdapterObservation){x.DNSIPv6=[]string{"2606:4700:4700::1111"}}},
  {"wrong guid",func(x *windowsDisposableAdapterObservation){x.InterfaceGuid="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"}},
  {"zero index",func(x *windowsDisposableAdapterObservation){x.InterfaceIndex=0}},
 }{
  t.Run(tc.name,func(t *testing.T){
   x:=disposableAdapterFixture();tc.change(&x)
   if _,err:=VerifyWindowsDisposableDNSAdapterReadOnly(context.Background(),
    labAdapterAlias,labAdapterGUID,disposableAdapterInspector([]windowsDisposableAdapterObservation{x}));err==nil{
    t.Fatal("unsafe host network adapter accepted as disposable")
   }
  })
 }
}
func TestDisposableDNSAdapterRejectsDuplicateMissingAndUntrustedAlias(t *testing.T){
 x:=disposableAdapterFixture()
 for _,items:=range [][]windowsDisposableAdapterObservation{nil,{x,x}}{
  if _,err:=VerifyWindowsDisposableDNSAdapterReadOnly(context.Background(),
   labAdapterAlias,labAdapterGUID,disposableAdapterInspector(items));err==nil{
   t.Fatal("missing or ambiguous isolated network adapter accepted")
  }
 }
 for _,alias:=range []string{
  "Ethernet","Wi-Fi","VOLVE-DNS-SERVER-0270",
  "VOLVE-CI-DNS-LAB-123","VOLVE-CI-DNS-LAB-1793423456789;Set-DnsClient",
 }{
  if _,err:=VerifyWindowsDisposableDNSAdapterReadOnly(context.Background(),
   alias,labAdapterGUID,disposableAdapterInspector([]windowsDisposableAdapterObservation{x}));err==nil{
   t.Fatalf("unsafe adapter alias accepted: %q",alias)
  }
 }
 if _,err:=VerifyWindowsDisposableDNSAdapterReadOnly(context.Background(),
  labAdapterAlias,strings.Repeat("0",38),disposableAdapterInspector([]windowsDisposableAdapterObservation{x}));err==nil{
  t.Fatal("malformed pinned adapter GUID accepted")
 }
}
func TestDisposableDNSAdapterRejectsQueryInjectionAndCancelledContext(t *testing.T){
 if _,err:=DefaultWindowsDisposableDNSInspect(context.Background(),"Get-NetAdapter | Set-DnsClientServerAddress");err==nil{
  t.Fatal("untrusted PowerShell query approved")
 }
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 if _,err:=VerifyWindowsDisposableDNSAdapterReadOnly(ctx,
  labAdapterAlias,labAdapterGUID,disposableAdapterInspector(nil));!errors.Is(err,context.Canceled){
  t.Fatal("cancelled inspection continued")
 }
}
func TestRealWindowsRunnerCannotBeMistakenForDisposableDNSAdapter(t *testing.T){
 if os.Getenv("VOLVE_CI_READONLY_ADAPTER_INSPECTION")!="1"{
  t.Skip("requires read-only Windows GitHub-hosted runner")
 }
 ctx,cancel:=context.WithTimeout(context.Background(),35*time.Second)
 defer cancel()
 if _,err:=VerifyWindowsDisposableDNSAdapterReadOnly(ctx,
  labAdapterAlias,labAdapterGUID,DefaultWindowsDisposableDNSInspect);err==nil{
  t.Fatal("hosted Windows runner accepted as sacrificial adapter")
 }
 // No writes. The workflow compares real DNS settings before and after.
}
