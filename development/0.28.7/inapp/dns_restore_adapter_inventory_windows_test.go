//go:build windows

package motorupdate

import (
 "context"
 "errors"
 "os"
 "strings"
 "testing"
 "time"
)

func fakeWindowsInventoryRunner(t *testing.T,adapters string,dns string)WindowsReadOnlyPowerShell{
 t.Helper()
 return func(ctx context.Context,query string)([]byte,error){
  if err:=ctx.Err();err!=nil{return nil,err}
  switch query {
  case windowsAdapterInventoryQuery:return []byte(adapters),nil
  case windowsEffectiveDNSQuery:return []byte(dns),nil
  default:t.Fatalf("unsafe/unrecognized PowerShell command");return nil,errors.New("invalid query")
  }
 }
}
const testWindowsAdapterJSON=`[{"InterfaceGuid":"12345678-1234-1234-1234-123456789abc","InterfaceIndex":14}]`
const testWindowsDNSJSON=`[{"InterfaceIndex":14,"Family":"IPv4","Servers":["127.0.0.1"]},{"InterfaceIndex":14,"Family":"IPv6","Servers":["::1"]}]`

func TestWindowsAdapterDNSPreflightBoundToRealGUID(t *testing.T){
 run:=fakeWindowsInventoryRunner(t,testWindowsAdapterJSON,testWindowsDNSJSON)
 for _,tc:=range []struct{family DNSAddressFamily;original DNSServerState}{
  {DNSIPv4,restoreFixture(DNSIPv4,DNSStatic,"9.9.9.9","1.1.1.1").Original},
  {DNSIPv6,restoreFixture(DNSIPv6,DNSAutomatic).Original},
 }{
  r:=restoreFixture(tc.family,tc.original.Mode,tc.original.Servers...)
  cmds,err:=PreflightWindowsVOLVEDNSRestore(context.Background(),r,run)
  if err!=nil{t.Fatal(err)}
  if len(cmds)==0||cmds[0].Program!="netsh.exe" {t.Fatal("no family-scoped restoration command")}
  if !strings.Contains(strings.Join(cmds[0].Args," "),"name=14") {t.Fatal("wrong interface index")}
  if !strings.Contains(strings.Join(cmds[0].Args," "),strings.ToLower(string(tc.family))) {t.Fatal("wrong address family")}
 }
}
func TestWindowsAdapterDNSPreflightRejectsAmbiguityAndExternalOverride(t *testing.T){
 record:=restoreFixture(DNSIPv4,DNSStatic,"8.8.8.8")
 cases:=[]struct{name,inventory,dns string}{
  {"duplicate-index",`[{"InterfaceGuid":"12345678-1234-1234-1234-123456789abc","InterfaceIndex":14},{"InterfaceGuid":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","InterfaceIndex":14}]`,testWindowsDNSJSON},
  {"missing-guid",`[{"InterfaceGuid":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","InterfaceIndex":14}]`,testWindowsDNSJSON},
  {"malformed-guid",`[{"InterfaceGuid":"adapters::fake","InterfaceIndex":14}]`,testWindowsDNSJSON},
  {"invented-server",testWindowsAdapterJSON,`[{"InterfaceIndex":14,"Family":"IPv4","Servers":["8.8.8.8"]}]`},
  {"dual-server",testWindowsAdapterJSON,`[{"InterfaceIndex":14,"Family":"IPv4","Servers":["127.0.0.1","8.8.8.8"]}]`},
  {"missing-family",testWindowsAdapterJSON,`[{"InterfaceIndex":14,"Family":"IPv6","Servers":["::1"]}]`},
  {"duplicate-family",testWindowsAdapterJSON,`[{"InterfaceIndex":14,"Family":"IPv4","Servers":["127.0.0.1"]},{"InterfaceIndex":14,"Family":"IPv4","Servers":["127.0.0.1"]}]`},
 }
 for _,tc:=range cases{t.Run(tc.name,func(t *testing.T){
  if cmds,err:=PreflightWindowsVOLVEDNSRestore(context.Background(),record,fakeWindowsInventoryRunner(t,tc.inventory,tc.dns));err==nil||len(cmds)>0{
   t.Fatalf("unsafe live DNS inventory approved: %+v",cmds)
  }
 })}
}
func TestWindowsAdapterDNSPreflightRejectsAdapterIndexRace(t *testing.T){
 r:=restoreFixture(DNSIPv4,DNSAutomatic)
 called:=0
 run:=func(_ context.Context,query string)([]byte,error){
  switch query {
  case windowsAdapterInventoryQuery:
   called++
   if called>1{return []byte(`[{"InterfaceGuid":"12345678-1234-1234-1234-123456789abc","InterfaceIndex":18}]`),nil}
   return []byte(testWindowsAdapterJSON),nil
  case windowsEffectiveDNSQuery:return []byte(testWindowsDNSJSON),nil
  default:t.Fatal("untrusted command");return nil,errors.New("unexpected query")
  }
 }
 if _,err:=PreflightWindowsVOLVEDNSRestore(context.Background(),r,run);err==nil{t.Fatal("adapter index race not detected")}
}
func TestWindowsAdapterInventoryIsReadOnlyOnGithubWindows(t *testing.T){
 if os.Getenv("VOLVE_CI_READONLY_ADAPTER_INSPECTION")!="1"{t.Skip("actual Windows inventory only in disposable CI")}
 ctx,cancel:=context.WithTimeout(context.Background(),30*time.Second)
 defer cancel()
 raw,err:=DefaultWindowsReadOnlyPowerShell(ctx,windowsAdapterInventoryQuery)
 if err!=nil{t.Fatal(err)}
 inventory,err:=parseWindowsAdapterInventory(raw)
 if err!=nil{t.Fatal(err)}
 if len(inventory)==0{t.Fatal("no real Windows adapters found")}
 for _,a:=range inventory {
  idx,err:=FindWindowsAdapterIndex(ctx,a.InterfaceGUID,DefaultWindowsReadOnlyPowerShell)
  if err!=nil||idx!=a.InterfaceIndex{t.Fatal("Windows GUID-to-index identity mismatch:",err)}
 }
 // Inventory intentionally never inspects or modifies private DNS values.
 t.Logf("PASS: inspected %d live Windows GUID/index bindings without DNS writes",len(inventory))
}
