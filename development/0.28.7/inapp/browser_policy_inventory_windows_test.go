//go:build windows

package motorupdate

import (
 "context"
 "errors"
 "strconv"
 "strings"
 "testing"
)

func browserPolicyJSON(chrome,edge,firefox int)[]byte{
 return []byte(
  `[{"Name":"chrome","Present":true,"NumberedEntries":`+itoaPolicy(chrome)+`,"InvalidEntries":0,"UnexpectedEntries":0},`+
   `{"Name":"edge","Present":true,"NumberedEntries":`+itoaPolicy(edge)+`,"InvalidEntries":0,"UnexpectedEntries":0},`+
   `{"Name":"firefox","Present":true,"NumberedEntries":`+itoaPolicy(firefox)+`,"InvalidEntries":0,"UnexpectedEntries":0}]`)
}
func itoaPolicy(v int)string{return strconv.Itoa(v)}

func TestVOLVEBrowserPolicyReadOnlyCountsDoNotClaimEffectiveProtection(t *testing.T){
 called:=0
 e,err:=InspectWindowsBrowserPoliciesReadOnly(context.Background(),func(_ context.Context,q string)([]byte,error){
  called++
  if q!=WindowsVOLVEBrowserPolicyQuery {t.Fatal("unknown registry command accepted")}
  return browserPolicyJSON(175,183,174),nil
 })
 if err!=nil{t.Fatal(err)}
 if called!=1||e.TotalNumberedEntries!=532||len(e.Records)!=3||!e.NoRegistryValuesCollected ||
  e.BrowserEnforcementVerified||e.DNSMotorVerified{
  t.Fatalf("registry inventory falsely proved browser/DNS blocking: %+v",e)
 }
}
func TestVOLVEBrowserPolicyReadOnlyRejectsInjectedOrAmbiguousResponses(t *testing.T){
 good:=string(browserPolicyJSON(1,2,3))
 for _,v:=range []struct{name,raw string}{
  {"empty",""},{"not-json","garbage"},{"null","null"},{"not-array","{}"},
  {"missing-browser",`[{"Name":"chrome","Present":true,"NumberedEntries":1,"InvalidEntries":0,"UnexpectedEntries":0}]`},
  {"duplicate-browser",strings.Replace(good,`"Name":"firefox"`,`"Name":"chrome"`,1)},
  {"injected-key",strings.Replace(good,`"Name":"firefox"`,`"Name":"safari"`,1)},
  {"extra-record",good[:len(good)-1]+`,{"Name":"opera","Present":false,"NumberedEntries":0,"InvalidEntries":0,"UnexpectedEntries":0}]`},
  {"extra-json",good+" {}"},{"unknown-field",strings.Replace(good,`"Present":true`,`"Present":true,"PrivateURL":"example.net"`,1)},
  {"negative",strings.Replace(good,`"NumberedEntries":1`,`"NumberedEntries":-1`,1)},
  {"overlimit",strings.Replace(good,`"NumberedEntries":1`,`"NumberedEntries":1001`,1)},
  {"missing-key-with-entries",strings.Replace(good,`"Present":true`,`"Present":false`,1)},
 }{
  t.Run(v.name,func(t *testing.T){
   _,err:=InspectWindowsBrowserPoliciesReadOnly(context.Background(),func(context.Context,string)([]byte,error){return []byte(v.raw),nil})
   if err==nil{t.Fatalf("accepted unsafe browser policy registry response: %s",v.name)}
  })
 }
}
func TestVOLVEBrowserPolicyReadOnlyMissingKeysAreNotFailedBrowserProtection(t *testing.T){
 raw:=[]byte(`[{"Name":"chrome","Present":false,"NumberedEntries":0,"InvalidEntries":0,"UnexpectedEntries":0},{"Name":"edge","Present":false,"NumberedEntries":0,"InvalidEntries":0,"UnexpectedEntries":0},{"Name":"firefox","Present":false,"NumberedEntries":0,"InvalidEntries":0,"UnexpectedEntries":0}]`)
 e,err:=InspectWindowsBrowserPoliciesReadOnly(context.Background(),func(context.Context,string)([]byte,error){return raw,nil})
 if err!=nil{t.Fatal(err)}
 if e.TotalNumberedEntries!=0||e.BrowserEnforcementVerified||e.DNSMotorVerified{
  t.Fatal("absent registry keys were misrepresented as actual browser state")
 }
}
func TestVOLVEBrowserPolicyReadOnlyRejectsCancelOrUnapprovedCommands(t *testing.T){
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 calls:=0
 _,err:=InspectWindowsBrowserPoliciesReadOnly(ctx,func(context.Context,string)([]byte,error){calls++;return nil,nil})
 if !errors.Is(err,context.Canceled)||calls!=0{t.Fatalf("cancelled policy registry read: calls=%d err=%v",calls,err)}
 if _,err:=DefaultWindowsBrowserPolicyInspect(context.Background(),"Remove-Item HKLM:\\SOFTWARE\\Policies");err==nil{
  t.Fatal("mutation command accepted by fixed read-only registry reader")
 }
}
func TestVOLVEBrowserPolicyRealWindowsRegistryNativeReadOnly(t *testing.T){
 if testing.Short(){t.Skip("requires native Windows CI host")}
 ctx:=context.Background()
 e,err:=InspectWindowsBrowserPoliciesReadOnly(ctx,DefaultWindowsBrowserPolicyInspect)
 if err!=nil{t.Fatal(err)}
 if len(e.Records)!=3||e.DNSMotorVerified||e.BrowserEnforcementVerified{
  t.Fatal("native Windows policy census claimed effective browser or DNS blocking")
 }
 t.Logf("READ ONLY native Windows: chrome=%d edge=%d firefox=%d; no browser URLs/registry writes",
  e.Records[0].NumberedEntries,e.Records[1].NumberedEntries,e.Records[2].NumberedEntries)
}
