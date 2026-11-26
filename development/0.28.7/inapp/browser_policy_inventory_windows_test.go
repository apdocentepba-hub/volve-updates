//go:build windows

package motorupdate

import (
 "context"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
 "strconv"
 "strings"
 "testing"
)

func browserPolicyJSON(chrome,edge,firefox int)[]byte{
 return []byte(
  `[{"Name":"chrome","Present":true,"NumberedEntries":`+itoaPolicy(chrome)+`,"InvalidEntries":0,"UnexpectedEntries":0,"ContentSHA256":"`+strings.Repeat("a",64)+`"},`+
   `{"Name":"edge","Present":true,"NumberedEntries":`+itoaPolicy(edge)+`,"InvalidEntries":0,"UnexpectedEntries":0,"ContentSHA256":"`+strings.Repeat("b",64)+`"},`+
   `{"Name":"firefox","Present":true,"NumberedEntries":`+itoaPolicy(firefox)+`,"InvalidEntries":0,"UnexpectedEntries":0,"ContentSHA256":"`+strings.Repeat("c",64)+`"}]`)
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
 if called!=1||e.TotalNumberedEntries!=532||len(e.Records)!=3||!e.NoRegistryValuesExported ||
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
 raw:=[]byte(`[{"Name":"chrome","Present":false,"NumberedEntries":0,"InvalidEntries":0,"UnexpectedEntries":0,"ContentSHA256":"`+strings.Repeat("a",64)+`"},{"Name":"edge","Present":false,"NumberedEntries":0,"InvalidEntries":0,"UnexpectedEntries":0,"ContentSHA256":"`+strings.Repeat("b",64)+`"},{"Name":"firefox","Present":false,"NumberedEntries":0,"InvalidEntries":0,"UnexpectedEntries":0,"ContentSHA256":"`+strings.Repeat("c",64)+`"}]`)
 e,err:=InspectWindowsBrowserPoliciesReadOnly(context.Background(),func(context.Context,string)([]byte,error){return raw,nil})
 if err!=nil{t.Fatal(err)}
 if e.TotalNumberedEntries!=0||e.BrowserEnforcementVerified||e.DNSMotorVerified{
  t.Fatal("absent registry keys were misrepresented as actual browser state")
 }
}
func TestVOLVEBrowserPolicyReadOnlyRejectsMissingOrMalformedFingerprints(t *testing.T){
 good:=string(browserPolicyJSON(1,2,3))
 for _,bad:=range []string{
  strings.Replace(good,`"ContentSHA256":"`+strings.Repeat("a",64)+`"`,`"ContentSHA256":""`,1),
  strings.Replace(good,`"ContentSHA256":"`+strings.Repeat("a",64)+`"`,`"ContentSHA256":"not-a-sha256"`,1),
 }{
  if _,err:=InspectWindowsBrowserPoliciesReadOnly(context.Background(),func(context.Context,string)([]byte,error){return []byte(bad),nil});err==nil{
   t.Fatal("missing or malformed full-policy fingerprint accepted")
  }
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

func makeBrowserOriginalCaptureFixture(t *testing.T)(WindowsBrowserPolicyEvidence,[]browserOriginalCaptureRow){
 t.Helper()
 e:=WindowsBrowserPolicyEvidence{Schema:1,Component:"browser-policy-registry-read-only",NoRegistryValuesExported:true}
 rows:=[]browserOriginalCaptureRow{}
 for _,name:=range []string{"chrome","edge","firefox"}{
  // Synthetic payloads test independent pinning, not registry encoding.
  raw:=[]byte("synthetic-"+name)
  sum:=sha256.Sum256(raw)
  p:=WindowsBrowserPolicyRecord{Name:name,Present:true,ContentSHA256:hex.EncodeToString(sum[:])}
  e.Records=append(e.Records,p)
  rows=append(rows,browserOriginalCaptureRow{WindowsBrowserPolicyRecord:p,PayloadBase64:base64.StdEncoding.EncodeToString(raw)})
 }
 return e,rows
}

func TestVOLVEBrowserOriginalCaptureIndependentPins(t *testing.T){
 e,rows:=makeBrowserOriginalCaptureFixture(t)
 raw,err:=json.Marshal(rows);if err!=nil{t.Fatal(err)}
 got,err:=captureOriginalBrowserPolicyBytes(context.Background(),e,func(context.Context)([]byte,error){return raw,nil})
 if err!=nil||len(got)!=3{t.Fatal("local capture rejected",err)}
 for _,name:=range []string{"chrome","edge","firefox"}{
  if string(got[name])!="synthetic-"+name{t.Fatal("local backup bytes differ")}
 }
}

func TestVOLVEBrowserOriginalCaptureRejectsDriftAndMalformedEvidence(t *testing.T){
 for _,kind:=range []string{"data","metadata","duplicate","missing","pin","trailing"}{
  t.Run(kind,func(t *testing.T){
   e,rows:=makeBrowserOriginalCaptureFixture(t)
   switch kind{
   case "data":rows[0].PayloadBase64=base64.StdEncoding.EncodeToString([]byte("changed"))
   case "metadata":rows[0].Present=false
   case "duplicate":rows[1]=rows[0]
   case "missing":rows=rows[:2]
   case "pin":e.Records[0].ContentSHA256=""
   }
   raw,err:=json.Marshal(rows);if err!=nil{t.Fatal(err)}
   if kind=="trailing"{raw=append(raw,[]byte(" {}")...)}
   got,err:=captureOriginalBrowserPolicyBytes(context.Background(),e,func(context.Context)([]byte,error){return raw,nil})
   if err==nil||got!=nil{t.Fatal("invalid private backup accepted")}
  })
 }
}

func TestVOLVEBrowserOriginalCaptureRealWindowsReadOnly(t *testing.T){
 if testing.Short(){t.Skip("native Windows CI")}
 ctx:=context.Background()
 e,err:=InspectWindowsBrowserPoliciesReadOnly(ctx,DefaultWindowsBrowserPolicyInspect)
 if err!=nil{t.Fatal(err)}
 got,err:=captureOriginalBrowserPolicyBytes(ctx,e,readOriginalBrowserPolicyLocal)
 if err!=nil||len(got)!=3{t.Fatal("real local policy capture rejected",err)}
 // Do not print the contents. Compare an independent post-read census.
 after,err:=InspectWindowsBrowserPoliciesReadOnly(ctx,DefaultWindowsBrowserPolicyInspect)
 if err!=nil{t.Fatal(err)}
 for i,p:=range e.Records{if p!=after.Records[i]{t.Fatal("browser registry changed during read-only capture")}}
 t.Log("PASS VOLVE_BROWSER_ORIGINAL_THREE_KEYS_NATIVE_READ_ONLY")
}
