//go:build windows

package motorupdate

import (
 "context"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
 "os"
 "os/exec"
 "path/filepath"
 "time"
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

func browserArchiveFixture(t *testing.T)(WindowsBrowserPolicyEvidence,map[string][]byte){
 t.Helper()
 e,rows:=makeBrowserOriginalCaptureFixture(t)
 raw,err:=json.Marshal(rows);if err!=nil{t.Fatal(err)}
 data,err:=captureOriginalBrowserPolicyBytes(context.Background(),e,func(context.Context)([]byte,error){return raw,nil})
 if err!=nil{t.Fatal(err)}
 return e,data
}

func TestVOLVEBrowserOriginalArchiveCreateOnlyAndTamper(t *testing.T){
 ctx:=context.Background()
 e,data:=browserArchiveFixture(t)
 parent:=filepath.Join(t.TempDir(),"original-protection-recovery")
 if err:=os.Mkdir(parent,0700);err!=nil{t.Fatal(err)}
 allow:=func(string)error{return nil}
 if err:=storeBrowserOriginalArchiveUnarmed(ctx,parent,e,data,allow,allow);err!=nil{t.Fatal(err)}
 got,err:=readBrowserOriginalArchiveUnarmed(ctx,parent,e,allow)
 if err!=nil||len(got)!=3{t.Fatal("reopen failed",err)}
 for n,v:=range data{if string(got[n])!=string(v){t.Fatal("original bytes differ")}}
 if err:=storeBrowserOriginalArchiveUnarmed(ctx,parent,e,data,allow,allow);err==nil{t.Fatal("overwrite permitted")}
 _,file,err:=browserOriginalArchivePaths(parent);if err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(file,[]byte("[]"),0600);err!=nil{t.Fatal(err)}
 if got,err:=readBrowserOriginalArchiveUnarmed(ctx,parent,e,allow);err==nil||got!=nil{t.Fatal("tampered archive accepted")}
}

func TestVOLVEBrowserOriginalArchiveRefusesPartialAndInvalidPayload(t *testing.T){
 ctx:=context.Background()
 e,data:=browserArchiveFixture(t)
 parent:=filepath.Join(t.TempDir(),"original-protection-recovery")
 if err:=os.Mkdir(parent,0700);err!=nil{t.Fatal(err)}
 allow:=func(string)error{return nil}
 deny:=func(string)error{return errors.New("fixture ACL denied")}
 dir,file,err:=browserOriginalArchivePaths(parent);if err!=nil{t.Fatal(err)}
 saved:=data["chrome"];data["chrome"]=[]byte("bad")
 if err:=storeBrowserOriginalArchiveUnarmed(ctx,parent,e,data,allow,allow);err==nil{t.Fatal("invalid payload accepted")}
 data["chrome"]=saved
 if err:=storeBrowserOriginalArchiveUnarmed(ctx,parent,e,data,allow,deny);err==nil{t.Fatal("unsafe parent accepted")}
 if _,err:=os.Lstat(dir);!os.IsNotExist(err){t.Fatal("stage created before verification")}
 if err:=storeBrowserOriginalArchiveUnarmed(ctx,parent,e,data,deny,allow);err==nil{t.Fatal("failed seal ignored")}
 if _,err:=os.Lstat(file);!os.IsNotExist(err){t.Fatal("payload written before directory seal")}
 if err:=storeBrowserOriginalArchiveUnarmed(ctx,parent,e,data,allow,allow);err==nil{t.Fatal("interrupted stage reused")}
}

func TestVOLVEBrowserOriginalArchiveRealNTFS(t *testing.T){
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{t.Skip("disposable runner only")}
 ctx,cancel:=context.WithTimeout(context.Background(),90*time.Second);defer cancel()
 e,data:=browserArchiveFixture(t)
 parent:=filepath.Join(t.TempDir(),"original-protection-recovery")
 if err:=os.Mkdir(parent,0700);err!=nil{t.Fatal(err)}
 if err:=sealDNSBackupLabNode(ctx,parent);err!=nil{t.Fatal(err)}
 seal:=func(path string)error{return sealDNSBackupLabNode(ctx,path)}
 check:=func(path string)error{return nativeDNSOriginalBackupACL(ctx,path)}
 if err:=storeBrowserOriginalArchiveUnarmed(ctx,parent,e,data,seal,check);err!=nil{t.Fatal(err)}
 got,err:=readBrowserOriginalArchiveUnarmed(ctx,parent,e,check)
 if err!=nil||len(got)!=3{t.Fatal("native archive reopen failed",err)}
 for n,v:=range data{if string(got[n])!=string(v){t.Fatal("original bytes differ")}}
 _,file,err:=browserOriginalArchivePaths(parent);if err!=nil{t.Fatal(err)}
 out,err:=exec.CommandContext(ctx,"icacls.exe",file,"/grant","*S-1-1-0:W").CombinedOutput()
 if err!=nil{t.Fatalf("fixture ACL change failed: %v %s",err,string(out))}
 if got,err:=readBrowserOriginalArchiveUnarmed(ctx,parent,e,check);err==nil||got!=nil{t.Fatal("weakened backup ACL accepted")}
 t.Log("PASS VOLVE_BROWSER_ARCHIVE_REAL_NTFS_FIXTURE")
}

func makeOriginalProtectionPairFixture(t *testing.T)(string,ProtectionSnapshot,WindowsBrowserPolicyEvidence,[]byte,map[string][]byte){
 t.Helper()
 parent:=filepath.Join(t.TempDir(),"original-protection-recovery")
 if err:=os.Mkdir(parent,0700);err!=nil{t.Fatal(err)}
 browser,data:=browserArchiveFixture(t)
 raw:=[]byte("# original fixture\r\n0.0.0.0 fixture.test\r\n")
 sum:=sha256.Sum256(raw)
 snap:=ProtectionSnapshot{HostsSHA256:hex.EncodeToString(sum[:]),HostsBlockedRuleCount:1,
  CatalogTaskDefinitionSHA256:strings.Repeat("a",64),DNSAdaptersSHA256:strings.Repeat("b",64)}
 for _,record:=range browser.Records{
  switch record.Name{case "chrome":snap.ChromePoliciesSHA256=record.ContentSHA256
  case "edge":snap.EdgePoliciesSHA256=record.ContentSHA256
  case "firefox":snap.FirefoxPoliciesSHA256=record.ContentSHA256}
 }
 return parent,snap,browser,raw,data
}
func TestVOLVEBrowserOriginalPairRefusesIncompleteAndForeignBaseline(t *testing.T){
 ctx:=context.Background()
 parent,snap,browser,raw,data:=makeOriginalProtectionPairFixture(t)
 allow:=func(string)error{return nil}
 pin:=WindowsHostsFileEvidence{SHA256:snap.HostsSHA256,BlockedRuleCount:snap.HostsBlockedRuleCount}
 if err:=storeOriginalWindowsHostsBackupUnarmed(ctx,parent,raw,pin,allow,allow);err!=nil{t.Fatal(err)}
 if receipt,err:=verifyOriginalProtectionPairUnarmed(ctx,parent,snap,browser,allow);err==nil||receipt!=(originalProtectionPairReceipt{}){t.Fatal("partial backup accepted")}
 if err:=storeBrowserOriginalArchiveUnarmed(ctx,parent,browser,data,allow,allow);err!=nil{t.Fatal(err)}
 bad:=snap;bad.ChromePoliciesSHA256=strings.Repeat("f",64)
 if receipt,err:=verifyOriginalProtectionPairUnarmed(ctx,parent,bad,browser,allow);err==nil||receipt!=(originalProtectionPairReceipt{}){t.Fatal("foreign baseline accepted")}
 bad=snap;bad.DNSAdaptersSHA256=""
 if receipt,err:=verifyOriginalProtectionPairUnarmed(ctx,parent,bad,browser,allow);err==nil||receipt!=(originalProtectionPairReceipt{}){t.Fatal("incomplete original census accepted")}
 receipt,err:=verifyOriginalProtectionPairUnarmed(ctx,parent,snap,browser,allow)
 if err!=nil||!receipt.HostsVerified||receipt.BrowserKeysVerified!=3||
  receipt.CatalogBackupVerified||receipt.DNSBackupVerified||receipt.CompleteRecoverySnapshot||receipt.InstallAuthorized||receipt.RestoreAuthorized{t.Fatal("pair receipt incorrect",err)}
}
func TestVOLVEBrowserOriginalPairRealNTFS(t *testing.T){
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{t.Skip("disposable runner only")}
 ctx,cancel:=context.WithTimeout(context.Background(),120*time.Second);defer cancel()
 parent,snap,browser,raw,data:=makeOriginalProtectionPairFixture(t)
 if err:=sealDNSBackupLabNode(ctx,parent);err!=nil{t.Fatal(err)}
 seal:=func(path string)error{return sealDNSBackupLabNode(ctx,path)}
 check:=func(path string)error{return nativeDNSOriginalBackupACL(ctx,path)}
 pin:=WindowsHostsFileEvidence{SHA256:snap.HostsSHA256,BlockedRuleCount:snap.HostsBlockedRuleCount}
 if err:=storeOriginalWindowsHostsBackupUnarmed(ctx,parent,raw,pin,seal,check);err!=nil{t.Fatal(err)}
 if err:=storeBrowserOriginalArchiveUnarmed(ctx,parent,browser,data,seal,check);err!=nil{t.Fatal(err)}
 receipt,err:=verifyOriginalProtectionPairUnarmed(ctx,parent,snap,browser,check)
 if err!=nil||!receipt.HostsVerified||receipt.BrowserKeysVerified!=3||receipt.CompleteRecoverySnapshot||receipt.InstallAuthorized||receipt.RestoreAuthorized{t.Fatal("native pair verification failed",err)}
 _,file,err:=originalHostsBackupPaths(parent);if err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(file,[]byte("changed"),0600);err!=nil{t.Fatal(err)}
 if receipt,err:=verifyOriginalProtectionPairUnarmed(ctx,parent,snap,browser,check);err==nil||receipt!=(originalProtectionPairReceipt{}){t.Fatal("modified member accepted")}
 t.Log("PASS VOLVE_ORIGINAL_PAIR_REAL_NTFS_NO_INSTALL")
}
