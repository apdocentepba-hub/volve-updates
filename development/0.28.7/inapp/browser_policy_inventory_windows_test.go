//go:build windows

package motorupdate

import (
 "bytes"
 "context"
 "crypto/sha256"
 "encoding/base64"
 "encoding/binary"
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

func TestVOLVEBrowserOriginalTripleBindsDNSProvenance(t *testing.T){
 ctx:=context.Background()
 parent,snap,browser,raw,data:=makeOriginalProtectionPairFixture(t)
 allow:=func(string)error{return nil}
 observed,err:=InspectWindowsDNSAssignmentProvenanceReadOnly(ctx,protectionSnapshotDNSInspect)
 if err!=nil{t.Fatal(err)}
 journal,digest,err:=BuildDNSOriginalJournal(ctx,observed.States)
 if err!=nil{t.Fatal(err)}
 snap.DNSAdaptersSHA256=observed.SHA256
 dnsParent:=filepath.Join(filepath.Dir(parent),"legacy-engine-recovery")
 if err:=os.Mkdir(dnsParent,0700);err!=nil{t.Fatal(err)}
 hostsPin:=WindowsHostsFileEvidence{SHA256:snap.HostsSHA256,BlockedRuleCount:snap.HostsBlockedRuleCount}
 if err:=storeOriginalWindowsHostsBackupUnarmed(ctx,parent,raw,hostsPin,allow,allow);err!=nil{t.Fatal(err)}
 if err:=storeBrowserOriginalArchiveUnarmed(ctx,parent,browser,data,allow,allow);err!=nil{t.Fatal(err)}
 if receipt,err:=verifyOriginalProtectionTripleUnarmed(ctx,parent,dnsParent,snap,browser,digest,allow);err==nil||receipt!=(originalProtectionPairReceipt{}){t.Fatal("missing DNS stage accepted")}
 if _,err:=StoreDNSOriginalBackupUnarmed(ctx,dnsParent,journal,digest,allow,allow);err!=nil{t.Fatal(err)}
 receipt,err:=verifyOriginalProtectionTripleUnarmed(ctx,parent,dnsParent,snap,browser,digest,allow)
 if err!=nil||!receipt.HostsVerified||receipt.BrowserKeysVerified!=3||!receipt.DNSBackupVerified||
  receipt.CatalogBackupVerified||receipt.CompleteRecoverySnapshot||receipt.InstallAuthorized||receipt.RestoreAuthorized{t.Fatal("incorrect combined receipt",err)}
 wrong:=snap;wrong.DNSAdaptersSHA256=strings.Repeat("f",64)
 if receipt,err:=verifyOriginalProtectionTripleUnarmed(ctx,parent,dnsParent,wrong,browser,digest,allow);err==nil||receipt!=(originalProtectionPairReceipt{}){t.Fatal("unrelated DNS baseline accepted")}
 if receipt,err:=verifyOriginalProtectionTripleUnarmed(ctx,parent,dnsParent,snap,browser,strings.Repeat("f",64),allow);err==nil||receipt!=(originalProtectionPairReceipt{}){t.Fatal("wrong journal pin accepted")}
 other:=filepath.Join(t.TempDir(),"legacy-engine-recovery")
 if receipt,err:=verifyOriginalProtectionTripleUnarmed(ctx,parent,other,snap,browser,digest,allow);err==nil||receipt!=(originalProtectionPairReceipt{}){t.Fatal("other transaction directory accepted")}
}
func TestVOLVEBrowserOriginalTripleRejectsDNSOrderAndModeDrift(t *testing.T){
 ctx:=context.Background()
 const guid="{12345678-1234-1234-1234-123456789abc}"
 original:=[]DNSServerState{
  {InterfaceGUID:guid,Family:DNSIPv4,Mode:DNSStatic,Servers:[]string{"9.9.9.9","1.1.1.1"}},
  {InterfaceGUID:guid,Family:DNSIPv6,Mode:DNSAutomatic,Servers:[]string{}},
 }
 encoded,err:=json.Marshal(original);if err!=nil{t.Fatal(err)}
 sum:=sha256.Sum256(encoded)
 _,snap,_,_,_:=makeOriginalProtectionPairFixture(t)
 snap.DNSAdaptersSHA256=hex.EncodeToString(sum[:])
 raw,pin,err:=BuildDNSOriginalJournal(ctx,original);if err!=nil{t.Fatal(err)}
 records,err:=VerifyDNSOriginalJournal(ctx,raw,pin);if err!=nil{t.Fatal(err)}
 if err:=originalDNSRecordsMatchProtectionBaseline(records,snap);err!=nil{t.Fatal("automatic nil/empty encoding mismatch",err)}
 for _,kind:=range []string{"server-order","assignment-mode"}{
  changed:=sortedDNSRecoveryRecords(records)
  switch kind{
  case "server-order":changed[0].Original.Servers=[]string{"1.1.1.1","9.9.9.9"}
  case "assignment-mode":changed[0].Original.Mode=DNSAutomatic;changed[0].Original.Servers=nil
  }
  if err:=originalDNSRecordsMatchProtectionBaseline(changed,snap);err==nil{t.Fatal("DNS baseline drift accepted",kind)}
 }
}

func browserStringDecodeFixture(t *testing.T,present bool,kind,encoded string)([]byte,WindowsBrowserPolicyRecord){
 t.Helper()
 var buf bytes.Buffer
 put:=func(s string){
  var lenBytes [10]byte
  n:=binary.PutUvarint(lenBytes[:],uint64(len(s)))
  buf.Write(lenBytes[:n]);buf.WriteString(s)
 }
 put("chrome")
 record:=WindowsBrowserPolicyRecord{Name:"chrome",Present:present}
 if present{
  buf.WriteByte(1)
  if err:=binary.Write(&buf,binary.LittleEndian,int32(1));err!=nil{t.Fatal(err)}
  put("1");put(kind);put(encoded);record.NumberedEntries=1
 }else{
  buf.WriteByte(0)
  if err:=binary.Write(&buf,binary.LittleEndian,int32(0));err!=nil{t.Fatal(err)}
 }
 raw:=buf.Bytes();sum:=sha256.Sum256(raw);record.ContentSHA256=hex.EncodeToString(sum[:])
 return raw,record
}
func TestVOLVEBrowserOriginalDecodeStringAndAbsent(t *testing.T){
 raw,record:=browserStringDecodeFixture(t,true,"String",`"https://example.test/área/😀"`)
 got,err:=decodeOriginalBrowserStringKey(raw,record)
 if err!=nil||!got.Present||len(got.Values)!=1||got.Values["1"]!="https://example.test/área/😀"{t.Fatal("original string was not reconstructed exactly",err)}
 raw,record=browserStringDecodeFixture(t,false,"","")
 got,err=decodeOriginalBrowserStringKey(raw,record)
 if err!=nil||got.Present||len(got.Values)!=0{t.Fatal("absent key was not reconstructed",err)}
}
func TestVOLVEBrowserOriginalDecodeRefusesUnsupportedAndMalformed(t *testing.T){
 for _,tc:=range []struct{kind,value string}{
  {"DWord","1"},{"ExpandString",`"%TEMP%"`},{"String","null"},{"String",`"\uD800"`},{"String",`"\u0000"`},
 }{
  raw,record:=browserStringDecodeFixture(t,true,tc.kind,tc.value)
  if _,err:=decodeOriginalBrowserStringKey(raw,record);err==nil{t.Fatal("uncertified value accepted")}
 }
 raw,record:=browserStringDecodeFixture(t,true,"String",`"fixture.test"`)
 record.ContentSHA256=strings.Repeat("0",64)
 if _,err:=decodeOriginalBrowserStringKey(raw,record);err==nil{t.Fatal("wrong digest accepted")}
 raw,record=browserStringDecodeFixture(t,true,"String",`"fixture.test"`)
 raw=append(raw,0);sum:=sha256.Sum256(raw);record.ContentSHA256=hex.EncodeToString(sum[:])
 if _,err:=decodeOriginalBrowserStringKey(raw,record);err==nil{t.Fatal("trailing bytes accepted")}
}

// Native registry roundtrip restricted to a random synthetic HKCU fixture.
// No actual browser policy is read or changed by this test. The entire key
// is created and removed in the same PowerShell invocation.
func TestVOLVEBrowserOriginalDecodeNativeStringRoundtrip(t *testing.T){
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{t.Skip("disposable hosted runner only")}
 ctx,cancel:=context.WithTimeout(context.Background(),45*time.Second);defer cancel()
 raw,record:=browserStringDecodeFixture(t,true,"String",`"https://example.test/área/😀"`)
 got,err:=decodeOriginalBrowserStringKey(raw,record)
 if err!=nil||!got.Present||len(got.Values)!=1{t.Fatal("fixture decoding failed",err)}
 // Encode synthetic UTF-8 value to avoid PowerShell argument/encoding
 // ambiguity. No real registry data or arbitrary paths are supplied.
 ps:=filepath.Join(os.Getenv("SystemRoot"),"System32","WindowsPowerShell","v1.0","powershell.exe")
 const script=`$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';
 if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'Hosted fixture only'};
 $name='Software\VOLVE-REGSZ-FIXTURE-'+[Guid]::NewGuid().ToString('N');
 $root=[Microsoft.Win32.Registry]::CurrentUser;
 if($null -ne ($existing=$root.OpenSubKey($name))){$existing.Dispose();throw 'Fixture collision'};
 $created=$false;
 try {
  $key=$root.CreateSubKey($name);$created=$true;
  try{
   $value=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:VOLVE_SYNTHETIC_REGSZ));
   $key.SetValue('1',$value,[Microsoft.Win32.RegistryValueKind]::String);
   $key.Flush();
  }finally{$key.Dispose()}
  $key=$root.OpenSubKey($name,$false);
  try{
   if($key.GetValueKind('1') -ne [Microsoft.Win32.RegistryValueKind]::String){throw 'Registry kind changed'};
   $value=$key.GetValue('1',$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames);
   if(@($key.GetValueNames()).Count -ne 1 -or $key.SubKeyCount -ne 0){throw 'Fixture structure changed'};
   $encoded=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$value));
   if($encoded -cne $env:VOLVE_SYNTHETIC_REGSZ){throw 'Registry string roundtrip mismatch'};
  }finally{$key.Dispose()}
 }finally{if($created){$root.DeleteSubKeyTree($name)}}
 if($null -ne ($left=$root.OpenSubKey($name))){$left.Dispose();throw 'Fixture cleanup failed'};
 Write-Output 'VOLVE_SYNTHETIC_REGSZ_ROUNDTRIP_OK'`
 cmd:=exec.CommandContext(ctx,ps,"-NoLogo","-NoProfile","-NonInteractive","-Command",script)
 cmd.Env=append(os.Environ(),"VOLVE_SYNTHETIC_REGSZ="+base64.StdEncoding.EncodeToString([]byte(got.Values["1"])))
 out,err:=cmd.Output()
 if err!=nil||strings.TrimSpace(string(out))!="VOLVE_SYNTHETIC_REGSZ_ROUNDTRIP_OK"{t.Fatal("native synthetic registry roundtrip or cleanup failed",err)}
 t.Log("PASS VOLVE_BROWSER_SYNTHETIC_HKCU_REGSZ_ROUNDTRIP_AND_CLEANUP")
}
