//go:build windows

package motorupdate

import (
 "bufio"
 "bytes"
 "context"
 "io"
 "os/exec"
 "crypto/ed25519"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
 "os"
 "time"
 "path/filepath"
 "strings"
 "testing"
)

func freshWindowsTaskJSON(t *testing.T,rows []windowsVOLVETaskRecord)[]byte{
 t.Helper();b,e:=json.Marshal(rows);if e!=nil{t.Fatal(e)};return b
}
func freshTaskFixture()windowsVOLVETaskRecord{
 return windowsVOLVETaskRecord{
  Name:"VOLVE-CATALOGO-0230",TaskPath:"\\",Principal:"SYSTEM",
  Actions:[]windowsVOLVETaskAction{{Execute:`C:\Program Files\VOLVE\VOLVE_Catalog.exe`,Arguments:"--catalog",WorkingDirectory:new(string)}},
  DefinitionSHA256:strings.Repeat("a",64),
 }
}
func TestWindowsFreshTaskInventoryExactCatalogAndUnknowns(t *testing.T){
 path:=filepath.Clean(`C:\Program Files\VOLVE\VOLVE_Catalog.exe`)
 good:=freshTaskFixture()
 for _,tc:=range []struct{name string;records []windowsVOLVETaskRecord;exe,args string;wantReady bool;wantUnknown int}{
  {"empty",[]windowsVOLVETaskRecord{},"","",true,0},
  {"expected-catalog",[]windowsVOLVETaskRecord{good},path,"--catalog",true,0},
  {"catalog-working-dir-unpinned",func()[]windowsVOLVETaskRecord{bad:=freshTaskFixture();wd:=`C:\Temp`;bad.Actions[0].WorkingDirectory=&wd;return []windowsVOLVETaskRecord{bad}}(),path,"--catalog",false,0},
  {"catalog-working-dir-missing",func()[]windowsVOLVETaskRecord{bad:=freshTaskFixture();bad.Actions[0].WorkingDirectory=nil;return []windowsVOLVETaskRecord{bad}}(),path,"--catalog",false,0},
  {"catalog-args-unknown",[]windowsVOLVETaskRecord{good},path,"--delete",false,0},
  {"catalog-path-unknown",[]windowsVOLVETaskRecord{good},"","",false,0},
  {"catalog-principal-untrusted",func()[]windowsVOLVETaskRecord{bad:=good;bad.Principal="Users";return []windowsVOLVETaskRecord{bad}}(),path,"--catalog",false,0},
  {"unknown-dns-task",[]windowsVOLVETaskRecord{{Name:"VOLVE-DNS-SERVER-0270",TaskPath:"\\",Principal:"SYSTEM",DefinitionSHA256:strings.Repeat("b",64)}},path,"--catalog",false,1},
  {"catalog-and-motor",[]windowsVOLVETaskRecord{good,{Name:"VOLVE-DNS-SERVER-0270",TaskPath:"\\",Principal:"SYSTEM",DefinitionSHA256:strings.Repeat("b",64)}},path,"--catalog",false,1},
 }{
  t.Run(tc.name,func(t *testing.T){
   called:=0
   result,err:=InspectWindowsVOLVETasksReadOnly(context.Background(),tc.exe,tc.args,
    func(_ context.Context,query string)([]byte,error){
     called++;if query!=WindowsVOLVETaskInventoryQuery{t.Fatal("not fixed read-only query")}
     return freshWindowsTaskJSON(t,tc.records),nil
    })
   if err!=nil{t.Fatal(err)}
   if called!=1 || len(result.UnknownTaskNames)!=tc.wantUnknown {t.Fatalf("query/unknown mismatch: %+v",result)}
   // Other five OS inventories are synthetic in THIS test; the task
   // inventory itself came from the injected Windows query response.
   evidence:=freshCompleteObservation()
   evidence.VOLVETaskCount=result.VOLVETaskCount
   evidence.VerifiedCatalogTask=result.VerifiedCatalogTask
   accepted:=CheckFreshMotorInstallReadiness(context.Background(),evidence)==nil
   if accepted!=tc.wantReady{t.Fatalf("unsafe fresh classification: accepted=%t want=%t inventory=%+v",accepted,tc.wantReady,result)}
  })
 }
}
func TestWindowsFreshTaskInventoryRejectsMalformedOrAmbiguous(t *testing.T){
 good:=freshTaskFixture()
 for _,tc:=range []struct{name string;raw []byte}{
  {"empty-bytes",nil},{"null",[]byte("null")},
  {"object-not-array",[]byte("{}")},
  {"trailing",[]byte("[] true")},
  {"bad-JSON",[]byte("[")}, 
  {"extra-field",[]byte(`[{"Name":"VOLVE-CATALOGO-0230","TaskPath":"\\","Principal":"SYSTEM","Actions":[],"DefinitionSHA256":"`+strings.Repeat("a",64)+`","Unexpected":true}]`)},
  {"duplicate",freshWindowsTaskJSON(t,[]windowsVOLVETaskRecord{good,good})},
  {"corrupted-SHA",func()[]byte{bad:=good;bad.DefinitionSHA256="not-sha";return freshWindowsTaskJSON(t,[]windowsVOLVETaskRecord{bad})}()},
  {"irrelevant-task",freshWindowsTaskJSON(t,[]windowsVOLVETaskRecord{{Name:"WindowsUpdate",TaskPath:"\\",DefinitionSHA256:strings.Repeat("b",64)}})},
 }{
  t.Run(tc.name,func(t *testing.T){
   _,err:=InspectWindowsVOLVETasksReadOnly(context.Background(),"","",
    func(context.Context,string)([]byte,error){return tc.raw,nil})
   if err==nil{t.Fatalf("unsafe task inventory accepted: %s",tc.name)}
  })
 }
}
func TestWindowsFreshTaskInventoryFailClosedOnCancelledOrUntrustedQuery(t *testing.T){
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 called:=false
 _,err:=InspectWindowsVOLVETasksReadOnly(ctx,"","",func(context.Context,string)([]byte,error){called=true;return []byte("[]"),nil})
 if !errors.Is(err,context.Canceled)||called{t.Fatalf("cancelled inventory was executed: %v",err)}
 if _,err:=DefaultWindowsFreshTaskInspect(context.Background(),"Start-ScheduledTask");err==nil{
  t.Fatal("unallowlisted PowerShell must not execute")
 }
}
// Actual read-only Windows API query with no fixture and no task mutations.
// Runner is disposable; an unrelated VOLVE task, if any, is reported instead
// of incorrectly classified as clean.
func TestWindowsFreshTaskInventoryRealTaskSchedulerReadOnly(t *testing.T){
 if testing.Short(){t.Skip("native Windows inventory only for integration")}
 ctx:=context.Background()
 result,err:=InspectWindowsVOLVETasksReadOnly(ctx,"","",DefaultWindowsFreshTaskInspect)
 if err!=nil{t.Fatalf("real Windows task inventory failed closed: %v",err)}
 if result.VOLVETaskCount!=len(result.UnknownTaskNames) && result.VerifiedCatalogTask==nil {
  t.Fatalf("task inventory count inconsistent: %+v",result)
 }
 t.Logf("READ ONLY: enumerated %d VOLVE tasks, catalog verified=%t, unknown task count=%d (NO task/DNS writes)",
  result.VOLVETaskCount,result.VerifiedCatalogTask!=nil&&result.VerifiedCatalogTask.ActionVerified,len(result.UnknownTaskNames))
}

func TestWindowsOriginalCatalogCaptureExactXMLAndDrift(t *testing.T){
 ctx:=context.Background()
 original:=[]byte("<Task><RegistrationInfo><Description>fixture</Description></RegistrationInfo></Task>")
 sum:=sha256.Sum256(original)
 task:=freshTaskFixture();task.DefinitionSHA256=hex.EncodeToString(sum[:])
 inventory,err:=InspectWindowsVOLVETasksReadOnly(ctx,task.Actions[0].Execute,task.Actions[0].Arguments,func(context.Context,string)([]byte,error){return freshWindowsTaskJSON(t,[]windowsVOLVETaskRecord{task}),nil})
 if err!=nil{t.Fatal(err)}
 snap:=ProtectionSnapshot{HostsSHA256:strings.Repeat("a",64),ChromePoliciesSHA256:strings.Repeat("b",64),EdgePoliciesSHA256:strings.Repeat("c",64),FirefoxPoliciesSHA256:strings.Repeat("d",64),CatalogTaskDefinitionSHA256:task.DefinitionSHA256,DNSAdaptersSHA256:strings.Repeat("e",64)}
 reader:=func(payload []byte)func(context.Context)([]byte,error){return func(context.Context)([]byte,error){
  return json.Marshal(map[string]any{"Present":true,"PayloadBase64":base64.StdEncoding.EncodeToString(payload)})
 }}
 got,err:=captureOriginalCatalogDefinition(ctx,snap,inventory,reader(original))
 if err!=nil||!got.Present||string(got.XML)!=string(original){t.Fatal("original catalog capture failed",err)}
 public,err:=json.Marshal(got);if err!=nil||strings.Contains(string(public),"fixture"){t.Fatal("private XML exported")}
 if _,err:=captureOriginalCatalogDefinition(ctx,snap,inventory,reader([]byte("changed")));err==nil{t.Fatal("changed definition accepted")}
 bad:=inventory;bad.UnknownTaskNames=[]string{"unknown"}
 if _,err:=captureOriginalCatalogDefinition(ctx,snap,bad,reader(original));err==nil{t.Fatal("unknown task accepted")}
}
func TestWindowsOriginalCatalogCaptureAbsenceAndMissingEvidence(t *testing.T){
 ctx:=context.Background()
 sum:=sha256.Sum256([]byte(catalogTaskAbsentMarker))
 snap:=ProtectionSnapshot{HostsSHA256:strings.Repeat("a",64),ChromePoliciesSHA256:strings.Repeat("b",64),EdgePoliciesSHA256:strings.Repeat("c",64),FirefoxPoliciesSHA256:strings.Repeat("d",64),CatalogTaskDefinitionSHA256:hex.EncodeToString(sum[:]),DNSAdaptersSHA256:strings.Repeat("e",64)}
 inventory:=WindowsFreshVOLVETaskInventory{}
 for _,v:=range []string{`{}`,`{"Present":null,"PayloadBase64":""}`,`{"Present":false}`,`{"Present":true,"PayloadBase64":""}`,`{"Present":false,"PayloadBase64":"YWJj"}`}{
  if _,err:=captureOriginalCatalogDefinition(ctx,snap,inventory,func(context.Context)([]byte,error){return []byte(v),nil});err==nil{t.Fatal("ambiguous absence accepted")}
 }
 got,err:=captureOriginalCatalogDefinition(ctx,snap,inventory,func(context.Context)([]byte,error){return []byte(`{"Present":false,"PayloadBase64":""}`),nil})
 if err!=nil||got.Present||got.XML!=nil{t.Fatal("explicit absent task rejected",err)}
}

func TestWindowsOriginalCatalogArchivePresentAndAbsent(t *testing.T){
 for _,present:=range []bool{true,false}{
  name:="absent";if present{name="present"}
  t.Run(name,func(t *testing.T){
   ctx:=context.Background()
   parent,snap,_,_,_:=makeOriginalProtectionPairFixture(t)
   definition:=originalCatalogDefinition{}
   inv:=WindowsFreshVOLVETaskInventory{}
   sum:=sha256.Sum256([]byte(catalogTaskAbsentMarker))
   if present{
    definition=originalCatalogDefinition{Present:true,XML:[]byte("<Task>synthetic</Task>")}
    sum=sha256.Sum256(definition.XML)
    task:=freshTaskFixture();task.DefinitionSHA256=hex.EncodeToString(sum[:])
    var err error
    inv,err=InspectWindowsVOLVETasksReadOnly(ctx,task.Actions[0].Execute,task.Actions[0].Arguments,func(context.Context,string)([]byte,error){return freshWindowsTaskJSON(t,[]windowsVOLVETaskRecord{task}),nil})
    if err!=nil{t.Fatal(err)}
   }
   snap.CatalogTaskDefinitionSHA256=hex.EncodeToString(sum[:])
   allow:=func(string)error{return nil}
   if err:=storeOriginalCatalogArchiveUnarmed(ctx,parent,snap,inv,definition,allow,allow);err!=nil{t.Fatal(err)}
   got,err:=readOriginalCatalogArchiveUnarmed(ctx,parent,snap,inv,allow)
   if err!=nil||got.Present!=present||string(got.XML)!=string(definition.XML){t.Fatal("catalog archive readback mismatch",err)}
   if err:=storeOriginalCatalogArchiveUnarmed(ctx,parent,snap,inv,definition,allow,allow);err==nil{t.Fatal("archive overwrite accepted")}
   _,file,err:=catalogOriginalArchivePaths(parent);if err!=nil{t.Fatal(err)}
   if err:=os.WriteFile(file,[]byte("{}"),0600);err!=nil{t.Fatal(err)}
   if _,err:=readOriginalCatalogArchiveUnarmed(ctx,parent,snap,inv,allow);err==nil{t.Fatal("corrupted archive accepted")}
  })
 }
}

func TestWindowsOriginalCatalogArchiveRealNTFS(t *testing.T){
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{t.Skip("disposable runner only")}
 ctx,cancel:=context.WithTimeout(context.Background(),90*time.Second);defer cancel()
 parent,snap,_,_,_:=makeOriginalProtectionPairFixture(t)
 definition:=originalCatalogDefinition{Present:true,XML:[]byte("<Task>synthetic native fixture</Task>")}
 sum:=sha256.Sum256(definition.XML)
 snap.CatalogTaskDefinitionSHA256=hex.EncodeToString(sum[:])
 task:=freshTaskFixture();task.DefinitionSHA256=snap.CatalogTaskDefinitionSHA256
 inv,err:=InspectWindowsVOLVETasksReadOnly(ctx,task.Actions[0].Execute,task.Actions[0].Arguments,func(context.Context,string)([]byte,error){return freshWindowsTaskJSON(t,[]windowsVOLVETaskRecord{task}),nil})
 if err!=nil{t.Fatal(err)}
 seal:=func(path string)error{return sealDNSBackupLabNode(ctx,path)}
 check:=func(path string)error{return nativeDNSOriginalBackupACL(ctx,path)}
 if err:=seal(parent);err!=nil{t.Fatal(err)}
 if err:=storeOriginalCatalogArchiveUnarmed(ctx,parent,snap,inv,definition,seal,check);err!=nil{t.Fatal(err)}
 got,err:=readOriginalCatalogArchiveUnarmed(ctx,parent,snap,inv,check)
 if err!=nil||!got.Present||string(got.XML)!=string(definition.XML){t.Fatal("native catalog archive readback mismatch",err)}
 t.Log("PASS VOLVE_CATALOG_ARCHIVE_REAL_NTFS_FIXTURE_NO_TASK_WRITES")
}

func TestWindowsOriginalCatalogArchiveFourComponentReview(t *testing.T){
 ctx:=context.Background()
 parent,snap,browser,hosts,policies:=makeOriginalProtectionPairFixture(t)
 allow:=func(string)error{return nil}
 observed,err:=InspectWindowsDNSAssignmentProvenanceReadOnly(ctx,protectionSnapshotDNSInspect)
 if err!=nil{t.Fatal(err)}
 journal,pin,err:=BuildDNSOriginalJournal(ctx,observed.States)
 if err!=nil{t.Fatal(err)}
 snap.DNSAdaptersSHA256=observed.SHA256
 dnsParent:=filepath.Join(filepath.Dir(parent),"legacy-engine-recovery")
 if err:=os.Mkdir(dnsParent,0700);err!=nil{t.Fatal(err)}
 sum:=sha256.Sum256([]byte(catalogTaskAbsentMarker))
 snap.CatalogTaskDefinitionSHA256=hex.EncodeToString(sum[:])
 inv:=WindowsFreshVOLVETaskInventory{}
 hostsPin:=WindowsHostsFileEvidence{SHA256:snap.HostsSHA256,BlockedRuleCount:snap.HostsBlockedRuleCount}
 if err:=storeOriginalWindowsHostsBackupUnarmed(ctx,parent,hosts,hostsPin,allow,allow);err!=nil{t.Fatal(err)}
 if err:=storeBrowserOriginalArchiveUnarmed(ctx,parent,browser,policies,allow,allow);err!=nil{t.Fatal(err)}
 if _,err:=StoreDNSOriginalBackupUnarmed(ctx,dnsParent,journal,pin,allow,allow);err!=nil{t.Fatal(err)}
 review:=func()(originalProtectionPairReceipt,error){
  return verifyOriginalProtectionArchivesUnarmed(ctx,parent,dnsParent,snap,browser,inv,pin,allow)
 }
 if got,err:=review();err==nil||got!=(originalProtectionPairReceipt{}){t.Fatal("missing catalog archive accepted")}
 if err:=storeOriginalCatalogArchiveUnarmed(ctx,parent,snap,inv,originalCatalogDefinition{},allow,allow);err!=nil{t.Fatal(err)}
 got,err:=review()
 if err!=nil||!got.HostsVerified||got.BrowserKeysVerified!=3||!got.DNSBackupVerified||!got.CatalogBackupVerified||
  got.CompleteRecoverySnapshot||got.InstallAuthorized||got.RestoreAuthorized{t.Fatal("four-component review incorrectly reported",err)}
 // Corrupt an earlier synthetic archive only when catalog verification starts.
 // The second triple check must refuse the result rather than report success.
 _,file,err:=catalogOriginalArchivePaths(parent);if err!=nil{t.Fatal(err)}
 _,browserFile,err:=browserOriginalArchivePaths(parent);if err!=nil{t.Fatal(err)}
 prior,err:=os.ReadFile(browserFile);if err!=nil{t.Fatal(err)}
 mutated:=false
 driftCheck:=func(p string)error{
  if p==file&&!mutated{mutated=true;return os.WriteFile(browserFile,[]byte("{}"),0600)}
  return nil
 }
 drift,driftErr:=verifyOriginalProtectionArchivesUnarmed(ctx,parent,dnsParent,snap,browser,inv,pin,driftCheck)
 if !mutated||driftErr==nil||drift!=(originalProtectionPairReceipt{}){t.Fatal("prior archive drift during catalog review accepted")}
 if err:=os.WriteFile(browserFile,prior,0600);err!=nil{t.Fatal(err)}
 if got,err:=review();err!=nil||!got.CatalogBackupVerified{t.Fatal("intact synthetic archives not verified after fixture reset",err)}
 t.Log("PASS VOLVE_FOUR_ARCHIVES_REJECT_DRIFT_DURING_CATALOG_REVIEW")
 if err:=os.WriteFile(file,[]byte("{}"),0600);err!=nil{t.Fatal(err)}
 if got,err:=review();err==nil||got!=(originalProtectionPairReceipt{}){t.Fatal("invalid catalog archive accepted")}
 t.Log("PASS VOLVE_FOUR_ORIGINAL_ARCHIVES_FIXTURE_REVIEW_NO_AUTHORIZATION")
}

func TestWindowsOriginalCatalogArchiveNativeDisplayReview(t *testing.T){
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{t.Skip("disposable runner only")}
 ctx,cancel:=context.WithTimeout(context.Background(),150*time.Second);defer cancel()
 parent,snap,browser,hosts,policies:=makeOriginalProtectionPairFixture(t)
 observed,err:=InspectWindowsDNSAssignmentProvenanceReadOnly(ctx,protectionSnapshotDNSInspect)
 if err!=nil{t.Fatal(err)}
 journal,pin,err:=BuildDNSOriginalJournal(ctx,observed.States)
 if err!=nil{t.Fatal(err)}
 snap.DNSAdaptersSHA256=observed.SHA256
 dnsParent:=filepath.Join(filepath.Dir(parent),"legacy-engine-recovery")
 if err:=os.Mkdir(dnsParent,0700);err!=nil{t.Fatal(err)}
 seal:=func(path string)error{return sealDNSBackupLabNode(ctx,path)}
 check:=func(path string)error{return nativeDNSOriginalBackupACL(ctx,path)}
 if err:=seal(parent);err!=nil{t.Fatal(err)}
 if err:=seal(dnsParent);err!=nil{t.Fatal(err)}
 sum:=sha256.Sum256([]byte(catalogTaskAbsentMarker))
 snap.CatalogTaskDefinitionSHA256=hex.EncodeToString(sum[:])
 inv:=WindowsFreshVOLVETaskInventory{}
 hostsPin:=WindowsHostsFileEvidence{SHA256:snap.HostsSHA256,BlockedRuleCount:snap.HostsBlockedRuleCount}
 if err:=storeOriginalWindowsHostsBackupUnarmed(ctx,parent,hosts,hostsPin,seal,check);err!=nil{t.Fatal(err)}
 if err:=storeBrowserOriginalArchiveUnarmed(ctx,parent,browser,policies,seal,check);err!=nil{t.Fatal(err)}
 if _,err:=StoreDNSOriginalBackupUnarmed(ctx,dnsParent,journal,pin,seal,check);err!=nil{t.Fatal(err)}
 if err:=storeOriginalCatalogArchiveUnarmed(ctx,parent,snap,inv,originalCatalogDefinition{},seal,check);err!=nil{t.Fatal(err)}
 report,err:=InspectOriginalBackupArchivesNativeReadOnly(ctx,parent,dnsParent,snap,browser,inv,pin)
 if err!=nil||report.Status!="FOUR_ARCHIVES_VERIFIED_READ_ONLY"||!report.HostsVerified||report.BrowserKeysVerified!=3||
  !report.CatalogBackupVerified||!report.DNSBackupVerified||report.CompleteRecoverySnapshot||report.InstallAuthorized||report.RestoreAuthorized{
  t.Fatal("native display review failed",err)
 }
 serialized,err:=json.Marshal(report);if err!=nil{t.Fatal(err)}
 if strings.Contains(string(serialized),parent)||strings.Contains(string(serialized),snap.HostsSHA256)||strings.Contains(string(serialized),pin){
  t.Fatal("private recovery data leaked to display")
 }
 wrong:=snap;wrong.DNSAdaptersSHA256=strings.Repeat("f",64)
 refused,err:=InspectOriginalBackupArchivesNativeReadOnly(ctx,parent,dnsParent,wrong,browser,inv,pin)
 if err==nil||refused!=(WindowsOriginalBackupReview{Status:"UNVERIFIED"}){t.Fatal("wrong original baseline received display credit")}
 t.Log("PASS VOLVE_FOUR_ARCHIVES_REAL_NTFS_DISPLAY_ONLY")
}

// This rehearsal uses actual independently observed Windows originals,
// rather than fixture content. Only new temporary archive files are written;
// all live OS queries are read-only. The temporary data is not published.
func TestWindowsOriginalCatalogArchiveNativeActualCensus(t *testing.T){
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{t.Skip("disposable hosted runner only")}
 ctx,cancel:=context.WithTimeout(context.Background(),240*time.Second);defer cancel()
 // Preserve the first failed census stage, but never log GUIDs, paths,
 // task names, DNS addresses or arbitrary native exception text.
 readers:=DefaultWindowsProtectionSnapshotInspectors()
 stage:="not-started"
 hostsReader:=readers.Hosts
 readers.Hosts=func(c context.Context)(WindowsHostsFileEvidence,error){stage="hosts";return hostsReader(c)}
 browserReader:=readers.Browser
 readers.Browser=func(c context.Context,q string)([]byte,error){stage="browser";return browserReader(c,q)}
 taskReader:=readers.Tasks
 readers.Tasks=func(c context.Context,q string)([]byte,error){stage="task-scheduler";return taskReader(c,q)}
 dnsReader:=readers.DNS
 readers.DNS=func(c context.Context,q string)([]byte,error){stage="dns-assignment";return dnsReader(c,q)}
 snap,browser,err:=InspectWindowsProtectionSnapshotReadOnly(ctx,"","",readers)
 if err!=nil{
  reason:="unclassified-validation"
  for _,entry:=range []struct{prefix,code string}{
   {"hosts baseline unavailable:","hosts-read"},
   {"hosts baseline hash or candidate count invalid","hosts-validation"},
   {"browser policy baseline unavailable:","browser-read-or-validation"},
   {"VOLVE catalog task baseline unavailable:","task-read-or-validation"},
   {"original DNS assignment provenance unavailable: Windows DNS assignment source unavailable: Windows read-only inventory failed (Unknown DNS client address family)","dns-native-family"},
   {"original DNS assignment provenance unavailable: Windows DNS assignment source unavailable: Windows read-only inventory failed (DNS interface index does not map to exactly one adapter GUID)","dns-native-mapping"},
   {"original DNS assignment provenance unavailable: Windows DNS assignment source unavailable: Windows read-only inventory failed (DNS servers exist on an interface without a unique adapter GUID)","dns-native-unmapped"},
   {"original DNS assignment provenance unavailable: Windows DNS assignment source unavailable: Windows read-only inventory failed (DNS interface index maps to conflicting adapter GUIDs)","dns-native-conflicting-guid"},
   {"original DNS assignment provenance unavailable: Windows DNS assignment source unavailable: Windows read-only inventory failed (DNS assignment registry key missing)","dns-native-registry-key"},
   {"original DNS assignment provenance unavailable: Windows DNS assignment source unavailable: Windows read-only inventory failed (PowerShell or Windows inventory command failed)","dns-native-command"},
   {"original DNS assignment provenance unavailable: Windows DNS assignment source unavailable:","dns-native-query"},
   {"original DNS assignment provenance unavailable: invalid Windows DNS assignment JSON:","dns-json"},
   {"original DNS assignment provenance unavailable: incomplete or ambiguous Windows DNS assignment evidence:","dns-incomplete-row"},
   {"original DNS assignment provenance unavailable: DNS interface identity or unsupported profile-specific source","dns-identity-or-profile"},
   {"original DNS assignment provenance unavailable: effective DNS server is invalid or in the wrong address family","dns-address-family"},
   {"original DNS assignment provenance unavailable: adapter ","dns-missing-family"},
   {"original DNS assignment provenance unavailable: automatic DNS assignment has contradictory static registry evidence","dns-automatic-source"},
   {"original DNS assignment provenance unavailable: static DNS source lacks a supported NameServer REG_SZ value","dns-static-source"},
   {"original DNS assignment provenance unavailable: static NameServer registry list does not match effective Windows DNS servers","dns-static-mismatch"},
   {"original DNS assignment provenance unavailable:","dns-other-validation"},
   {"VOLVE catalog task is present but not uniquely publisher-pinned","task-identity"},
  }{if strings.HasPrefix(err.Error(),entry.prefix){reason=entry.code;break}}
  t.Fatalf("native original census unavailable: stage=%s reason=%s",stage,reason)
 }
 inv,err:=InspectWindowsVOLVETasksReadOnly(ctx,"","",DefaultWindowsFreshTaskInspect)
 if err!=nil||inv.VOLVETaskCount!=0||len(inv.UnknownTaskNames)!=0||inv.VerifiedCatalogTask!=nil{t.Fatal("native clean-task observation unavailable")}
 hostsPin:=WindowsHostsFileEvidence{SHA256:snap.HostsSHA256,BlockedRuleCount:snap.HostsBlockedRuleCount}
 hosts,err:=captureOriginalWindowsHostsBackup(ctx,filepath.Join(os.Getenv("SystemRoot"),"System32","drivers","etc","hosts"),hostsPin)
 if err!=nil{t.Fatal("native original hosts capture unavailable")}
 policies,err:=captureOriginalBrowserPolicyBytes(ctx,browser,readOriginalBrowserPolicyLocal)
 if err!=nil{t.Fatal("native original registry capture unavailable")}
 observed,err:=InspectWindowsDNSAssignmentProvenanceReadOnly(ctx,DefaultWindowsReadOnlyPowerShell)
 if err!=nil||observed.SHA256!=snap.DNSAdaptersSHA256{t.Fatal("native DNS source observation drifted")}
 journal,pin,err:=BuildDNSOriginalJournal(ctx,observed.States)
 if err!=nil{t.Fatal("native original DNS journal not representable")}
 definition,err:=captureOriginalCatalogDefinition(ctx,snap,inv,readOriginalCatalogDefinitionLocal)
 if err!=nil||definition.Present{t.Fatal("native catalog absence not independently verified")}
 // The random outer temp directory isolates this synthetic transaction ID.
 transactionID:=strings.Repeat("c",32)
 root:=filepath.Join(t.TempDir(),transactionID)
 parent:=filepath.Join(root,"original-protection-recovery")
 dnsParent:=filepath.Join(root,"legacy-engine-recovery")
 seal:=func(path string)error{return sealDNSBackupLabNode(ctx,path)}
 check:=func(path string)error{return nativeDNSOriginalBackupACL(ctx,path)}
 for _,dir:=range []string{root,parent,dnsParent}{
  if err:=os.Mkdir(dir,0700);err!=nil{t.Fatal("local archive directory unavailable")}
  if err:=seal(dir);err!=nil{t.Fatal("local archive directory ACL unavailable")}
 }
 if err:=storeOriginalWindowsHostsBackupUnarmed(ctx,parent,hosts,hostsPin,seal,check);err!=nil{t.Fatal("native hosts staging failed")}
 if err:=storeBrowserOriginalArchiveUnarmed(ctx,parent,browser,policies,seal,check);err!=nil{t.Fatal("native registry staging failed")}
 if _,err:=StoreDNSOriginalBackupUnarmed(ctx,dnsParent,journal,pin,seal,check);err!=nil{t.Fatal("native DNS staging failed")}
 if err:=storeOriginalCatalogArchiveUnarmed(ctx,parent,snap,inv,definition,seal,check);err!=nil{t.Fatal("native catalog staging failed")}
 // Use real native census pins in the transaction-bound review; the pin
 // remains in the test controller and is not an installation permit.
 binding,err:=originalRecoveryReviewPin(transactionID,snap,pin)
 if err!=nil{t.Fatal("native recovery binding unavailable",err)}
 if err:=verifyOriginalHostsBackupNode(root,true,check);err!=nil{t.Fatal("transaction root ACL invalid",err)}
 report,err:=verifyBoundOriginalRecoveryArchivesUnarmed(ctx,transactionID,binding,parent,dnsParent,snap,browser,inv,pin,check)
 if err!=nil||!report.HostsVerified||report.BrowserKeysVerified!=3||!report.DNSBackupVerified||!report.CatalogBackupVerified||
  report.CompleteRecoverySnapshot||report.InstallAuthorized||report.RestoreAuthorized{
  t.Fatal("actual Windows bound archive review failed",err)
 }
 if err:=verifyOriginalHostsBackupNode(root,true,check);err!=nil{t.Fatal("transaction root changed",err)}
 bad,err:=verifyBoundOriginalRecoveryArchivesUnarmed(ctx,transactionID,strings.Repeat("f",64),parent,dnsParent,snap,browser,inv,pin,check)
 if err==nil||bad!=(originalProtectionPairReceipt{}){t.Fatal("foreign native transaction pin accepted")}
 after,_,err:=InspectWindowsProtectionSnapshotReadOnly(ctx,"","",DefaultWindowsProtectionSnapshotInspectors())
 if err!=nil||after!=snap{t.Fatal("live Windows original state differs after temporary archive rehearsal")}
 // A separate reader must reopen the durable, unarmed evidence with the
 // independent pin. An interrupted/truncated record is never accepted.
 // The new sealer must refuse every unrelated object, including the
 // already protected transaction root and both component directories.
 for _,unrelated:=range []string{root,parent,dnsParent,filepath.Join(root,"unrelated.json")}{
  if err:=nativeSealNewOriginalRecoveryReviewNode(ctx,root,transactionID,unrelated);err==nil||err.Error()!="review seal refused unrelated path"{t.Fatal("review seal did not reject unrelated path")}
 }
 if err:=PersistBoundOriginalRecoveryNativeUnarmed(ctx,root,transactionID,binding,snap,browser,inv,pin);err!=nil{t.Fatal("native leased staging failed",err)}
 t.Log("PASS VOLVE_NATIVE_REVIEW_SEAL_EXACT_PATH_ONLY")
 t.Log("PASS VOLVE_NATIVE_LEASED_CREATE_ONLY_REVIEW_STAGING")
 if err:=loadOriginalRecoveryReviewEvidenceUnarmed(ctx,root,transactionID,binding,check);err!=nil{t.Fatal("durable review reopen failed",err)}
 reopened,err:=reopenOriginalRecoveryReviewUnarmed(ctx,root,transactionID,binding,snap,browser,inv,pin,check)
 if err!=nil||reopened!=report{t.Fatal("fresh four-archive review failed",err)}
 childInput:=originalRecoveryChildInput{root,transactionID,binding,snap,browser,inv,pin}
 runOriginalRecoveryReviewChild(t,childInput,true)
 _,archiveFile,err:=catalogOriginalArchivePaths(parent)
 if err!=nil{t.Fatal(err)}
 priorArchive,err:=os.ReadFile(archiveFile)
 if err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(archiveFile,[]byte("{}"),0600);err!=nil{t.Fatal(err)}
 if err:=loadOriginalRecoveryReviewEvidenceUnarmed(ctx,root,transactionID,binding,check);err!=nil{t.Fatal("historical record unexpectedly changed",err)}
 stale,err:=reopenOriginalRecoveryReviewUnarmed(ctx,root,transactionID,binding,snap,browser,inv,pin,check)
 if err==nil||stale!=(originalProtectionPairReceipt{}){t.Fatal("stale historical review accepted as current evidence")}
 runOriginalRecoveryReviewChild(t,childInput,false)
 if err:=os.WriteFile(archiveFile,priorArchive,0600);err!=nil{t.Fatal(err)}
 reopened,err=reopenOriginalRecoveryReviewUnarmed(ctx,root,transactionID,binding,snap,browser,inv,pin,check)
 if err!=nil||reopened!=report{t.Fatal("intact fixture rejected after reset",err)}
 t.Log("PASS VOLVE_DURABLE_REOPEN_REJECTS_STALE_ARCHIVE")
 if err:=loadOriginalRecoveryReviewEvidenceUnarmed(ctx,root,transactionID,strings.Repeat("f",64),check);err==nil{t.Fatal("foreign durable pin accepted")}
 if err:=PersistBoundOriginalRecoveryNativeUnarmed(ctx,root,transactionID,binding,snap,browser,inv,pin);err==nil{t.Fatal("existing durable evidence overwritten")}
 if err:=ctx.Err();err!=nil{t.Fatal("native staging retry context expired",err)}
 path,err:=originalRecoveryEvidencePath(root,transactionID)
 if err!=nil{t.Fatal(err)}
 // Reset only the disposable fixture's review slot, never a real journal.
 if err:=os.Remove(path);err!=nil{t.Fatal("lab review reset failed",err)}
 if _,err:=os.Lstat(path);!os.IsNotExist(err){t.Fatal("lab review reset not verified")}
 runOriginalRecoveryInterruptedWriter(t,childInput,false)
 partial,err:=os.ReadFile(path)
 if err!=nil||string(partial)!="{"{t.Fatal("terminated writer did not leave the expected durable partial record",err)}
 t.Log("PASS VOLVE_LAB_WRITER_TERMINATED_AFTER_PARTIAL_SYNC")
 if err:=loadOriginalRecoveryReviewEvidenceUnarmed(ctx,root,transactionID,binding,check);err==nil{t.Fatal("truncated evidence accepted")}
 runOriginalRecoveryReviewChild(t,childInput,false)
 t.Log("PASS VOLVE_NATIVE_LEASE_BOUND_REVIEW_CHILD")
 t.Log("PASS VOLVE_NEW_PROCESS_REOPENS_VALID_AND_REFUSES_STALE_TRUNCATED_REVIEW")
 if err:=PersistBoundOriginalRecoveryNativeUnarmed(ctx,root,transactionID,binding,snap,browser,inv,pin);err==nil{t.Fatal("interrupted evidence slot reused")}
 if err:=ctx.Err();err!=nil{t.Fatal("native test context expired; refusal evidence invalid",err)}
 t.Log("PASS VOLVE_DURABLE_UNARMED_REVIEW_NTFS_REJECTS_INTERRUPTION")
 t.Log("PASS VOLVE_NATIVE_BOUND_FOUR_ARCHIVES_AND_LIVE_RECENSUS")
 t.Log("PASS VOLVE_ACTUAL_NATIVE_ORIGINALS_ARCHIVED_AND_RECENSUSED_NO_OS_WRITES")
}

// Lab-only bridge: route a native, inert synthetic task export through the
// actual VOLVE catalog archive codec and ACL checks. The catalog identity
// metadata below is a synthetic fixture, NOT evidence about a live catalog.
// The workflow owns the random temporary directory and task lifecycle.
func TestVOLVESyntheticCatalogArchiveBridge(t *testing.T){
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{t.Skip("hosted lab only")}
 dir:=os.Getenv("VOLVE_LAB_CATALOG_DIR")
 root:=os.Getenv("RUNNER_TEMP")
 if !filepath.IsAbs(root)||!filepath.IsAbs(dir)||filepath.Clean(dir)!=dir||
  !strings.EqualFold(filepath.Dir(dir),filepath.Clean(root))||
  !strings.HasPrefix(filepath.Base(dir),"volve-catalog-xml-")||len(filepath.Base(dir))!=len("volve-catalog-xml-")+32{t.Fatal("invalid synthetic bridge directory")}
 suffix:=strings.TrimPrefix(filepath.Base(dir),"volve-catalog-xml-")
 if b,err:=hex.DecodeString(suffix);err!=nil||len(b)!=16{t.Fatal("invalid synthetic directory identity")}
 source:=filepath.Join(dir,"catalog.xml")
 before,err:=os.Lstat(source)
 if err!=nil||!before.Mode().IsRegular()||before.Size()<1||before.Size()>catalogOriginalXMLLimit{t.Fatal("invalid synthetic XML input")}
 xml,err:=os.ReadFile(source)
 if err!=nil||int64(len(xml))!=before.Size(){t.Fatal("synthetic XML read failed",err)}
 sum:=sha256.Sum256(xml)
 pin:=hex.EncodeToString(sum[:])
 if pin!=os.Getenv("VOLVE_LAB_CATALOG_SHA256"){t.Fatal("independent synthetic XML digest mismatch")}
 ctx,cancel:=context.WithTimeout(context.Background(),90*time.Second);defer cancel()
 parent,snap,_,_,_:=makeOriginalProtectionPairFixture(t)
 snap.CatalogTaskDefinitionSHA256=pin
 task:=freshTaskFixture();task.DefinitionSHA256=pin
 inv,err:=InspectWindowsVOLVETasksReadOnly(ctx,task.Actions[0].Execute,task.Actions[0].Arguments,func(context.Context,string)([]byte,error){return freshWindowsTaskJSON(t,[]windowsVOLVETaskRecord{task}),nil})
 if err!=nil{t.Fatal(err)}
 seal:=func(p string)error{return sealDNSBackupLabNode(ctx,p)}
 check:=func(p string)error{return nativeDNSOriginalBackupACL(ctx,p)}
 if err:=seal(parent);err!=nil{t.Fatal(err)}
 if err:=storeOriginalCatalogArchiveUnarmed(ctx,parent,snap,inv,originalCatalogDefinition{Present:true,XML:xml},seal,check);err!=nil{t.Fatal("catalog codec archive failed",err)}
 xml=nil
 got,err:=readOriginalCatalogArchiveUnarmed(ctx,parent,snap,inv,check)
 if err!=nil||!got.Present||sha256.Sum256(got.XML)!=sum{t.Fatal("catalog codec readback failed",err)}
 out,err:=os.OpenFile(filepath.Join(dir,"verified-catalog.xml"),os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
 if err!=nil{t.Fatal(err)}
 n,werr:=out.Write(got.XML)
 syncErr:=out.Sync()
 closeErr:=out.Close()
 if n!=len(got.XML)||werr!=nil||syncErr!=nil||closeErr!=nil{t.Fatal("verified synthetic output not persisted")}
 t.Log("PASS VOLVE_SYNTHETIC_CATALOG_REAL_ARCHIVE_CODEC_BRIDGE")
}

func TestWindowsOriginalCatalogArchiveBoundTransaction(t *testing.T){
 ctx,cancel:=context.WithTimeout(context.Background(),150*time.Second);defer cancel()
 src,snap,browser,hosts,policies:=makeOriginalProtectionPairFixture(t)
 _=src
 id:=strings.Repeat("a",32)
 root:=filepath.Join(t.TempDir(),id)
 parent:=filepath.Join(root,"original-protection-recovery")
 dnsParent:=filepath.Join(root,"legacy-engine-recovery")
 for _,dir:=range []string{root,parent,dnsParent}{if err:=os.Mkdir(dir,0700);err!=nil{t.Fatal(err)}}
 observed,err:=InspectWindowsDNSAssignmentProvenanceReadOnly(ctx,protectionSnapshotDNSInspect)
 if err!=nil{t.Fatal(err)}
 journal,dnsPin,err:=BuildDNSOriginalJournal(ctx,observed.States)
 if err!=nil{t.Fatal(err)}
 snap.DNSAdaptersSHA256=observed.SHA256
 sum:=sha256.Sum256([]byte(catalogTaskAbsentMarker))
 snap.CatalogTaskDefinitionSHA256=hex.EncodeToString(sum[:])
 inv:=WindowsFreshVOLVETaskInventory{}
 allow:=func(string)error{return nil}
 seal:=allow
 hosted:=os.Getenv("GITHUB_ACTIONS")=="true"&&os.Getenv("RUNNER_ENVIRONMENT")=="github-hosted"
 if hosted{
  seal=func(p string)error{return sealDNSBackupLabNode(ctx,p)}
  allow=func(p string)error{return nativeDNSOriginalBackupACL(ctx,p)}
  for _,dir:=range []string{root,parent,dnsParent}{if err:=seal(dir);err!=nil{t.Fatal(err)}}
 }
 if err:=storeOriginalWindowsHostsBackupUnarmed(ctx,parent,hosts,WindowsHostsFileEvidence{SHA256:snap.HostsSHA256,BlockedRuleCount:snap.HostsBlockedRuleCount},seal,allow);err!=nil{t.Fatal(err)}
 if err:=storeBrowserOriginalArchiveUnarmed(ctx,parent,browser,policies,seal,allow);err!=nil{t.Fatal(err)}
 if _,err:=StoreDNSOriginalBackupUnarmed(ctx,dnsParent,journal,dnsPin,seal,allow);err!=nil{t.Fatal(err)}
 if err:=storeOriginalCatalogArchiveUnarmed(ctx,parent,snap,inv,originalCatalogDefinition{},seal,allow);err!=nil{t.Fatal(err)}
 pin,err:=originalRecoveryReviewPin(id,snap,dnsPin)
 if err!=nil{t.Fatal(err)}
 got,err:=verifyBoundOriginalRecoveryArchivesUnarmed(ctx,id,pin,parent,dnsParent,snap,browser,inv,dnsPin,allow)
 if err!=nil||!got.HostsVerified||got.BrowserKeysVerified!=3||!got.DNSBackupVerified||!got.CatalogBackupVerified||got.CompleteRecoverySnapshot||got.InstallAuthorized||got.RestoreAuthorized{t.Fatal("bound review incorrect",err)}
 changed:=snap;changed.HostsSHA256=strings.Repeat("f",64)
 foreign:=strings.Repeat("b",32)
 for _,tc:=range []struct{name,id,pin,parent,dns,digest string;snapshot ProtectionSnapshot}{
  {"wrong-id",foreign,pin,parent,dnsParent,dnsPin,snap},
  {"wrong-pin",id,strings.Repeat("0",64),parent,dnsParent,dnsPin,snap},
  {"wrong-baseline",id,pin,parent,dnsParent,dnsPin,changed},
  {"wrong-dns",id,pin,parent,dnsParent,strings.Repeat("f",64),snap},
  {"wrong-directory",id,pin,filepath.Join(filepath.Dir(root),foreign,"original-protection-recovery"),dnsParent,dnsPin,snap},
 }{
  t.Run(tc.name,func(t *testing.T){
   called:=false
   check:=func(string)error{called=true;return nil}
   got,err:=verifyBoundOriginalRecoveryArchivesUnarmed(ctx,tc.id,tc.pin,tc.parent,tc.dns,tc.snapshot,browser,inv,tc.digest,check)
   if err==nil||called||got!=(originalProtectionPairReceipt{}){t.Fatal("foreign transaction reached archive inspection")}
  })
 }
 t.Log("PASS VOLVE_BOUND_ORIGINAL_ARCHIVES_REJECT_FOREIGN_TRANSACTION")
 pub,private,err:=ed25519.GenerateKey(nil)
 if err!=nil{t.Fatal("ephemeral fixture key unavailable")}
 signed:=SignedOriginalRecoveryReview{1,signedOriginalRecoveryReviewComponent,id,pin}
 raw,err:=json.Marshal(signed)
 if err!=nil{t.Fatal(err)}
 sig:=ed25519.Sign(private,raw)
 authenticated,err:=VerifySignedOriginalRecoveryReview(ctx,raw,sig,pub,id,snap,dnsPin)
 if err!=nil||authenticated!=signed{t.Fatal("valid signed review refused",err)}
 otherPub,_,err:=ed25519.GenerateKey(nil)
 if err!=nil{t.Fatal(err)}
 wrong:=signed;wrong.Component="volve-publisher-dns-original-binding-v1"
 wrongRaw,err:=json.Marshal(wrong)
 if err!=nil{t.Fatal(err)}
 noncanonical:=append(append([]byte(nil),raw...),byte(' '))
 badSig:=append([]byte(nil),sig...);badSig[0]^=1
 for _,tc:=range []struct{name string;raw,sig []byte;key ed25519.PublicKey;id,dns string;baseline ProtectionSnapshot}{
  {"wrong-key",raw,sig,otherPub,id,dnsPin,snap},
  {"bad-signature",raw,badSig,pub,id,dnsPin,snap},
  {"wrong-domain",wrongRaw,ed25519.Sign(private,wrongRaw),pub,id,dnsPin,snap},
  {"noncanonical",noncanonical,ed25519.Sign(private,noncanonical),pub,id,dnsPin,snap},
  {"foreign-id",raw,sig,pub,foreign,dnsPin,snap},
  {"foreign-census",raw,sig,pub,id,dnsPin,changed},
  {"foreign-dns",raw,sig,pub,id,strings.Repeat("f",64),snap},
 }{
  t.Run("signed-"+tc.name,func(t *testing.T){
   got,err:=VerifySignedOriginalRecoveryReview(ctx,tc.raw,tc.sig,tc.key,tc.id,tc.baseline,tc.dns)
   if err==nil||got!=(SignedOriginalRecoveryReview{}){t.Fatal("foreign signed evidence accepted")}
  })
 }
 t.Log("PASS VOLVE_SIGNED_FOUR_ARCHIVE_REVIEW_REJECTS_FOREIGN_EVIDENCE")

 if hosted{
  input:=originalRecoveryChildInput{root,id,pin,snap,browser,inv,dnsPin}
  runOriginalRecoveryInterruptedWriter(t,input,true)
  // A complete sealed record can be re-observed, even when the original
  // writer never returned success. It still cannot grant permission.
  runOriginalRecoveryReviewChild(t,input,true)
  // Hold the same kernel mutex in this process; the separate reader must
  // report explicit lease refusal and zero evidence before we release it.
  func(){
   release,err:=AcquireProtectedResidentTransitionLease(ctx)
   if err!=nil||release==nil{t.Fatal("fixture lease unavailable",err)}
   defer release()
   runOriginalRecoveryContendedReader(t,input)
  }()
  runOriginalRecoveryReviewChild(t,input,true)
  t.Log("PASS VOLVE_NATIVE_REVIEW_REFUSES_CROSS_PROCESS_CONTENTION_AND_RECOVERS")
  signedReport,err:=InspectSignedBoundOriginalRecoveryNativeReadOnly(ctx,root,id,raw,sig,pub,snap,browser,inv,dnsPin)
  if err!=nil||signedReport.Status!="BOUND_FOUR_ARCHIVES_VERIFIED_READ_ONLY"||!signedReport.HostsVerified||signedReport.BrowserKeysVerified!=3||!signedReport.DNSBackupVerified||!signedReport.CatalogBackupVerified||signedReport.InstallAuthorized||signedReport.RestoreAuthorized||signedReport.CompleteRecoverySnapshot{t.Fatal("native signed review failed",err)}
  deniedSigned,err:=InspectSignedBoundOriginalRecoveryNativeReadOnly(ctx,root,id,raw,badSig,pub,snap,browser,inv,dnsPin)
  if err==nil||deniedSigned!=(WindowsOriginalBackupReview{Status:"UNVERIFIED"}){t.Fatal("native invalid signature accepted")}
  t.Log("PASS VOLVE_NATIVE_SIGNED_REVIEW_UNARMED")

  if err:=persistOriginalRecoveryReviewEvidenceUnarmed(ctx,root,id,pin,snap,browser,inv,dnsPin,seal,allow);err==nil{t.Fatal("terminated real writer slot reused")}
  if err:=ctx.Err();err!=nil{t.Fatal("real writer test expired",err)}
  t.Log("PASS VOLVE_REAL_REVIEW_WRITER_TERMINATED_AFTER_SEAL")
 }

}


// Pass independent census evidence via stdin to a new test executable process.
// No environment secrets, raw archive payloads or real system mutations.
type originalRecoveryChildInput struct{
 Root,ID,Binding string
 Snapshot ProtectionSnapshot
 Browser WindowsBrowserPolicyEvidence
 Inventory WindowsFreshVOLVETaskInventory
 DNSPin string
}

func runOriginalRecoveryReviewChild(t *testing.T,input originalRecoveryChildInput,wantVerified bool){
 t.Helper()
 raw,err:=json.Marshal(input)
 if err!=nil||len(raw)>16384{t.Fatal("child input encoding failed")}
 exe,err:=os.Executable()
 if err!=nil{t.Fatal("test executable unavailable")}
 ctx,cancel:=context.WithTimeout(context.Background(),60*time.Second);defer cancel()
 cmd:=exec.CommandContext(ctx,exe,"-test.run=^TestVOLVEOriginalRecoveryReviewChild$","-test.count=1","-test.v")
 cmd.Env=append(os.Environ(),"VOLVE_REVIEW_CHILD=1")
 cmd.Stdin=bytes.NewReader(raw)
 out,err:=cmd.CombinedOutput()
 if err!=nil{t.Fatal("independent review process failed",err)}
 want:="VOLVE_CHILD_REVIEW_REFUSED"
 other:="VOLVE_CHILD_REVIEW_VERIFIED"
 if wantVerified{want,other=other,want}
 if strings.Count(string(out),want)!=1||strings.Contains(string(out),other){t.Fatal("independent process result differs from expected")}
}

func TestVOLVEOriginalRecoveryReviewChild(t *testing.T){
 if os.Getenv("VOLVE_REVIEW_CHILD")!="1"{t.Skip("explicit subprocess only")}
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{t.Fatal("hosted lab only")}
 raw,err:=io.ReadAll(io.LimitReader(os.Stdin,16385))
 if err!=nil||len(raw)==0||len(raw)>16384{t.Fatal("invalid child input")}
 var input originalRecoveryChildInput
 if err:=residentCanonical(raw,&input);err!=nil{t.Fatal("child evidence not canonical")}
 ctx,cancel:=context.WithTimeout(context.Background(),45*time.Second);defer cancel()
 receipt,err:=InspectBoundOriginalRecoveryNativeReadOnly(ctx,input.Root,input.ID,input.Binding,input.Snapshot,input.Browser,input.Inventory,input.DNSPin)
 if err:=ctx.Err();err!=nil{t.Fatal("child review context expired; refusal invalid",err)}
 if err!=nil{
  if receipt!=(WindowsOriginalBackupReview{Status:"UNVERIFIED"}){t.Fatal("failed child returned evidence")}
  t.Log("VOLVE_CHILD_REVIEW_REFUSED")
  return
 }
 if receipt.Status!="BOUND_FOUR_ARCHIVES_VERIFIED_READ_ONLY"||!receipt.HostsVerified||receipt.BrowserKeysVerified!=3||!receipt.DNSBackupVerified||!receipt.CatalogBackupVerified||
  receipt.CompleteRecoverySnapshot||receipt.InstallAuthorized||receipt.RestoreAuthorized{t.Fatal("invalid child receipt")}
 t.Log("VOLVE_CHILD_REVIEW_VERIFIED")
}


// Fault injection uses a test-only partial writer rather than changing the
// production journal writer. The parent kills exactly its own subprocess
// after a confirmed flush; no Windows shutdown or system mutation.
func runOriginalRecoveryInterruptedWriter(t *testing.T,input originalRecoveryChildInput,realWriter bool){
 t.Helper()
 raw,err:=json.Marshal(input)
 if err!=nil||len(raw)>16384{t.Fatal("writer input encoding failed")}
 exe,err:=os.Executable()
 if err!=nil{t.Fatal("test executable unavailable")}
 ctx,cancel:=context.WithTimeout(context.Background(),60*time.Second);defer cancel()
 cmd:=exec.CommandContext(ctx,exe,"-test.run=^TestVOLVEOriginalRecoveryInterruptedWriter$","-test.count=1","-test.v")
 cmd.Env=append(os.Environ(),"VOLVE_REVIEW_PARTIAL_WRITER=1")
 marker:="VOLVE_LAB_PARTIAL_SYNC_READY"
 if realWriter{cmd.Env=append(cmd.Env,"VOLVE_REVIEW_REAL_WRITER=1");marker="VOLVE_LAB_REAL_SEAL_READY"}
 cmd.Stdin=bytes.NewReader(raw)
 stdout,err:=cmd.StdoutPipe()
 if err!=nil{t.Fatal(err)}
 if err:=cmd.Start();err!=nil{t.Fatal(err)}
 waited:=false
 defer func(){if !waited{_ = cmd.Process.Kill();_ = cmd.Wait()}}()
 scanner:=bufio.NewScanner(stdout)
 ready:=false
 for scanner.Scan(){if scanner.Text()==marker{ready=true;break}}
 if !ready||ctx.Err()!=nil{t.Fatal("writer did not confirm partial sync within live context")}
 if err:=cmd.Process.Kill();err!=nil{t.Fatal("writer termination failed",err)}
 err=cmd.Wait()
 waited=true
 var exit *exec.ExitError
 if !errors.As(err,&exit)||exit.Success(){t.Fatal("writer termination not observed")}
}

func TestVOLVEOriginalRecoveryInterruptedWriter(t *testing.T){
 if os.Getenv("VOLVE_REVIEW_PARTIAL_WRITER")!="1"{t.Skip("explicit fault injection subprocess only")}
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{t.Fatal("hosted lab only")}
 raw,err:=io.ReadAll(io.LimitReader(os.Stdin,16385))
 if err!=nil||len(raw)==0||len(raw)>16384{t.Fatal("invalid writer input")}
 var input originalRecoveryChildInput
 if err:=residentCanonical(raw,&input);err!=nil{t.Fatal("writer input not canonical")}
 ctx,cancel:=context.WithTimeout(context.Background(),45*time.Second);defer cancel()
 check:=func(p string)error{return nativeDNSOriginalBackupACL(ctx,p)}
 if os.Getenv("VOLVE_REVIEW_REAL_WRITER")=="1"{
  seal:=func(p string)error{
   if err:=sealDNSBackupLabNode(ctx,p);err!=nil{return err}
   if err:=check(p);err!=nil{return err}
   if _,err:=os.Stdout.WriteString("VOLVE_LAB_REAL_SEAL_READY\n");err!=nil{return err}
   time.Sleep(60*time.Second)
   return errors.New("real writer was not terminated")
  }
  if err:=persistOriginalRecoveryReviewEvidenceUnarmed(ctx,input.Root,input.ID,input.Binding,input.Snapshot,input.Browser,input.Inventory,input.DNSPin,seal,check);err!=nil{t.Fatal("real writer exited before termination",err)}
  t.Fatal("real writer unexpectedly completed")
 }
 receipt,err:=verifyBoundOriginalRecoveryArchivesUnarmed(ctx,input.ID,input.Binding,filepath.Join(input.Root,"original-protection-recovery"),filepath.Join(input.Root,"legacy-engine-recovery"),input.Snapshot,input.Browser,input.Inventory,input.DNSPin,check)
 if err!=nil||!receipt.HostsVerified||receipt.BrowserKeysVerified!=3||!receipt.DNSBackupVerified||!receipt.CatalogBackupVerified||receipt.RestoreAuthorized||receipt.InstallAuthorized{t.Fatal("writer fixture not independently verified")}
 path,err:=originalRecoveryEvidencePath(input.Root,input.ID)
 if err!=nil{t.Fatal(err)}
 if err:=verifyOriginalHostsBackupNode(input.Root,true,check);err!=nil{t.Fatal("writer fixture root not protected")}
 file,err:=os.OpenFile(path,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
 if err!=nil{t.Fatal("fault injection slot unavailable")}
 defer file.Close()
 n,err:=file.Write([]byte("{"))
 if err!=nil||n!=1{t.Fatal("partial write failed")}
 if err:=file.Sync();err!=nil{t.Fatal("partial sync failed")}
 if _,err:=os.Stdout.WriteString("VOLVE_LAB_PARTIAL_SYNC_READY\n");err!=nil{t.Fatal("writer handshake failed")}
 // No success exit is permitted. The parent must terminate this process.
 time.Sleep(60*time.Second)
 t.Fatal("writer was not terminated")
}


// The fixture parent holds the real mutex throughout this child's lifetime.
// Distinguish intentional lease deadline from any archive validation error.
func runOriginalRecoveryContendedReader(t *testing.T,input originalRecoveryChildInput){
 t.Helper()
 raw,err:=json.Marshal(input)
 if err!=nil||len(raw)>16384{t.Fatal("contention input encoding failed")}
 exe,err:=os.Executable()
 if err!=nil{t.Fatal("test executable unavailable")}
 ctx,cancel:=context.WithTimeout(context.Background(),15*time.Second);defer cancel()
 cmd:=exec.CommandContext(ctx,exe,"-test.run=^TestVOLVEOriginalRecoveryContendedReader$","-test.count=1","-test.v")
 cmd.Env=append(os.Environ(),"VOLVE_REVIEW_CONTENDED_CHILD=1")
 cmd.Stdin=bytes.NewReader(raw)
 out,err:=cmd.CombinedOutput()
 if err!=nil||ctx.Err()!=nil{t.Fatal("contended child failed to report",err)}
 if strings.Count(string(out),"VOLVE_CHILD_LEASE_CONTENTION_CONFIRMED")!=1{t.Fatal("missing specific contention evidence")}
}

func TestVOLVEOriginalRecoveryContendedReader(t *testing.T){
 if os.Getenv("VOLVE_REVIEW_CONTENDED_CHILD")!="1"{t.Skip("explicit contention subprocess only")}
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{t.Fatal("hosted lab only")}
 raw,err:=io.ReadAll(io.LimitReader(os.Stdin,16385))
 if err!=nil||len(raw)==0||len(raw)>16384{t.Fatal("invalid contention input")}
 var input originalRecoveryChildInput
 if err:=residentCanonical(raw,&input);err!=nil{t.Fatal("contention input not canonical")}
 ctx,cancel:=context.WithTimeout(context.Background(),1200*time.Millisecond);defer cancel()
 start:=time.Now()
 report,err:=InspectBoundOriginalRecoveryNativeReadOnly(ctx,input.Root,input.ID,input.Binding,input.Snapshot,input.Browser,input.Inventory,input.DNSPin)
 if err==nil||err.Error()!="protected recovery review lease unavailable"||
  !errors.Is(ctx.Err(),context.DeadlineExceeded)||time.Since(start)<time.Second||
  report!=(WindowsOriginalBackupReview{Status:"UNVERIFIED"}){t.Fatal("lease contention not specifically verified")}
 t.Log("VOLVE_CHILD_LEASE_CONTENTION_CONFIRMED")
}
