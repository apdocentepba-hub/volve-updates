//go:build windows

package motorupdate

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestCountWindowsHostsBlockedRulesDoesNotReturnNames(t *testing.T){
 raw:=[]byte("# managed blocklist\r\n127.0.0.1 localhost\n::1 localhost.localdomain\n"+
  "0.0.0.0 ads.example tracker.example # comment\n"+
  "127.0.0.1 telemetry.example\n192.168.1.1 router.local\n"+
  "::1 local.example\n")
 if got:=countWindowsHostsBlockedRules(raw);got!=4{
  t.Fatalf("candidate loopback mappings=%d, want 4",got)
 }
}

func TestWindowsHostsFileReadOnlyHashAndNoContentExport(t *testing.T){
 path:=filepath.Join(t.TempDir(),"hosts")
 raw:=[]byte("127.0.0.1 localhost\n0.0.0.0 ads.example tracker.example\n")
 if err:=os.WriteFile(path,raw,0600);err!=nil{t.Fatal(err)}
 evidence,err:=inspectWindowsHostsFileAtReadOnly(context.Background(),path)
 if err!=nil{t.Fatal(err)}
 sum:=sha256.Sum256(raw)
 if evidence.SHA256!=hex.EncodeToString(sum[:])||evidence.BlockedRuleCount!=2{
  t.Fatalf("unexpected hosts evidence: %+v",evidence)
 }
 encoded,err:=json.Marshal(evidence);if err!=nil{t.Fatal(err)}
 if strings.Contains(string(encoded),"ads.example")||strings.Contains(string(encoded),"tracker.example"){
  t.Fatal("hosts entries escaped the local fingerprint collector")
 }
}

func TestWindowsHostsFileReadOnlyRejectsUnsafePaths(t *testing.T){
 root:=t.TempDir()
 regular:=filepath.Join(root,"hosts")
 if err:=os.WriteFile(regular,[]byte("127.0.0.1 localhost"),0600);err!=nil{t.Fatal(err)}
 if _,err:=inspectWindowsHostsFileAtReadOnly(context.Background(),"relative-hosts");err==nil{
  t.Fatal("relative hosts path accepted")
 }
 link:=filepath.Join(root,"hosts-link")
 if err:=os.Symlink(regular,link);err!=nil{t.Skipf("symlink unavailable in this runner: %v",err)}
 if _,err:=inspectWindowsHostsFileAtReadOnly(context.Background(),link);err==nil{
  t.Fatal("hosts symlink accepted")
 }
}

func TestWindowsHostsFileReadOnlyRejectsOversizedFile(t *testing.T){
 path:=filepath.Join(t.TempDir(),"hosts")
 if err:=os.WriteFile(path,make([]byte,windowsHostsFileMaxBytes+1),0600);err!=nil{t.Fatal(err)}
 if _,err:=inspectWindowsHostsFileAtReadOnly(context.Background(),path);err==nil{
  t.Fatal("oversized hosts file accepted")
 }
}

func protectionSnapshotBrowserJSON()[]byte{
 return []byte(`[{"Name":"chrome","Present":true,"NumberedEntries":1,"InvalidEntries":0,"UnexpectedEntries":0,"ContentSHA256":"`+strings.Repeat("a",64)+`"},`+
  `{"Name":"edge","Present":false,"NumberedEntries":0,"InvalidEntries":0,"UnexpectedEntries":0,"ContentSHA256":"`+strings.Repeat("b",64)+`"},`+
  `{"Name":"firefox","Present":false,"NumberedEntries":0,"InvalidEntries":0,"UnexpectedEntries":0,"ContentSHA256":"`+strings.Repeat("c",64)+`"}]`)
}

func protectionSnapshotDNSInspect(ctx context.Context,query string)([]byte,error){
 if query!=windowsDNSAssignmentSourceQuery{return nil,errors.New("unexpected DNS assignment query")}
 return protectionSnapshotDNSJSON(),nil
}

func TestWindowsProtectionSnapshotCapturesAllDeclaredSurfaces(t *testing.T){
 expectedHosts:=strings.Repeat("d",64)
 snapshot,browser,err:=InspectWindowsProtectionSnapshotReadOnly(context.Background(),"","",
  WindowsProtectionSnapshotInspectors{
   Hosts:func(context.Context)(WindowsHostsFileEvidence,error){return WindowsHostsFileEvidence{SHA256:expectedHosts,BlockedRuleCount:2},nil},
   Browser:func(context.Context,string)([]byte,error){return protectionSnapshotBrowserJSON(),nil},
   Tasks:func(context.Context,string)([]byte,error){return []byte("[]"),nil},
   DNS:protectionSnapshotDNSInspect,
  })
 if err!=nil{t.Fatal(err)}
 if snapshot.HostsSHA256!=expectedHosts||snapshot.HostsBlockedRuleCount!=2||
  snapshot.ChromePoliciesSHA256!=strings.Repeat("a",64)||
  snapshot.EdgePoliciesSHA256!=strings.Repeat("b",64)||
  snapshot.FirefoxPoliciesSHA256!=strings.Repeat("c",64)||
  snapshot.DNSAdaptersSHA256==""||!validProtectionSnapshot(snapshot)||len(browser.Records)!=3||
  !browser.NoRegistryValuesExported{
  t.Fatalf("incomplete privacy-preserving protection snapshot: %+v %+v",snapshot,browser)
 }
}

func TestWindowsProtectionSnapshotRequiresPinnedExistingCatalogTask(t *testing.T){
 taskJSON:=func(executable,args string)[]byte{
  row:=map[string]any{
   "Name":"VOLVE-CATALOGO-0230","TaskPath":"\\","Principal":"SYSTEM",
   "Actions":[]any{map[string]any{"Execute":executable,"Arguments":args,"WorkingDirectory":""}},
   "DefinitionSHA256":strings.Repeat("e",64),
  }
  raw,err:=json.Marshal([]any{row});if err!=nil{t.Fatal(err)};return raw
 }
 hosts:=func(context.Context)(WindowsHostsFileEvidence,error){return WindowsHostsFileEvidence{SHA256:strings.Repeat("d",64)},nil}
 browser:=func(context.Context,string)([]byte,error){return protectionSnapshotBrowserJSON(),nil}
 const exe="C:\\Program Files\\VOLVE\\VOLVE-CATALOGO-0230.exe"
 const args="--catalog-service"
 good,_,err:=InspectWindowsProtectionSnapshotReadOnly(context.Background(),exe,args,
  WindowsProtectionSnapshotInspectors{
   Hosts:hosts,Browser:browser,
   Tasks:func(context.Context,string)([]byte,error){return taskJSON(exe,args),nil},
   DNS:protectionSnapshotDNSInspect,
  })
 if err!=nil{t.Fatal(err)}
 if good.CatalogTaskDefinitionSHA256!=strings.Repeat("e",64){t.Fatalf("catalog task fingerprint missing: %+v",good)}
 _,_,err=InspectWindowsProtectionSnapshotReadOnly(context.Background(),"","",
  WindowsProtectionSnapshotInspectors{
   Hosts:hosts,Browser:browser,
   Tasks:func(context.Context,string)([]byte,error){return taskJSON(exe,args),nil},
  })
 if err==nil{t.Fatal("existing but unpinned catalog task accepted")}
}

func TestWindowsProtectionSnapshotRejectsUnknownOrContradictoryTaskInventory(t *testing.T){
 for _,raw:=range [][]byte{
  []byte(`[{"Name":"VOLVE-UNKNOWN","TaskPath":"\\","Principal":"SYSTEM","Actions":[],"DefinitionSHA256":"`+strings.Repeat("e",64)+`"}]`),
  []byte(`[{"Name":"VOLVE-CATALOGO-0230","TaskPath":"\\","Principal":"SYSTEM","Actions":[],"DefinitionSHA256":"`+strings.Repeat("e",64)+`"}]`),
 }{
  _,_,err:=InspectWindowsProtectionSnapshotReadOnly(context.Background(),"","",
   WindowsProtectionSnapshotInspectors{
    Hosts:func(context.Context)(WindowsHostsFileEvidence,error){return WindowsHostsFileEvidence{SHA256:strings.Repeat("d",64)},nil},
    Browser:func(context.Context,string)([]byte,error){return protectionSnapshotBrowserJSON(),nil},
    Tasks:func(context.Context,string)([]byte,error){return raw,nil},
    DNS:protectionSnapshotDNSInspect,
   })
  if err==nil{t.Fatal("unknown or unverified task inventory accepted")}
 }
}

func TestWindowsProtectionSnapshotRejectsMissingInspectorsAndCancelledContext(t *testing.T){
 if _,_,err:=InspectWindowsProtectionSnapshotReadOnly(context.Background(),"","",WindowsProtectionSnapshotInspectors{});err==nil{
  t.Fatal("missing inspectors accepted")
 }
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 calls:=0
 _,_,err:=InspectWindowsProtectionSnapshotReadOnly(ctx,"","",WindowsProtectionSnapshotInspectors{
  Hosts:func(context.Context)(WindowsHostsFileEvidence,error){calls++;return WindowsHostsFileEvidence{},nil},
  Browser:func(context.Context,string)([]byte,error){calls++;return nil,nil},
  Tasks:func(context.Context,string)([]byte,error){calls++;return nil,nil},
  DNS:func(context.Context,string)([]byte,error){calls++;return nil,nil},
 })
 if !errors.Is(err,context.Canceled)||calls!=0{t.Fatalf("cancelled snapshot performed reads: calls=%d err=%v",calls,err)}
}

func TestWindowsProtectionSnapshotCannotPassIfHostBaselineIsMalformed(t *testing.T){
 _,_,err:=InspectWindowsProtectionSnapshotReadOnly(context.Background(),"","",
  WindowsProtectionSnapshotInspectors{
   Hosts:func(context.Context)(WindowsHostsFileEvidence,error){return WindowsHostsFileEvidence{SHA256:"bad"},nil},
   Browser:func(context.Context,string)([]byte,error){return protectionSnapshotBrowserJSON(),nil},
   Tasks:func(context.Context,string)([]byte,error){return []byte("[]"),nil},
  })
 if err==nil{t.Fatal("malformed hosts baseline accepted")}
}
