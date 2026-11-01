//go:build windows

package main

import (
 "context"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"

 "volve-browser-protection/motorupdate"
)

func testStateDirectory(t *testing.T)(string,string){
 t.Helper()
 prev:=stateDirName
 stateDirName="VOLVE-Browser-Filter"
 t.Cleanup(func(){stateDirName=prev})
 programData:=t.TempDir()
 root:=filepath.Join(programData,stateDirName)
 if err:=os.Mkdir(root,0700);err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(filepath.Join(root,"estado.json"),[]byte("{\"version\":\"test\"}"),0600);err!=nil{t.Fatal(err)}
 return programData,root
}

func fakeReadOnlyHost(localIPv6 bool)motorupdate.WindowsMotorRouteInspectors{
 dns:=`[{"InterfaceIndex":17,"Family":"IPv4","Servers":["8.8.8.8"]},{"InterfaceIndex":17,"Family":"IPv6","Servers":["2001:4860:4860::8888"]}]`
 if localIPv6 { dns=`[{"InterfaceIndex":17,"Family":"IPv4","Servers":["8.8.8.8"]},{"InterfaceIndex":17,"Family":"IPv6","Servers":["::1"]}]` }
 return motorupdate.WindowsMotorRouteInspectors{
  Host:motorupdate.WindowsFreshPartialHostInspectors{
   Admin:func(context.Context,string)([]byte,error){return []byte(`{"Elevated":true}`),nil},
   Tasks:func(context.Context,string)([]byte,error){return []byte("[]"),nil},
   Services:func(context.Context,string)([]byte,error){return []byte("[]"),nil},
   DNS:func(context.Context,string)([]byte,error){return []byte(dns),nil},
  },
  Port53:func(context.Context,string)([]byte,error){return []byte("[]"),nil},
  RecoveryACL:func(context.Context,string)error{return nil},
 }
}

func TestStandaloneAuditReadOnlyReportsNoMotorOnlyAfterRealMarkerAndSixQueries(t *testing.T){
 pd,root:=testStateDirectory(t)
 before,err:=os.ReadDir(root);if err!=nil{t.Fatal(err)}
 got:=diagnosis(context.Background(),pd,true,fakeReadOnlyHost(false))
 after,err:=os.ReadDir(root);if err!=nil{t.Fatal(err)}
 if got.Result!="REVIEW_ONLY"||got.Mode!="READ_ONLY_NOT_AN_INSTALLER"||
  got.Route==nil||got.Route.InventoriesChecked!=6||
  got.Route.Route!=motorupdate.MotorRouteFreshCandidate||
  got.Route.CanModifyDNS||got.Route.FreshInstallAuthorized||
  got.Route.SignedUpgradeAuthorized||len(before)!=len(after){
  t.Fatalf("standalone falsely allowed or modified install: %#v",got)
 }
}
func TestStandaloneAuditLocalIPv6AndOrphanedMotorAreNeverFresh(t *testing.T){
 pd,root:=testStateDirectory(t)
 dns:=diagnosis(context.Background(),pd,true,fakeReadOnlyHost(true))
 if dns.Result!="REVIEW_ONLY"||dns.Route==nil||
  dns.Route.Route!=motorupdate.MotorRouteConflictingResidue{
  t.Fatalf("IPv6 ::1 protection was discarded: %+v",dns)
 }
 if err:=os.WriteFile(filepath.Join(root,"VOLVE_DNS_Server_0270.exe"),[]byte("MZ_legacy_fixture"),0600);err!=nil{t.Fatal(err)}
 old:=diagnosis(context.Background(),pd,true,fakeReadOnlyHost(false))
 if old.Result!="REVIEW_ONLY"||old.Route==nil||
  old.Route.Route!=motorupdate.MotorRouteConflictingResidue{
  t.Fatalf("installed legacy EXE without actual SYSTEM task was treated as fresh: %+v",old)
 }
}
func TestStandaloneAuditNeverGuessesMissingRootOrInsufficientPrivileges(t *testing.T){
 pd,root:=testStateDirectory(t)
 for _,tc:=range []struct{name string; pd string;admin bool;removeState bool}{
  {"not-admin",pd,false,false},
  {"no-programdata","",true,false},
  {"uninstalled-root",filepath.Join(pd,"other"),true,false},
  {"missing-original-state",pd,true,true},
 }{
  t.Run(tc.name,func(t *testing.T){
   if tc.removeState{
    if err:=os.Remove(filepath.Join(root,"estado.json"));err!=nil{t.Fatal(err)}
    defer func(){_ = os.WriteFile(filepath.Join(root,"estado.json"),[]byte("{}"),0600)}()
   }
   got:=diagnosis(context.Background(),tc.pd,tc.admin,fakeReadOnlyHost(false))
   if got.Result!="INCOMPLETE"||got.Route!=nil{
    t.Fatalf("%s guessed motor status without trusted installer evidence: %+v",tc.name,got)
   }
  })
 }
 stateDirName="UNCONFIGURED_DO_NOT_USE"
 got:=diagnosis(context.Background(),pd,true,fakeReadOnlyHost(false))
 if got.Result!="INCOMPLETE"||got.Route!=nil{t.Fatal("unconfigured release folder accepted")}
}

func TestStandaloneReportWritesOnlyNewPersonalDownloadsFile(t *testing.T){
 home:=t.TempDir()
 download:=filepath.Join(home,"Downloads")
 if err:=os.Mkdir(download,0700);err!=nil{t.Fatal(err)}
 report:=Diagnosis{
  Schema:1,Component:reportComponent,Mode:"READ_ONLY_NOT_AN_INSTALLER",
  Result:"INCOMPLETE",Explanation:"No Windows task write was performed",
 }
 p,err:=outputToDownloads(home,report)
 if err!=nil{t.Fatal(err)}
 if filepath.Dir(p)!=download||!strings.HasSuffix(p,".json"){t.Fatal("report escaped Downloads")}
 data,err:=os.ReadFile(p);if err!=nil{t.Fatal(err)}
 var got Diagnosis
 if err:=json.Unmarshal(data,&got);err!=nil{t.Fatal(err)}
 if got.Result!="INCOMPLETE"||got.Route!=nil||got.Component!=reportComponent{
  t.Fatalf("incomplete report was falsely claimed healthy: %+v",got)
 }
 // The app never creates or repairs Downloads itself.
 other:=t.TempDir()
 if _,err:=outputToDownloads(other,report);err==nil{t.Fatal("created a new profile Downloads directory without consent")}
}

func TestStandaloneAuditSeparateBrowserPoliciesFromDNSMotor(t *testing.T){
 pd,_:=testStateDirectory(t)
 browserJSON:=[]byte(`[{"Name":"chrome","Present":true,"NumberedEntries":12,"InvalidEntries":0,"UnexpectedEntries":0},{"Name":"edge","Present":true,"NumberedEntries":10,"InvalidEntries":0,"UnexpectedEntries":0},{"Name":"firefox","Present":false,"NumberedEntries":0,"InvalidEntries":0,"UnexpectedEntries":0}]`)
 got:=diagnosisWithBrowserPolicies(context.Background(),pd,true,
  fakeReadOnlyHost(true),func(context.Context,string)([]byte,error){return browserJSON,nil})
 if got.Result!="REVIEW_ONLY" || got.Route==nil || got.Route.Route!=motorupdate.MotorRouteConflictingResidue ||
  got.BrowserPolicies==nil || got.BrowserPolicies.TotalNumberedEntries!=22 ||
  got.BrowserPolicies.BrowserEnforcementVerified || got.BrowserPolicies.DNSMotorVerified ||
  got.BrowserPoliciesStatus!="REGISTRY_COUNTS_ONLY_NOT_BROWSER_ENFORCEMENT"{
  t.Fatalf("diagnosis conflated observed browser policy entries with running DNS motor: %+v",got)
 }
 raw,err:=json.Marshal(got);if err!=nil{t.Fatal(err)}
 if strings.Contains(string(raw),"betwarrior")||strings.Contains(string(raw),"example.org"){
  t.Fatal("browser filter URLs leaked into read-only report")
 }
}

func TestStandaloneAuditBrowserPolicyFailureNeverInventsBlocking(t *testing.T){
 pd,_:=testStateDirectory(t)
 got:=diagnosisWithBrowserPolicies(context.Background(),pd,true,
  fakeReadOnlyHost(false),func(context.Context,string)([]byte,error){return []byte("null"),nil})
 if got.BrowserPolicies!=nil || got.BrowserPoliciesStatus!="UNKNOWN_REGISTRY_QUERY_FAILED" ||
  got.Result!="REVIEW_ONLY" || got.Route==nil {
  t.Fatalf("invalid browser evidence yielded fake successful policy status: %+v",got)
 }
 noAdmin:=diagnosisWithBrowserPolicies(context.Background(),pd,false,
  fakeReadOnlyHost(false),func(context.Context,string)([]byte,error){
   t.Fatal("browser registry queried without admin")
   return nil,nil
  })
 if noAdmin.BrowserPolicies!=nil||noAdmin.BrowserPoliciesStatus!="NOT_INSPECTED_NO_ADMIN_TOKEN"||
  noAdmin.Result!="INCOMPLETE"{t.Fatalf("admin absence ignored: %+v",noAdmin)}
}


func TestStandaloneReportReturnsPrivacySafeSixInventoryDetails(t *testing.T){
 pd,_:=testStateDirectory(t)
 got:=diagnosisWithBrowserPolicies(context.Background(),pd,true,fakeReadOnlyHost(true),
  func(context.Context,string)([]byte,error){
   return []byte(`[{"Name":"chrome","Present":true,"NumberedEntries":40,"InvalidEntries":0,"UnexpectedEntries":0},{"Name":"edge","Present":true,"NumberedEntries":40,"InvalidEntries":0,"UnexpectedEntries":0},{"Name":"firefox","Present":true,"NumberedEntries":80,"InvalidEntries":0,"UnexpectedEntries":0}]`),nil
  })
 if got.Route==nil||got.HostEvidence==nil||got.BrowserPolicies==nil||
  got.HostEvidence.InventoriesObserved!=6||!got.HostEvidence.LocalDNSIPv6Seen||
  got.HostEvidence.CanModifyDNS||got.HostEvidence.SignedUpgradeAuthorized||
  got.BrowserPolicies.TotalNumberedEntries!=160||got.BrowserPolicies.DNSMotorVerified||
  got.BrowserPolicies.BrowserEnforcementVerified {
  t.Fatalf("standalone browser policy and host motor state conflated: %+v",got)
 }
 raw,err:=json.Marshal(got);if err!=nil{t.Fatal(err)}
 if strings.Contains(string(raw),`C:\\Program Files`) ||strings.Contains(string(raw),`"::1"`) {
  t.Fatal("private executable action path or literal DNS address escaped into report")
 }
}
