//go:build windows

package motorupdate

import (
 "context"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func routeFixtureReaders(t *testing.T, tasks []windowsVOLVETaskRecord,localDNS,occupied bool)WindowsMotorRouteInspectors {
 t.Helper()
 host:=partialHostInspectors(t,true,tasks,[]windowsVOLVEServiceRecord{})
 if localDNS {
  host.DNS=func(_ context.Context,q string)([]byte,error){
   if q!=WindowsFreshDNSAdapterQuery{t.Fatal("unexpected DNS adapter query")}
   return freshDNSRows(t,[]windowsFreshDNSAdapterRow{
    {InterfaceIndex:17,Family:"IPv4",Servers:[]string{"8.8.8.8"}},
    {InterfaceIndex:17,Family:"IPv6",Servers:[]string{"::1"}},
   }),nil
  }
 }
 port:=[]windowsFreshPort53Row{}
 if occupied{port=append(port,windowsFreshPort53Row{Transport:"UDP",Address:"::1",Port:53,PID:7})}
 return WindowsMotorRouteInspectors{
  Host:host,
  Port53:func(_ context.Context,q string)([]byte,error){
   if q!=WindowsFreshPort53Query{t.Fatal("unexpected port53 query")}
   return freshPort53Fixture(t,port),nil
  },
  RecoveryACL:allowRecoveryACLFixture,
 }
}

func TestWindowsMotorRouteEndToEndPreservesCatalogAndCannotEraseLoopback(t *testing.T){
 for _,tc:=range []struct {
  name string
  tasks []windowsVOLVETaskRecord
  file string
  localDNS,occupied,recovery bool
  want MotorInstallRoute
 }{
  {"empty-host",[]windowsVOLVETaskRecord{},"",false,false,false,MotorRouteFreshCandidate},
  {"catalog-only",[]windowsVOLVETaskRecord{freshTaskFixture()},"",false,false,false,MotorRouteCatalogCandidate},
  {"catalog-plus-local-ipv6",[]windowsVOLVETaskRecord{freshTaskFixture()},"",true,false,false,MotorRouteConflictingResidue},
  {"catalog-plus-local-port53",[]windowsVOLVETaskRecord{freshTaskFixture()},"",false,true,false,MotorRouteConflictingResidue},
  {"legacy-motor-and-task",[]windowsVOLVETaskRecord{{
   Name:"VOLVE-DNS-SERVER-0270",TaskPath:"\\",Principal:"SYSTEM",DefinitionSHA256:strings.Repeat("b",64),
  }},"VOLVE_DNS_Server_0270.exe",false,true,false,MotorRouteLegacyReview},
  {"orphan-legacy-engine",[]windowsVOLVETaskRecord{},"VOLVE_DNS_Server_0270.exe",false,false,false,MotorRouteConflictingResidue},
  {"recovery-parent",[]windowsVOLVETaskRecord{},"",false,false,true,MotorRouteRecoveryReview},
 }{
  t.Run(tc.name,func(t *testing.T){
   root:=t.TempDir()
   if tc.file!=""{
    if err:=os.WriteFile(filepath.Join(root,tc.file),[]byte("MZ_LAB_MOTOR_NOT_A_PRODUCTION_BINARY"),0600);err!=nil{t.Fatal(err)}
   }
   if tc.recovery{
    if err:=os.Mkdir(filepath.Join(root,freshRecoveryParentName),0700);err!=nil{t.Fatal(err)}
   }
   readers:=routeFixtureReaders(t,tc.tasks,tc.localDNS,tc.occupied)
   catalogExe:=""
   catalogArgs:=""
   if len(tc.tasks)>0&&tc.tasks[0].Name=="VOLVE-CATALOGO-0230"{
    catalogExe=filepath.Clean(`C:\Program Files\VOLVE\VOLVE_Catalog.exe`)
    catalogArgs="--catalog"
   }
   route,err:=InspectWindowsMotorRouteReadOnly(context.Background(),root,catalogExe,catalogArgs,readers)
   if err!=nil{t.Fatal(err)}
   if route.Route!=tc.want{t.Fatalf("route %s instead of %s: %s",route.Route,tc.want,route.Reason)}
   if route.InventoriesChecked!=6||RequireMotorRouteReviewOnly(route)!=nil{
    t.Fatalf("native complete census returned unsafe action: %+v",route)
   }
  })
 }
}

func TestWindowsMotorRouteFailsClosedBeforeReturningClassification(t *testing.T){
 root:=t.TempDir()
 readers:=routeFixtureReaders(t,[]windowsVOLVETaskRecord{},false,false)
 readers.Host.Admin=func(context.Context,string)([]byte,error){return []byte(`{"Elevated":false}`),nil}
 got,err:=InspectWindowsMotorRouteReadOnly(context.Background(),root,"","",readers)
 if err==nil||got.Route!=""{t.Fatal("unprivileged probe produced a Windows installation route")}
 readers=routeFixtureReaders(t,[]windowsVOLVETaskRecord{},false,false)
 readers.Port53=func(context.Context,string)([]byte,error){return nil,nil}
 got,err=InspectWindowsMotorRouteReadOnly(context.Background(),root,"","",readers)
 if err==nil||got.Route!=""{t.Fatal("missing port53 evidence produced a route")}
 readers=routeFixtureReaders(t,[]windowsVOLVETaskRecord{},false,false)
 got,err=InspectWindowsMotorRouteReadOnly(context.Background(),filepath.Join(root,"missing"),"","",readers)
 if err==nil||got.Route!=""{t.Fatal("missing installed root produced a route")}
}

func TestWindowsMotorRouteRealOSReadOnly(t *testing.T){
 if testing.Short(){t.Skip("requires native hosted Windows")}
 ctx:=context.Background()
 admin,err:=InspectWindowsElevatedTokenReadOnly(ctx,DefaultWindowsFreshAdminInspect)
 if err!=nil{t.Fatal(err)}
 if !admin{t.Skip("Windows runner token not elevated")}
 // The root is temporary, but all other read-only inventories are genuinely
 // obtained from Windows APIs, including actual DNS and TCP/UDP port53.
 root:=t.TempDir()
 report,err:=InspectWindowsMotorRouteReadOnly(ctx,root,"","",DefaultWindowsMotorRouteInspectors())
 if err!=nil{t.Fatal(err)}
 if report.InventoriesChecked!=6||RequireMotorRouteReviewOnly(report)!=nil{
  t.Fatal("native Windows diagnosis unexpectedly allowed an installation")
 }
 t.Logf("READ ONLY REAL WINDOWS: route=%s; explanation=%s; NO changes",report.Route,report.Reason)
}
