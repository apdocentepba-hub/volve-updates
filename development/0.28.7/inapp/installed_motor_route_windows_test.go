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

func installedRouteReadersForTest(tasks string,localIPv6 bool)motorupdate.WindowsMotorRouteInspectors{
 dns:=`[{"InterfaceIndex":17,"Family":"IPv4","Servers":["8.8.8.8"]},{"InterfaceIndex":17,"Family":"IPv6","Servers":["2606:4700:4700::1111"]}]`
 if localIPv6{dns=`[{"InterfaceIndex":17,"Family":"IPv4","Servers":["8.8.8.8"]},{"InterfaceIndex":17,"Family":"IPv6","Servers":["::1"]}]`}
 return motorupdate.WindowsMotorRouteInspectors{
  Host:motorupdate.WindowsFreshPartialHostInspectors{
   Admin:func(context.Context,string)([]byte,error){return []byte(`{"Elevated":true}`),nil},
   Tasks:func(context.Context,string)([]byte,error){return []byte(tasks),nil},
   Services:func(context.Context,string)([]byte,error){return []byte("[]"),nil},
   DNS:func(context.Context,string)([]byte,error){return []byte(dns),nil},
  },
  Port53:func(context.Context,string)([]byte,error){return []byte("[]"),nil},
  RecoveryACL:func(context.Context,string)error{return nil},
 }
}

func TestInstalledMotorRouteCLIReportNeverClaimsInstall(t *testing.T){
 for _,tc:=range []struct{name string;tasks string;localIPv6 bool;want motorupdate.MotorInstallRoute}{
  {"empty-VM","[]",false,motorupdate.MotorRouteFreshCandidate},
  {"local-ipv6-residue","[]",true,motorupdate.MotorRouteConflictingResidue},
  {"catalog-action-not-publisher-pinned",
   `[{"Name":"VOLVE-CATALOGO-0230","TaskPath":"\\","Principal":"SYSTEM","DefinitionSHA256":"`+
    strings.Repeat("a",64)+`","Actions":[{"Execute":"C:\\VOLVE\\VOLVE_Catalog.exe","Arguments":"--catalog","WorkingDirectory":""}]}]`,
   false,motorupdate.MotorRouteUnverified},
 }{
  t.Run(tc.name,func(t *testing.T){
   root:=t.TempDir()
   before,err:=os.ReadDir(root);if err!=nil{t.Fatal(err)}
   got,err:=inspectInstalledMotorRouteReadOnly(context.Background(),root,installedRouteReadersForTest(tc.tasks,tc.localIPv6))
   if err!=nil{t.Fatal(err)}
   after,err:=os.ReadDir(root);if err!=nil{t.Fatal(err)}
   if len(after)!=len(before){t.Fatal("diagnostic wrote files into installed directory")}
   if got.Schema!=1||got.Component!="dns-engine-install-route-audit-only"||
    got.Decision.Route!=tc.want||got.Decision.InventoriesChecked!=6||
    got.Decision.CanModifyDNS||got.Decision.FreshInstallAuthorized||
    got.Decision.SignedUpgradeAuthorized{
    t.Fatalf("unsafe or inaccurate read-only installed status: %+v",got)
   }
   raw,err:=json.Marshal(got);if err!=nil{t.Fatal(err)}
   if !strings.Contains(string(raw),"READ ONLY")||strings.Contains(string(raw),"private_key"){
    t.Fatal("Windows diagnosis JSON leaks private key or omits read-only disclaimer")
   }
  })
 }
}

func TestInstalledMotorRouteCLIRejectsInaccessibleRootAndCancellation(t *testing.T){
 readers:=installedRouteReadersForTest("[]",false)
 root:=t.TempDir()
 got,err:=inspectInstalledMotorRouteReadOnly(context.Background(),filepath.Join(root,"missing"),readers)
 if err==nil||got.Component!=""{t.Fatal("missing installed root produced valid update decision")}
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 got,err=inspectInstalledMotorRouteReadOnly(ctx,root,readers)
 if err==nil||got.Component!=""{t.Fatal("cancelled OS inspection issued a valid status")}
}
