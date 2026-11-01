//go:build windows

package motorupdate

import (
 "context"
 "errors"
 "os"
 "path/filepath"
 "testing"
)

func TestWindowsSixOfSixReadOnlyEvidenceAndSafeClassification(t *testing.T){
 for _,tc:=range []struct{name string;recovery bool;busy bool}{
  {"clean-test-root",false,false},
  {"old-recovery-parent",true,false},
  {"tcp53-occupied",false,true},
 } {
  t.Run(tc.name,func(t *testing.T){
   root:=t.TempDir()
   if tc.recovery {
    if err:=os.Mkdir(filepath.Join(root,freshRecoveryParentName),0700);err!=nil{t.Fatal(err)}
   }
   endpoints:=[]windowsFreshPort53Row{}
   if tc.busy{endpoints=append(endpoints,windowsFreshPort53Row{
    Transport:"TCP",Address:"127.0.0.1",Port:53,PID:4,
   })}
   got,err:=InspectWindowsFreshSixOfSixReadOnly(context.Background(),root,"","",
    partialHostInspectors(t,true,[]windowsVOLVETaskRecord{},[]windowsVOLVEServiceRecord{}),
    func(context.Context,string)([]byte,error){return freshPort53Fixture(t,endpoints),nil},
    allowRecoveryACLFixture)
   if err!=nil{t.Fatal(err)}
   e:=got.Host.Host.Host.Evidence
   if !e.InspectedAsAdministrator||!e.InspectedMotorFiles||!e.InspectedTaskScheduler||
    !e.InspectedServices||!e.InspectedDNSAdapters||!e.InspectedPort53Listeners||
    !e.InspectedRecoveryState||e.RecoveryArtifactsPresent!=tc.recovery{
    t.Fatalf("six independent Windows evidence flags missing or wrong: %+v",e)
   }
   allowed:=CheckFreshMotorInstallReadiness(context.Background(),e)==nil
   if allowed!=(tc.name=="clean-test-root"){
    t.Fatalf("recovery/port53 residue ignored in READINESS policy: %t %+v",allowed,e)
   }
   // A successful READINESS verdict NEVER installs anything and does not
   // certify a production switch or a legitimate publisher signature.
  })
 }
}

func TestWindowsSixOfSixRejectsACLFailureAndMissingInspector(t *testing.T){
 root:=t.TempDir()
 if err:=os.Mkdir(filepath.Join(root,freshRecoveryParentName),0700);err!=nil{t.Fatal(err)}
 inspect:=partialHostInspectors(t,true,[]windowsVOLVETaskRecord{},[]windowsVOLVEServiceRecord{})
 port:=func(context.Context,string)([]byte,error){return []byte("[]"),nil}
 if got,err:=InspectWindowsFreshSixOfSixReadOnly(context.Background(),root,"","",inspect,port,nil);
  err==nil||got.Host.Host.Host.Evidence.InspectedRecoveryState{
  t.Fatal("nil privileged recovery verifier bypassed sixth inventory")
 }
 if got,err:=InspectWindowsFreshSixOfSixReadOnly(context.Background(),root,"","",inspect,port,
  func(context.Context,string)error{return errors.New("untrusted recovery owner")});
  err==nil||got.Host.Host.Host.Evidence.InspectedRecoveryState{
  t.Fatal("untrusted recovery DACL leaked a success-shaped host snapshot")
 }
}

func TestWindowsSixOfSixNativeReadOnlyQueries(t *testing.T){
 if testing.Short(){t.Skip("native Windows host integration")}
 root:=t.TempDir()
 ctx:=context.Background()
 admin,err:=InspectWindowsElevatedTokenReadOnly(ctx,DefaultWindowsFreshAdminInspect)
 if err!=nil{t.Fatal(err)}
 if !admin{t.Skip("native Windows hosted CI is not elevated; other inspector tests reject it")}
 got,err:=InspectWindowsFreshSixOfSixReadOnly(ctx,root,"","",WindowsFreshPartialHostInspectors{
  Admin:DefaultWindowsFreshAdminInspect,
  Tasks:DefaultWindowsFreshTaskInspect,
  Services:DefaultWindowsFreshServiceInspect,
  DNS:DefaultWindowsFreshDNSAdapterInspect,
 },DefaultWindowsFreshPort53Inspect,DefaultWindowsFreshRecoveryACLInspect)
 if err!=nil{t.Fatalf("native Windows six-inventory READ ONLY preflight: %v",err)}
 e:=got.Host.Host.Host.Evidence
 if !e.InspectedRecoveryState||!e.InspectedPort53Listeners||!e.InspectedDNSAdapters {
  t.Fatal("not all six Windows checks completed")
 }
 t.Logf("READ ONLY: 6/6 Windows inventories, tasks=%d services=%d TCP53v4=%d UDP53v4=%d recovery=%t; NO system changes",
  e.VOLVETaskCount,e.VOLVEServiceCount,e.TCP53IPv4OwnerCount,e.UDP53IPv4OwnerCount,e.RecoveryArtifactsPresent)
}
