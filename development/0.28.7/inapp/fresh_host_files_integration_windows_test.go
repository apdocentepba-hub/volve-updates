//go:build windows

package motorupdate

import (
 "context"
 "os"
 "path/filepath"
 "testing"
)

func TestWindowsFourOfSixReadOnlyNeverAuthorizesInstall(t *testing.T){
 cases:=[]struct{name,filename string; wantMotor,wantReceipt bool}{
  {"empty-known-root","",false,false},
  {"legacy-motor","VOLVE_DNS_Server_0270.exe",true,false},
  {"versioned-motor","VOLVE_DNS_Motor_0_28_7.exe",true,false},
  {"existing-engine-receipt","installed-engines",false,true},
 }
 for _,tc:=range cases{t.Run(tc.name,func(t *testing.T){
  root:=t.TempDir()
  if tc.filename=="installed-engines"{
   if err:=os.Mkdir(filepath.Join(root,tc.filename),0700);err!=nil{t.Fatal(err)}
  }else if tc.filename!=""{
   if err:=os.WriteFile(filepath.Join(root,tc.filename),[]byte("fixture-only"),0600);err!=nil{t.Fatal(err)}
  }
  inspectors:=partialHostInspectors(t,true,[]windowsVOLVETaskRecord{},[]windowsVOLVEServiceRecord{})
  got,err:=InspectWindowsFreshFourOfSixReadOnly(context.Background(),root,"","",inspectors)
  if err!=nil{t.Fatal(err)}
  e:=got.Host.Evidence
  if !e.InspectedAsAdministrator || !e.InspectedTaskScheduler || !e.InspectedServices ||
   !e.InspectedDNSAdapters || !e.InspectedMotorFiles ||
   e.InspectedPort53Listeners || e.InspectedRecoveryState {
   t.Fatalf("four-of-six snapshot fabricated missing inventories: %+v",e)
  }
  if e.InstalledEngineInventoryPresent!=tc.wantReceipt ||
   (e.LegacyExecutablePresent||e.VersionedMotorPresent)!=tc.wantMotor {
   t.Fatalf("motor/receipt evidence incorrectly merged: %+v",e)
  }
  if err:=CheckFreshMotorInstallReadiness(context.Background(),e);err==nil{
   t.Fatal("incomplete four-of-six Windows host evidence authorized installation")
  }
 })}
}

func TestWindowsFourOfSixRejectsFileAndTokenFailure(t *testing.T){
 root:=t.TempDir()
 inspect:=partialHostInspectors(t,false,[]windowsVOLVETaskRecord{},[]windowsVOLVEServiceRecord{})
 if out,err:=InspectWindowsFreshFourOfSixReadOnly(context.Background(),root,"","",inspect);err==nil||out.Host.Evidence.InspectedMotorFiles{
  t.Fatal("non-elevated Windows token accepted in combined inventory")
 }
 inspect=partialHostInspectors(t,true,[]windowsVOLVETaskRecord{},[]windowsVOLVEServiceRecord{})
 if out,err:=InspectWindowsFreshFourOfSixReadOnly(context.Background(),filepath.Join(root,"missing"),"","",inspect);err==nil||out.Host.Evidence.InspectedMotorFiles{
  t.Fatal("uninspected root fabricated completed installed-file census")
 }
}
