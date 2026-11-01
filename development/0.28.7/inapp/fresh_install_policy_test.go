package motorupdate

import (
 "context"
 "errors"
 "testing"
)

// Synthetic complete observation for policy tests ONLY. A real Windows
// installer cannot set these flags without reading all six independent
// operating-system inventories.
func freshCompleteObservation() FreshMotorInstallEvidence {
 return FreshMotorInstallEvidence{
  InspectedAsAdministrator:true,
  InspectedMotorFiles:true,InspectedTaskScheduler:true,InspectedServices:true,
  InspectedDNSAdapters:true,InspectedPort53Listeners:true,InspectedRecoveryState:true,
 }
}
func freshCompleteObservationWithCatalog()FreshMotorInstallEvidence{
 e:=freshCompleteObservation()
 e.VOLVETaskCount=1
 e.VerifiedCatalogTask=verifiedCatalogFixture()
 return e
}
func TestFreshMotorPolicyRejectsUninspectedWindowsState(t *testing.T){
 if err:=CheckFreshMotorInstallReadiness(context.Background(),FreshMotorInstallEvidence{InspectedAsAdministrator:true});err==nil{
  t.Fatal("uninspected Windows host was treated as safe zero-valued inventory")
 }
 for _,tc:=range []struct{name string;omit func(*FreshMotorInstallEvidence)}{
  {"files",func(e *FreshMotorInstallEvidence){e.InspectedMotorFiles=false}},
  {"tasks",func(e *FreshMotorInstallEvidence){e.InspectedTaskScheduler=false}},
  {"services",func(e *FreshMotorInstallEvidence){e.InspectedServices=false}},
  {"DNS",func(e *FreshMotorInstallEvidence){e.InspectedDNSAdapters=false}},
  {"port53",func(e *FreshMotorInstallEvidence){e.InspectedPort53Listeners=false}},
  {"rollback",func(e *FreshMotorInstallEvidence){e.InspectedRecoveryState=false}},
 }{
  t.Run(tc.name,func(t *testing.T){
   e:=freshCompleteObservation();tc.omit(&e)
   if err:=CheckFreshMotorInstallReadiness(context.Background(),e);err==nil{
    t.Fatal("partial Windows host inventory was treated as clean")
   }
  })
 }
}
func TestFreshMotorPolicyCleanHostIsReadinessOnly(t *testing.T) {
 e:=freshCompleteObservation()
 if err:=CheckFreshMotorInstallReadiness(context.Background(),e);err!=nil{t.Fatal(err)}
}
func TestFreshMotorPolicyRejectsEveryUnsafeResidue(t *testing.T){
 for _,tc:=range []struct{name string;edit func(*FreshMotorInstallEvidence)}{
  {"not-admin",func(e *FreshMotorInstallEvidence){e.InspectedAsAdministrator=false}},
  {"legacy-exe",func(e *FreshMotorInstallEvidence){e.LegacyExecutablePresent=true}},
  {"versioned-engine",func(e *FreshMotorInstallEvidence){e.VersionedMotorPresent=true}},
  {"installed-inventory",func(e *FreshMotorInstallEvidence){e.InstalledEngineInventoryPresent=true}},
  {"legacy-task",func(e *FreshMotorInstallEvidence){e.VOLVETaskCount=1}},
  {"unknown-task",func(e *FreshMotorInstallEvidence){e.VOLVETaskCount=5}},
  {"service",func(e *FreshMotorInstallEvidence){e.VOLVEServiceCount=1}},
  {"udp53-v4-occupied",func(e *FreshMotorInstallEvidence){e.UDP53IPv4OwnerCount=1}},
  {"udp53-v6-occupied",func(e *FreshMotorInstallEvidence){e.UDP53IPv6OwnerCount=1}},
  {"tcp53-v4-occupied",func(e *FreshMotorInstallEvidence){e.TCP53IPv4OwnerCount=1}},
  {"tcp53-v6-occupied",func(e *FreshMotorInstallEvidence){e.TCP53IPv6OwnerCount=1}},
  {"negative-tcp-owner",func(e *FreshMotorInstallEvidence){e.TCP53IPv4OwnerCount=-1}},
  {"ipv4-local",func(e *FreshMotorInstallEvidence){e.LocalIPv4DNSConfigured=true}},
  {"ipv6-local",func(e *FreshMotorInstallEvidence){e.LocalIPv6DNSConfigured=true}},
  {"artifacts-even-with-terminal-journal",func(e *FreshMotorInstallEvidence){e.RecoveryArtifactsPresent=true}},
  {"journal",func(e *FreshMotorInstallEvidence){e.RecoveryJournalPresent=true}},
  {"rollback",func(e *FreshMotorInstallEvidence){e.PendingRollbackPresent=true}},
  {"unknown-task-count",func(e *FreshMotorInstallEvidence){e.VOLVETaskCount=-1}},
  {"unknown-service-count",func(e *FreshMotorInstallEvidence){e.VOLVEServiceCount=-1}},
  {"unknown-udp-owner",func(e *FreshMotorInstallEvidence){e.UDP53IPv4OwnerCount=-1}},
 }{
  t.Run(tc.name,func(t *testing.T){
   e:=freshCompleteObservation()
   tc.edit(&e)
   if err:=CheckFreshMotorInstallReadiness(context.Background(),e);err==nil{
    t.Fatal("unsafe host would be allowed into the clean-install path")
   }
  })
 }
}
func TestFreshMotorPolicyCancelledWithoutSideEffects(t *testing.T){
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 if err:=CheckFreshMotorInstallReadiness(ctx,freshCompleteObservation());!errors.Is(err,context.Canceled){
  t.Fatalf("cancelled preflight accepted: %v",err)
 }
}

// Regression: the user's 0.28.6 installation has a catalog task but NO DNS motor.
// It may be preserved only after independent action/principal verification.
func verifiedCatalogFixture() *VerifiedFreshCatalogTask {
 return &VerifiedFreshCatalogTask{
  Name:"VOLVE-CATALOGO-0230", TaskPath:"\\", ActionCount:1,
  ActionVerified:true, PrincipalVerified:true, DefinitionSHA256:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
 }
}
func TestFreshMotorPolicyPartialProtectionCatalogIsNotDNSMotor(t *testing.T) {
 e:=freshCompleteObservationWithCatalog()
 if err:=CheckFreshMotorInstallReadiness(context.Background(),e);err!=nil{t.Fatal(err)}
}
func TestFreshMotorPolicyRejectsUntrustedCatalogEvidence(t *testing.T) {
 cases:=[]struct{name string;mutate func(*FreshMotorInstallEvidence)}{
  {"missing-proof",func(e *FreshMotorInstallEvidence){e.VerifiedCatalogTask=nil}},
  {"unknown-task",func(e *FreshMotorInstallEvidence){e.VerifiedCatalogTask.Name="VOLVE-DNS-SERVER-0270"}},
  {"wrong-path",func(e *FreshMotorInstallEvidence){e.VerifiedCatalogTask.TaskPath="\\Other\\"}},
  {"wrong-action-count",func(e *FreshMotorInstallEvidence){e.VerifiedCatalogTask.ActionCount=2}},
  {"unverified-action",func(e *FreshMotorInstallEvidence){e.VerifiedCatalogTask.ActionVerified=false}},
  {"unverified-principal",func(e *FreshMotorInstallEvidence){e.VerifiedCatalogTask.PrincipalVerified=false}},
  {"unsigned-definition",func(e *FreshMotorInstallEvidence){e.VerifiedCatalogTask.DefinitionSHA256=""}},
  {"other-volve-tasks",func(e *FreshMotorInstallEvidence){e.VOLVETaskCount=2}},
 }
 for _,tc:=range cases {t.Run(tc.name,func(t *testing.T){
  e:=freshCompleteObservationWithCatalog()
  tc.mutate(&e)
  if err:=CheckFreshMotorInstallReadiness(context.Background(),e);err==nil{t.Fatal("unsafe task accepted")}
 })}
}
func TestFreshMotorPolicyContradictoryInventoryRejected(t *testing.T){
 e:=func()FreshMotorInstallEvidence{e:=freshCompleteObservation();e.VerifiedCatalogTask=verifiedCatalogFixture();return e}()
 if err:=CheckFreshMotorInstallReadiness(context.Background(),e);err==nil{t.Fatal("task count contradiction accepted")}
}
