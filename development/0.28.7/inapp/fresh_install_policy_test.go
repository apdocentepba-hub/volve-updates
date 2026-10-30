package motorupdate

import (
 "context"
 "errors"
 "testing"
)

func TestFreshMotorPolicyCleanHostIsReadinessOnly(t *testing.T) {
 e:=FreshMotorInstallEvidence{InspectedAsAdministrator:true}
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
  {"ipv4-local",func(e *FreshMotorInstallEvidence){e.LocalIPv4DNSConfigured=true}},
  {"ipv6-local",func(e *FreshMotorInstallEvidence){e.LocalIPv6DNSConfigured=true}},
  {"journal",func(e *FreshMotorInstallEvidence){e.RecoveryJournalPresent=true}},
  {"rollback",func(e *FreshMotorInstallEvidence){e.PendingRollbackPresent=true}},
  {"unknown-task-count",func(e *FreshMotorInstallEvidence){e.VOLVETaskCount=-1}},
  {"unknown-service-count",func(e *FreshMotorInstallEvidence){e.VOLVEServiceCount=-1}},
  {"unknown-udp-owner",func(e *FreshMotorInstallEvidence){e.UDP53IPv4OwnerCount=-1}},
 }{
  t.Run(tc.name,func(t *testing.T){
   e:=FreshMotorInstallEvidence{InspectedAsAdministrator:true}
   tc.edit(&e)
   if err:=CheckFreshMotorInstallReadiness(context.Background(),e);err==nil{
    t.Fatal("unsafe host would be allowed into the clean-install path")
   }
  })
 }
}
func TestFreshMotorPolicyCancelledWithoutSideEffects(t *testing.T){
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 if err:=CheckFreshMotorInstallReadiness(ctx,FreshMotorInstallEvidence{InspectedAsAdministrator:true});!errors.Is(err,context.Canceled){
  t.Fatalf("cancelled preflight accepted: %v",err)
 }
}
