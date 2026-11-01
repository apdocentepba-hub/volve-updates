package motorupdate

import (
 "context"
 "testing"
)

func TestMotorRouteSixInventoriesClassifyWithoutAuthorizingAnyWrites(t *testing.T){
 for _,tc:=range []struct{
  name string
  change func(*FreshMotorInstallEvidence)
  names []string
  want MotorInstallRoute
 }{
  {"truly-unobserved-host",func(e *FreshMotorInstallEvidence){e.InspectedRecoveryState=false},nil,MotorRouteUnverified},
  {"fresh-candidate-not-installed",nil,nil,MotorRouteFreshCandidate},
  {"verified-catalog-only",func(e *FreshMotorInstallEvidence){
   e.VOLVETaskCount=1;e.VerifiedCatalogTask=verifiedCatalogFixture()
  },nil,MotorRouteCatalogCandidate},
  {"catalog-task-but-unverified",func(e *FreshMotorInstallEvidence){
   e.VOLVETaskCount=1
   e.VerifiedCatalogTask=verifiedCatalogFixture()
   e.VerifiedCatalogTask.ActionVerified=false
  },nil,MotorRouteUnverified},
  {"old-exe-and-old-task",func(e *FreshMotorInstallEvidence){
   e.LegacyExecutablePresent=true;e.VOLVETaskCount=1
  },[]string{"\\VOLVE-DNS-SERVER-0270"},MotorRouteLegacyReview},
  {"old-exe-without-task",func(e *FreshMotorInstallEvidence){
   e.LegacyExecutablePresent=true
  },nil,MotorRouteConflictingResidue},
  {"old-task-without-exe",func(e *FreshMotorInstallEvidence){
   e.VOLVETaskCount=1
  },[]string{"\\VOLVE-DNS-SERVER-0270"},MotorRouteConflictingResidue},
  {"random-task-and-old-exe",func(e *FreshMotorInstallEvidence){
   e.LegacyExecutablePresent=true;e.VOLVETaskCount=1
  },[]string{"\\VOLVE-UNTRUSTED-OTHER"},MotorRouteConflictingResidue},
  {"renamed-task-with-old-exe",func(e *FreshMotorInstallEvidence){
   e.LegacyExecutablePresent=true;e.VOLVETaskCount=1
  },[]string{"\\Renamed-Known-Motor"},MotorRouteConflictingResidue},
  {"legacy-plus-catalog",func(e *FreshMotorInstallEvidence){
   e.LegacyExecutablePresent=true;e.VOLVETaskCount=2
   e.VerifiedCatalogTask=verifiedCatalogFixture()
  },[]string{"\\VOLVE-DNS-SERVER-0270"},MotorRouteConflictingResidue},
  {"managed-receipt",func(e *FreshMotorInstallEvidence){
   e.InstalledEngineInventoryPresent=true
  },nil,MotorRouteManagedReview},
  {"new-motor-exe",func(e *FreshMotorInstallEvidence){
   e.VersionedMotorPresent=true
  },nil,MotorRouteManagedReview},
  {"mixed-old-managed",func(e *FreshMotorInstallEvidence){
   e.LegacyExecutablePresent=true;e.VersionedMotorPresent=true
  },nil,MotorRouteConflictingResidue},
  {"local-IPv6-with-catalog-task",func(e *FreshMotorInstallEvidence){
   e.VOLVETaskCount=1;e.VerifiedCatalogTask=verifiedCatalogFixture()
   e.LocalIPv6DNSConfigured=true
  },nil,MotorRouteConflictingResidue},
  {"local-IPv4-with-no-motor",func(e *FreshMotorInstallEvidence){
   e.LocalIPv4DNSConfigured=true
  },nil,MotorRouteConflictingResidue},
  {"port53-owned-with-no-motor",func(e *FreshMotorInstallEvidence){
   e.UDP53IPv4OwnerCount=1
  },nil,MotorRouteConflictingResidue},
  {"tcp53-owned-with-no-motor",func(e *FreshMotorInstallEvidence){
   e.TCP53IPv6OwnerCount=1
  },nil,MotorRouteConflictingResidue},
  {"stopped-VOLVE-service",func(e *FreshMotorInstallEvidence){
   e.VOLVEServiceCount=1
  },nil,MotorRouteConflictingResidue},
  {"pending-rollback",func(e *FreshMotorInstallEvidence){
   e.PendingRollbackPresent=true
  },nil,MotorRouteRecoveryReview},
  {"terminal-journal-still-present",func(e *FreshMotorInstallEvidence){
   e.RecoveryJournalPresent=true
  },nil,MotorRouteRecoveryReview},
  {"old-recovery-parent-empty",func(e *FreshMotorInstallEvidence){
   e.RecoveryArtifactsPresent=true
  },nil,MotorRouteRecoveryReview},
  {"catalog-count-contradiction",func(e *FreshMotorInstallEvidence){
   e.VerifiedCatalogTask=verifiedCatalogFixture()
  },nil,MotorRouteUnverified},
  {"fabricated-task-names",nil,[]string{"\\VOLVE-DNS-SERVER-0270"},MotorRouteUnverified},
  {"missing-task-name",func(e *FreshMotorInstallEvidence){
   e.VOLVETaskCount=1
  },nil,MotorRouteUnverified},
  {"negative-task-count",func(e *FreshMotorInstallEvidence){
   e.VOLVETaskCount=-1
  },nil,MotorRouteUnverified},
  {"negative-service-count",func(e *FreshMotorInstallEvidence){
   e.VOLVEServiceCount=-1
  },nil,MotorRouteUnverified},
  {"negative-udp53",func(e *FreshMotorInstallEvidence){
   e.UDP53IPv4OwnerCount=-1
  },nil,MotorRouteUnverified},
  {"negative-tcp53",func(e *FreshMotorInstallEvidence){
   e.TCP53IPv6OwnerCount=-1
  },nil,MotorRouteUnverified},
 }{
  t.Run(tc.name,func(t *testing.T){
   e:=freshCompleteObservation()
   if tc.change!=nil{tc.change(&e)}
   got,err:=ClassifyMotorInstallRouteReadOnly(context.Background(),e,tc.names)
   if err!=nil{t.Fatal(err)}
   if got.Route!=tc.want{t.Fatalf("wrong route: got=%s expected=%s, reason=%s",got.Route,tc.want,got.Reason)}
   if got.Reason==""{t.Fatal("route has no rationale")}
   if err:=RequireMotorRouteReviewOnly(got);err!=nil{t.Fatal(err)}
   if got.CanModifyDNS||got.SignedUpgradeAuthorized||got.FreshInstallAuthorized{
    t.Fatal("classification unexpectedly grants a production action")
   }
   if (tc.name=="truly-unobserved-host") != (got.InventoriesChecked==0){
    t.Fatalf("wrong inventory completeness: %d",got.InventoriesChecked)
   }
  })
 }
}

func TestMotorRouteCancelledCannotProduceVerdict(t *testing.T){
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 got,err:=ClassifyMotorInstallRouteReadOnly(ctx,freshCompleteObservation(),nil)
 if err==nil||got.Reason!=""{t.Fatalf("cancelled read-only decision returned evidence: %+v, %v",got,err)}
}

func TestMotorRouteNeverAcceptsInjectedActionFlags(t *testing.T){
 for _,change:=range []func(*MotorInstallRouteReport){
  func(r *MotorInstallRouteReport){r.FreshInstallAuthorized=true},
  func(r *MotorInstallRouteReport){r.SignedUpgradeAuthorized=true},
  func(r *MotorInstallRouteReport){r.CanModifyDNS=true},
 }{
  r:=MotorInstallRouteReport{Route:MotorRouteFreshCandidate}
  change(&r)
  if err:=RequireMotorRouteReviewOnly(r);err==nil{t.Fatal("unsafe action was allowed in the read-only route result")}
 }
}
