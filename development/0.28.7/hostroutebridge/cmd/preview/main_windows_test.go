//go:build windows

package main

import (
 "context"
 "encoding/json"
 "strings"
 "testing"

 motorupdate "volve-browser-protection/motorupdate"
 bridge "volve.local/installer/singlefile/hostroutebridge"
)

func TestSetupPreviewRejectsNonHostedMachinesBeforeAnyInventory(t *testing.T) {
 t.Setenv("GITHUB_ACTIONS","false")
 t.Setenv("RUNNER_ENVIRONMENT","github-hosted")
 report,err:=inspectCIHostReadOnly(context.Background())
 if err==nil || report.Component!="" ||
  !strings.Contains(err.Error(),"disposable hosted Windows CI") {
  t.Fatalf("untrusted machine reached signed preview: %+v %v",report,err)
 }
}

func TestSetupPreviewRejectsMissingExternalPublisherPinsBeforeHostInventory(t *testing.T) {
 t.Setenv("GITHUB_ACTIONS","true")
 t.Setenv("RUNNER_ENVIRONMENT","github-hosted")
 t.Setenv("VOLVE_CI_ED25519_PUB","")
 report,err:=inspectCIHostReadOnly(context.Background())
 if err==nil || report.Component!="" ||
  !strings.Contains(err.Error(),"Ed25519 trust pin") {
  t.Fatalf("unsigned preview was accepted: %+v %v",report,err)
 }
}


func TestSetupPreviewJSONPreservesLegacyMigrationBlockers(t *testing.T) {
 blockers:=[]string{
  "legacy_three_task_backup_unverified",
  "legacy_transitive_dependencies_uncertified",
  "legacy_reboot_recovery_unverified",
 }
 report:=setupPreviewReport{MigrationBlockers:blockers}
 raw,err:=json.Marshal(report)
 if err!=nil { t.Fatal(err) }
 var decoded struct {
  MigrationBlockers []string `json:"migration_blockers"`
  CanInstall bool `json:"can_install"`
  CanUpgrade bool `json:"can_upgrade"`
  CanChangeDNS bool `json:"can_change_dns"`
  CanChangeTasks bool `json:"can_change_tasks"`
 }
 if err:=json.Unmarshal(raw,&decoded);err!=nil { t.Fatal(err) }
 if len(decoded.MigrationBlockers)!=len(blockers) {
  t.Fatalf("preview JSON lost migration blockers: %s",raw)
 }
 for i,want:=range blockers {
  if decoded.MigrationBlockers[i]!=want {
   t.Fatalf("preview blocker %d=%q want %q",i,decoded.MigrationBlockers[i],want)
  }
 }
 if decoded.CanInstall||decoded.CanUpgrade||decoded.CanChangeDNS||decoded.CanChangeTasks {
  t.Fatalf("blocker serialization authorized mutation: %s",raw)
 }
}

func TestReadOnlyProgressRequiresCanonicalProtectedReview(t *testing.T){
 ctx:=context.Background()
 for _,tc:=range []struct{route motorupdate.MotorInstallRoute;want int}{
  {motorupdate.MotorRouteFreshCandidate,25},
  {motorupdate.MotorRouteCatalogCandidate,25},
  {motorupdate.MotorRouteLegacyReview,25},
  {motorupdate.MotorRouteManagedReview,25},
  {motorupdate.MotorRouteRecoveryReview,0},
  {motorupdate.MotorRouteConflictingResidue,0},
  {motorupdate.MotorRouteUnverified,0},
 }{
  review:=bridge.Review{Schema:1,Component:"installer-signed-bundle-windows-route-review",Release:"0.28.7",PackageParts:7,WindowsPublisherAndPackageVerified:true,InventoriesChecked:6,Route:tc.route,Reason:"test fixture",Status:"REVIEW_ONLY_NEVER_INSTALL_OR_MIGRATE"}
  plan,err:=bridge.PlanFromVerifiedReview(ctx,review)
  if err!=nil{t.Fatal(err)}
  v,err:=projectReadOnlyProgress(ctx,review,plan,false)
  if err!=nil||v.Percent!=0{t.Fatalf("unprotected review advanced: %+v %v",v,err)}
  v,err=projectReadOnlyProgress(ctx,review,plan,true)
  if err!=nil||v.Percent!=tc.want||v.RebootRequired{t.Fatalf("wrong review projection: %+v %v",v,err)}
  if tc.want==25&&string(v.Next)!="backup_verified"{t.Fatal(v)}
  altered:=plan
  altered.CanInstall=true
  if _,err:=projectReadOnlyProgress(ctx,review,altered,true);err==nil{t.Fatal("mutated plan accepted")}
  altered=plan
  altered.Prerequisites=nil
  if _,err:=projectReadOnlyProgress(ctx,review,altered,true);err==nil{t.Fatal("missing prerequisites accepted")}
  review.WindowsPublisherAndPackageVerified=false
  if _,err:=projectReadOnlyProgress(ctx,review,plan,true);err==nil{t.Fatal("unverified package accepted")}
 }
}

func TestSetupPreviewOriginalBackupReviewIsNotBackupCompletion(t *testing.T){
 report:=setupPreviewReport{OriginalBackupReview:motorupdate.WindowsOriginalBackupReview{Status:"NOT_CHECKED_NO_ARCHIVES"},ReviewProgressPercent:25,ReviewProgressNext:"backup_verified"}
 raw,err:=json.Marshal(report);if err!=nil{t.Fatal(err)}
 var decoded setupPreviewReport
 if err:=json.Unmarshal(raw,&decoded);err!=nil{t.Fatal(err)}
 if decoded.OriginalBackupReview.Status!="NOT_CHECKED_NO_ARCHIVES"||
  decoded.OriginalBackupReview.HostsVerified||decoded.OriginalBackupReview.BrowserKeysVerified!=0||
  decoded.OriginalBackupReview.DNSBackupVerified||decoded.OriginalBackupReview.CatalogBackupVerified||
  decoded.OriginalBackupReview.CompleteRecoverySnapshot||decoded.OriginalBackupReview.InstallAuthorized||
  decoded.OriginalBackupReview.RestoreAuthorized||decoded.CanInstall||decoded.ReviewProgressPercent!=25{
  t.Fatal("read-only preview misrepresented archive verification")
 }
}
