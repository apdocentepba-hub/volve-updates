//go:build windows

package main

import (
 "context"
 "encoding/json"
 "strings"
 "testing"
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
