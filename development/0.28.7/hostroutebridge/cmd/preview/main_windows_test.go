//go:build windows

package main

import (
 "context"
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
