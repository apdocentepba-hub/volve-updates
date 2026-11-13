//go:build windows

// setup-preview is a Windows CI-only preinstallation inspector. It cannot
// install VOLVE, start or stop SYSTEM tasks, or change DNS or browser policy.
// Its output is an advisory preview, NEVER an installation authorization.
package main

import (
 "context"
 "crypto/ed25519"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "time"

 motorupdate "volve-browser-protection/motorupdate"
 bridge "volve.local/installer/singlefile/hostroutebridge"
)

type setupPreviewReport struct {
 Schema int `json:"schema"`
 Component string `json:"component"`
 Scope string `json:"scope"`
 Result string `json:"result"`
 TargetRelease string `json:"target_release"`
 Route motorupdate.MotorInstallRoute `json:"observed_host_route"`
 Mode bridge.PlanMode `json:"next_review_mode"`
 WindowsInventories int `json:"windows_inventories_checked"`
 SignedCIContainerVerified bool `json:"synthetic_ci_signed_container_verified"`
 ProtectedTransitionMutexHeld bool `json:"protected_transition_mutex_held_during_review"`
 BrowserRegistryKeysChecked int `json:"browser_registry_keys_checked"`
 BrowserRegistryNumberedEntries int `json:"browser_registry_numbered_entries"`
 BrowserPolicyCensusStable bool `json:"browser_policy_census_stable_under_lock"`
 HostsBaselineChecked bool `json:"hosts_baseline_checked"`
 CatalogTaskBaselineChecked bool `json:"catalog_task_baseline_checked"`
 PartialProtectionSnapshotStable bool `json:"partial_protection_snapshot_stable_under_lock"`
 BrowserPolicyValuesExported bool `json:"browser_policy_values_exported"`
 BrowserEnforcementVerified bool `json:"browser_enforcement_verified"`
 Preconditions []string `json:"unmet_production_prerequisites"`
 CanInstall bool `json:"can_install"`
 CanUpgrade bool `json:"can_upgrade"`
 CanChangeDNS bool `json:"can_change_dns"`
 CanChangeTasks bool `json:"can_change_tasks"`
 Status string `json:"status"`
}

func inspectCIHostReadOnly(ctx context.Context) (setupPreviewReport,error) {
 return inspectCIHostWithProtectedOption(ctx,false)
}

func inspectCIHostUnderProtectedMutexReadOnly(ctx context.Context) (setupPreviewReport,error) {
 return inspectCIHostWithProtectedOption(ctx,true)
}

func inspectCIHostWithProtectedOption(ctx context.Context, holdProtectedMutex bool) (setupPreviewReport,error) {
 var refused setupPreviewReport
 if ctx==nil{return refused,errors.New("a non-nil Windows inspection context is required")}
 if err:=ctx.Err();err!=nil{return refused,err}
 // This binary is not for customer machines. Environment gating is a CI
 // boundary, not a replacement for the future signed production installer.
 if os.Getenv("GITHUB_ACTIONS")!="true" ||
   os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted" {
  return refused,errors.New("setup preview allowed only in disposable hosted Windows CI")
 }
 pub,err:=hex.DecodeString(os.Getenv("VOLVE_CI_ED25519_PUB"))
 if err!=nil || len(pub)!=ed25519.PublicKeySize{
  return refused,errors.New("external synthetic Ed25519 trust pin missing")
 }
 exe:=os.Getenv("VOLVE_CI_AUTHENTICODE_OS_BINARY")
 cert:=os.Getenv("VOLVE_CI_AUTHENTICODE_CERT_SHA256")
 fileHash:=os.Getenv("VOLVE_CI_AUTHENTICODE_FILE_SHA256")
 if !filepath.IsAbs(exe)||len(cert)!=64||len(fileHash)!=64 {
  return refused,errors.New("exact trusted test executable/certificate pins required")
 }
 if _,err:=hex.DecodeString(cert);err!=nil{return refused,errors.New("certificate pin malformed")}
 if _,err:=hex.DecodeString(fileHash);err!=nil{return refused,errors.New("file pin malformed")}
 runnerTemp:=os.Getenv("RUNNER_TEMP")
 if !filepath.IsAbs(runnerTemp) {
  return refused,errors.New("hosted runner temporary directory missing")
 }
 // The host root is a NEW, disposable inventory sandbox, not an existing
 // product root. Actual Scheduler, DNS, services and ports still come from
 // the hosted Windows OS. Never interpret this as a clean customer PC.
 root,err:=os.MkdirTemp(runnerTemp,"VOLVE-CI-SetupPreview-")
 if err!=nil{return refused,fmt.Errorf("temporary CI inventory root: %w",err)}
 defer os.Remove(root) // only delete our own newly-created empty root
 // The protected path is the important rehearsal: the real signed package
 // and entire live Windows six-inventory census are rechecked under the
 // same native kernel mutex owned by the updater and SYSTEM watchdog.
 var review bridge.Review
 var plan bridge.InstallerPlanReadOnly
 var browser motorupdate.WindowsBrowserPolicyEvidence
 var protectionSnapshot motorupdate.ProtectionSnapshot
 inspectors:=motorupdate.DefaultWindowsMotorRouteInspectors()
 if holdProtectedMutex {
  review,plan,browser,protectionSnapshot,err=bridge.InspectAndPlanWithBrowserCensusUnderProtectedLeaseReadOnly(
   ctx,exe,ed25519.PublicKey(pub),cert,fileHash,root,inspectors,
   motorupdate.DefaultWindowsBrowserPolicyInspect,
  )
  if err==nil && (len(browser.Records)!=3||!browser.NoRegistryValuesExported||
   protectionSnapshot.HostsSHA256==""||protectionSnapshot.ChromePoliciesSHA256==""||
   protectionSnapshot.EdgePoliciesSHA256==""||protectionSnapshot.FirefoxPoliciesSHA256==""||
   protectionSnapshot.CatalogTaskDefinitionSHA256==""||
   browser.BrowserEnforcementVerified||browser.DNSMotorVerified){
   err=errors.New("protected browser census could not prove three independent read-only observations")
  }
 }else{
  review,plan,err=bridge.InspectAndPlanWindowsHostReadOnly(
   ctx,exe,ed25519.PublicKey(pub),cert,fileHash,root,inspectors,
  )
 }
 if err!=nil{return refused,fmt.Errorf("signed Windows host review rejected: %w",err)}
 if review.InstallAuthorized||review.UpgradeAuthorized||review.CanModifyDNS||
    plan.CanInstall||plan.CanUpgrade||plan.CanChangeDNS||plan.CanChangeTasks||
    review.InventoriesChecked!=6||!plan.SignedPackageVerified ||
    plan.Disposition!="READ_ONLY_PLAN_NOT_AN_INSTALLATION_PERMIT" {
  return refused,errors.New("non-authorizing preinstallation proof violated")
 }
 return setupPreviewReport{
  Schema:1,
  Component:"VOLVE-0287-WINDOWS-SETUP-PREVIEW-CI",
  Scope:"DISPOSABLE_WINDOWS_CI_ONLY_NOT_USER_PC",
  Result:"REVIEW_ONLY",
  TargetRelease:plan.TargetRelease,
  Route:review.Route,Mode:plan.Mode,
  WindowsInventories:review.InventoriesChecked,
  SignedCIContainerVerified:true,
  ProtectedTransitionMutexHeld:holdProtectedMutex,
  BrowserRegistryKeysChecked:len(browser.Records),
  BrowserRegistryNumberedEntries:browser.TotalNumberedEntries,
  BrowserPolicyCensusStable:holdProtectedMutex&&len(browser.Records)==3,
  HostsBaselineChecked:holdProtectedMutex&&protectionSnapshot.HostsSHA256!="",
  CatalogTaskBaselineChecked:holdProtectedMutex&&protectionSnapshot.CatalogTaskDefinitionSHA256!="",
  PartialProtectionSnapshotStable:holdProtectedMutex&&protectionSnapshot.HostsSHA256!=""&&
   protectionSnapshot.ChromePoliciesSHA256!=""&&protectionSnapshot.EdgePoliciesSHA256!=""&&
   protectionSnapshot.FirefoxPoliciesSHA256!=""&&protectionSnapshot.CatalogTaskDefinitionSHA256!="",
  BrowserPolicyValuesExported:false,
  BrowserEnforcementVerified:false,
  Preconditions:append([]string(nil),plan.Prerequisites...),
  CanInstall:false,CanUpgrade:false,CanChangeDNS:false,CanChangeTasks:false,
  Status:"NO_INSTALL_OR_DNS_CHANGE_AUTHORIZED",
 },nil
}

func main() {
 if len(os.Args)!=2||(os.Args[1]!="--review-only"&&os.Args[1]!="--review-under-protected-lock"){
  fmt.Fprintln(os.Stderr,"VOLVE setup preview: --review-only | --review-under-protected-lock (CI ONLY; NO INSTALL)")
  os.Exit(2)
 }
 ctx,cancel:=context.WithTimeout(context.Background(),125*time.Second)
 defer cancel()
 var report setupPreviewReport
 var err error
 if os.Args[1]=="--review-under-protected-lock"{
  report,err=inspectCIHostUnderProtectedMutexReadOnly(ctx)
 }else{
  report,err=inspectCIHostReadOnly(ctx)
 }
 if err!=nil{
  fmt.Fprintln(os.Stderr,"VOLVE setup review failed closed:",err)
  os.Exit(1)
 }
 if err:=json.NewEncoder(os.Stdout).Encode(report);err!=nil{
  fmt.Fprintln(os.Stderr,"VOLVE setup review JSON output failed:",err)
  os.Exit(1)
 }
}
