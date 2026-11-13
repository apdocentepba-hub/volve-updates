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
 Preconditions []string `json:"unmet_production_prerequisites"`
 CanInstall bool `json:"can_install"`
 CanUpgrade bool `json:"can_upgrade"`
 CanChangeDNS bool `json:"can_change_dns"`
 CanChangeTasks bool `json:"can_change_tasks"`
 Status string `json:"status"`
}

func inspectCIHostReadOnly(ctx context.Context) (setupPreviewReport,error) {
 var refused setupPreviewReport
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
 review,plan,err:=bridge.InspectAndPlanWindowsHostReadOnly(
  ctx,exe,ed25519.PublicKey(pub),cert,fileHash,root,
  motorupdate.DefaultWindowsMotorRouteInspectors(),
 )
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
  Preconditions:append([]string(nil),plan.Prerequisites...),
  CanInstall:false,CanUpgrade:false,CanChangeDNS:false,CanChangeTasks:false,
  Status:"NO_INSTALL_OR_DNS_CHANGE_AUTHORIZED",
 },nil
}

func main() {
 if len(os.Args)!=2||os.Args[1]!="--review-only"{
  fmt.Fprintln(os.Stderr,"VOLVE setup preview: --review-only (CI ONLY; NO INSTALL)")
  os.Exit(2)
 }
 ctx,cancel:=context.WithTimeout(context.Background(),125*time.Second)
 defer cancel()
 report,err:=inspectCIHostReadOnly(ctx)
 if err!=nil{
  fmt.Fprintln(os.Stderr,"VOLVE setup review failed closed:",err)
  os.Exit(1)
 }
 if err:=json.NewEncoder(os.Stdout).Encode(report);err!=nil{
  fmt.Fprintln(os.Stderr,"VOLVE setup review JSON output failed:",err)
  os.Exit(1)
 }
}
