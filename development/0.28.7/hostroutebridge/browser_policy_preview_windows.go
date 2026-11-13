//go:build windows

package hostroutebridge

// Browser policy registry census for a SIGNED, mutex-bound preinstallation
// inspection. It observes only numeric entry counts, not policy URLs or
// browser history. It cannot prove browser enforcement or authorize writes.
import (
 "context"
 "crypto/ed25519"
 "errors"
 "fmt"
 "reflect"

 motorupdate "volve-browser-protection/motorupdate"
)

func validateStableReadOnlyBrowserEvidence(before,after motorupdate.WindowsBrowserPolicyEvidence) error {
 if before.Schema!=1||after.Schema!=1||
  before.Component!="browser-policy-registry-read-only"||
  after.Component!="browser-policy-registry-read-only"||
  len(before.Records)!=3||len(after.Records)!=3||
  !before.NoRegistryValuesCollected||!after.NoRegistryValuesCollected||
  before.BrowserEnforcementVerified||after.BrowserEnforcementVerified||
  before.DNSMotorVerified||after.DNSMotorVerified {
  return errors.New("browser policy census incomplete or falsely claims protection")
 }
 // Count equality is NOT content equality: production still requires
 // separately sealed hashes of complete policy values + hosts/task backups.
 if !reflect.DeepEqual(before,after){
  return errors.New("browser policy registry counts changed during preinstallation review")
 }
 return nil
}

// InspectAndPlanWithBrowserCensusUnderProtectedLeaseReadOnly observes the
// three registry policy groups on both sides of the dual-signed Windows
// six-inventory census, all under the SAME OS-wide protected mutex.
// It returns only anonymous counts. No installation capability can result.
func InspectAndPlanWithBrowserCensusUnderProtectedLeaseReadOnly(
 ctx context.Context,
 signedEXE string,
 publisherPublicKey ed25519.PublicKey,
 windowsSignerCertSHA256, signedEXESHA256, installedRoot string,
 readers motorupdate.WindowsMotorRouteInspectors,
 policyInspect motorupdate.WindowsBrowserPolicyInspect,
) (Review,InstallerPlanReadOnly,motorupdate.WindowsBrowserPolicyEvidence,error) {
 var emptyReview Review
 var emptyPlan InstallerPlanReadOnly
 var emptyPolicy motorupdate.WindowsBrowserPolicyEvidence
 if ctx==nil{return emptyReview,emptyPlan,emptyPolicy,errors.New("missing Windows inspection context")}
 if err:=ctx.Err();err!=nil{return emptyReview,emptyPlan,emptyPolicy,err}
 if policyInspect==nil{return emptyReview,emptyPlan,emptyPolicy,errors.New("fixed read-only browser policy inspector required")}
 release,err:=motorupdate.AcquireProtectedResidentTransitionLease(ctx)
 if err!=nil{return emptyReview,emptyPlan,emptyPolicy,fmt.Errorf("protected SYSTEM/updater mutex denied: %w",err)}
 if release==nil{return emptyReview,emptyPlan,emptyPolicy,errors.New("protected OS mutex missing release callback")}
 defer release()

 before,err:=motorupdate.InspectWindowsBrowserPoliciesReadOnly(ctx,policyInspect)
 if err!=nil{return emptyReview,emptyPlan,emptyPolicy,fmt.Errorf("browser census before signed review failed: %w",err)}
 review,plan,err:=InspectAndPlanWindowsHostReadOnly(
  ctx,signedEXE,publisherPublicKey,windowsSignerCertSHA256,
  signedEXESHA256,installedRoot,readers,
 )
 if err!=nil{return emptyReview,emptyPlan,emptyPolicy,err}
 after,err:=motorupdate.InspectWindowsBrowserPoliciesReadOnly(ctx,policyInspect)
 if err!=nil{return emptyReview,emptyPlan,emptyPolicy,fmt.Errorf("browser census after signed review failed: %w",err)}
 if err:=validateStableReadOnlyBrowserEvidence(before,after);err!=nil{return emptyReview,emptyPlan,emptyPolicy,err}
 if review.InstallAuthorized||review.UpgradeAuthorized||review.CanModifyDNS||
  plan.CanInstall||plan.CanUpgrade||plan.CanChangeDNS||plan.CanChangeTasks||
  plan.Disposition!="READ_ONLY_PLAN_NOT_AN_INSTALLATION_PERMIT" {
  return emptyReview,emptyPlan,emptyPolicy,errors.New("preinstallation browser census unexpectedly authorized any write")
 }
 if err:=ctx.Err();err!=nil{return emptyReview,emptyPlan,emptyPolicy,err}
 return review,plan,after,nil
}
