//go:build windows

package hostroutebridge

// Browser policy registry census for a SIGNED, mutex-bound preinstallation
// inspection. It fingerprints all registry values locally and returns only entry counts
// plus hashes; raw policy values and browser history are never exported.
// A registry key or stable digest cannot prove browser enforcement.
import (
 "context"
 "crypto/ed25519"
 "encoding/hex"
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
  !before.NoRegistryValuesExported||!after.NoRegistryValuesExported||
  before.BrowserEnforcementVerified||after.BrowserEnforcementVerified||
  before.DNSMotorVerified||after.DNSMotorVerified {
  return errors.New("browser policy census incomplete or falsely claims protection")
 }
 // Independently validate each browser identity and SHA-256 fingerprint
 // before comparing. Counts alone would miss value edits that preserve slots.
 for _,snapshot:=range []motorupdate.WindowsBrowserPolicyEvidence{before,after}{
  seen:=map[string]bool{}
  for _,record:=range snapshot.Records{
   if record.Name!="chrome"&&record.Name!="edge"&&record.Name!="firefox"{
    return errors.New("unexpected browser policy identity")
   }
   if seen[record.Name]{return errors.New("duplicate browser policy identity")}
   seen[record.Name]=true
   digest,err:=hex.DecodeString(record.ContentSHA256)
   if err!=nil||len(digest)!=32{return errors.New("browser policy content fingerprint malformed")}
   if record.NumberedEntries<0||record.InvalidEntries<0||record.UnexpectedEntries<0{
    return errors.New("negative browser policy inventory count")
   }
  }
  if len(seen)!=3{return errors.New("incomplete browser policy identity set")}
 }
 // Full-content fingerprints catch value edits even when entry counts stay
 // equal. They are not a durable backup or restore source.
 if !reflect.DeepEqual(before,after){
  return errors.New("browser policy registry content changed during preinstallation review")
 }
 return nil
}

// InspectAndPlanWithBrowserCensusUnderProtectedLeaseReadOnly observes hosts,
// browser policies and catalog-task identity before/after the signed six-way
// Windows census, all under the SAME OS-wide protected mutex.
// It returns only counts and SHA-256 fingerprints. No raw values
// are exported and no installation capability can result.
func InspectAndPlanWithBrowserCensusUnderProtectedLeaseReadOnly(
 ctx context.Context,
 signedEXE string,
 publisherPublicKey ed25519.PublicKey,
 windowsSignerCertSHA256, signedEXESHA256, installedRoot string,
 readers motorupdate.WindowsMotorRouteInspectors,
 policyInspect motorupdate.WindowsBrowserPolicyInspect,
) (Review,InstallerPlanReadOnly,motorupdate.WindowsBrowserPolicyEvidence,motorupdate.ProtectionSnapshot,error) {
 snapshotInspectors:=motorupdate.WindowsProtectionSnapshotInspectors{
  Hosts:motorupdate.DefaultWindowsHostsFileInspect,
  Browser:policyInspect,
  Tasks:readers.Host.Tasks,
  DNS:motorupdate.DefaultWindowsReadOnlyPowerShell,
 }
 return InspectAndPlanWithProtectionSnapshotUnderProtectedLeaseReadOnly(
  ctx,signedEXE,publisherPublicKey,windowsSignerCertSHA256,signedEXESHA256,
  installedRoot,readers,snapshotInspectors,
 )
}

// InspectAndPlanWithProtectionSnapshotUnderProtectedLeaseReadOnly is the
// injectable, still non-authorizing transaction review. Production supplies
// native readers; tests can supply deterministic DNS evidence while still
// exercising the real Win32 mutex and live Windows host census.
func InspectAndPlanWithProtectionSnapshotUnderProtectedLeaseReadOnly(
 ctx context.Context,
 signedEXE string,
 publisherPublicKey ed25519.PublicKey,
 windowsSignerCertSHA256, signedEXESHA256, installedRoot string,
 readers motorupdate.WindowsMotorRouteInspectors,
 snapshotInspectors motorupdate.WindowsProtectionSnapshotInspectors,
) (Review,InstallerPlanReadOnly,motorupdate.WindowsBrowserPolicyEvidence,motorupdate.ProtectionSnapshot,error) {
 return inspectAndPlanWithSnapshotAndExtraReview(ctx,signedEXE,publisherPublicKey,windowsSignerCertSHA256,signedEXESHA256,installedRoot,readers,snapshotInspectors,nil)
}

// This fixed native review includes two DNS override count observations under
// the same lease as the signed package and original protection baseline.
// Identical counts do not prove identical values, active DoH use or restoration.
func InspectAndPlanWithDNSOverrideCensusUnderProtectedLeaseReadOnly(
 ctx context.Context,signedEXE string,publisherPublicKey ed25519.PublicKey,
 windowsSignerCertSHA256,signedEXESHA256,installedRoot string,
 readers motorupdate.WindowsMotorRouteInspectors,
)(Review,InstallerPlanReadOnly,motorupdate.WindowsBrowserPolicyEvidence,motorupdate.ProtectionSnapshot,motorupdate.WindowsDNSOverrideCensus,error){
 var census motorupdate.WindowsDNSOverrideCensus
 calls:=0
 observe:=func(c context.Context)error{
  got,err:=motorupdate.InspectWindowsDNSOverrideCensusReadOnly(c,motorupdate.DefaultWindowsReadOnlyPowerShell)
  if err!=nil{return err}
  if calls==0{census=got}else if calls!=1||got!=census{return errors.New("DNS override counts changed during protected review")}
  calls++
  return nil
 }
 snapshotInspectors:=motorupdate.WindowsProtectionSnapshotInspectors{
  Hosts:motorupdate.DefaultWindowsHostsFileInspect,
  Browser:motorupdate.DefaultWindowsBrowserPolicyInspect,
  Tasks:readers.Host.Tasks,
  DNS:motorupdate.DefaultWindowsReadOnlyPowerShell,
 }
 review,plan,browser,snapshot,err:=inspectAndPlanWithSnapshotAndExtraReview(ctx,signedEXE,publisherPublicKey,windowsSignerCertSHA256,signedEXESHA256,installedRoot,readers,snapshotInspectors,observe)
 if err!=nil{return Review{},InstallerPlanReadOnly{},motorupdate.WindowsBrowserPolicyEvidence{},motorupdate.ProtectionSnapshot{},motorupdate.WindowsDNSOverrideCensus{},err}
 if calls!=2{return Review{},InstallerPlanReadOnly{},motorupdate.WindowsBrowserPolicyEvidence{},motorupdate.ProtectionSnapshot{},motorupdate.WindowsDNSOverrideCensus{},errors.New("protected DNS override census incomplete")}
 return review,plan,browser,snapshot,census,nil
}

func inspectAndPlanWithSnapshotAndExtraReview(
 ctx context.Context,signedEXE string,publisherPublicKey ed25519.PublicKey,
 windowsSignerCertSHA256,signedEXESHA256,installedRoot string,
 readers motorupdate.WindowsMotorRouteInspectors,
 snapshotInspectors motorupdate.WindowsProtectionSnapshotInspectors,
 extraReadOnlyReview func(context.Context)error,
)(Review,InstallerPlanReadOnly,motorupdate.WindowsBrowserPolicyEvidence,motorupdate.ProtectionSnapshot,error){
 var emptyReview Review
 var emptyPlan InstallerPlanReadOnly
 var emptyPolicy motorupdate.WindowsBrowserPolicyEvidence
 var emptySnapshot motorupdate.ProtectionSnapshot
 if ctx==nil{return emptyReview,emptyPlan,emptyPolicy,emptySnapshot,errors.New("missing Windows inspection context")}
 if err:=ctx.Err();err!=nil{return emptyReview,emptyPlan,emptyPolicy,emptySnapshot,err}
 if snapshotInspectors.Browser==nil{return emptyReview,emptyPlan,emptyPolicy,emptySnapshot,errors.New("fixed read-only browser policy inspector required")}
 release,err:=acquireReviewLease(ctx,motorupdate.AcquireProtectedResidentTransitionLease)
 if err!=nil{return emptyReview,emptyPlan,emptyPolicy,emptySnapshot,fmt.Errorf("protected SYSTEM/updater mutex denied: %w",err)}
 defer release()
 if extraReadOnlyReview!=nil{
  if err:=extraReadOnlyReview(ctx);err!=nil{return emptyReview,emptyPlan,emptyPolicy,emptySnapshot,fmt.Errorf("additional protected census before review failed: %w",err)}
 }

 beforeSnapshot,beforeBrowser,err:=motorupdate.InspectWindowsProtectionSnapshotReadOnly(
  ctx,"","",snapshotInspectors,
 )
 if err!=nil{return emptyReview,emptyPlan,emptyPolicy,emptySnapshot,fmt.Errorf("complete protection baseline before signed review failed: %w",err)}
 if err:=ctx.Err();err!=nil{return emptyReview,emptyPlan,emptyPolicy,emptySnapshot,err}
 review,plan,err:=InspectAndPlanWindowsHostReadOnly(
  ctx,signedEXE,publisherPublicKey,windowsSignerCertSHA256,
  signedEXESHA256,installedRoot,readers,
 )
 if err!=nil{return emptyReview,emptyPlan,emptyPolicy,emptySnapshot,err}
 if err:=ctx.Err();err!=nil{return emptyReview,emptyPlan,emptyPolicy,emptySnapshot,err}
 afterSnapshot,afterBrowser,err:=motorupdate.InspectWindowsProtectionSnapshotReadOnly(
  ctx,"","",snapshotInspectors,
 )
 if err!=nil{return emptyReview,emptyPlan,emptyPolicy,emptySnapshot,fmt.Errorf("complete protection baseline after signed review failed: %w",err)}
 if err:=validateStableReadOnlyBrowserEvidence(beforeBrowser,afterBrowser);err!=nil{
  return emptyReview,emptyPlan,emptyPolicy,emptySnapshot,err
 }
 if err:=motorupdate.VerifyPartialProtectionPreserved(beforeSnapshot,afterSnapshot);err!=nil{
  return emptyReview,emptyPlan,emptyPolicy,emptySnapshot,fmt.Errorf("existing hosts/browser/catalog protection changed during review: %w",err)
 }
 if review.InstallAuthorized||review.UpgradeAuthorized||review.CanModifyDNS||
  plan.CanInstall||plan.CanUpgrade||plan.CanChangeDNS||plan.CanChangeTasks||
  plan.Disposition!="READ_ONLY_PLAN_NOT_AN_INSTALLATION_PERMIT" {
  return emptyReview,emptyPlan,emptyPolicy,emptySnapshot,errors.New("preinstallation browser census unexpectedly authorized any write")
 }
 if extraReadOnlyReview!=nil{
  if err:=extraReadOnlyReview(ctx);err!=nil{return emptyReview,emptyPlan,emptyPolicy,emptySnapshot,fmt.Errorf("additional protected census after review failed: %w",err)}
 }
 if err:=ctx.Err();err!=nil{return emptyReview,emptyPlan,emptyPolicy,emptySnapshot,err}
 return review,plan,afterBrowser,afterSnapshot,nil
}
