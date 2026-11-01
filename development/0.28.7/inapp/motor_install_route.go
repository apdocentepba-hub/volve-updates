package motorupdate

// A read-only ROUTE classifier. It explains which verification flow to
// investigate, NEVER authorizes an install, motor switch or cleanup. In
// particular, browser-policy protection is outside this inventory, so a
// fresh DNS candidate does not mean the installed device is unprotected.
import (
 "context"
 "errors"
)

// MotorInstallRoute is a recommendation for the NEXT READ-ONLY verification,
// not a release authorization or a product version assertion.
type MotorInstallRoute string

const (
 MotorRouteUnverified MotorInstallRoute = "unverified-host-stop"
 MotorRouteFreshCandidate MotorInstallRoute = "fresh-dns-candidate-review-only"
 MotorRouteCatalogCandidate MotorInstallRoute = "catalog-only-dns-candidate-review-only"
 MotorRouteLegacyReview MotorInstallRoute = "legacy-motor-publisher-review-only"
 MotorRouteManagedReview MotorInstallRoute = "existing-managed-motor-signed-update-review-only"
 MotorRouteRecoveryReview MotorInstallRoute = "recovery-state-review-no-write"
 MotorRouteConflictingResidue MotorInstallRoute = "contradictory-installed-protection-no-write"
)

type MotorInstallRouteReport struct {
 Route MotorInstallRoute `json:"route"`
 Reason string `json:"reason"`
 InventoriesChecked int `json:"inventories_checked"`
 SignedUpgradeAuthorized bool `json:"signed_upgrade_authorized"`
 FreshInstallAuthorized bool `json:"fresh_install_authorized"`
 CanModifyDNS bool `json:"can_modify_dns"`
}

// ClassifyMotorInstallRouteReadOnly must be fed the exact Task Scheduler
// task-name output from the SAME six-observation census. It never guesses
// a legacy engine version from Centro version or executable filename.
func ClassifyMotorInstallRouteReadOnly(
 ctx context.Context,e FreshMotorInstallEvidence,observedUnknownTaskNames []string,
)(MotorInstallRouteReport,error){
 var zero MotorInstallRouteReport
 if err:=ctx.Err();err!=nil{return zero,err}
 report:=MotorInstallRouteReport{
  Route:MotorRouteUnverified,
  Reason:"Privileged six-inventory host evidence missing or inconsistent; do not install or change DNS.",
 }
 if !e.InspectedAsAdministrator || !e.InspectedMotorFiles ||
  !e.InspectedTaskScheduler || !e.InspectedServices ||
  !e.InspectedDNSAdapters || !e.InspectedPort53Listeners ||
  !e.InspectedRecoveryState {
  return report,nil
 }
 report.InventoriesChecked=6
 // The task inspector carries unknown tasks separately from a pinned,
 // independently verified catalog task. Synthetic task-name arrays must
 // never be allowed to invent or hide an extra task.
 if e.VOLVETaskCount<0||e.VOLVEServiceCount<0||
  e.UDP53IPv4OwnerCount<0||e.UDP53IPv6OwnerCount<0||
  e.TCP53IPv4OwnerCount<0||e.TCP53IPv6OwnerCount<0||
  len(observedUnknownTaskNames)>e.VOLVETaskCount {
  report.Reason="Invalid or contradictory Windows inventory counts."
  return report,nil
 }
 knownCatalog:=allowedFreshAuxiliaryTask(e.VerifiedCatalogTask)
 namedCatalogCount:=0
 if e.VerifiedCatalogTask!=nil{
  if !knownCatalog{
   // An unpinned catalog must NEVER hide an observed legacy DNS motor,
   // occupied local DNS listeners or extra scheduled tasks. The actual 0.28.6
   // host has all of those. It is a conflicting EXISTING install requiring
   // targeted identity review, not a candidate for a fresh installation.
   if e.LegacyExecutablePresent || e.VersionedMotorPresent ||
    e.InstalledEngineInventoryPresent || e.VOLVETaskCount>1 ||
    e.VOLVEServiceCount>0 || e.LocalIPv4DNSConfigured ||
    e.LocalIPv6DNSConfigured || e.UDP53IPv4OwnerCount>0 ||
    e.UDP53IPv6OwnerCount>0 || e.TCP53IPv4OwnerCount>0 ||
    e.TCP53IPv6OwnerCount>0 {
    report.Route=MotorRouteConflictingResidue
    report.Reason="Unverified catalog task coexists with installed DNS motor, additional VOLVE tasks or local DNS evidence. Preserve existing protections; identify tasks and port53 owner before signed migration."
    return report,nil
   }
   report.Reason="Catalog task exists but executable, owner or definition is not verified."
   return report,nil
  }
  namedCatalogCount=1
 }
 if len(observedUnknownTaskNames)+namedCatalogCount!=e.VOLVETaskCount {
  report.Reason="Task Scheduler count does not match independently observed task identities."
  return report,nil
 }
 if e.PendingRollbackPresent || e.RecoveryJournalPresent || e.RecoveryArtifactsPresent {
  report.Route=MotorRouteRecoveryReview
  report.Reason="An existing original backup or recovery journal must be audited, even if already terminal; no fresh install or cleanup."
  return report,nil
 }
 if e.VOLVEServiceCount>0{
  report.Route=MotorRouteConflictingResidue
  report.Reason="Installed or stopped VOLVE service prevents treating this host as a clean DNS installation."
  return report,nil
 }
 if e.LegacyExecutablePresent && (e.VersionedMotorPresent||e.InstalledEngineInventoryPresent){
  report.Route=MotorRouteConflictingResidue
  report.Reason="Mixed legacy and managed engine artifacts need identity and rollback reconciliation."
  return report,nil
 }
 if e.VersionedMotorPresent||e.InstalledEngineInventoryPresent{
  report.Route=MotorRouteManagedReview
  report.Reason="A managed or versioned motor is present; inspect its original signed manifest, receipt and running SYSTEM identity."
  return report,nil
 }
 if e.LegacyExecutablePresent {
  // Only an exact root task NAME and the legacy executable form a lead
  // for the publisher review. This is NEVER an attestation of task SID,
  // live PID, disk image, port ownership or historical engine version.
  if e.VOLVETaskCount==1 && !knownCatalog &&
   len(observedUnknownTaskNames)==1 &&
   observedUnknownTaskNames[0]=="\\VOLVE-DNS-SERVER-0270" {
   report.Route=MotorRouteLegacyReview
   report.Reason="Legacy executable and exact task name observed; still require signed editorial permit, matching live SYSTEM task/port53 and protected rollback."
   return report,nil
  }
  report.Route=MotorRouteConflictingResidue
  report.Reason="Legacy motor file exists without its exact task identity; never overwrite or silently restore DNS."
  return report,nil
 }
 if e.VOLVETaskCount>0 && !(e.VOLVETaskCount==1&&knownCatalog){
  report.Route=MotorRouteConflictingResidue
  report.Reason="A VOLVE task exists but has no separately verified associated engine or catalog identity."
  return report,nil
 }
 // Even with no named VOLVE engine, local DNS can be set to ::1 or a
 // different process can own UDP/TCP 53; both make fresh install unsafe.
 if e.LocalIPv4DNSConfigured||e.LocalIPv6DNSConfigured||
  e.UDP53IPv4OwnerCount>0||e.UDP53IPv6OwnerCount>0||
  e.TCP53IPv4OwnerCount>0||e.TCP53IPv6OwnerCount>0{
  report.Route=MotorRouteConflictingResidue
  report.Reason="Local DNS configuration or existing port53 process remains; preserve it pending an independent recovery audit."
  return report,nil
 }
 // Reuse the canonical policy, rather than duplicating eligibility logic.
 // Its success is only a preflight for consideration by a SEPARATE future
 // privileged installer, not a right to install.
 if err:=CheckFreshMotorInstallReadiness(ctx,e);err!=nil{
  report.Reason="Fresh-install readiness rejects this Windows evidence: "+err.Error()
  return report,nil
 }
 if e.VOLVETaskCount==1 {
  report.Route=MotorRouteCatalogCandidate
  report.Reason="Verified catalog task only, no observed DNS motor; separate signed fresh-motor and watchdog approvals still required."
 }else{
  report.Route=MotorRouteFreshCandidate
  report.Reason="No DNS motor observed in six Windows inventories; separate signed fresh-motor and watchdog approvals still required."
 }
 return report,nil
}

// This contract requires proof at every call site and refuses to return an
// authorization flag. Import errors is intentional to support a strict
// opt-in helper for future external consumers.
func RequireMotorRouteReviewOnly(report MotorInstallRouteReport) error {
 if report.CanModifyDNS||report.FreshInstallAuthorized||report.SignedUpgradeAuthorized {
  return errors.New("read-only motor route cannot carry installation authorization")
 }
 return nil
}
