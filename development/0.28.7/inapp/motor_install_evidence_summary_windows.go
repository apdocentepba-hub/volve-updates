//go:build windows

package motorupdate

// Privacy-preserving details from the SAME privileged six-way inventory
// used to classify a Windows VOLVE install. Zero hostname, IP address,
// executable path, task action, URL-block value or sensitive registry data
// escapes this report. No second scan / modification is performed.
import (
 "context"
 "errors"
)

type WindowsMotorRouteSummary struct {
 InventoriesObserved int `json:"inventories_observed"`
 VOLVETasks int `json:"volve_tasks"`
 CatalogTaskSeen bool `json:"catalog_task_seen"`
 CatalogTaskPublisherPinned bool `json:"catalog_task_publisher_pinned"`
 OtherTaskCount int `json:"other_task_count"`
 VOLVEServices int `json:"volve_services"`
 LegacyDNSMotorFileSeen bool `json:"legacy_dns_motor_file_seen"`
 VersionedDNSMotorFileSeen bool `json:"versioned_dns_motor_file_seen"`
 InstalledEngineInventorySeen bool `json:"installed_engine_inventory_seen"`
 LocalDNSIPv4Seen bool `json:"local_dns_ipv4_seen"`
 LocalDNSIPv6Seen bool `json:"local_dns_ipv6_seen"`
 UDP53IPv4Listeners int `json:"udp53_ipv4_listeners"`
 UDP53IPv6Listeners int `json:"udp53_ipv6_listeners"`
 TCP53IPv4Listeners int `json:"tcp53_ipv4_listeners"`
 TCP53IPv6Listeners int `json:"tcp53_ipv6_listeners"`
 RecoveryArtifactsSeen bool `json:"recovery_artifacts_seen"`
 RecoveryJournalSeen bool `json:"recovery_journal_seen"`
 PendingRollbackSeen bool `json:"pending_rollback_seen"`
 SignedUpgradeAuthorized bool `json:"signed_upgrade_authorized"`
 CanModifyDNS bool `json:"can_modify_dns"`
}

type WindowsMotorRouteDetails struct {
 Decision MotorInstallRouteReport `json:"decision"`
 Summary WindowsMotorRouteSummary `json:"summary"`
}

// InspectWindowsMotorRouteWithSummaryReadOnly has the same no-write and
// fail-closed contract as InspectWindowsMotorRouteReadOnly, but retains a
// sanitized snapshot when catalog task identity cannot be publisher-pinned.
// No filename or service status here grants ability to install or migrate.
func InspectWindowsMotorRouteWithSummaryReadOnly(
 ctx context.Context,trustedInstalledRoot,expectedCatalogExe,expectedCatalogArgs string,
 readers WindowsMotorRouteInspectors,
)(WindowsMotorRouteDetails,error){
 var zero WindowsMotorRouteDetails
 if err:=ctx.Err();err!=nil{return zero,err}
 if trustedInstalledRoot==""||readers.Port53==nil||readers.RecoveryACL==nil{
  return zero,errors.New("trusted root and all six privileged Windows inventories required")
 }
 census,err:=InspectWindowsFreshSixOfSixReadOnly(ctx,trustedInstalledRoot,
  expectedCatalogExe,expectedCatalogArgs,readers.Host,readers.Port53,readers.RecoveryACL)
 if err!=nil{return zero,err}
 e:=census.Host.Host.Host.Evidence
 otherTasks:=census.Host.Host.Host.TaskNames
 route,err:=ClassifyMotorInstallRouteReadOnly(ctx,e,otherTasks)
 if err!=nil{return zero,err}
 if err:=RequireMotorRouteReviewOnly(route);err!=nil{return zero,err}
 if route.InventoriesChecked!=6{return zero,errors.New("incomplete six-way Windows observation")}
 if e.VOLVETaskCount<0 || e.VOLVEServiceCount<0 || len(otherTasks)>e.VOLVETaskCount{
  return zero,errors.New("ambiguous observed Windows task inventory")
 }
 seenCatalog:=e.VerifiedCatalogTask!=nil
 counts:=WindowsMotorRouteSummary{
  InventoriesObserved:6,
  VOLVETasks:e.VOLVETaskCount,
  CatalogTaskSeen:seenCatalog,
  CatalogTaskPublisherPinned:allowedFreshAuxiliaryTask(e.VerifiedCatalogTask),
  OtherTaskCount:len(otherTasks),
  VOLVEServices:e.VOLVEServiceCount,
  LegacyDNSMotorFileSeen:e.LegacyExecutablePresent,
  VersionedDNSMotorFileSeen:e.VersionedMotorPresent,
  InstalledEngineInventorySeen:e.InstalledEngineInventoryPresent,
  LocalDNSIPv4Seen:e.LocalIPv4DNSConfigured,
  LocalDNSIPv6Seen:e.LocalIPv6DNSConfigured,
  UDP53IPv4Listeners:e.UDP53IPv4OwnerCount,
  UDP53IPv6Listeners:e.UDP53IPv6OwnerCount,
  TCP53IPv4Listeners:e.TCP53IPv4OwnerCount,
  TCP53IPv6Listeners:e.TCP53IPv6OwnerCount,
  RecoveryArtifactsSeen:e.RecoveryArtifactsPresent,
  RecoveryJournalSeen:e.RecoveryJournalPresent,
  PendingRollbackSeen:e.PendingRollbackPresent,
 }
 if counts.UDP53IPv4Listeners<0||counts.UDP53IPv6Listeners<0||
  counts.TCP53IPv4Listeners<0||counts.TCP53IPv6Listeners<0 {
  return zero,errors.New("invalid Windows DNS port ownership counts")
 }
 if err:=ctx.Err();err!=nil{return zero,err}
 return WindowsMotorRouteDetails{Decision:route,Summary:counts},nil
}
