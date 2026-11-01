//go:build windows

package motorupdate

import (
 "context"
 "errors"
 "fmt"
)

// WindowsFreshFourOfSixReadOnlyEvidence preserves the native task/service/DNS
// snapshot and then inventories the previously pinned installed motor root.
// It is still PARTIAL evidence: port 53 and recovery state remain unknown.
// This is NOT an installation operation or an authorization for a switch.
type WindowsFreshFourOfSixReadOnlyEvidence struct {
 Host WindowsFreshPartialHostEvidence
 Files WindowsFreshMotorFileInventory
}

// InspectWindowsFreshFourOfSixReadOnly requires the existing installed root
// resolved by the trusted caller, NOT a release-provided path. It returns
// only after independent token, task, service, DNS and filesystem reads.
func InspectWindowsFreshFourOfSixReadOnly(
 ctx context.Context, existingInstallRoot, expectedCatalogExe, expectedCatalogArgs string,
 inspectors WindowsFreshPartialHostInspectors,
) (WindowsFreshFourOfSixReadOnlyEvidence,error) {
 var zero WindowsFreshFourOfSixReadOnlyEvidence
 if err:=ctx.Err();err!=nil{return zero,err}
 if existingInstallRoot=="" {return zero,errors.New("installed root not verified")}
 host,err:=InspectWindowsFreshPartialHostReadOnly(ctx,expectedCatalogExe,expectedCatalogArgs,inspectors)
 if err!=nil{return zero,fmt.Errorf("partial Windows host census incomplete: %w",err)}
 if !host.Evidence.InspectedAsAdministrator || !host.Evidence.InspectedTaskScheduler ||
  !host.Evidence.InspectedServices || !host.Evidence.InspectedDNSAdapters {
  return zero,errors.New("Windows task/service/DNS evidence not independently complete")
 }
 files,err:=InspectWindowsFreshMotorFilesReadOnly(ctx,existingInstallRoot)
 if err!=nil{return zero,fmt.Errorf("installed motor file evidence incomplete: %w",err)}
 if err:=ctx.Err();err!=nil{return zero,err}
 host.Evidence.InspectedMotorFiles=true
 host.Evidence.LegacyExecutablePresent=files.LegacyExecutablePresent
 host.Evidence.VersionedMotorPresent=files.VersionedMotorPresent
 host.Evidence.InstalledEngineInventoryPresent=files.InstalledEngineInventoryPresent
 // Never mark unobserved port 53 or rollback journal as inspected.
 host.Evidence.InspectedPort53Listeners=false
 host.Evidence.InspectedRecoveryState=false
 return WindowsFreshFourOfSixReadOnlyEvidence{Host:host,Files:files},nil
}
