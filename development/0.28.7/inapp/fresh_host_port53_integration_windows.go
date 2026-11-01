//go:build windows

package motorupdate

import (
 "context"
 "errors"
 "fmt"
)

// WindowsFreshFiveOfSixReadOnlyEvidence extends the privilege/task/service/
// adapter/file census with an independent host-wide TCP+UDP port53 census.
// It does not inspect persistent recovery journals, and cannot enable install.
type WindowsFreshFiveOfSixReadOnlyEvidence struct {
 Host WindowsFreshFourOfSixReadOnlyEvidence
 Port53 WindowsFreshPort53Inventory
}

func InspectWindowsFreshFiveOfSixReadOnly(
 ctx context.Context, existingInstallRoot, expectedCatalogExe, expectedCatalogArgs string,
 inspectors WindowsFreshPartialHostInspectors, port53 WindowsFreshPort53Inspect,
) (WindowsFreshFiveOfSixReadOnlyEvidence,error) {
 var zero WindowsFreshFiveOfSixReadOnlyEvidence
 if err:=ctx.Err();err!=nil{return zero,err}
 if port53==nil{return zero,errors.New("missing Windows TCP/UDP port53 inspector")}
 host,err:=InspectWindowsFreshFourOfSixReadOnly(ctx,existingInstallRoot,expectedCatalogExe,expectedCatalogArgs,inspectors)
 if err!=nil{return zero,fmt.Errorf("four-of-six host census incomplete: %w",err)}
 scan,err:=InspectWindowsFreshPort53ReadOnly(ctx,port53)
 if err!=nil{return zero,fmt.Errorf("TCP/UDP port53 evidence incomplete: %w",err)}
 if err:=ctx.Err();err!=nil{return zero,err}
 e:=&host.Host.Evidence
 if !e.InspectedAsAdministrator || !e.InspectedMotorFiles || !e.InspectedTaskScheduler ||
  !e.InspectedServices || !e.InspectedDNSAdapters {
  return zero,errors.New("other five Windows conditions are not independently verified")
 }
 e.UDP53IPv4OwnerCount=scan.UDP53IPv4OwnerCount
 e.UDP53IPv6OwnerCount=scan.UDP53IPv6OwnerCount
 e.TCP53IPv4OwnerCount=scan.TCP53IPv4OwnerCount
 e.TCP53IPv6OwnerCount=scan.TCP53IPv6OwnerCount
 e.InspectedPort53Listeners=true
 // This does not inspect protected recovery journal, backup XML, rollback
 // transitions or pending watchdog tasks. Never set this flag by inference.
 e.InspectedRecoveryState=false
 return WindowsFreshFiveOfSixReadOnlyEvidence{Host:host,Port53:scan},nil
}
