//go:build windows

package motorupdate

import (
 "context"
 "errors"
 "fmt"
)

// WindowsFreshSixOfSixReadOnlyEvidence is a complete, independent read-only
// Windows preflight snapshot: files, Task Scheduler, Win32_Service, adapter
// DNS, TCP/UDP port53 and protected original/recovery journal state.
// This NEVER authorizes a production switch, starts a DNS motor or writes
// any files, ACLs, network settings or tasks. A real installer must recheck
// under an exclusive elevated transaction lock immediately before any write.
type WindowsFreshSixOfSixReadOnlyEvidence struct {
 Host WindowsFreshFiveOfSixReadOnlyEvidence
 Recovery WindowsFreshRecoveryInventory
}

func InspectWindowsFreshSixOfSixReadOnly(
 ctx context.Context, existingInstallRoot, expectedCatalogExe, expectedCatalogArgs string,
 inspect WindowsFreshPartialHostInspectors, port53 WindowsFreshPort53Inspect,
 recoveryACL WindowsFreshRecoveryACLInspect,
)(WindowsFreshSixOfSixReadOnlyEvidence,error){
 var zero WindowsFreshSixOfSixReadOnlyEvidence
 if err:=ctx.Err();err!=nil{return zero,err}
 if recoveryACL==nil{return zero,errors.New("independent Windows recovery ACL inspector unavailable")}
 host,err:=InspectWindowsFreshFiveOfSixReadOnly(ctx,existingInstallRoot,expectedCatalogExe,expectedCatalogArgs,inspect,port53)
 if err!=nil{return zero,fmt.Errorf("Windows five-inventory preflight incomplete: %w",err)}
 recovery,err:=InspectWindowsFreshRecoveryReadOnly(ctx,existingInstallRoot,recoveryACL)
 if err!=nil{return zero,fmt.Errorf("legacy recovery state cannot be trusted: %w",err)}
 if err:=ctx.Err();err!=nil{return zero,err}
 e:=&host.Host.Host.Evidence
 if !e.InspectedAsAdministrator||!e.InspectedMotorFiles||!e.InspectedTaskScheduler||
  !e.InspectedServices||!e.InspectedDNSAdapters||!e.InspectedPort53Listeners {
  return zero,errors.New("some mandatory Windows preflight inventory is missing")
 }
 e.InspectedRecoveryState=true
 e.RecoveryArtifactsPresent=recovery.RecoveryArtifactsPresent
 e.RecoveryJournalPresent=recovery.RecoveryJournalPresent
 e.PendingRollbackPresent=recovery.PendingRollbackPresent
 return WindowsFreshSixOfSixReadOnlyEvidence{Host:host,Recovery:recovery},nil
}
