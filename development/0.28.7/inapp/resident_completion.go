package motorupdate

// Signed resident updates must NEVER write a "committed" or "restored"
// recovery receipt merely because Task Scheduler accepted an action or a
// PowerShell command returned success. The future Windows driver supplies
// independent checks of the exact task+executable identity and both DNS and
// external connectivity, not UI state or a simulated acknowledgement.
import (
 "context"
 "errors"
 "fmt"
)

// ResidentCompletionChecks is deliberately a narrow OS-specific contract.
// VerifyRunningIdentity MUST inspect the real SYSTEM task and verify the
// expected signed executable for "committed", or the backed-up original for
// "restored". ProbeLocalDNS and ProbeConnectivity MUST independently exercise
// the actual, running network path. This package does not implement those
// Windows checks and must not be wired to the production updater yet.
type ResidentCompletionChecks interface {
 VerifyRunningIdentity(context.Context, ResidentRecoveryIntent, string) error
 ProbeLocalDNS(context.Context) error
 ProbeConnectivity(context.Context) error
}

// ConfirmResidentRecoveryOutcome is an anti-false-success gate. A pending
// journal remains recoverable if any identity/DNS/Internet check fails.
// Two identity checks bracket both probes to reduce false confirmation if
// the live SYSTEM task changes in the middle of health assessment.
// Finalization is create-only: a second terminal receipt can never overwrite
// a prior decision. Actual reboot-resume safety still requires a persistent
// independent SYSTEM watchdog that is not implemented here.
// AuditResidentRecoveryOutcome is an independent READ-ONLY decision. It uses
// exactly the same health gates as the terminal receipt writer but never
// changes the journal. Even an all-green audit is NOT permission to switch a
// real DNS motor: the publisher-signed permit, boot-persistent watchdog and
// independent Windows switch controller remain separately required.
func AuditResidentRecoveryOutcome(
 ctx context.Context, dir, outcome string,
 protect func(string)error, checks ResidentCompletionChecks,
) (ResidentRecoveryIntent,error) {
 var empty ResidentRecoveryIntent
 if outcome!="committed" && outcome!="restored" {
  return empty,errors.New("unknown resident transaction outcome")
 }
 if checks==nil || protect==nil {
  return empty,errors.New("resident outcome has no trusted health checks or ACL services")
 }
 if err:=ctx.Err();err!=nil{return empty,err}
 current,err:=InspectResidentRecoveryJournal(ctx,dir,protect)
 if err!=nil{return empty,fmt.Errorf("unverifiable resident transaction: %w",err)}
 if current.Status!="recovery-required" {
  return empty,fmt.Errorf("resident transaction not pending: %s",current.Status)
 }
 if err:=checks.VerifyRunningIdentity(ctx,current.Intent,outcome);err!=nil {
  return empty,fmt.Errorf("running SYSTEM motor identity unverified: %w",err)
 }
 if err:=ctx.Err();err!=nil{return empty,err}
 if err:=checks.ProbeLocalDNS(ctx);err!=nil {
  return empty,fmt.Errorf("local DNS not recovered: %w",err)
 }
 if err:=ctx.Err();err!=nil{return empty,err}
 if err:=checks.ProbeConnectivity(ctx);err!=nil {
  return empty,fmt.Errorf("Internet/connectivity not recovered: %w",err)
 }
 if err:=ctx.Err();err!=nil{return empty,err}
 if err:=checks.VerifyRunningIdentity(ctx,current.Intent,outcome);err!=nil {
  return empty,fmt.Errorf("running SYSTEM motor changed during health probes: %w",err)
 }
 latest,err:=InspectResidentRecoveryJournal(ctx,dir,protect)
 if err!=nil{return empty,fmt.Errorf("transaction changed during health probes: %w",err)}
 if latest.Status!="recovery-required" || latest.Intent!=current.Intent {
  return empty,errors.New("recovery journal changed during health verification")
 }
 return current.Intent,nil
}

// ConfirmResidentRecoveryOutcome invokes the identical independent audit and
// only then creates a terminal recovery receipt, never overwriting an old one.
// The terminal writer must still run under a trusted persistent SYSTEM
// controller. This function is not directly exposed to the installed panel.
func ConfirmResidentRecoveryOutcome(
 ctx context.Context, dir, outcome string,
 seal, protect func(string)error, checks ResidentCompletionChecks,
) error {
 if seal==nil {
  return errors.New("resident outcome has no trusted health checks or ACL services")
 }
 if _,err:=AuditResidentRecoveryOutcome(ctx,dir,outcome,protect,checks);err!=nil {
  return err
 }
 return FinishResidentRecoveryIntent(ctx,dir,outcome,seal,protect)
}
