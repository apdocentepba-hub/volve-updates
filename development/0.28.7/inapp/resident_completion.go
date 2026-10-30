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
func ConfirmResidentRecoveryOutcome(
 ctx context.Context, dir, outcome string,
 seal, protect func(string)error, checks ResidentCompletionChecks,
) error {
 if outcome!="committed" && outcome!="restored" {
  return errors.New("unknown resident transaction outcome")
 }
 if checks==nil || seal==nil || protect==nil {
  return errors.New("resident outcome has no trusted health checks or ACL services")
 }
 if err:=ctx.Err();err!=nil{return err}
 current,err:=InspectResidentRecoveryJournal(ctx,dir,protect)
 if err!=nil{return fmt.Errorf("unverifiable resident transaction: %w",err)}
 if current.Status!="recovery-required" {
  return fmt.Errorf("resident transaction not pending: %s",current.Status)
 }
 if err:=checks.VerifyRunningIdentity(ctx,current.Intent,outcome);err!=nil {
  return fmt.Errorf("running SYSTEM motor identity unverified: %w",err)
 }
 if err:=ctx.Err();err!=nil{return err}
 if err:=checks.ProbeLocalDNS(ctx);err!=nil {
  return fmt.Errorf("local DNS not recovered: %w",err)
 }
 if err:=ctx.Err();err!=nil{return err}
 if err:=checks.ProbeConnectivity(ctx);err!=nil {
  return fmt.Errorf("Internet/connectivity not recovered: %w",err)
 }
 if err:=ctx.Err();err!=nil{return err}
 if err:=checks.VerifyRunningIdentity(ctx,current.Intent,outcome);err!=nil {
  return fmt.Errorf("running SYSTEM motor changed during health probes: %w",err)
 }
 latest,err:=InspectResidentRecoveryJournal(ctx,dir,protect)
 if err!=nil{return fmt.Errorf("transaction changed during health probes: %w",err)}
 if latest.Status!="recovery-required" || latest.Intent!=current.Intent {
  return errors.New("recovery journal changed during health verification")
 }
 return FinishResidentRecoveryIntent(ctx,dir,outcome,seal,protect)
}
