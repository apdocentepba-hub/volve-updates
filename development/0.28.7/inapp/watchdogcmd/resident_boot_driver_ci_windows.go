//go:build windows

package main

// Explicitly isolated Windows adapter from the shared boot-recovery policy to
// the existing resident CI-task restoration function. It has NO production
// CLI, publisher migration authorization, or access to the real VOLVÉ task.
// It MUST NOT be substituted for a production SYSTEM recovery driver.
import (
 "context"
 "errors"
 "fmt"
 "path/filepath"
 "strings"

 "volve-browser-protection/motorupdate"
)

type residentCIBootDriver struct {
 root string
 disposableTask string
 runner func(context.Context,string)(string,error)
}

func newResidentCIBootDriver(root,task string,
 runner func(context.Context,string)(string,error)) (*residentCIBootDriver,error) {
 if !filepath.IsAbs(root) || !pilotTaskPattern.MatchString(task) || runner==nil {
  return nil,errors.New("boot recovery driver limited to a disposable Windows CI task")
 }
 return &residentCIBootDriver{root:root,disposableTask:task,runner:runner},nil
}

func(d *residentCIBootDriver) AcquireExclusive(ctx context.Context)(func(),error){
 if d==nil || !pilotTaskPattern.MatchString(d.disposableTask){return nil,errors.New("unsafe pilot task identity")}
 suffix:=strings.TrimPrefix(d.disposableTask,"VOLVE-CI-ManagedMotor-")
 return acquireCIBootMutex(ctx,"VOLVE-CI-BootLock-"+suffix)
}

func(d *residentCIBootDriver) VerifySealedOriginal(ctx context.Context,
 intent motorupdate.ResidentRecoveryIntent)error {
 if d==nil{return errors.New("missing CI boot driver")}
 // This executes AFTER a switch/crash, so the active old executable may
 // legitimately be missing. Only the sealed fallback and pending journal
 // can establish the original identity at this stage.
 proof,err:=auditPostSwitchResidentRecovery(ctx,d.root)
 if err!=nil{return err}
 if proof.LegacySHA256!=intent.LegacySHA256 ||
  proof.TaskXMLSHA256!=intent.TaskXMLSHA256 ||
  proof.TargetSHA256!=intent.TargetSHA256 ||
  proof.TargetVersion!=intent.TargetVersion ||
  proof.IntentNonce!=intent.Nonce {
  return errors.New("CI boot driver and immutable journal identify different original/candidate")
 }
 return nil
}

func(d *residentCIBootDriver) RestoreOriginal(ctx context.Context,
 intent motorupdate.ResidentRecoveryIntent)error {
 if d==nil{return errors.New("missing CI boot driver")}
 if err:=d.VerifySealedOriginal(ctx,intent);err!=nil{
  return fmt.Errorf("original motor changed before independent restoration: %w",err)
 }
 // The policy already owns the OS-level mutex for the entire transaction.
 // Do NOT call restoreMissingOriginalAndDisposableTaskCILab, which would
 // acquire the same lock again. First recover the missing original bytes
 // without clobbering any DIFFERENT live executable. Then import only the
 // exact original disposable SYSTEM task under the existing lock.
 // No product task can pass these CI-name and hosted-runner allowlists.
 if err:=restoreMissingLegacyExecutableCILab(ctx,d.root,d.disposableTask);err!=nil {
  return fmt.Errorf("CI-only protected original executable restore refused: %w",err)
 }
 return restoreResidentPilotSYSTEMTaskWithRunner(ctx,d.root,d.disposableTask,d.runner)
}
