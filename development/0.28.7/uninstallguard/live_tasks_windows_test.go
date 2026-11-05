//go:build windows

package uninstallguard

import (
    "context"
    "testing"
    "time"
)

// Run on the guarded GitHub Windows runner, where the workflow first verifies
// that no VOLVE tasks exist. No task is registered, stopped or deleted.
func TestNativeWindowsLiveScheduledTaskCensusCannotClaimSyntheticInstallation(t *testing.T){
    ctx,cancel:=context.WithTimeout(context.Background(),55*time.Second)
    defer cancel()
    observed,err:=liveWindowsVolveTasks(ctx)
    if err!=nil{t.Fatalf("native read-only scheduled task inventory failed: %v",err)}
    if len(observed)!=0{
        t.Fatalf("protected/nonempty VOLVE task inventory in CI runner: %d",len(observed))
    }
    r,synthetic:=signedTaskFixture()
    _,err=auditReceiptTasksAgainstObservation(ctx,r,observed)
    if err==nil{
        t.Fatalf("missing real Task Scheduler object matched fake signed task: %q",synthetic.Name)
    }
}
