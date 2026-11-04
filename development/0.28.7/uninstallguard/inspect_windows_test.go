//go:build windows

package uninstallguard

import (
    "context"
    "testing"
    "time"
)

// This exercises the real Windows read-only census, not a simulation.
func TestNativeWindowsUninstallReviewNeverGrantsDestructiveRights(t *testing.T) {
    ctx,cancel:=context.WithTimeout(context.Background(),65*time.Second)
    defer cancel()
    e,err:=InspectWindowsReadOnly(ctx)
    if err!=nil{t.Fatal(err)}
    if !e.Elevated{t.Fatal("CI runner must be elevated for a complete census")}
    plan,err:=Review(e)
    if err!=nil{t.Fatal(err)}
    if plan.CanUninstall||plan.CanStopMotor||plan.CanChangeDNS||plan.CanDeleteTasks||plan.CanRemoveBrowserPolicies||plan.CanDeleteFiles{
        t.Fatalf("read-only Windows inspection authorized destructive operation: %+v",plan)
    }
}
