//go:build windows

package uninstallguard

import (
    "context"
    "testing"
    "time"
)

// A signed receipt and all eight matching TEST files are deliberately not
// enough to claim a nonexistent SYSTEM task. No task is created or changed.
func TestNativeSignedOwnershipRequiresRealTaskInAdditionToMatchingFiles(t *testing.T){
    r,install,data:=buildFileFixture(t)
    r.InstallRoot=install
    r.DataRoot=data
    raw,sig,pub,_:=testSigned(t,r)
    ctx,cancel:=context.WithTimeout(context.Background(),70*time.Second)
    defer cancel()
    verdict,err:=AuditSignedInstalledOwnershipReadOnly(ctx,raw,sig,pub)
    if err==nil {
        t.Fatalf("a synthetic signed receipt without an installed task gained ownership: %+v",verdict)
    }
    if verdict.Schema!=0 || verdict.CanUninstall || verdict.CanChangeDNS ||
        verdict.CanDeleteTasks || verdict.CanDeleteFiles || verdict.CanStopMotor {
        t.Fatalf("partial ownership verification leaked a permissive report: %+v",verdict)
    }
}
