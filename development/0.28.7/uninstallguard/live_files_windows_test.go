//go:build windows

package uninstallguard

import (
    "context"
    "os"
    "path/filepath"
    "testing"
)

// A real native Windows filesystem test: uses only t.TempDir() and private
// synthetic signed fixtures. No VOLVE tasks, DNS or browser settings change.
func TestWindowsNativeSignedReceiptAndEightDiskFilesNoMutations(t *testing.T){
    r,install,data:=buildFileFixture(t)
    r.InstallRoot=install
    r.DataRoot=data
    raw,sig,pub,_:=testSigned(t,r)
    report,err:=AuditSignedInstalledFilesReadOnly(context.Background(),raw,sig,pub)
    if err!=nil{t.Fatalf("native signed disk audit refused authentic fixture: %v",err)}
    if report.CheckedFiles!=8 || report.MatchedFiles!=8 ||
        report.CanUninstall || report.CanStopMotor || report.CanChangeDNS ||
        report.CanDeleteTasks || report.CanDeleteFiles ||
        report.TaskOwnershipVerified || report.ProcessOwnershipVerified{
        t.Fatalf("native Win64 signed disk audit authorized a removal: %+v",report)
    }

    // A disk mutation after receipt signing must invalidate the ENTIRE audit.
    p:=filepath.Join(install,r.Files[0].File)
    if err:=os.WriteFile(p,[]byte("tampered native Windows file"),0600);err!=nil{t.Fatal(err)}
    report,err=AuditSignedInstalledFilesReadOnly(context.Background(),raw,sig,pub)
    if err==nil||report.MatchedFiles!=0{
        t.Fatalf("native Windows filesystem mismatch was accepted: %+v %v",report,err)
    }
}
