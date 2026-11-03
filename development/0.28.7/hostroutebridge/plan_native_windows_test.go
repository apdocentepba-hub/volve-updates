//go:build windows

package hostroutebridge

import (
    "context"
    "testing"
    "time"

    motorupdate "volve-browser-protection/motorupdate"
)

// The signed fixture is a REAL Authenticode-bearing Windows PE. All six
// inspectors call actual Windows on a disposable GitHub-hosted Windows VM.
// No privileged transaction, product task, DNS or network change is permitted.
func TestSignedPackageRealWindowsRouteProducesNonAuthorizingPlan(t *testing.T) {
    fixture:=labEvidence(t)
    ctx,cancel:=context.WithTimeout(context.Background(),120*time.Second)
    defer cancel()
    installedRoot:=t.TempDir()
    review,plan,err:=ReviewAndPlanReadOnly(ctx,func(inner context.Context)(Review,error){
        return ReviewReadOnly(inner,fixture.exe,fixture.key,fixture.certPin,fixture.exePin,
            installedRoot,motorupdate.DefaultWindowsMotorRouteInspectors())
    })
    if err!=nil{t.Fatal(err)}
    if !review.WindowsPublisherAndPackageVerified||review.PackageParts!=8||
        review.InventoriesChecked!=6||plan.CompleteHostInventories!=6||
        !plan.SignedPackageVerified||plan.HostRoute!=review.Route||
        plan.TargetRelease!="0.28.7"||plan.Mode==""||
        plan.Disposition!="READ_ONLY_PLAN_NOT_AN_INSTALLATION_PERMIT"{
        t.Fatalf("signed EXE / live Windows inventory / plan chain incomplete: review=%+v plan=%+v",review,plan)
    }
    if plan.CanInstall||plan.CanUpgrade||plan.CanChangeDNS||plan.CanChangeTasks||
        review.InstallAuthorized||review.UpgradeAuthorized||review.CanModifyDNS{
        t.Fatalf("read-only installation preview gained write capabilities: %+v",plan)
    }
    t.Logf("PASS VOLVE_WIN_SETUP_PLAN_LAB route=%s mode=%s NO_INSTALL NO_DNS_CHANGE",review.Route,plan.Mode)
}
