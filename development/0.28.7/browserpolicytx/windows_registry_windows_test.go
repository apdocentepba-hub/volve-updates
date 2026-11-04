//go:build windows

package browserpolicytx

import (
    "context"
    "os"
    "testing"
)

func TestActualWindowsRegistrySandbox772ValueRoundTrip(t *testing.T){
    if os.Getenv("GITHUB_ACTIONS")!="true" ||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{
        t.Skip("actual Windows registry lab reserved for hosted disposable CI")
    }
    store,err:=NewWindowsRegistryLab()
    if err!=nil{t.Fatal(err)}
    t.Cleanup(func(){if err:=store.Cleanup();err!=nil{t.Errorf("lab Registry cleanup failed: %v",err)}})
    p:=fixturePlan()
    result,err:=Rehearse(context.Background(),p,store)
    if err!=nil{t.Fatal(err)}
    if result.Created!=PlanEntries||result.Reverted!=PlanEntries||
        result.State!="LAB_ROLLBACK_COMPLETE_NO_INSTALL"||result.CanInstall{
        t.Fatalf("actual Windows registry lab rollback incomplete: %+v",result)
    }
    t.Logf("PASS VOLVE_772_POLICY_VALUES_REAL_WINDOWS_HKCU_CI_ONLY_CREATED_AND_REVERTED count=%d NO_BROWSER_POLICIES NO_INSTALL",result.Reverted)
}
func TestActualWindowsRegistryRefusesPreExistingUnownedValue(t *testing.T){
    if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{
        t.Skip("hosted Windows CI only")
    }
    // Separate test root is deliberately not created; construction of another
    // instance must refuse an existing root, not reuse or delete its content.
    // Do not run concurrently with the full 772-value round-trip.
    store,err:=NewWindowsRegistryLab()
    if err!=nil{t.Fatal(err)}
    t.Cleanup(func(){if err:=store.Cleanup();err!=nil{t.Errorf("Registry cleanup failed: %v",err)}})
    sameRoot,err:=NewWindowsRegistryLab()
    if err==nil||sameRoot!=nil{t.Fatal("existing HKCU laboratory root was reused")}
    p:=fixturePlan()
    if err:=store.CreateOnly(context.Background(),p.RegistryValues[0]);err!=nil{t.Fatal(err)}
    _,err=Rehearse(context.Background(),p,store)
    if err==nil{t.Fatal("existing unowned registry policy value was overwritten")}
    exists,err:=store.Exists(context.Background(),p.RegistryValues[0])
    if err!=nil||!exists{t.Fatalf("pre-existing registry value unexpectedly removed: %v",err)}
    if err:=store.DeleteOnlyIfEqual(context.Background(),p.RegistryValues[0]);err!=nil{t.Fatal(err)}
}
