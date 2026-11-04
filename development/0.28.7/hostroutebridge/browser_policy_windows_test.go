//go:build windows

package hostroutebridge

import (
    "context"
    "errors"
    "syscall"
    "testing"
)

func TestBrowserPolicyInventoryFindsAllCleanOrOwnedUnknownLocations(t *testing.T) {
    calls:=0
    census,err:=inspectBrowserPolicyWith(context.Background(),
        func(root syscall.Handle,path,name string)(bool,error){
            if path==""{t.Fatal("empty registry path")}
            if root!=syscall.HKEY_LOCAL_MACHINE&&root!=syscall.HKEY_CURRENT_USER {t.Fatal("unknown hive")}
            calls++
            return false,nil
        })
    if err!=nil{t.Fatal(err)}
    if calls!=browserPolicyProbes||census.LocationsChecked!=browserPolicyProbes||
        census.ExistingLocations!=0||census.ReviewRequired||
        census.Status!="NO_BROWSER_REINFORCEMENT_POLICY_LOCATIONS_FOUND"{
        t.Fatalf("incomplete clean-policy review: %+v, calls=%d",census,calls)
    }
}

func TestBrowserPolicyInventoryNeverCallsExistingPoliciesOwned(t *testing.T){
    calls:=0
    census,err:=inspectBrowserPolicyWith(context.Background(),
        func(root syscall.Handle,path,name string)(bool,error){
            calls++
            return path==`SOFTWARE\Policies\Google\Chrome\URLBlocklist`&&root==syscall.HKEY_LOCAL_MACHINE,nil
        })
    if err!=nil{t.Fatal(err)}
    if calls!=browserPolicyProbes||!census.ReviewRequired||census.ExistingLocations!=1||
        census.Status!="EXISTING_UNOWNED_BROWSER_POLICIES_REQUIRE_REVIEW"{
        t.Fatalf("pre-existing policy silently treated as fresh or as VOLVE-owned: %+v",census)
    }
}

func TestBrowserPolicyInventoryFailsClosedOnErrorOrCancel(t *testing.T){
    n:=0
    census,err:=inspectBrowserPolicyWith(context.Background(),
        func(syscall.Handle,string,string)(bool,error){
            n++
            if n==3{return false,errors.New("policy access denied")}
            return false,nil
        })
    if err==nil||census.LocationsChecked!=0||census.ExistingLocations!=0{
        t.Fatalf("partial browser inventory leaked or was accepted: %+v, %v",census,err)
    }
    ctx,cancel:=context.WithCancel(context.Background());cancel()
    census,err=inspectBrowserPolicyWith(ctx,func(syscall.Handle,string,string)(bool,error){
        t.Fatal("cancelled audit touched Windows");return false,nil
    })
    if !errors.Is(err,context.Canceled)||census.LocationsChecked!=0{
        t.Fatalf("cancelled census accepted: %+v, %v",census,err)
    }
}

func TestActualBrowserPolicyCensusUsesWindowsReadOnlyRegistry(t *testing.T){
    census,err:=InspectBrowserPolicyRegistryReadOnly(context.Background())
    if err!=nil{t.Fatal(err)}
    if census.LocationsChecked!=browserPolicyProbes||
        census.ReviewRequired!=(census.ExistingLocations>0)||
        census.ExistingLocations<0||census.ExistingLocations>browserPolicyProbes{
        t.Fatalf("native read-only Windows policy census incomplete: %+v",census)
    }
}
