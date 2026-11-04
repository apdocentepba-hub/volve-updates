//go:build windows

package hostroutebridge

// Independent read-only census of browser policy locations. A clean DNS
// motor inventory is not proof that no browser GPO policy is already in use.
// This module never creates, edits or deletes registry values.
import (
    "context"
    "errors"
    "fmt"
    "syscall"
)

const browserPolicyProbes = 14

type BrowserPolicyCensus struct {
    LocationsChecked int `json:"locations_checked"`
    ExistingLocations int `json:"existing_locations"`
    ReviewRequired bool `json:"review_required"`
    Status string `json:"status"`
}

type browserPolicyLocation struct { path, valueName string }
var browserPolicyLocations = []browserPolicyLocation{
    {`SOFTWARE\Policies\Google\Chrome\URLBlocklist`, ""},
    {`SOFTWARE\Policies\Microsoft\Edge\URLBlocklist`, ""},
    {`SOFTWARE\Policies\Mozilla\Firefox\WebsiteFilter\Block`, ""},
    {`SOFTWARE\Policies\Google\Chrome`, "DnsOverHttpsMode"},
    {`SOFTWARE\Policies\Microsoft\Edge`, "DnsOverHttpsMode"},
    {`SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS`, "Enabled"},
    {`SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS`, "Locked"},
}

type browserPolicyLookup func(root syscall.Handle, path, name string)(bool,error)

func nativeBrowserPolicyLookup(root syscall.Handle, path, name string)(bool,error){
    ptr,err:=syscall.UTF16PtrFromString(path)
    if err!=nil{return false,err}
    var key syscall.Handle
    err=syscall.RegOpenKeyEx(root,ptr,0,syscall.KEY_READ|syscall.KEY_WOW64_64KEY,&key)
    if errors.Is(err,syscall.ERROR_FILE_NOT_FOUND)||errors.Is(err,syscall.ERROR_PATH_NOT_FOUND){
        return false,nil
    }
    if err!=nil{return false,fmt.Errorf("read-only policy key refused: %w",err)}
    defer syscall.RegCloseKey(key)
    if name=="" {return true,nil}
    valuePtr,err:=syscall.UTF16PtrFromString(name)
    if err!=nil{return false,err}
    var kind,bytes uint32
    err=syscall.RegQueryValueEx(key,valuePtr,nil,&kind,nil,&bytes)
    if errors.Is(err,syscall.ERROR_FILE_NOT_FOUND)||errors.Is(err,syscall.ERROR_PATH_NOT_FOUND){
        return false,nil
    }
    if err==nil||errors.Is(err,syscall.ERROR_MORE_DATA){return true,nil}
    return false,fmt.Errorf("read-only policy value refused: %w",err)
}

func inspectBrowserPolicyWith(ctx context.Context, lookup browserPolicyLookup)(BrowserPolicyCensus,error){
    var zero BrowserPolicyCensus
    if ctx==nil||lookup==nil{return zero,errors.New("context and read-only policy lookup required")}
    if err:=ctx.Err();err!=nil{return zero,err}
    var out BrowserPolicyCensus
    for _,root:=range []syscall.Handle{syscall.HKEY_LOCAL_MACHINE,syscall.HKEY_CURRENT_USER}{
        for _,location:=range browserPolicyLocations {
            if err:=ctx.Err();err!=nil{return zero,err}
            found,err:=lookup(root,location.path,location.valueName)
            if err!=nil{return zero,fmt.Errorf("browser policy census unavailable: %w",err)}
            out.LocationsChecked++
            if found {out.ExistingLocations++}
        }
    }
    if out.LocationsChecked!=browserPolicyProbes{return zero,errors.New("incomplete browser policy census")}
    out.ReviewRequired=out.ExistingLocations>0
    if out.ReviewRequired {
        out.Status="EXISTING_UNOWNED_BROWSER_POLICIES_REQUIRE_REVIEW"
    } else {
        out.Status="NO_BROWSER_REINFORCEMENT_POLICY_LOCATIONS_FOUND"
    }
    return out,nil
}

// InspectBrowserPolicyRegistryReadOnly queries only the 64-bit registry view.
// An empty policy key still counts as pre-existing and may not be overwritten.
// Absence of these keys does NOT authorize installation or registry mutation.
func InspectBrowserPolicyRegistryReadOnly(ctx context.Context)(BrowserPolicyCensus,error){
    return inspectBrowserPolicyWith(ctx,nativeBrowserPolicyLookup)
}
