//go:build windows

package motorupdate

import (
 "context"
 "os"
 "strings"
 "testing"
)

// The normal hosted runner is an elevated admin, NOT LocalSystem. Real
// mutation is never attempted here: this must reject before acquiring a
// kernel mutex, inspecting adapters or invoking native netsh.
func TestWindowsProtectedDNSActivationLeaseRejectsNonSYSTEMEntry(t *testing.T){
 if os.Getenv("GITHUB_ACTIONS")!="true"{t.Skip("hosted Windows CI only")}
 if err:=VerifyWindowsCurrentSystemSIDReadOnly();err==nil{
  t.Skip("actual LocalSystem environment: no installer mutation test is permitted")
 }
 journal,pin:=windowsNativeActivationInput(t)
 host:=windowsActivationHostFixture()
 guard:=&windowsActivationIndependentGuard{h:host}
 err:=activateWindowsDNSAsProtectedSYSTEM(context.Background(),journal,pin,guard)
 if err==nil||!strings.Contains(err.Error(),"LocalSystem")||
  host.invocations!=0||guard.armCount!=0{
  t.Fatalf("non-SYSTEM OS token incorrectly admitted to DNS activation: %v",err)
 }
}
