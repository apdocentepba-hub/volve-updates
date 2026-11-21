//go:build windows

package motorupdate

import (
 "context"
 "os"
 "strings"
 "testing"
 "time"
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
 // Use a genuine test-only Ed25519 signature and short-lived exact grant:
 // the negative result must arise from real Windows SID, not missing trust.
 fixture:=makeDNSGrantFixture(t)
 fixture.now=time.Now().UTC()
 fixture.grant.IssuedAtUnix=fixture.now.Add(-time.Minute).Unix()
 fixture.grant.ExpiresAtUnix=fixture.now.Add(10*time.Minute).Unix()
 fixture.pins.OriginalDNSJournalSHA256=pin
 fixture.grant.OriginalDNSJournalSHA256=pin
 raw,sig:=signDNSActivationFixture(t,fixture)
 auth:=DNSActivationPublisherAuthorization{
  GrantJSON:raw,Signature:sig,PinnedPublisherKey:fixture.pub,PinnedEvidence:fixture.pins,
 }
 err:=activateWindowsDNSAsProtectedSYSTEM(context.Background(),journal,pin,guard,auth)
 if err==nil||!strings.Contains(err.Error(),"LocalSystem")||
  host.invocations!=0||guard.armCount!=0{
  t.Fatalf("non-SYSTEM OS token incorrectly admitted to DNS activation: %v",err)
 }
}
