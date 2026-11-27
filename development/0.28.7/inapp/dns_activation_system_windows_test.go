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
 err:=activateWindowsDNSAsProtectedSYSTEM(context.Background(),journal,pin,guard,auth,"")
 if err==nil||!strings.Contains(err.Error(),"LocalSystem")||
  host.invocations!=0||guard.armCount!=0{
  t.Fatalf("non-SYSTEM OS token incorrectly admitted to DNS activation: %v",err)
 }
}


type dnsOverrideActivationFixtureGuard struct{armed,live,committed,recovered int}
func(g *dnsOverrideActivationFixtureGuard)VerifyArmed(context.Context,string)error{g.armed++;return nil}
func(g *dnsOverrideActivationFixtureGuard)VerifyLiveProtection(context.Context,string)error{g.live++;return nil}
func(g *dnsOverrideActivationFixtureGuard)CommitActive(context.Context,string)error{g.committed++;return nil}
func(g *dnsOverrideActivationFixtureGuard)RecoverIndependently(context.Context,string)error{g.recovered++;return nil}

func TestWindowsDNSActivationOverrideGuardRejectsDriftWithoutSuppressingRecovery(t *testing.T){
 ctx:=context.Background()
 initial:=WindowsDNSOverrideCensus{Schema:1,Component:"windows-dns-override-census-v1",DoHCmdletAvailable:true,KnownDoHServers:12,fingerprints:[4]string{strings.Repeat("a",64),strings.Repeat("b",64),strings.Repeat("c",64),strings.Repeat("d",64)}}
 current:=initial
 inner:=&dnsOverrideActivationFixtureGuard{}
 g:=&dnsActivationOverrideGuard{inner:inner,observe:func(context.Context)(WindowsDNSOverrideCensus,error){return current,nil}}
 if err:=g.VerifyArmed(ctx,"pin");err==nil||inner.armed!=0{t.Fatal("uninitialized policy baseline admitted")}
 for _,alter:=range []func(*WindowsDNSOverrideCensus){
  func(c *WindowsDNSOverrideCensus){c.LocalNRPTRules=1},
  func(c *WindowsDNSOverrideCensus){c.EffectiveNRPTPolicies=1},
  func(c *WindowsDNSOverrideCensus){c.GroupPolicyKeyPresent=true},
  func(c *WindowsDNSOverrideCensus){c.DoHCmdletAvailable=false},
  func(c *WindowsDNSOverrideCensus){c.fingerprints[0]=""},
 }{
  current=initial;alter(&current)
  if err:=g.capture(ctx);err==nil||g.captured{t.Fatal("unsupported or incomplete policy admitted")}
 }
 current=initial
 if err:=g.capture(ctx);err!=nil{t.Fatal(err)}
 if err:=g.VerifyArmed(ctx,"pin");err!=nil||inner.armed!=1{t.Fatal("valid baseline refused",err)}
 if err:=g.VerifyLiveProtection(ctx,"pin");err!=nil||inner.live!=1{t.Fatal("valid policy health refused",err)}
 if err:=g.CommitActive(ctx,"pin");err!=nil||inner.committed!=1{t.Fatal("valid commit refused",err)}
 current.fingerprints[2]=strings.Repeat("e",64)
 if err:=g.capture(ctx);err==nil{t.Fatal("baseline reset admitted")}
 if g.VerifyArmed(ctx,"pin")==nil||g.VerifyLiveProtection(ctx,"pin")==nil||g.CommitActive(ctx,"pin")==nil{t.Fatal("same-count drift admitted")}
 if inner.armed!=1||inner.live!=1||inner.committed!=1{t.Fatal("inner guard reached after policy drift")}
 g.observe=nil
 if err:=g.RecoverIndependently(ctx,"pin");err!=nil||inner.recovered!=1{t.Fatal("policy drift blocked independent recovery",err)}
 t.Log("PASS VOLVE_DNS_ACTIVATION_POLICY_GUARD_REJECTS_DRIFT_PRESERVES_RECOVERY")
}
