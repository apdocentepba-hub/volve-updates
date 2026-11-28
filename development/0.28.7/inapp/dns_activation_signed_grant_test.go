package motorupdate

import (
 "bytes"
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "encoding/base64"
 "encoding/json"
 "errors"
 "strings"
 "testing"
 "time"
)

type dnsGrantFixture struct {
 grant SignedDNSActivationGrant
 pins DNSActivationExternallyPinnedEvidence
 pub ed25519.PublicKey
 priv ed25519.PrivateKey
 now time.Time
}
func makeDNSGrantFixture(t *testing.T)dnsGrantFixture{
 t.Helper()
 pub,priv,err:=ed25519.GenerateKey(rand.Reader)
 if err!=nil{t.Fatal(err)}
 now:=time.Date(2026,11,21,14,0,0,0,time.UTC)
 pins:=DNSActivationExternallyPinnedEvidence{
  IntentNonce:strings.Repeat("a",32),
  OriginalDNSJournalSHA256:strings.Repeat("b",64),
  TargetMotorSHA256:strings.Repeat("c",64),
  WatchdogTaskXMLSHA256:strings.Repeat("d",64),
 }
 grant:=SignedDNSActivationGrant{
  Schema:1,Component:dnsActivationGrantComponent,
  Operation:dnsActivationGrantOperation,
  IntentNonce:pins.IntentNonce,
  OriginalDNSJournalSHA256:pins.OriginalDNSJournalSHA256,
  TargetMotorSHA256:pins.TargetMotorSHA256,
  WatchdogTaskXMLSHA256:pins.WatchdogTaskXMLSHA256,
  IssuedAtUnix:now.Add(-time.Minute).Unix(),
  ExpiresAtUnix:now.Add(10*time.Minute).Unix(),
 }
 return dnsGrantFixture{grant:grant,pins:pins,pub:pub,priv:priv,now:now}
}
func signDNSActivationFixture(t *testing.T,f dnsGrantFixture)([]byte,[]byte){
 t.Helper()
 raw,err:=json.Marshal(f.grant)
 if err!=nil{t.Fatal(err)}
 return raw,[]byte(base64.StdEncoding.EncodeToString(ed25519.Sign(f.priv,raw)))
}

func TestPublisherSignedDNSActivationGrantAcceptsOnlyExactScopedShortLivedIntent(t *testing.T){
 f:=makeDNSGrantFixture(t)
 raw,sig:=signDNSActivationFixture(t,f)
 got,err:=VerifyPublisherSignedDNSActivationGrant(
  context.Background(),raw,sig,f.pub,f.pins,f.now)
 if err!=nil{t.Fatal(err)}
 if got!=f.grant{t.Fatal("verified publisher grant differs from exact signed fields")}
}

func TestPublisherSignedDNSActivationGrantRejectsWrongBoundIdentityEvenWithValidSignature(t *testing.T){
 for _,tc:=range []struct{name string;alter func(*SignedDNSActivationGrant)}{
  {"replayed-nonce",func(p *SignedDNSActivationGrant){p.IntentNonce=strings.Repeat("e",32)}},
  {"other-dns-journal",func(p *SignedDNSActivationGrant){p.OriginalDNSJournalSHA256=strings.Repeat("f",64)}},
  {"other-motor",func(p *SignedDNSActivationGrant){p.TargetMotorSHA256=strings.Repeat("1",64)}},
  {"other-watchdog",func(p *SignedDNSActivationGrant){p.WatchdogTaskXMLSHA256=strings.Repeat("2",64)}},
  {"migration-instead-of-activation",func(p *SignedDNSActivationGrant){p.Operation="restore-dns-after-failure"}},
  {"other-component",func(p *SignedDNSActivationGrant){p.Component="volve-recovery-original-receipt"}},
  {"unsupported-schema",func(p *SignedDNSActivationGrant){p.Schema=2}},
  {"uppercase-hash",func(p *SignedDNSActivationGrant){p.TargetMotorSHA256=strings.Repeat("A",64)}},
  {"empty-nonce",func(p *SignedDNSActivationGrant){p.IntentNonce=""}},
 }{
  t.Run(tc.name,func(t *testing.T){
   f:=makeDNSGrantFixture(t);tc.alter(&f.grant)
   raw,sig:=signDNSActivationFixture(t,f)
   if _,err:=VerifyPublisherSignedDNSActivationGrant(
    context.Background(),raw,sig,f.pub,f.pins,f.now);err==nil{
    t.Fatal("publisher-signed unrelated or malformed activation scope admitted")
   }
  })
 }
}

func TestPublisherSignedDNSActivationGrantRejectsExpiredFutureAndOversizedWindows(t *testing.T){
 for _,tc:=range []struct{name string;alter func(*dnsGrantFixture)}{
  {"expired",func(f *dnsGrantFixture){f.grant.ExpiresAtUnix=f.now.Add(-time.Second).Unix()}},
  {"future-issued",func(f *dnsGrantFixture){f.grant.IssuedAtUnix=f.now.Add(3*time.Minute).Unix()}},
  {"too-long-lived",func(f *dnsGrantFixture){f.grant.ExpiresAtUnix=f.now.Add(24*time.Hour).Unix()}},
  {"negative-window",func(f *dnsGrantFixture){f.grant.ExpiresAtUnix=f.grant.IssuedAtUnix}},
  {"zero-clock",func(f *dnsGrantFixture){f.now=time.Time{}}},
 }{
  t.Run(tc.name,func(t *testing.T){
   f:=makeDNSGrantFixture(t);tc.alter(&f)
   raw,sig:=signDNSActivationFixture(t,f)
   if _,err:=VerifyPublisherSignedDNSActivationGrant(context.Background(),raw,sig,f.pub,f.pins,f.now);err==nil{
    t.Fatal("invalid publisher grant expiry or timestamp accepted")
   }
  })
 }
}

func TestPublisherSignedDNSActivationGrantRejectsForgeryAndNonCanonicalJSON(t *testing.T){
 f:=makeDNSGrantFixture(t)
 raw,sig:=signDNSActivationFixture(t,f)
 otherPub,_,err:=ed25519.GenerateKey(rand.Reader)
 if err!=nil{t.Fatal(err)}
 mutated:=append([]byte(nil),raw...);mutated[len(mutated)-2]^=1
 pretty:=new(bytes.Buffer)
 if err:=json.Indent(pretty,raw,"","  ");err!=nil{t.Fatal(err)}
 prettySig:=[]byte(base64.StdEncoding.EncodeToString(ed25519.Sign(f.priv,pretty.Bytes())))
 dupe:=append(bytes.TrimSuffix(append([]byte(nil),raw...),[]byte("}")),
  []byte(`,"schema":1}`)...)
 dupeSig:=[]byte(base64.StdEncoding.EncodeToString(ed25519.Sign(f.priv,dupe)))
 trailing:=append(append([]byte(nil),raw...),[]byte("{}")...)
 trailingSig:=[]byte(base64.StdEncoding.EncodeToString(ed25519.Sign(f.priv,trailing)))
 for _,tc:=range []struct{name string;raw,sig []byte;key ed25519.PublicKey}{
  {"forged-bytes",mutated,sig,f.pub},
  {"wrong-publisher",raw,sig,otherPub},
  {"no-publisher",raw,sig,nil},
  {"no-signature",raw,nil,f.pub},
  {"noncanonical-signed-json",pretty.Bytes(),prettySig,f.pub},
  {"duplicate-signed-key",dupe,dupeSig,f.pub},
  {"signed-trailing-json",trailing,trailingSig,f.pub},
 }{
  t.Run(tc.name,func(t *testing.T){
   if _,err:=VerifyPublisherSignedDNSActivationGrant(context.Background(),tc.raw,tc.sig,tc.key,f.pins,f.now);err==nil{
    t.Fatal("forged, duplicated or noncanonical Ed25519 activation grant accepted")
   }
  })
 }
}

func TestPublisherSignedDNSActivationGrantRequiresIndependentExternalPins(t *testing.T){
 f:=makeDNSGrantFixture(t)
 raw,sig:=signDNSActivationFixture(t,f)
 for _,tc:=range []struct{name string;change func(*DNSActivationExternallyPinnedEvidence)}{
  {"nonce",func(e *DNSActivationExternallyPinnedEvidence){e.IntentNonce=""}},
  {"journal",func(e *DNSActivationExternallyPinnedEvidence){e.OriginalDNSJournalSHA256=""}},
  {"motor",func(e *DNSActivationExternallyPinnedEvidence){e.TargetMotorSHA256=""}},
  {"watchdog",func(e *DNSActivationExternallyPinnedEvidence){e.WatchdogTaskXMLSHA256=""}},
  {"other-watchdog",func(e *DNSActivationExternallyPinnedEvidence){e.WatchdogTaskXMLSHA256=strings.Repeat("3",64)}},
 }{
  t.Run(tc.name,func(t *testing.T){
   pins:=f.pins;tc.change(&pins)
   if _,err:=VerifyPublisherSignedDNSActivationGrant(context.Background(),raw,sig,f.pub,pins,f.now);err==nil{
    t.Fatal("self-declared, missing or mismatched publisher activation identity approved")
   }
  })
 }
}

func TestPublisherSignedDNSActivationGrantRefusesCancelledContext(t *testing.T){
 f:=makeDNSGrantFixture(t)
 raw,sig:=signDNSActivationFixture(t,f)
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 if _,err:=VerifyPublisherSignedDNSActivationGrant(ctx,raw,sig,f.pub,f.pins,f.now);!errors.Is(err,context.Canceled){
  t.Fatalf("cancelled DNS activation grant verification accepted: %v",err)
 }
}
