package uninstallguard

import (
 "bytes"
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "encoding/json"
 "errors"
 "strings"
 "testing"
 "time"
)

func supportFixture(t *testing.T)(InstalledReceipt,[]byte,[]byte,ed25519.PublicKey,[]byte,[]byte,ed25519.PublicKey,time.Time,ed25519.PrivateKey){
 t.Helper()
 install:=testReceipt()
 installedRaw,installedSig,publisherKey,_:=testSigned(t,install)
 supportKey,private,err:=ed25519.GenerateKey(rand.Reader)
 if err!=nil{t.Fatal(err)}
 now:=time.Date(2026,time.November,14,15,0,0,0,time.UTC)
 p:=SupportReleasePermit{
  Schema:1,Component:supportReleaseComponent,
  InstallationID:install.InstallationID,
  OriginalDNSSnapshotSHA256:install.OriginalDNSSnapshotSHA256,
  RecoveryJournalSHA256:install.RecoveryJournalSHA256,
  Action:supportReleaseAction,
  CaseID:strings.Repeat("a",32),
  Nonce:strings.Repeat("b",32),
  IssuedUTC:now.Add(-time.Hour).Format(time.RFC3339),
  ExpiresUTC:now.Add(time.Hour).Format(time.RFC3339),
  RequiresUserApproval:true,RequiresOriginalRecovery:true,
 }
 raw,err:=json.Marshal(p)
 if err!=nil{t.Fatal(err)}
 sig:=ed25519.Sign(private,raw)
 return install,installedRaw,installedSig,publisherKey,raw,sig,supportKey,now,private
}

func TestSupportReleaseSignedPermitOnlyProducesNonAuthorizingReview(t *testing.T){
 install,installedRaw,installedSig,publisherKey,raw,sig,supportKey,now,_:=supportFixture(t)
 permit,err:=VerifySignedSupportReleasePermit(context.Background(),raw,sig,supportKey,publisherKey,install,now)
 if err!=nil||permit.InstallationID!=install.InstallationID{t.Fatalf("valid support signature refused: %v",err)}
 host:=knownHost()
 host.OtherVolveTasks=1;host.ProgramFilesRoot=true;host.ProgramDataResidues=1
 result,err:=ReviewSupportRemovalOnly(context.Background(),host,installedRaw,installedSig,publisherKey,raw,sig,supportKey,now)
 if err!=nil{t.Fatal(err)}
 if !result.VerifiedPublisherReceipt||!result.VerifiedIndependentSupportSignature||
  !result.BoundToInstallationAndOriginalDNS||result.OneTimeNonceConsumed||
  result.UserApproved||result.OriginalDNSRestored||
  result.CanUninstall||result.CanChangeDNS||result.CanDeleteTasks{
  t.Fatalf("signed support review granted forbidden removal: %+v",result)
 }
 // Repeated verification is allowed for auditing, never redeemed: a future
 // privileged atomic nonce ledger must be present before any removal.
 repeat,err:=ReviewSupportRemovalOnly(context.Background(),host,installedRaw,installedSig,publisherKey,raw,sig,supportKey,now)
 if err!=nil||repeat.OneTimeNonceConsumed||repeat.CanUninstall{
  t.Fatal("repeat read-only review incorrectly consumed or authorized the token")
 }
}

func TestSupportReleaseDeniesForgedAndWrongScope(t *testing.T){
 installed,_,_,publisherKey,raw,sig,supportKey,now,private:=supportFixture(t)
 var original SupportReleasePermit
 if err:=json.Unmarshal(raw,&original);err!=nil{t.Fatal(err)}
 cases:=map[string]func(*SupportReleasePermit){
  "wrong-installation":func(p *SupportReleasePermit){p.InstallationID=strings.Repeat("2",32)},
  "wrong-original-dns":func(p *SupportReleasePermit){p.OriginalDNSSnapshotSHA256=strings.Repeat("2",64)},
  "wrong-recovery":func(p *SupportReleasePermit){p.RecoveryJournalSHA256=strings.Repeat("2",64)},
  "wrong-action":func(p *SupportReleasePermit){p.Action="force-uninstall"},
  "missing-user-approval":func(p *SupportReleasePermit){p.RequiresUserApproval=false},
  "missing-original-recovery":func(p *SupportReleasePermit){p.RequiresOriginalRecovery=false},
  "nonrandom-case-id":func(p *SupportReleasePermit){p.CaseID="support@example.org"},
  "short-nonce":func(p *SupportReleasePermit){p.Nonce="1"},
  "expired":func(p *SupportReleasePermit){p.ExpiresUTC=now.Add(-time.Minute).Format(time.RFC3339)},
  "premature":func(p *SupportReleasePermit){p.IssuedUTC=now.Add(time.Hour).Format(time.RFC3339)},
  "long-lived":func(p *SupportReleasePermit){p.ExpiresUTC=now.Add(48*time.Hour).Format(time.RFC3339)},
 }
 for name,mutate:=range cases{t.Run(name,func(t *testing.T){
  p:=original;mutate(&p)
  encoded,err:=json.Marshal(p)
  if err!=nil{t.Fatal(err)}
  validSig:=ed25519.Sign(private,encoded)
  if _,err:=VerifySignedSupportReleasePermit(context.Background(),encoded,validSig,supportKey,publisherKey,installed,now);err==nil{
   t.Fatal("even valid support signature must not authorize mismatched scope")
  }
 })}
 modified:=append([]byte(nil),raw...)
 modified[len(modified)-5]^=1
 cases2:=[]struct{name string;payload,signature []byte;supportKey,publisherKey ed25519.PublicKey}{
  {"tampered",modified,sig,supportKey,publisherKey},
  {"missing-signature",raw,nil,supportKey,publisherKey},
  {"same-publisher-key",raw,sig,publisherKey,publisherKey},
  {"missing-publisher-key",raw,sig,supportKey,nil},
  {"trailing-data",append(append([]byte(nil),raw...),[]byte("{}")...),sig,supportKey,publisherKey},
 }
 for _,tc:=range cases2{t.Run(tc.name,func(t *testing.T){
  if _,err:=VerifySignedSupportReleasePermit(context.Background(),tc.payload,tc.signature,tc.supportKey,tc.publisherKey,installed,now);err==nil{
   t.Fatal("forged or noncanonical signed support authorization accepted")
  }
 })}
 pretty:=new(bytes.Buffer)
 if err:=json.Indent(pretty,raw,"","  ");err!=nil{t.Fatal(err)}
 if _,err:=VerifySignedSupportReleasePermit(context.Background(),pretty.Bytes(),
  ed25519.Sign(private,pretty.Bytes()),supportKey,publisherKey,installed,now);err==nil{
  t.Fatal("noncanonical but signed support JSON accepted")
 }
}

func TestSupportReleaseRefusesInvalidInstalledEvidenceAndActiveRecovery(t *testing.T){
 _,installedRaw,installedSig,publisherKey,raw,sig,supportKey,now,_:=supportFixture(t)
 host:=knownHost()
 host.OtherVolveTasks=1;host.ProgramFilesRoot=true;host.ProgramDataResidues=1
 for name,change:=range map[string]func(*Evidence){
  "legacy":func(e *Evidence){e.LegacyTasks=3},
  "pending-recovery":func(e *Evidence){e.RecoveryJournalPresent=true},
  "no-host-evidence":func(e *Evidence){e.Complete=false},
 }{
  t.Run(name,func(t *testing.T){
   e:=host;change(&e)
   result,err:=ReviewSupportRemovalOnly(context.Background(),e,installedRaw,installedSig,publisherKey,raw,sig,supportKey,now)
   if err==nil||result.CanUninstall||result.VerifiedIndependentSupportSignature{
    t.Fatal("untrusted live environment given support release review")
   }
  })
 }
 tamperedReceipt:=append([]byte(nil),installedRaw...)
 tamperedReceipt[len(tamperedReceipt)-4]^=1
 if _,err:=ReviewSupportRemovalOnly(context.Background(),host,tamperedReceipt,installedSig,publisherKey,raw,sig,supportKey,now);err==nil{
  t.Fatal("valid support signature bypassed forged installed publisher receipt")
 }
}

func TestSupportReleaseCancellationAndClockFailure(t *testing.T){
 installed,_,_,publisherKey,raw,sig,supportKey,now,_:=supportFixture(t)
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 if _,err:=VerifySignedSupportReleasePermit(ctx,raw,sig,supportKey,publisherKey,installed,now);!errors.Is(err,context.Canceled){
  t.Fatal("cancelled support verification accepted")
 }
 if _,err:=VerifySignedSupportReleasePermit(context.Background(),raw,sig,supportKey,publisherKey,installed,time.Time{});err==nil{
  t.Fatal("unknown clock accepted for short-lived support permit")
 }
}
