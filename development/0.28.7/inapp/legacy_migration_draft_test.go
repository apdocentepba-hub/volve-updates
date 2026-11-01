package motorupdate

import (
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"
)

func TestLegacyMigrationDraftRechecksProtectedHostAndNeverAuthorizes(t *testing.T){
 f:=newSignedBridge(t)
 calls:=0
 draft,err:=PrepareLegacyMigrationDraftReadOnly(context.Background(),
  f.live,f.backup,f.candidate,"0.28.7",f.pub,
  testSecureLabFolderBridge,func()error{calls++;return nil},time.Now().UTC())
 if err!=nil{t.Fatal(err)}
 if calls!=2||draft.Component!=UnsignedLegacyDraftComponent||
  draft.Disposition!=UnsignedLegacyDraftDisposition||
  draft.SignaturePresent||draft.MigrationAuthorized||draft.ReadyToSwitch||
  draft.Review.PublisherPublicKeySHA256==""{
  t.Fatalf("unsigned migration draft overclaims permission or skips live probes: %+v, calls=%d",draft,calls)
 }
 raw,err:=DraftPermitBytesReadOnly(draft);if err!=nil{t.Fatal(err)}
 digest:=sha256.Sum256(raw)
 if hex.EncodeToString(digest[:])!=draft.PermitJSONSHA256{
  t.Fatal("offline publisher draft hash not bound to canonical permit")
 }
 if draft.Permit.FromSHA256!=f.permit.FromSHA256||
  draft.Permit.FromTaskXMLSHA256!=f.permit.FromTaskXMLSHA256||
  draft.Permit.ToSHA256!=f.permit.ToSHA256||
  draft.Permit.ToVersion!="0.28.7"{
  t.Fatal("offline permit draft not pinned to original and signed target")
 }
 issued,err:=time.Parse(time.RFC3339,draft.Permit.IssuedUTC);if err!=nil{t.Fatal(err)}
 expires,err:=time.Parse(time.RFC3339,draft.Permit.ExpiresUTC);if err!=nil{t.Fatal(err)}
 if expires.Sub(issued)!=24*time.Hour{t.Fatal("draft permission lifetime too long")}
 // A JSON draft is not a migration permit. Only a distinct legitimate
 // private-key operation OUTSIDE this repository would create the signature.
 if _,err=VerifySignedUnversionedLegacyMigration(context.Background(),f.live,f.backup,
  f.candidate,"0.28.7",raw,nil,f.pub,testSecureLabFolderBridge,func()error{return nil});err==nil {
  t.Fatal("unsigned draft incorrectly authorized productive migration")
 }
 // A short-lived, CI-only private key demonstrates byte compatibility;
 // it is NOT the legitimate publisher key and is NEVER persisted in repo.
 sig:=[]byte(base64.StdEncoding.EncodeToString(ed25519.Sign(f.priv,raw)))
 if _,err=VerifySignedUnversionedLegacyMigration(context.Background(),f.live,f.backup,
  f.candidate,"0.28.7",raw,sig,f.pub,testSecureLabFolderBridge,func()error{return nil});err!=nil {
  t.Fatalf("offline draft is not compatible with existing strict permit verifier: %v",err)
 }
 otherPub,_,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 if _,err=VerifySignedUnversionedLegacyMigration(context.Background(),f.live,f.backup,
  f.candidate,"0.28.7",raw,sig,otherPub,testSecureLabFolderBridge,func()error{return nil});err==nil {
  t.Fatal("foreign publisher key signature accepted")
 }
 before,err:=os.ReadFile(f.live);if err!=nil{t.Fatal(err)}
 after,err:=os.ReadFile(f.live);if err!=nil{t.Fatal(err)}
 if string(before)!=string(after){t.Fatal("read-only draft mutated old motor")}
 b,err:=json.Marshal(draft);if err!=nil{t.Fatal(err)}
 for _,secret:=range []string{f.live,f.backup,f.candidate,f.root}{
  if strings.Contains(string(b),secret){t.Fatal("unsigned draft leaked installed path")}
 }
}

func TestLegacyMigrationDraftFailsClosedOnChangedOriginalPublisherCandidateAndClock(t *testing.T){
 for _,scenario:=range []string{
  "alter-old","alter-backup","alter-signed-target","foreign-public-key",
  "weak-acl","failed-preflight","clock-past","clock-future",
  "already-managed","invalid-panel","unsigned-target","context-cancelled",
 }{
  t.Run(scenario,func(t *testing.T){
   f:=newSignedBridge(t)
   pub:=f.pub
   secure:=testSecureLabFolderBridge
   var acl func(string)error=secure
   var preflight func()error=func()error{return nil}
   ctx:=context.Background()
   panel:="0.28.7"
   when:=time.Now().UTC()
   switch scenario{
    case "alter-old":_ = os.WriteFile(f.live,[]byte("MZ_OTHER"),0600)
    case "alter-backup":_ = os.WriteFile(filepath.Join(f.backup,legacyBackupExe),[]byte("MZ_OTHER"),0600)
    case "alter-signed-target":_ = os.WriteFile(f.candidate,[]byte("MZ_WRONG"),0600)
    case "foreign-public-key":pub,_,_=ed25519.GenerateKey(rand.Reader)
    case "weak-acl":acl=func(string)error{return os.ErrPermission}
    case "failed-preflight":preflight=func()error{return os.ErrPermission}
    case "clock-past":when=when.Add(-time.Hour)
    case "clock-future":when=when.Add(time.Hour)
    case "already-managed":
     dir:=filepath.Join(f.root,"installed-engines")
     if err:=os.Mkdir(dir,0700);err!=nil{t.Fatal(err)}
     if err:=os.WriteFile(filepath.Join(dir,installedReceiptName),[]byte("{}"),0600);err!=nil{t.Fatal(err)}
    case "invalid-panel":panel="0.28.6"
    case "unsigned-target":_ = os.Remove(f.candidate+".sig")
    case "context-cancelled":
     c,cancel:=context.WithCancel(ctx);cancel();ctx=c
   }
   got,err:=PrepareLegacyMigrationDraftReadOnly(ctx,f.live,f.backup,f.candidate,panel,
    pub,acl,preflight,when)
   if err==nil||got.Component!=""{t.Fatalf("unsafe scenario %s produced review: %+v",scenario,got)}
  })
 }
}

func TestLegacyMigrationDraftCannotBePromotedOrModifiedWithoutRehash(t *testing.T){
 f:=newSignedBridge(t)
 build:=func()UnsignedLegacyMigrationDraft{
  t.Helper()
  draft,err:=PrepareLegacyMigrationDraftReadOnly(context.Background(),f.live,f.backup,
   f.candidate,"0.28.7",f.pub,testSecureLabFolderBridge,func()error{return nil},time.Now().UTC())
  if err!=nil{t.Fatal(err)}
  return draft
 }
 for _,scenario:=range []string{
  "fake-authorized","fake-signed","fake-ready","change-old-hash","change-to-hash",
  "change-version","change-size","change-review","change-key-fingerprint","change-digest",
 }{
  t.Run(scenario,func(t *testing.T){
   d:=build()
   switch scenario {
   case "fake-authorized":d.MigrationAuthorized=true
   case "fake-signed":d.SignaturePresent=true
   case "fake-ready":d.ReadyToSwitch=true
   case "change-old-hash":d.Permit.FromSHA256=strings.Repeat("a",64)
   case "change-to-hash":d.Permit.ToSHA256=strings.Repeat("b",64)
   case "change-version":d.Permit.ToVersion="0.29.0"
   case "change-size":d.Permit.ToSize++
   case "change-review":d.Review.FromSHA256=strings.Repeat("a",64)
   case "change-key-fingerprint":d.Review.PublisherPublicKeySHA256=strings.Repeat("0",64)
   case "change-digest":d.PermitJSONSHA256=strings.Repeat("1",64)
   }
   if _,err:=DraftPermitBytesReadOnly(d);err==nil{t.Fatalf("tampered unsigned draft accepted: %s",scenario)}
  })
 }
}
