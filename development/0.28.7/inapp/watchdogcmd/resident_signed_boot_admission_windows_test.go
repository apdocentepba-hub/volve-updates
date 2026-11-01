//go:build windows

package main

import (
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "errors"
 "os"
 "path/filepath"
 "testing"

 "volve-browser-protection/motorupdate"
)

// The fixtures use real protected NTFS paths and ephemeral editor signatures,
// never the installed VOLVE motor or the real production task.
func TestSignedBootAdmissionRejectsMissingGrantThenAcceptsExactSealedGrant(t *testing.T){
 root,raw,sig,pub:=windowsDurableGrantFixture(t)
 ctx:=context.Background()
 if _,err:=auditResidentSignedBootAdmission(ctx,root,pub,
  durableWindowsACL,durableWindowsACL,durableWindowsACL);err==nil{
  t.Fatal("unsigned pending recovery was accepted")
 }
 seal:=func(p string)error{hardenedTestACL(t,p,p);return nil}
 if err:=motorupdate.PersistResidentDurablePublisherGrant(ctx,
  root,raw,sig,pub,seal,durableWindowsACL,durableWindowsACL,durableWindowsACL);err!=nil{
  t.Fatal(err)
 }
 result,err:=auditResidentSignedBootAdmission(ctx,root,pub,
  durableWindowsACL,durableWindowsACL,durableWindowsACL)
 if err!=nil||result.Status!="recovery-required"||
  result.Action!="signed-evidence-verified-read-only"||
  result.OriginalSHA256==""||!result.PublisherVerified{
  t.Fatalf("genuine sealed editorial grant rejected: %+v %v",result,err)
 }
 // The auditor must never consume or finalize the create-only intent.
 journal:=filepath.Join(root,residentRecoveryParent,residentJournalDirName)
 state,err:=auditResidentJournal(ctx,journal)
 if err!=nil||state.Status!="recovery-required"{
  t.Fatalf("readonly admission modified journal: %+v %v",state,err)
 }
}

func TestSignedBootAdmissionRejectsWrongKeyOrTamperedGrantWithoutChangingJournal(t *testing.T){
 root,raw,sig,pub:=windowsDurableGrantFixture(t)
 ctx:=context.Background()
 seal:=func(p string)error{hardenedTestACL(t,p,p);return nil}
 if err:=motorupdate.PersistResidentDurablePublisherGrant(ctx,
  root,raw,sig,pub,seal,durableWindowsACL,durableWindowsACL,durableWindowsACL);err!=nil{
  t.Fatal(err)
 }
 other,_,err:=ed25519.GenerateKey(rand.Reader)
 if err!=nil{t.Fatal(err)}
 if _,err:=auditResidentSignedBootAdmission(ctx,root,other,
  durableWindowsACL,durableWindowsACL,durableWindowsACL);err==nil{
  t.Fatal("mismatched editorial public key accepted")
 }
 path:=filepath.Join(root,residentRecoveryParent,"publisher-authorization","migration-permit.sig")
 if err:=os.WriteFile(path,[]byte("INVALID_PUBLISHER_SIGNATURE"),0600);err!=nil{t.Fatal(err)}
 if _,err:=auditResidentSignedBootAdmission(ctx,root,pub,
  durableWindowsACL,durableWindowsACL,durableWindowsACL);err==nil{
  t.Fatal("tampered signature was accepted")
 }
 journal:=filepath.Join(root,residentRecoveryParent,residentJournalDirName)
 state,err:=auditResidentJournal(ctx,journal)
 if err!=nil||state.Status!="recovery-required"{
  t.Fatalf("failed publisher audit consumed the pending recovery: %+v %v",state,err)
 }
}

func TestSignedBootAdmissionRejectsCancelledOrUntrustedReaders(t *testing.T){
 root,_,_,pub:=windowsDurableGrantFixture(t)
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 _,err:=auditResidentSignedBootAdmission(ctx,root,pub,
  durableWindowsACL,durableWindowsACL,durableWindowsACL)
 if !errors.Is(err,context.Canceled){t.Fatalf("cancelled boot admission accepted: %v",err)}
 _,err=auditResidentSignedBootAdmission(context.Background(),root,pub,
  nil,durableWindowsACL,durableWindowsACL)
 if err==nil{t.Fatal("missing NTFS authorizer accepted")}
}
