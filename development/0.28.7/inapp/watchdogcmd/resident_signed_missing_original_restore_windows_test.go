//go:build windows

package main

import (
 "context"
 "crypto/ed25519"
 "errors"
 "os"
 "path/filepath"
 "strings"
 "testing"

 "volve-browser-protection/motorupdate"
)

func signedMissingRecoveryFixture(t *testing.T)(
 root string,key ed25519.PublicKey,deps residentMissingOriginalRestoreDeps){
 t.Helper()
 root,permit,sig,key:=windowsDurableGrantFixture(t)
 ctx:=context.Background()
 seal:=func(path string)error{hardenedTestACL(t,path,path);return nil}
 if err:=motorupdate.PersistResidentDurablePublisherGrant(ctx,root,
  permit,sig,key,seal,durableWindowsACL,durableWindowsACL,durableWindowsACL);err!=nil{
  t.Fatal(err)
 }
 deps=residentMissingOriginalRestoreDeps{
  VerifySystem:func(context.Context)error{return nil},
  VerifyACL:durableWindowsACL,
  SealNew:seal,
  ProbeQuiescence:func(context.Context,string)(residentQuiescenceDecision,error){
   return residentQuiescenceDecision{TaskIdentityVerified:true,
    DNSPortFree:true,MotorProcessesStopped:true,ReadyForFurtherChecks:true},nil
  },
 }
 return root,key,deps
}

func TestSignedMissingOriginalRestorePublishesSealedBytesWithoutFinalizing(t *testing.T){
 root,key,deps:=signedMissingRecoveryFixture(t)
 live:=filepath.Join(root,residentLegacyExe)
 expected,err:=os.ReadFile(live);if err!=nil{t.Fatal(err)}
 if err:=os.Remove(live);err!=nil{t.Fatal(err)}
 if err:=restoreSignedMissingOriginalWindows(context.Background(),root,key,deps);err!=nil{
  t.Fatalf("signed SYSTEM+protected ACL original file recovery refused: %v",err)
 }
 got,err:=os.ReadFile(live)
 if err!=nil||string(got)!=string(expected){t.Fatalf("restored original not identical: %v",err)}
 if err:=durableWindowsACL(live);err!=nil{t.Fatalf("restored original NTFS ACL not protected: %v",err)}
 journal:=filepath.Join(root,residentRecoveryParent,residentJournalDirName)
 state,err:=auditResidentJournal(context.Background(),journal)
 if err!=nil||state.Status!="recovery-required"{
  t.Fatalf("filesystem publish incorrectly finalized boot recovery: %+v %v",state,err)
 }
 if _,err:=os.Lstat(filepath.Join(journal,motorupdate.ResidentResultFile));!os.IsNotExist(err){
  t.Fatalf("missing-only restoration created a false terminal receipt: %v",err)
 }
 // A second invocation can only report that an original is already present.
 prior,err:=os.Stat(live);if err!=nil{t.Fatal(err)}
 if err:=restoreSignedMissingOriginalWindows(context.Background(),root,key,deps);err==nil{
  t.Fatal("missing-only recovery attempted to rewrite an existing verified motor")
 }
 again,err:=os.Stat(live)
 if err!=nil||!os.SameFile(prior,again){t.Fatalf("idempotent refusal changed original: %v",err)}
}

func TestSignedMissingOriginalRestoreRejectsForeignExistingImage(t *testing.T){
 root,key,deps:=signedMissingRecoveryFixture(t)
 live:=filepath.Join(root,residentLegacyExe)
 foreign:=[]byte("MZ-UNRECOGNIZED-INSTALLED-MOTOR")
 if err:=os.WriteFile(live,foreign,0600);err!=nil{t.Fatal(err)}
 if err:=restoreSignedMissingOriginalWindows(context.Background(),root,key,deps);err==nil{
  t.Fatal("foreign motor overwritten by signed recovery")
 }
 got,err:=os.ReadFile(live)
 if err!=nil||string(got)!=string(foreign){t.Fatalf("foreign bytes were modified: %v",err)}
}

func TestSignedMissingOriginalRestoreRejectsMissingSystemAndLivePort53(t *testing.T){
 root,key,deps:=signedMissingRecoveryFixture(t)
 live:=filepath.Join(root,residentLegacyExe)
 if err:=os.Remove(live);err!=nil{t.Fatal(err)}
 deps.VerifySystem=func(context.Context)error{return errors.New("not SYSTEM")}
 if err:=restoreSignedMissingOriginalWindows(context.Background(),root,key,deps);err==nil{
  t.Fatal("administrator/non-SYSTEM identity passed")
 }
 deps.VerifySystem=func(context.Context)error{return nil}
 deps.ProbeQuiescence=func(context.Context,string)(residentQuiescenceDecision,error){
  return residentQuiescenceDecision{
   TaskIdentityVerified:true,DNSPortFree:false,
   MotorProcessesStopped:true,ReadyForFurtherChecks:false},errors.New("DNS port 53 in use")
 }
 if err:=restoreSignedMissingOriginalWindows(context.Background(),root,key,deps);err==nil{
  t.Fatal("live DNS53 motor was changed")
 }
 if _,err:=os.Lstat(live);!os.IsNotExist(err){t.Fatalf("refused recovery wrote original: %v",err)}
}

func TestSignedMissingOriginalRestoreRejectsCorruptProtectedBackup(t *testing.T){
 root,key,deps:=signedMissingRecoveryFixture(t)
 live:=filepath.Join(root,residentLegacyExe)
 if err:=os.Remove(live);err!=nil{t.Fatal(err)}
 snap:=filepath.Join(root,residentRecoveryParent,residentRecoveryFolder,residentRecoveryExe)
 if err:=os.WriteFile(snap,[]byte("CORRUPT-NON-MOTOR"),0600);err!=nil{t.Fatal(err)}
 if err:=restoreSignedMissingOriginalWindows(context.Background(),root,key,deps);err==nil{
  t.Fatal("corrupted sealed snapshot was used to reconstruct original")
 }
 if _,err:=os.Lstat(live);!os.IsNotExist(err){t.Fatalf("corrupted snapshot created original: %v",err)}
}

func TestSignedMissingOriginalRestoreRejectsStageACLTamperWithoutPublishing(t *testing.T){
 root,key,deps:=signedMissingRecoveryFixture(t)
 live:=filepath.Join(root,residentLegacyExe)
 if err:=os.Remove(live);err!=nil{t.Fatal(err)}
 deps.SealNew=func(path string)error{
  if !strings.Contains(filepath.Base(path),".volve-signed-original-recovery-"){t.Fatal("wrong staged path")}
  return errors.New("simulated NTFS ACL seal failure")
 }
 if err:=restoreSignedMissingOriginalWindows(context.Background(),root,key,deps);err==nil{
  t.Fatal("unprotected stage was published")
 }
 if _,err:=os.Lstat(live);!os.IsNotExist(err){t.Fatalf("unsealed stage created original: %v",err)}
}

func TestSignedMissingOriginalRestoreRejectsChangedQuiescenceBeforePublishing(t *testing.T){
 root,key,deps:=signedMissingRecoveryFixture(t)
 live:=filepath.Join(root,residentLegacyExe)
 if err:=os.Remove(live);err!=nil{t.Fatal(err)}
 checked:=0
 deps.ProbeQuiescence=func(context.Context,string)(residentQuiescenceDecision,error){
  checked++
  if checked==1 {
   return residentQuiescenceDecision{TaskIdentityVerified:true,DNSPortFree:true,
    MotorProcessesStopped:true,ReadyForFurtherChecks:true},nil
  }
  return residentQuiescenceDecision{TaskIdentityVerified:true,DNSPortFree:false,
   MotorProcessesStopped:false},errors.New("motor restarted during staging")
 }
 if err:=restoreSignedMissingOriginalWindows(context.Background(),root,key,deps);err==nil{
  t.Fatal("second process/DNS53 check was bypassed")
 }
 if checked<2{t.Fatalf("quiescence was checked only %d times",checked)}
 if _,err:=os.Lstat(live);!os.IsNotExist(err){t.Fatalf("motor restored while port53 was in use: %v",err)}
}
