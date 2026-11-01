//go:build windows

package main

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "os"
 "path/filepath"
 "strings"
 "testing"

 "volve-browser-protection/motorupdate"
)

func TestPostSwitchCILabActuallyRecreatesMissingLegacyExecutableFromSealedBackup(t *testing.T){
 root,journalDir,_,protect:=chainFixture(t,false)
 old:=filepath.Join(root,residentLegacyExe)
 expected,err:=os.ReadFile(old);if err!=nil{t.Fatal(err)}
 expectedSHA:=sha256.Sum256(expected)
 if err:=os.Remove(old);err!=nil{t.Fatal(err)}
 if err:=restoreMissingLegacyExecutableCILab(context.Background(),root,disposableResidentTask);err!=nil{
  t.Fatalf("CI original was not recreated from a verified fallback: %v",err)
 }
 restored,err:=os.ReadFile(old)
 if err!=nil||string(restored)!=string(expected){t.Fatalf("recovered original differs: %v",err)}
 if hex.EncodeToString(expectedSHA[:])==""{t.Fatal("missing SHA256 test expected")}
 // Idempotence: a second recovery may NOT rewrite a healthy original.
 a,err:=os.Stat(old);if err!=nil{t.Fatal(err)}
 if err:=restoreMissingLegacyExecutableCILab(context.Background(),root,disposableResidentTask);err!=nil{
  t.Fatalf("already intact CI original should be left alone: %v",err)
 }
 after,err:=os.Stat(old);if err!=nil{t.Fatal(err)}
 if !os.SameFile(a,after){t.Fatal("second invocation rewrote healthy original")}
 journal,err:=motorupdate.InspectResidentRecoveryJournal(context.Background(),journalDir,protect)
 if err!=nil||journal.Status!="recovery-required"{
  t.Fatalf("copying original bytes incorrectly finalized DNS/network recovery: %+v %v",journal,err)
 }
 if _,err:=os.Lstat(filepath.Join(journalDir,motorupdate.ResidentResultFile));!os.IsNotExist(err){
  t.Fatalf("file-only recovery wrote a false finished receipt: %v",err)
 }
}

func TestPostSwitchCILabRefusesToOverwriteDifferentInstalledMotor(t *testing.T){
 root,_,_,_:=chainFixture(t,false)
 active:=filepath.Join(root,residentLegacyExe)
 replacement:=[]byte("MZ_NOT_THE_ORIGINAL_MOTOR")
 if err:=os.WriteFile(active,replacement,0600);err!=nil{t.Fatal(err)}
 err:=restoreMissingLegacyExecutableCILab(context.Background(),root,disposableResidentTask)
 if err==nil||!strings.Contains(err.Error(),"different installed executable"){
  t.Fatalf("CI recovery unexpectedly clobbered new/unknown motor: %v",err)
 }
 got,err:=os.ReadFile(active);if err!=nil||string(got)!=string(replacement){
  t.Fatalf("recovery destroyed different installed executable: %v",err)
 }
}

func TestPostSwitchCILabNeverPublishesCorruptedFallback(t *testing.T){
 root,_,_,_:=chainFixture(t,false)
 old:=filepath.Join(root,residentLegacyExe)
 if err:=os.Remove(old);err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(filepath.Join(root,residentRecoveryParent,residentRecoveryFolder,residentRecoveryExe),
  []byte("MZ_BACKUP_MODIFIED"),0600);err!=nil{t.Fatal(err)}
 if err:=restoreMissingLegacyExecutableCILab(context.Background(),root,disposableResidentTask);err==nil{
  t.Fatal("altered sealed source accepted")
 }
 if _,err:=os.Lstat(old);!os.IsNotExist(err){t.Fatalf("untrusted backup created original: %v",err)}
}

func TestPostSwitchCILabOnlyAcceptsDisposableTaskAndTempRoot(t *testing.T){
 root,_,_,_:=chainFixture(t,false)
 for _,task:=range []string{"VOLVE-DNS-SERVER-0270","VOLVE-CI-ManagedMotor-42","other"}{
  if err:=restoreMissingLegacyExecutableCILab(context.Background(),root,task);err==nil{
   t.Fatalf("accepted productive/unknown task %q",task)
  }
 }
 if err:=restoreMissingLegacyExecutableCILab(context.Background(),filepath.Clean(os.Getenv("WINDIR")),disposableResidentTask);err==nil{
  t.Fatal("attempted copy outside CI temp directory")
 }
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 if err:=restoreMissingLegacyExecutableCILab(ctx,root,disposableResidentTask);err==nil{
  t.Fatal("cancelled CI restore copied any bytes")
 }
}
