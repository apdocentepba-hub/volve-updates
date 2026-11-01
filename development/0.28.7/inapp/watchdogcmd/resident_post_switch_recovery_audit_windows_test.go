//go:build windows

package main

import (
 "context"
 "os"
 "path/filepath"
 "strings"
 "testing"

 "volve-browser-protection/motorupdate"
)

// Synthetic snapshots are isolated in a disposable Windows CI directory.
// No real task is registered, and installed VOLVE never receives writes.
func TestPostSwitchRecoveryTrustsSealedOriginalAfterActiveMotorWasReplaced(t *testing.T){
 for _,kind:=range []string{"missing-old-exe","replaced-old-exe","unchanged-old-exe"}{
  t.Run(kind,func(t *testing.T){
   root,dir,_,protect:=chainFixture(t,false)
   live:=filepath.Join(root,residentLegacyExe)
   switch kind{
   case "missing-old-exe":
    if err:=os.Remove(live);err!=nil{t.Fatal(err)}
   case "replaced-old-exe":
    if err:=os.WriteFile(live,[]byte("MZ_CI_SIGNED_NEW_MOTOR_DIFFERENT_BYTES"),0600);err!=nil{t.Fatal(err)}
   }
   evidence,err:=auditPostSwitchResidentRecovery(context.Background(),root)
   if err!=nil||evidence.LegacySHA256==""||evidence.TaskXMLSHA256==""||
    evidence.TargetSHA256==""||evidence.IntentNonce==""||evidence.TargetVersion!="0.28.7"{
    t.Fatalf("trusted independent recovery copy was refused after switch: %+v %v",evidence,err)
   }
   if kind!="unchanged-old-exe"{
    if _,err:=auditPendingResidentChain(context.Background(),root);err==nil{
     t.Fatal("pre-switch checker must NEVER accept replaced/missing original")
    }
   }
   state,err:=motorupdate.InspectResidentRecoveryJournal(context.Background(),dir,protect)
   if err!=nil||state.Status!="recovery-required"{
    t.Fatalf("read-only post-switch audit changed pending recovery journal: %+v %v",state,err)
   }
   if _,err:=os.Lstat(filepath.Join(dir,motorupdate.ResidentResultFile));!os.IsNotExist(err){
    t.Fatalf("read-only audit wrote terminal status: %v",err)
   }
  })
 }
}

func TestPostSwitchRecoveryRejectsMismatchedOrTamperedProtectedOriginal(t *testing.T){
 for _,kind:=range []string{"wrong-journal","damaged-exe","damaged-task-xml","missing-receipt","terminal-journal","unexpected-file"}{
  t.Run(kind,func(t *testing.T){
   root,dir,seal,protect:=chainFixture(t,kind=="wrong-journal")
   live:=filepath.Join(root,residentLegacyExe)
   if err:=os.Remove(live);err!=nil{t.Fatal(err)}
   recoveryDir:=filepath.Join(root,residentRecoveryParent,residentRecoveryFolder)
   switch kind{
   case "damaged-exe":
    if err:=os.WriteFile(filepath.Join(recoveryDir,residentRecoveryExe),[]byte("MZ_TAMPERED"),0600);err!=nil{t.Fatal(err)}
   case "damaged-task-xml":
    if err:=os.WriteFile(filepath.Join(recoveryDir,residentRecoveryTask),[]byte("MZ_FAKE_TASK_XML"),0600);err!=nil{t.Fatal(err)}
   case "missing-receipt":
    if err:=os.Remove(filepath.Join(recoveryDir,residentRecoveryReceipt));err!=nil{t.Fatal(err)}
   case "terminal-journal":
    if err:=motorupdate.FinishResidentRecoveryIntent(context.Background(),dir,"committed",seal,protect);err!=nil{t.Fatal(err)}
   case "unexpected-file":
    if err:=os.WriteFile(filepath.Join(recoveryDir,"forged.exe"),[]byte("MZ"),0600);err!=nil{t.Fatal(err)}
   }
   if _,err:=auditPostSwitchResidentRecovery(context.Background(),root);err==nil{
    t.Fatalf("%s bypassed post-switch sealed backup/journal validation",kind)
   }
  })
 }
}

func TestPostSwitchRecoveryAuditRejectsUnsafeRootsAndCancelledContext(t *testing.T){
 root,_,_,_:=chainFixture(t,false)
 for _,p:=range []string{"relative","",filepath.Join(root,"..","elsewhere"),root+"\\."}{
  if _,err:=auditPostSwitchResidentRecovery(context.Background(),p);err==nil{
   t.Fatalf("unsafe/ambiguous root accepted: %q",p)
  }
 }
 cancelled,cancel:=context.WithCancel(context.Background());cancel()
 if _,err:=auditPostSwitchResidentRecovery(cancelled,root);err==nil{
  t.Fatal("cancelled protected original audit accepted")
 }
}

func TestPostSwitchRecoveryDoesNotTreatUnsignedPacketAsPermission(t *testing.T){
 root,_,_,_:=chainFixture(t,false)
 if err:=os.Remove(filepath.Join(root,residentLegacyExe));err!=nil{t.Fatal(err)}
 proof,err:=auditPostSwitchResidentRecovery(context.Background(),root)
 if err!=nil{t.Fatal(err)}
 // This is a read-only snapshot/journal correlation ONLY. There is no
 // signature, authorized action or Windows SYSTEM task re-registration.
 if strings.TrimSpace(proof.LegacySHA256)==""{t.Fatal("missing bounded backup evidence")}
 if _,err:=os.Stat(filepath.Join(root,residentLegacyExe));!os.IsNotExist(err){
  t.Fatalf("read-only recovery audit recreated old motor: %v",err)
 }
}
