//go:build windows

package main

import (
 "context"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "testing"

 "volve-browser-protection/motorupdate"
)

// Boot audit tests operate on a disposable protected snapshot/journal only.
// The actual Windows Task Scheduler and DNS/53 remain untouched.
func TestIndependentBootAuditNeverTreatsPendingAsCommitted(t *testing.T){
 root,dir,seal,protect:=chainFixture(t,false)
 plan,err:=auditResidentBootPlan(context.Background(),root)
 if err!=nil||plan.Status!="recovery-required"||plan.Action!="recover-original"{
  t.Fatalf("read-only boot plan did not detect interrupted update: %+v %v",plan,err)
 }
 if err:=motorupdate.FinishResidentRecoveryIntent(context.Background(),dir,
   "restored",seal,protect);err!=nil{t.Fatal(err)}
 plan,err=auditResidentBootPlan(context.Background(),root)
 if err!=nil||plan.Status!="restored"||plan.Action!="no-action" {
  t.Fatalf("completed recovery triggered a second restore: %+v %v",plan,err)
 }
}

func TestIndependentBootAuditPlansRecoveryAfterOldMotorDisappearsOrIsReplaced(t *testing.T){
 for _,stage:=range []string{"removed","overwritten","intact"} {
  t.Run(stage,func(t *testing.T){
   root,dir,_,protect:=chainFixture(t,false)
   live:=filepath.Join(root,residentLegacyExe)
   switch stage {
   case "removed":
    if err:=os.Remove(live);err!=nil{t.Fatal(err)}
   case "overwritten":
    if err:=os.WriteFile(live,[]byte("MZ_different_incomplete_motor"),0600);err!=nil{t.Fatal(err)}
   }
   // A pre-switch verifier MUST refuse a modified/missing live motor.
   // After a crash, however, the independent signed-backup decision must
   // succeed without rewriting that live path or resolving DNS.
   if stage!="intact" {
    if _,err:=auditPendingResidentChain(context.Background(),root);err==nil {
     t.Fatal("pre-switch motor proof accepted missing/replaced live executable")
    }
   }
   plan,err:=auditResidentBootPlan(context.Background(),root)
   if err!=nil || plan.Status!="recovery-required" ||
    plan.Action!="recover-original" || plan.LegacySHA256==""{
    t.Fatalf("boot lost its pending protected rollback when live exe %s: %+v %v",stage,plan,err)
   }
   current,err:=motorupdate.InspectResidentRecoveryJournal(context.Background(),dir,protect)
   if err!=nil || current.Status!="recovery-required"{
    t.Fatalf("boot audit consumed the journal: %+v %v",current,err)
   }
   if _,err:=os.Stat(live);stage=="removed" && !os.IsNotExist(err){
    t.Fatalf("read-only boot audit unexpectedly recreated installed EXE: %v",err)
   }
  })
 }
}

func TestIndependentBootAuditRejectsTamperedProtectedBackupAfterLiveMotorMissing(t *testing.T) {
 for _,item:=range []string{residentRecoveryExe,residentRecoveryTask,residentRecoveryReceipt}{
  t.Run(item,func(t *testing.T){
   root,_,_,_:=chainFixture(t,false)
   if err:=os.Remove(filepath.Join(root,residentLegacyExe));err!=nil{t.Fatal(err)}
   protected:=filepath.Join(root,residentRecoveryParent,residentRecoveryFolder,item)
   if err:=os.WriteFile(protected,[]byte("MZ_tampered_backup"),0600);err!=nil{t.Fatal(err)}
   if plan,err:=auditResidentBootPlan(context.Background(),root);err==nil{
    t.Fatalf("tampered protected %s was accepted: %+v",item,plan)
   }
  })
 }
}

func TestIndependentBootAuditReadOnlyCLIChild(t *testing.T){
 if os.Getenv("VOLVE_CI_BOOT_PLAN_CHILD")!="yes"{return}
 root:=os.Getenv("VOLVE_CI_BOOT_PLAN_ROOT")
 if root==""{t.Fatal("missing CI-only boot audit root")}
 os.Args=[]string{os.Args[0],"--audit-resident-boot-plan",root}
 main()
}

func TestIndependentBootAuditAcrossFreshProcesses(t *testing.T){
 root,dir,seal,protect:=chainFixture(t,false)
 invoke:=func()([]byte,error){
  cmd:=exec.Command(os.Args[0],"-test.run=^TestIndependentBootAuditReadOnlyCLIChild$")
  cmd.Env=append(os.Environ(),"VOLVE_CI_BOOT_PLAN_CHILD=yes",
   "VOLVE_CI_BOOT_PLAN_ROOT="+root)
  return cmd.CombinedOutput()
 }
 raw,err:=invoke()
 if err!=nil||!strings.Contains(string(raw),"Acción verificada: recover-original")||
    !strings.Contains(string(raw),"Estado: recovery-required")||
    !strings.Contains(string(raw),"SOLO LECTURA"){
  t.Fatalf("new independent watchdog missed pending rollback: %v %s",err,raw)
 }
 if err:=motorupdate.FinishResidentRecoveryIntent(context.Background(),dir,
   "committed",seal,protect);err!=nil{t.Fatal(err)}
 raw,err=invoke()
 if err!=nil||!strings.Contains(string(raw),"Acción verificada: no-action")||
    !strings.Contains(string(raw),"Estado: committed"){
  t.Fatalf("watchdog attempted repeat after valid terminal: %v %s",err,raw)
 }
}

func TestIndependentBootAuditDeniedForUnsafeJournal(t *testing.T){
 root,dir,_,_:=chainFixture(t,false)
 intent:=filepath.Join(dir,motorupdate.ResidentIntentFile)
 if err:=os.WriteFile(intent,[]byte("truncated JSON"),0600);err!=nil{t.Fatal(err)}
 if _,err:=auditResidentBootPlan(context.Background(),root);err==nil{
  t.Fatal("invalid pending boot journal returned a recovery plan")
 }
}


func TestIndependentBootAuditRejectsAlteredSnapshotBeforeAnyPlan(t *testing.T){
 root,_,_,_:=chainFixture(t,false)
 taskXML:=filepath.Join(root,residentRecoveryParent,residentRecoveryFolder,residentRecoveryTask)
 if err:=os.WriteFile(taskXML,[]byte("MALFORMED SYSTEM TASK XML"),0600);err!=nil{t.Fatal(err)}
 if plan,err:=auditResidentBootPlan(context.Background(),root);err==nil{
  t.Fatalf("tampered protected recovery XML was accepted: %+v",plan)
 }
}

func TestIndependentBootAuditRejectsForgedTerminalReceipt(t *testing.T){
 root,dir,seal,protect:=chainFixture(t,false)
 if err:=motorupdate.FinishResidentRecoveryIntent(context.Background(),dir,
  "committed",seal,protect);err!=nil{t.Fatal(err)}
 result:=filepath.Join(dir,motorupdate.ResidentResultFile)
 if err:=os.WriteFile(result,[]byte(`{"schema":1,"component":"dns-engine-recovery-result","outcome":"committed"}`),0600);err!=nil{t.Fatal(err)}
 if plan,err:=auditResidentBootPlan(context.Background(),root);err==nil{
  t.Fatalf("forged success receipt caused a false no-op plan: %+v",plan)
 }
}
