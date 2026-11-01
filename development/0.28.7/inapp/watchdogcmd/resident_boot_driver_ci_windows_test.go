//go:build windows

package main

// CI-only integration of the actual boot policy, protected Windows NTFS
// recovery bundle and real OS mutex. PowerShell task changes are injected
// as harmless synthetic results; no task, DNS or system policy is modified.
import (
 "context"
 "errors"
 "os"
 "path/filepath"
 "strings"
 "testing"

 "volve-browser-protection/motorupdate"
)

type ciBootHealth struct{
 identityChecks int
 firstOriginalMissing bool
 rejectDNS bool
 rejectNetwork bool
 afterDNSProbe func()error
}
func(h *ciBootHealth) VerifyRunningIdentity(_ context.Context,
 _ motorupdate.ResidentRecoveryIntent,outcome string) error{
 h.identityChecks++
 if outcome!="restored"{return errors.New("CI recovery cannot confirm candidate")}
 if h.firstOriginalMissing && h.identityChecks==1{return errors.New("simulated original task missing")}
 return nil
}
func(h *ciBootHealth)ProbeLocalDNS(context.Context)error{
 if h.afterDNSProbe!=nil{if err:=h.afterDNSProbe();err!=nil{return err}}
 if h.rejectDNS{return errors.New("simulated DNS failure")}
 return nil
}
func(h *ciBootHealth)ProbeConnectivity(context.Context)error{
 if h.rejectNetwork{return errors.New("simulated offline recovery")}
 return nil
}

func TestResidentCIBootDriverIntegratesProtectedChainMutexAndPolicy(t *testing.T){
 root,dir,seal,protect:=chainFixture(t,false)
 ran:=0
 driver,err:=newResidentCIBootDriver(root,disposableResidentTask,
  func(_ context.Context,script string)(string,error){
   ran++
   for _,token:=range []string{"Register-ScheduledTask","Get-ScheduledTask",
    "VOLVE_CI_RESIDENT_RESTORED",disposableResidentTask,"$oldHash","$xmlHash"}{
    if !strings.Contains(script,token){t.Fatalf("CI-only Windows recovery missing %q",token)}
   }
   return "VOLVE_CI_RESIDENT_RESTORED",nil
  })
 if err!=nil{t.Fatal(err)}
 health:=&ciBootHealth{firstOriginalMissing:true}
 outcome,err:=motorupdate.RecoverPendingResidentAfterBoot(context.Background(),
  dir,seal,protect,health,driver)
 if err!=nil||outcome!="restored"{t.Fatalf("CI boot recovery failed: %s %v",outcome,err)}
 if ran!=1||health.identityChecks!=3{
  t.Fatalf("boot driver failed OS lock/restore/health sequence: calls=%d identity=%d",ran,health.identityChecks)
 }
 state,err:=motorupdate.InspectResidentRecoveryJournal(context.Background(),dir,protect)
 if err!=nil||state.Status!="restored"{t.Fatalf("CI protected journal did not finalize: %+v %v",state,err)}
 again,err:=motorupdate.RecoverPendingResidentAfterBoot(context.Background(),
  dir,seal,protect,&ciBootHealth{},driver)
 if err!=nil||again!="restored"||ran!=1{
  t.Fatalf("second boot replayed finished recovery: %s %v, calls=%d",again,err,ran)
 }
}

func TestResidentCIBootDriverNeverCertifiesFailedDNSOrBrokenSnapshot(t *testing.T){
 for _,stage:=range []string{"dns","changed-original","powershell-failure"} {
  t.Run(stage,func(t *testing.T){
   root,dir,seal,protect:=chainFixture(t,false)
   called:=0
   driver,err:=newResidentCIBootDriver(root,disposableResidentTask,
    func(context.Context,string)(string,error){
     called++
     if stage=="powershell-failure"{return "",errors.New("simulated broken restore")}
     return "VOLVE_CI_RESIDENT_RESTORED",nil
    })
   if err!=nil{t.Fatal(err)}
   if stage=="changed-original" {
    if err:=os.WriteFile(filepath.Join(root,residentLegacyExe),[]byte("tampered"),0600);err!=nil{t.Fatal(err)}
   }
   health:=&ciBootHealth{firstOriginalMissing:true,rejectDNS:stage=="dns"}
   if _,err:=motorupdate.RecoverPendingResidentAfterBoot(context.Background(),
    dir,seal,protect,health,driver);err==nil{
    t.Fatal("unhealthy or tampered CI boot was accepted")
   }
   if stage=="changed-original"&&called!=0{t.Fatal("damaged protected original reached restore runner")}
   state,err:=motorupdate.InspectResidentRecoveryJournal(context.Background(),dir,protect)
   if err!=nil||state.Status!="recovery-required"{
    t.Fatalf("failed recovery consumed pending journal: %+v %v",state,err)
   }
  })
 }
}

func TestResidentCIBootDriverRejectsProductiveTaskBeforeOSLock(t *testing.T){
 for _,task:=range []string{"VOLVE-DNS-SERVER-0270","VOLVE-CI-BootRecovery-123456789012",
 "VOLVE-CI-ManagedMotor-42","../../VOLVE-CI-ManagedMotor-123456789012"} {
  if d,err:=newResidentCIBootDriver(t.TempDir(),task,
   func(context.Context,string)(string,error){t.Fatal("unsafe Windows runner invoked");return "",nil});err==nil||d!=nil{
   t.Fatalf("CI-only driver accepted unowned task %q",task)
  }
 }
 if d,err:=newResidentCIBootDriver(t.TempDir(),disposableResidentTask,nil);err==nil||d!=nil{
  t.Fatal("CI boot driver accepted missing privileged task executor")
 }
}

func TestResidentCIBootDriverRejectsBackupDriftDuringDNSProbe(t *testing.T){
 root,dir,seal,protect:=chainFixture(t,false)
 restored:=0
 driver,err:=newResidentCIBootDriver(root,disposableResidentTask,
  func(context.Context,string)(string,error){
   restored++
   return "VOLVE_CI_RESIDENT_RESTORED",nil
  })
 if err!=nil{t.Fatal(err)}
 health:=&ciBootHealth{}
 altered:=false
 health.afterDNSProbe=func()error{
  health.afterDNSProbe=nil
  // Synthetic NTFS recovery fixture in the ephemeral Windows CI VM only:
  // corrupt the sealed backup AFTER its first independent verification,
  // not the live executable: recovery still depends on the protected copy.
  if err:=os.WriteFile(filepath.Join(root,residentRecoveryParent,residentRecoveryFolder,residentRecoveryExe),[]byte("MZ_CI_CHANGED_PROTECTED_FALLBACK_DURING_NETWORK_HEALTH"),0600);err!=nil{return err}
  altered=true
  return nil
 }
 outcome,err:=motorupdate.RecoverPendingResidentAfterBoot(context.Background(),
  dir,seal,protect,health,driver)
 if err==nil||outcome!=""||!altered||!strings.Contains(err.Error(),"original recovery snapshot changed during health checks"){
  t.Fatalf("second sealed fallback recheck not proven: altered=%v outcome=%s err=%v",altered,outcome,err)
 }
 if restored!=0||health.identityChecks!=3{
  t.Fatalf("changed original caused unapproved restore or skipped health: %d checks=%d",restored,health.identityChecks)
 }
 state,err:=motorupdate.InspectResidentRecoveryJournal(context.Background(),dir,protect)
 if err!=nil||state.Status!="recovery-required"{
  t.Fatalf("corrupt fallback lost pending recovery evidence: %+v %v",state,err)
 }
 if _,err:=os.Lstat(filepath.Join(dir,motorupdate.ResidentResultFile));!os.IsNotExist(err){
  t.Fatalf("restore receipt appeared despite fallback tamper: %v",err)
 }
}


func TestResidentCIBootDriverRebuildsMissingExeBeforeTaskRecovery(t *testing.T){
 if os.Getenv("GITHUB_ACTIONS")!="true" || os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted" {
  t.Skip("requires disposable GitHub-hosted Windows VM and temp-only fixture")
 }
 root,dir,seal,protect:=chainFixture(t,false)
 live:=filepath.Join(root,residentLegacyExe)
 if err:=os.Remove(live);err!=nil{t.Fatal(err)}
 ran:=0
 driver,err:=newResidentCIBootDriver(root,disposableResidentTask,
  func(_ context.Context,script string)(string,error){
   ran++
   if !strings.Contains(script,"Register-ScheduledTask")||
      !strings.Contains(script,disposableResidentTask){
    return "",errors.New("missing isolated SYSTEM task restore contract")
   }
   return "VOLVE_CI_RESIDENT_RESTORED",nil
  })
 if err!=nil{t.Fatal(err)}
 health:=&ciBootHealth{firstOriginalMissing:true}
 state,err:=motorupdate.RecoverPendingResidentAfterBoot(context.Background(),
  dir,seal,protect,health,driver)
 if err!=nil || state!="restored" || ran!=1 {
  t.Fatalf("missing motor not recovered by isolated boot chain: state=%q calls=%d err=%v",state,ran,err)
 }
 if _,err:=auditPendingResidentChain(context.Background(),root);err==nil {
  // Once journal is terminal the pre-switch pending audit must not be reused.
  t.Fatal("pre-switch audit accepted a terminal recovery journal")
 }
 if got,err:=digestResidentLive(context.Background(),live);err!=nil || got=="" {
  t.Fatalf("missing original EXE was not physically recovered from protected bytes: %s %v",got,err)
 }
 old,err:=auditResidentRollback(context.Background(),root)
 if err!=nil{t.Fatal(err)}
 hash,err:=digestResidentLive(context.Background(),live)
 if err!=nil || hash!=old.LegacySHA256 {
  t.Fatalf("restored original bytes differ from sealed recovery copy: %s %v",hash,err)
 }
 if _,err:=os.Lstat(filepath.Join(dir,motorupdate.ResidentResultFile));err!=nil {
  t.Fatalf("boot recovered DNS but did not publish durable terminal receipt: %v",err)
 }
}

func TestResidentCIBootDriverRestoresExactJournalPinnedCandidateThenHealthChecks(t *testing.T){
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{
  t.Skip("only hosted disposable CI Windows sandbox may replace a lab executable")
 }
 root,dir,seal,protect:=chainFixture(t,false)
 live:=filepath.Join(root,residentLegacyExe)
 original,err:=os.ReadFile(live);if err!=nil{t.Fatal(err)}
 // The exact synthetic target hash was pinned before the recovery journal
 // was armed. This is a CI fixture, NOT a signed production candidate.
 if err:=os.WriteFile(live,[]byte("publisher-signed candidate CI bytes"),0600);err!=nil{t.Fatal(err)}
 runnerCalled:=0
 driver,err:=newResidentCIBootDriver(root,disposableResidentTask,
  func(_ context.Context,script string)(string,error){
   runnerCalled++
   if !strings.Contains(script,"Register-ScheduledTask"){return "",errors.New("missing real restore command")}
   recovered,err:=os.ReadFile(live)
   if err!=nil || string(recovered)!=string(original){
    return "",errors.New("task restoration attempted BEFORE physical original was recovered")
   }
   return "VOLVE_CI_RESIDENT_RESTORED",nil
  })
 if err!=nil{t.Fatal(err)}
 health:=&ciBootHealth{firstOriginalMissing:true}
 status,err:=motorupdate.RecoverPendingResidentAfterBoot(context.Background(),
  dir,seal,protect,health,driver)
 if err!=nil || status!="restored" || runnerCalled!=1 || health.identityChecks!=3{
  t.Fatalf("replaced executable not recovered in correct order: status=%s calls=%d checks=%d err=%v",
   status,runnerCalled,health.identityChecks,err)
 }
 got,err:=os.ReadFile(live)
 if err!=nil || string(got)!=string(original){t.Fatalf("original bytes not restored: %v",err)}
 after,err:=motorupdate.InspectResidentRecoveryJournal(context.Background(),dir,protect)
 if err!=nil || after.Status!="restored"{
  t.Fatalf("health-check completion was not reflected in trusted journal: %+v %v",after,err)
 }
}
