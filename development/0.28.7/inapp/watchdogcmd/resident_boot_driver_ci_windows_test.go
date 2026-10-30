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
}
func(h *ciBootHealth) VerifyRunningIdentity(_ context.Context,
 _ motorupdate.ResidentRecoveryIntent,outcome string) error{
 h.identityChecks++
 if outcome!="restored"{return errors.New("CI recovery cannot confirm candidate")}
 if h.firstOriginalMissing && h.identityChecks==1{return errors.New("simulated original task missing")}
 return nil
}
func(h *ciBootHealth)ProbeLocalDNS(context.Context)error{
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
