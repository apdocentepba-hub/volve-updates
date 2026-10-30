package motorupdate

import (
 "context"
 "errors"
 "os"
 "path/filepath"
 "testing"
)

type residentCompletionLab struct{
 identityCalls,dnsCalls,connectivityCalls int
 failOn string
 onConnectivity func()
}
func (l *residentCompletionLab) VerifyRunningIdentity(_ context.Context,_ ResidentRecoveryIntent,_ string)error{
 l.identityCalls++
 if l.failOn=="identity" || (l.failOn=="identity-recheck" && l.identityCalls==2){
  return errors.New("simulated task/engine identity mismatch")
 }
 return nil
}
func (l *residentCompletionLab) ProbeLocalDNS(context.Context)error{
 l.dnsCalls++
 if l.failOn=="dns"{return errors.New("simulated local DNS outage")}
 return nil
}
func (l *residentCompletionLab) ProbeConnectivity(context.Context)error{
 l.connectivityCalls++
 if l.onConnectivity!=nil{l.onConnectivity()}
 if l.failOn=="network"{return errors.New("simulated Internet outage")}
 return nil
}
func TestResidentCompletionRequiresVerifiedIdentityAndBothProbes(t *testing.T){
 for _,outcome:=range []string{"committed","restored"}{
  t.Run(outcome,func(t *testing.T){
   dir:=t.TempDir()
   if _,err:=ArmResidentRecoveryIntent(context.Background(),dir,residentFixture(),
     residentLabACL,residentLabACL);err!=nil{t.Fatal(err)}
   fake:=&residentCompletionLab{}
   if err:=ConfirmResidentRecoveryOutcome(context.Background(),dir,outcome,
     residentLabACL,residentLabACL,fake);err!=nil{t.Fatal(err)}
   if fake.identityCalls!=2 || fake.dnsCalls!=1 || fake.connectivityCalls!=1{
    t.Fatalf("critical checks missing: %+v",fake)
   }
   state,err:=InspectResidentRecoveryJournal(context.Background(),dir,residentLabACL)
   if err!=nil||state.Status!=outcome{t.Fatalf("terminal not durably verified: %+v %v",state,err)}
   if err:=ConfirmResidentRecoveryOutcome(context.Background(),dir,outcome,
     residentLabACL,residentLabACL,fake);err==nil{
     t.Fatal("already completed recovery journal was reused")
   }
  })
 }
}

func TestResidentCompletionPreservesPendingOnAnyProbeFailure(t *testing.T){
 for _,stage:=range []string{"identity","dns","network","identity-recheck"}{
  t.Run(stage,func(t *testing.T){
   dir:=t.TempDir()
   if _,err:=ArmResidentRecoveryIntent(context.Background(),dir,residentFixture(),
     residentLabACL,residentLabACL);err!=nil{t.Fatal(err)}
   fake:=&residentCompletionLab{failOn:stage}
   if err:=ConfirmResidentRecoveryOutcome(context.Background(),dir,"committed",
     residentLabACL,residentLabACL,fake);err==nil{t.Fatal("false success accepted")}
   state,err:=InspectResidentRecoveryJournal(context.Background(),dir,residentLabACL)
   if err!=nil||state.Status!="recovery-required"{
    t.Fatalf("failed health check consumed recovery journal: %+v %v",state,err)
   }
   if _,err:=os.Stat(filepath.Join(dir,ResidentResultFile));!os.IsNotExist(err){
    t.Fatalf("false terminal receipt written: %v",err)
   }
  })
 }
}

func TestResidentCompletionDetectsJournalChangedDuringProbe(t *testing.T){
 dir:=t.TempDir()
 if _,err:=ArmResidentRecoveryIntent(context.Background(),dir,residentFixture(),
   residentLabACL,residentLabACL);err!=nil{t.Fatal(err)}
 fake:=&residentCompletionLab{}
 fake.onConnectivity=func(){
  // Simulated concurrent writer stole the terminal decision. Never
  // report success or overwrite the existing receipt.
  if err:=FinishResidentRecoveryIntent(context.Background(),dir,"restored",
    residentLabACL,residentLabACL);err!=nil{t.Error(err)}
 }
 if err:=ConfirmResidentRecoveryOutcome(context.Background(),dir,"committed",
   residentLabACL,residentLabACL,fake);err==nil{
  t.Fatal("concurrent journal terminal accepted as a successful commit")
 }
 state,err:=InspectResidentRecoveryJournal(context.Background(),dir,residentLabACL)
 if err!=nil||state.Status!="restored"{
  t.Fatalf("concurrent receipt unexpectedly overwritten: %+v %v",state,err)
 }
}

func TestResidentCompletionRejectsMissingHealthEvidenceAndCancellation(t *testing.T){
 dir:=t.TempDir()
 fake:=&residentCompletionLab{}
 for _,outcome:=range []string{"","success","rolling-back"}{
  if err:=ConfirmResidentRecoveryOutcome(context.Background(),dir,outcome,
   residentLabACL,residentLabACL,fake);err==nil{t.Fatal("unknown outcome accepted: "+outcome)}
 }
 if err:=ConfirmResidentRecoveryOutcome(context.Background(),dir,"committed",
   residentLabACL,residentLabACL,nil);err==nil{
  t.Fatal("missing live health checker accepted")
 }
 if err:=ConfirmResidentRecoveryOutcome(context.Background(),dir,"committed",
   nil,residentLabACL,fake);err==nil{
  t.Fatal("missing ACL sealer accepted")
 }
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 if err:=ConfirmResidentRecoveryOutcome(ctx,dir,"committed",
   residentLabACL,residentLabACL,fake);err==nil{
  t.Fatal("cancelled health verification accepted")
 }
 if fake.identityCalls!=0{t.Fatal("a rejected completion ran the external health gate")}
}


func TestResidentHealthAuditOnlyReadsPendingJournal(t *testing.T) {
 dir:=t.TempDir()
 created,err:=ArmResidentRecoveryIntent(context.Background(),dir,residentFixture(),
  residentLabACL,residentLabACL)
 if err!=nil{t.Fatal(err)}
 audit:=&residentCompletionLab{}
 proof,err:=AuditResidentRecoveryOutcome(context.Background(),dir,"restored",
  residentLabACL,audit)
 if err!=nil||proof!=created{t.Fatalf("read-only audit failed: %v %+v",err,proof)}
 if audit.identityCalls!=2||audit.dnsCalls!=1||audit.connectivityCalls!=1{
  t.Fatalf("health gates not run: %+v",audit)
 }
 if _,err:=os.Stat(filepath.Join(dir,ResidentResultFile));!os.IsNotExist(err){
  t.Fatalf("read-only audit unexpectedly wrote terminal receipt: %v",err)
 }
 again,err:=AuditResidentRecoveryOutcome(context.Background(),dir,"restored",
  residentLabACL,&residentCompletionLab{})
 if err!=nil||again!=proof{t.Fatalf("read-only audit consumed pending journal: %v",err)}
 // Audit is evidence only, and does not prevent a future privileged writer
 // from completing the same transaction after independent confirmation.
 if err:=ConfirmResidentRecoveryOutcome(context.Background(),dir,"restored",
  residentLabACL,residentLabACL,&residentCompletionLab{});err!=nil{t.Fatal(err)}
 if _,err:=AuditResidentRecoveryOutcome(context.Background(),dir,"restored",
  residentLabACL,&residentCompletionLab{});err==nil{
  t.Fatal("completed journal was accepted as still pending")
 }
}

func TestResidentHealthAuditRejectsFailedProbeWithoutMutation(t *testing.T) {
 for _,stage:=range []string{"identity","dns","network","identity-recheck"} {
  t.Run(stage,func(t *testing.T){
   dir:=t.TempDir()
   if _,err:=ArmResidentRecoveryIntent(context.Background(),dir,residentFixture(),
    residentLabACL,residentLabACL);err!=nil{t.Fatal(err)}
   if _,err:=AuditResidentRecoveryOutcome(context.Background(),dir,"committed",
    residentLabACL,&residentCompletionLab{failOn:stage});err==nil{
    t.Fatalf("audit reported false health success for %s",stage)
   }
   state,err:=InspectResidentRecoveryJournal(context.Background(),dir,residentLabACL)
   if err!=nil||state.Status!="recovery-required"{
    t.Fatalf("failed audit consumed recovery: %v %+v",err,state)
   }
   if _,err:=os.Stat(filepath.Join(dir,ResidentResultFile));!os.IsNotExist(err){
    t.Fatalf("failed audit wrote terminal receipt: %v",err)
   }
  })
 }
}
