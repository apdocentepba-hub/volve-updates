package motorupdate

import (
 "context"
 "errors"
 "os"
 "path/filepath"
 "testing"
)

type bootPolicyLab struct{
 lockCalls,unlockCalls,verifyCalls,restoreCalls int
 failStage string
 terminalDuringVerify func()
}
func(l *bootPolicyLab)AcquireExclusive(context.Context)(func(),error){
 l.lockCalls++
 if l.failStage=="lock"{return nil,errors.New("simulated mutex held elsewhere")}
 if l.failStage=="no-release"{return nil,nil}
 return func(){l.unlockCalls++},nil
}
func(l *bootPolicyLab)VerifySealedOriginal(context.Context,ResidentRecoveryIntent)error{
 l.verifyCalls++
 if l.terminalDuringVerify!=nil{l.terminalDuringVerify()}
 if l.failStage=="backup"{return errors.New("simulated corrupted protected backup")}
 return nil
}
func(l *bootPolicyLab)RestoreOriginal(context.Context,ResidentRecoveryIntent)error{
 l.restoreCalls++
 if l.failStage=="restore"{return errors.New("simulated Windows task restore failure")}
 return nil
}
type bootIdentityLab struct{
 checks int
 failFirst bool
 failForever bool
 networkFailure bool
}
func(c *bootIdentityLab) VerifyRunningIdentity(context.Context,ResidentRecoveryIntent,string)error{
 c.checks++
 if c.failForever || (c.failFirst && c.checks==1){return errors.New("original SYSTEM DNS task missing")}
 return nil
}
func(c *bootIdentityLab)ProbeLocalDNS(context.Context)error{return nil}
func(c *bootIdentityLab)ProbeConnectivity(context.Context)error{
 if c.networkFailure{return errors.New("network unreachable")}
 return nil
}

func armBootPolicyJournal(t *testing.T)string{
 t.Helper()
 dir:=t.TempDir()
 if _,err:=ArmResidentRecoveryIntent(context.Background(),dir,residentFixture(),
  residentLabACL,residentLabACL);err!=nil{t.Fatal(err)}
 return dir
}
func TestBootRecoveryRestoresInterruptedOriginalAndConfirmsRealChecks(t *testing.T){
 dir:=armBootPolicyJournal(t)
 lab:=&bootPolicyLab{}
 checks:=&bootIdentityLab{failFirst:true}
 state,err:=RecoverPendingResidentAfterBoot(context.Background(),dir,
  residentLabACL,residentLabACL,checks,lab)
 if err!=nil||state!="restored"{t.Fatalf("recovery not finalized: %s %v",state,err)}
 if lab.lockCalls!=1||lab.unlockCalls!=1||lab.verifyCalls!=1||lab.restoreCalls!=1{
  t.Fatalf("recovery did not use exclusive lock and one restore: %+v",lab)
 }
 if checks.checks!=3{t.Fatalf("expected preflight plus two post-DNS checks: %d",checks.checks)}
 journal,err:=InspectResidentRecoveryJournal(context.Background(),dir,residentLabACL)
 if err!=nil||journal.Status!="restored"{t.Fatalf("terminal recovery not durable: %+v %v",journal,err)}
 // A new watchdog process can re-open the journal and safely NO-OP.
 status,err:=RecoverPendingResidentAfterBoot(context.Background(),dir,
  residentLabACL,residentLabACL,&bootIdentityLab{},lab)
 if err!=nil||status!="restored"{t.Fatalf("idempotent reboot failed: %s %v",status,err)}
 if lab.restoreCalls!=1||lab.unlockCalls!=2{t.Fatalf("terminal result caused repeated task changes: %+v",lab)}
}
func TestBootRecoveryAlreadyOriginalStillRequiresHealth(t *testing.T){
 dir:=armBootPolicyJournal(t)
 lab:=&bootPolicyLab{}
 checks:=&bootIdentityLab{}
 state,err:=RecoverPendingResidentAfterBoot(context.Background(),dir,
  residentLabACL,residentLabACL,checks,lab)
 if err!=nil||state!="restored"||lab.restoreCalls!=0{
  t.Fatalf("healthy original was needlessly switched: %s %v %+v",state,err,lab)
 }
}
func TestBootRecoveryFailureNeverWritesFalseTerminal(t *testing.T){
 for _,failure:=range []string{"lock","no-release","backup","restore","identity","network"}{
  t.Run(failure,func(t *testing.T){
   dir:=armBootPolicyJournal(t)
   lab:=&bootPolicyLab{failStage:failure}
   checks:=&bootIdentityLab{failFirst:true}
   if failure=="identity"{checks.failForever=true}
   if failure=="network"{checks.networkFailure=true}
   _,err:=RecoverPendingResidentAfterBoot(context.Background(),dir,
    residentLabACL,residentLabACL,checks,lab)
   if err==nil{t.Fatal("unsafe reboot was called restored")}
   journal,err:=InspectResidentRecoveryJournal(context.Background(),dir,residentLabACL)
   if err!=nil||journal.Status!="recovery-required"{
    t.Fatalf("failed reboot lost pending record: %+v %v",journal,err)
   }
   if _,err:=os.Lstat(filepath.Join(dir,ResidentResultFile));!os.IsNotExist(err){
    t.Fatalf("unsafe terminal receipt present: %v",err)
   }
   if failure=="lock" && lab.restoreCalls!=0{t.Fatal("failed lock still restored task")}
   if failure!="lock"&&failure!="no-release"&&lab.unlockCalls!=1{
    t.Fatal("exclusive recovery lease was not released after failure")
   }
  })
 }
}
func TestBootRecoveryDetectsConcurrentTerminalBeforeRestore(t *testing.T){
 dir:=armBootPolicyJournal(t)
 lab:=&bootPolicyLab{}
 lab.terminalDuringVerify=func(){
  if err:=FinishResidentRecoveryIntent(context.Background(),dir,"committed",
   residentLabACL,residentLabACL);err!=nil{t.Error(err)}
 }
 _,err:=RecoverPendingResidentAfterBoot(context.Background(),dir,
  residentLabACL,residentLabACL,&bootIdentityLab{failFirst:true},lab)
 if err==nil{t.Fatal("concurrently committed upgrade was incorrectly rolled back")}
 if lab.restoreCalls!=0{t.Fatal("concurrently finished journal led to motor modification")}
 journal,err:=InspectResidentRecoveryJournal(context.Background(),dir,residentLabACL)
 if err!=nil||journal.Status!="committed"{t.Fatalf("journal result overwritten: %+v %v",journal,err)}
}
func TestBootRecoverySkipsUnarmedAndTerminalTransactions(t *testing.T){
 for _,kind:=range []string{"not-armed","committed","restored"}{
  t.Run(kind,func(t *testing.T){
   dir:=t.TempDir()
   if kind!="not-armed"{
    if _,err:=ArmResidentRecoveryIntent(context.Background(),dir,residentFixture(),
     residentLabACL,residentLabACL);err!=nil{t.Fatal(err)}
    if err:=FinishResidentRecoveryIntent(context.Background(),dir,kind,
     residentLabACL,residentLabACL);err!=nil{t.Fatal(err)}
   }
   lab:=&bootPolicyLab{}
   actual,err:=RecoverPendingResidentAfterBoot(context.Background(),dir,
    residentLabACL,residentLabACL,&bootIdentityLab{},lab)
   if err!=nil||actual!=kind{t.Fatalf("terminal/no-op failed: %s %v",actual,err)}
   if lab.verifyCalls!=0||lab.restoreCalls!=0{t.Fatal("inactive journal triggered task operation")}
  })
 }
}
func TestBootRecoveryRefusesInvalidInputsOrCancellation(t *testing.T){
 dir:=armBootPolicyJournal(t)
 lab:=&bootPolicyLab{}
 for _,tc:=range []struct{
  seal,protect func(string)error
  checks ResidentCompletionChecks
  driver ResidentBootRecoveryDriver
 }{
  {residentLabACL,residentLabACL,nil,lab},
  {nil,residentLabACL,&bootIdentityLab{},lab},
  {residentLabACL,nil,&bootIdentityLab{},lab},
  {residentLabACL,residentLabACL,&bootIdentityLab{},nil},
 }{
  if _,err:=RecoverPendingResidentAfterBoot(context.Background(),dir,
   tc.seal,tc.protect,tc.checks,tc.driver);err==nil{
   t.Fatal("unsafe incomplete boot policy accepted")
  }
 }
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 if _,err:=RecoverPendingResidentAfterBoot(ctx,dir,
  residentLabACL,residentLabACL,&bootIdentityLab{},lab);err==nil{
  t.Fatal("cancelled boot recovery started")
 }
 if lab.lockCalls!=0{t.Fatal("invalid recovery acquired privileged lease")}
}
