package motorupdate

import (
 "context"
 "encoding/json"
 "errors"
 "os"
 "path/filepath"
 "testing"
)

type bootPolicyLab struct{
 lockCalls,unlockCalls,verifyCalls,restoreCalls int
 failStage string
 failVerifyAt int
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
 if l.failStage=="backup" || (l.failVerifyAt>0 && l.verifyCalls==l.failVerifyAt){return errors.New("simulated corrupted protected backup")}
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
 if lab.lockCalls!=1||lab.unlockCalls!=1||lab.verifyCalls!=2||lab.restoreCalls!=1{
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


func TestBootRecoveryRetryAfterRestoreSucceededButHealthFailed(t *testing.T){
 dir:=armBootPolicyJournal(t)
 lab:=&bootPolicyLab{}
 checks:=&bootIdentityLab{failFirst:true,networkFailure:true}
 // A crash or failed network probe AFTER restoring the original cannot
 // produce a terminal receipt. The next independent boot must safely retry.
 if _,err:=RecoverPendingResidentAfterBoot(context.Background(),dir,
  residentLabACL,residentLabACL,checks,lab);err==nil{
  t.Fatal("DNS restored without network confirmation")
 }
 if lab.restoreCalls!=1{t.Fatalf("original motor was not restored once: %+v",lab)}
 state,err:=InspectResidentRecoveryJournal(context.Background(),dir,residentLabACL)
 if err!=nil||state.Status!="recovery-required"{t.Fatalf("interrupted boot lost pending transaction: %v %+v",err,state)}
 // A later invocation observes the original motor still running and should
 // finalize after fresh DNS/network probes WITHOUT re-switching the task.
 checks.networkFailure=false
 status,err:=RecoverPendingResidentAfterBoot(context.Background(),dir,
  residentLabACL,residentLabACL,checks,lab)
 if err!=nil||status!="restored"{t.Fatalf("second boot could not recover: %s %v",status,err)}
 if lab.restoreCalls!=1||lab.lockCalls!=2||lab.unlockCalls!=2{
  t.Fatalf("boot retry switched task twice or leaked mutex: %+v",lab)
 }
 final,err:=InspectResidentRecoveryJournal(context.Background(),dir,residentLabACL)
 if err!=nil||final.Status!="restored"{t.Fatalf("journal did not finalize after healthy retry: %+v %v",final,err)}
}

func TestBootRecoveryRejectsCorruptIntentWithoutTouchingMotor(t *testing.T){
 dir:=armBootPolicyJournal(t)
 intentFile:=filepath.Join(dir,ResidentIntentFile)
 if err:=os.WriteFile(intentFile,[]byte("{\"schema\":1"),0600);err!=nil{t.Fatal(err)}
 lab:=&bootPolicyLab{}
 if _,err:=RecoverPendingResidentAfterBoot(context.Background(),dir,
  residentLabACL,residentLabACL,&bootIdentityLab{},lab);err==nil{
  t.Fatal("partial/corrupt recovery intent was trusted")
 }
 if lab.verifyCalls!=0||lab.restoreCalls!=0{t.Fatal("corrupt journal triggered privileged task operation")}
 if _,err:=os.Lstat(filepath.Join(dir,ResidentResultFile));!os.IsNotExist(err){
  t.Fatalf("corrupt journal incorrectly finalized: %v",err)
 }
}

func TestBootRecoveryRechecksSealedOriginalAfterHealthyDNSBeforeTerminal(t *testing.T){
 dir:=armBootPolicyJournal(t)
 lab:=&bootPolicyLab{failVerifyAt:2}
 checks:=&bootIdentityLab{}
 state,err:=RecoverPendingResidentAfterBoot(context.Background(),dir,
  residentLabACL,residentLabACL,checks,lab)
 if err==nil||state!=""{t.Fatalf("damaged sealed original incorrectly finalized: %s %v",state,err)}
 if lab.verifyCalls!=2||lab.restoreCalls!=0||lab.unlockCalls!=1{
  t.Fatalf("second sealed-original recheck not enforced or changed healthy original: %+v",lab)
 }
 if checks.checks!=3{t.Fatalf("health checks unexpectedly skipped: %d",checks.checks)}
 pending,err:=InspectResidentRecoveryJournal(context.Background(),dir,residentLabACL)
 if err!=nil||pending.Status!="recovery-required"{
  t.Fatalf("damaged original claimed restored in journal: %+v %v",pending,err)
 }
 if _,err:=os.Lstat(filepath.Join(dir,ResidentResultFile));!os.IsNotExist(err){
  t.Fatalf("terminal receipt written despite lost fallback: %v",err)
 }
 // On a subsequent independent boot, only a freshly verified fallback
 // can allow successful closure. No unnecessary task restore is permitted.
 lab.failVerifyAt=0
 state,err=RecoverPendingResidentAfterBoot(context.Background(),dir,
  residentLabACL,residentLabACL,&bootIdentityLab{},lab)
 if err!=nil||state!="restored"||lab.restoreCalls!=0||lab.verifyCalls!=4{
  t.Fatalf("healthy retry did not safely close pending journal: %s %v %+v",state,err,lab)
 }
}

func TestBootRecoveryNeverWritesRestoredReceiptWhenOriginalChangesAfterRestore(t *testing.T){
 dir:=armBootPolicyJournal(t)
 lab:=&bootPolicyLab{failVerifyAt:2}
 checks:=&bootIdentityLab{failFirst:true}
 state,err:=RecoverPendingResidentAfterBoot(context.Background(),dir,
  residentLabACL,residentLabACL,checks,lab)
 if err==nil||state!=""||lab.restoreCalls!=1||lab.verifyCalls!=2{
  t.Fatalf("post-restore corrupted snapshot was incorrectly accepted: %s %v %+v",state,err,lab)
 }
 pending,err:=InspectResidentRecoveryJournal(context.Background(),dir,residentLabACL)
 if err!=nil||pending.Status!="recovery-required"{
  t.Fatalf("post-restore corrupted fallback consumed pending intent: %+v %v",pending,err)
 }
}


// Contract tests only: no OS mutations. The real native SYSTEM adapter must
// implement the stopped-candidate proof and signed census separately.
type bootDNSPolicyLab struct{
 bootPolicyLab
 dnsRestores,dnsChecks,startCalls int
 failDNSRestore bool
 failDNSCheckAt int
 failStart bool
 order []string
}
func(l *bootDNSPolicyLab)RestoreOriginalDNS(context.Context,ResidentRecoveryIntent)error{
 if l.lockCalls!=l.unlockCalls+1{return errors.New("DNS restore outside exclusive lease")}
 l.order=append(l.order,"restore-dns")
 l.dnsRestores++
 if l.failDNSRestore{return errors.New("simulated DNS recovery failure")}
 return nil
}
func(l *bootDNSPolicyLab)VerifyOriginalDNS(context.Context,ResidentRecoveryIntent)error{
 if l.lockCalls!=l.unlockCalls+1{return errors.New("DNS readback outside exclusive lease")}
 l.order=append(l.order,"verify-dns")
 l.dnsChecks++
 if l.dnsChecks==l.failDNSCheckAt{return errors.New("simulated original DNS mismatch")}
 return nil
}
func(l *bootDNSPolicyLab)StartOriginal(context.Context,ResidentRecoveryIntent)error{
 if l.lockCalls!=l.unlockCalls+1{return errors.New("original motor start outside exclusive lease")}
 l.order=append(l.order,"start-original")
 l.startCalls++
 if l.failStart{return errors.New("simulated original motor start failure")}
 return nil
}
func TestDNSAwareBootRecoveryChecksOriginalEvenWhenMotorAlreadyRunning(t *testing.T){
 dir:=armBootPolicyJournal(t)
 lab:=&bootDNSPolicyLab{}
 checks:=&bootIdentityLab{}
 state,err:=RecoverPendingResidentAfterBootWithOriginalDNS(context.Background(),dir,residentLabACL,residentLabACL,checks,lab)
 if err!=nil||state!="restored"||lab.restoreCalls!=0||lab.dnsRestores!=1||lab.dnsChecks!=2||lab.startCalls!=1||lab.unlockCalls!=1{
  t.Fatalf("DNS recovery/start order incomplete: %s %v %+v",state,err,lab)
 }
 state,err=RecoverPendingResidentAfterBootWithOriginalDNS(context.Background(),dir,residentLabACL,residentLabACL,checks,lab)
 if err!=nil||state!="restored"||lab.dnsRestores!=1||lab.dnsChecks!=2||lab.startCalls!=1{t.Fatal("terminal receipt triggered DNS or motor mutations")}
}
func TestDNSAwareBootRecoveryNeverFinalizesOnWrongOriginalDNS(t *testing.T){
 for _,tc:=range []struct{name string;restoreFail bool;checkAt int;identityFail bool;networkFail bool;expectedDNSCalls int}{
  {"restore-fails",true,0,false,false,1},
  {"initial-readback-fails",false,1,false,false,1},
  {"final-readback-fails-after-healthy-network",false,2,false,false,1},
  {"motor-still-wrong",false,0,true,false,1},
  {"network-fails",false,0,false,true,1},
 }{
  t.Run(tc.name,func(t *testing.T){
   dir:=armBootPolicyJournal(t)
   lab:=&bootDNSPolicyLab{failDNSRestore:tc.restoreFail,failDNSCheckAt:tc.checkAt}
   checks:=&bootIdentityLab{failForever:tc.identityFail,networkFailure:tc.networkFail}
   state,err:=RecoverPendingResidentAfterBootWithOriginalDNS(context.Background(),dir,residentLabACL,residentLabACL,checks,lab)
   if err==nil||state!=""||lab.dnsRestores!=tc.expectedDNSCalls||lab.unlockCalls!=1{t.Fatalf("unsafe completion or restore: %s %v %+v",state,err,lab)}
   journal,e:=InspectResidentRecoveryJournal(context.Background(),dir,residentLabACL)
   if e!=nil||journal.Status!="recovery-required"{t.Fatalf("lost pending journal: %+v %v",journal,e)}
   if _,e:=os.Lstat(filepath.Join(dir,ResidentResultFile));!os.IsNotExist(e){t.Fatal("failure created terminal receipt")}
   // Retry after a recoverable fault. A new audit must prove both original
   // DNS readbacks, not reuse the prior successful connectivity result.
   lab.failDNSRestore=false
   lab.failDNSCheckAt=0
   checks.failForever=false
   checks.networkFailure=false
   state,err=RecoverPendingResidentAfterBootWithOriginalDNS(context.Background(),dir,residentLabACL,residentLabACL,checks,lab)
   if err!=nil||state!="restored"||lab.unlockCalls!=2{t.Fatalf("safe retry failed: %s %v",state,err)}
  })
 }
}

func TestDNSAwareBootRecoveryStartsOriginalOnlyAfterDNSReadback(t *testing.T){
 dir:=armBootPolicyJournal(t)
 lab:=&bootDNSPolicyLab{}
 checks:=&bootIdentityLab{}
 state,err:=RecoverPendingResidentAfterBootWithOriginalDNS(context.Background(),dir,residentLabACL,residentLabACL,checks,lab)
 if err!=nil||state!="restored"{t.Fatalf("ordered DNS recovery failed: %s %v",state,err)}
 want:=[]string{"restore-dns","verify-dns","start-original","verify-dns"}
 if len(lab.order)!=len(want){t.Fatalf("unexpected recovery sequence: %#v",lab.order)}
 for i:=range want{if lab.order[i]!=want[i]{t.Fatalf("recovery order[%d]=%q want %q; full=%#v",i,lab.order[i],want[i],lab.order)}}
 if lab.startCalls!=1||lab.unlockCalls!=1{t.Fatalf("start not under one exclusive recovery lease: %+v",lab)}
}
func TestDNSAwareBootRecoveryStartFailureKeepsJournalPending(t *testing.T){
 dir:=armBootPolicyJournal(t)
 lab:=&bootDNSPolicyLab{failStart:true}
 state,err:=RecoverPendingResidentAfterBootWithOriginalDNS(context.Background(),dir,residentLabACL,residentLabACL,&bootIdentityLab{},lab)
 if err==nil||state!=""||lab.startCalls!=1||lab.unlockCalls!=1{t.Fatalf("failed original start was treated as success: %s %v %+v",state,err,lab)}
 journal,e:=InspectResidentRecoveryJournal(context.Background(),dir,residentLabACL)
 if e!=nil||journal.Status!="recovery-required"{t.Fatalf("failed start consumed recovery journal: %+v %v",journal,e)}
 if _,e:=os.Lstat(filepath.Join(dir,ResidentResultFile));!os.IsNotExist(e){t.Fatal("failed original start wrote terminal receipt")}
}

func TestDNSAwareBootRecoveryRequiresExplicitDriverAndContext(t *testing.T){
 dir:=armBootPolicyJournal(t)
 checks:=&bootIdentityLab{}
 if _,err:=RecoverPendingResidentAfterBootWithOriginalDNS(context.Background(),dir,residentLabACL,residentLabACL,checks,nil);err==nil{t.Fatal("missing DNS recovery driver accepted")}
 lab:=&bootDNSPolicyLab{}
 if _,err:=RecoverPendingResidentAfterBootWithOriginalDNS(nil,dir,residentLabACL,residentLabACL,checks,lab);err==nil||lab.lockCalls!=0{t.Fatal("missing context acquired privileged lease")}
}


func TestDNSAwareBootRecoveryRejectsMotorOnlyDispatch(t *testing.T){
 dir:=armBootPolicyJournal(t)
 lab:=&bootDNSPolicyLab{}
 var base ResidentBootRecoveryDriver=lab
 checks:=&bootIdentityLab{}
 state,err:=RecoverPendingResidentAfterBoot(context.Background(),dir,residentLabACL,residentLabACL,checks,base)
 if err==nil||state!=""||lab.lockCalls!=0||lab.verifyCalls!=0||lab.restoreCalls!=0||lab.dnsRestores!=0||lab.dnsChecks!=0||checks.checks!=0{
  t.Fatalf("DNS-capable driver incorrectly entered motor-only recovery: %s %v %+v",state,err,lab)
 }
 pending,err:=InspectResidentRecoveryJournal(context.Background(),dir,residentLabACL)
 if err!=nil||pending.Status!="recovery-required"{t.Fatalf("wrong entrypoint consumed pending recovery: %+v %v",pending,err)}
 state,err=RecoverPendingResidentAfterBootWithOriginalDNS(context.Background(),dir,residentLabACL,residentLabACL,checks,lab)
 if err!=nil||state!="restored"||lab.dnsRestores!=1||lab.dnsChecks!=2||lab.startCalls!=1||lab.unlockCalls!=1{t.Fatalf("correct dispatch failed: %s %v %+v",state,err,lab)}
}


type partialBootLeaseLab struct{bootPolicyLab}
func(l *partialBootLeaseLab)AcquireExclusive(context.Context)(func(),error){
 l.lockCalls++
 return func(){l.unlockCalls++},errors.New("partial lease acquisition")
}
func TestBootRecoveryReleasesPartialFailedLease(t *testing.T){
 dir:=armBootPolicyJournal(t)
 lab:=&partialBootLeaseLab{}
 status,err:=RecoverPendingResidentAfterBoot(context.Background(),dir,residentLabACL,residentLabACL,&bootIdentityLab{},lab)
 if err==nil||status!=""||lab.lockCalls!=1||lab.unlockCalls!=1||lab.restoreCalls!=0||lab.verifyCalls!=0{t.Fatalf("unsafe partial lease handling: %s %v %+v",status,err,lab)}
 pending,e:=InspectResidentRecoveryJournal(context.Background(),dir,residentLabACL)
 if e!=nil||pending.Status!="recovery-required"{t.Fatalf("pending recovery lost: %+v %v",pending,e)}
}
type canceledBootIdentityLab struct{
 bootIdentityLab
 cancel context.CancelFunc
}
func(c *canceledBootIdentityLab)VerifyRunningIdentity(context.Context,ResidentRecoveryIntent,string)error{
 c.cancel()
 return context.Canceled
}
func TestBootRecoveryDoesNotRestoreAfterCanceledIdentityProbe(t *testing.T){
 for _,dns:=range []bool{false,true}{
  dir:=armBootPolicyJournal(t)
  ctx,cancel:=context.WithCancel(context.Background())
  checks:=&canceledBootIdentityLab{cancel:cancel}
  lab:=&bootDNSPolicyLab{}
  var status string
  var err error
  if dns{status,err=RecoverPendingResidentAfterBootWithOriginalDNS(ctx,dir,residentLabACL,residentLabACL,checks,lab)
  }else{status,err=RecoverPendingResidentAfterBoot(ctx,dir,residentLabACL,residentLabACL,checks,&lab.bootPolicyLab)}
  cancel()
  if !errors.Is(err,context.Canceled)||status!=""||lab.restoreCalls!=0||lab.dnsRestores!=0||lab.unlockCalls!=1{t.Fatalf("canceled probe caused mutation: %s %v %+v",status,err,lab)}
  pending,e:=InspectResidentRecoveryJournal(context.Background(),dir,residentLabACL)
  if e!=nil||pending.Status!="recovery-required"{t.Fatalf("pending recovery lost: %+v %v",pending,e)}
 }
}

func TestBootRecoveryRejectsReplacementAtTerminalBoundary(t *testing.T){
 for _,dns:=range []bool{false,true}{
  name:="motor-only";if dns{name="motor-and-dns"}
  t.Run(name,func(t *testing.T){
   ctx:=context.Background()
   dir:=armBootPolicyJournal(t)
   state,err:=InspectResidentRecoveryJournal(ctx,dir,residentLabACL)
   if err!=nil{t.Fatal(err)}
   lab:=&bootDNSPolicyLab{}
   path:=filepath.Join(dir,ResidentIntentFile)
   armed:=false
   reads:=0
   lab.terminalDuringVerify=func(){if lab.verifyCalls==2{armed=true}}
   protect:=func(p string)error{
    if !armed||p!=path{return nil}
    reads++
    if reads==2{
     replacement:=state.Intent;replacement.TargetVersion="0.28.8"
     raw,e:=json.Marshal(replacement);if e!=nil{return e}
     return os.WriteFile(path,raw,0600)
    }
    return nil
   }
   checks:=&bootIdentityLab{}
   var outcome string
   if dns{outcome,err=RecoverPendingResidentAfterBootWithOriginalDNS(ctx,dir,residentLabACL,protect,checks,lab)}else{
    outcome,err=RecoverPendingResidentAfterBoot(ctx,dir,residentLabACL,protect,checks,&lab.bootPolicyLab)
   }
   if err==nil||outcome!=""||reads<2||lab.unlockCalls!=1||lab.verifyCalls!=2{t.Fatalf("replacement not rejected at terminal boundary: %s %v %+v",outcome,err,lab)}
   if _,err:=os.Stat(filepath.Join(dir,ResidentResultFile));!os.IsNotExist(err){t.Fatal("replacement received a false terminal receipt")}
   latest,err:=InspectResidentRecoveryJournal(ctx,dir,residentLabACL)
   if err!=nil||latest.Status!="recovery-required"||latest.Intent.TargetVersion!="0.28.8"{t.Fatalf("pending evidence not preserved: %+v %v",latest,err)}
  })
 }
}
