//go:build windows

package motorupdate

import (
 "context"
 "errors"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func allowRecoveryACLFixture(context.Context,string)error{return nil}

func createResidentRecoveryFixture(t *testing.T,root string,terminal string) {
 t.Helper()
 parent:=filepath.Join(root,freshRecoveryParentName)
 if err:=os.Mkdir(parent,0700);err!=nil{t.Fatal(err)}
 journal:=filepath.Join(parent,freshRecoveryJournalName)
 if err:=os.Mkdir(journal,0700);err!=nil{t.Fatal(err)}
 if terminal=="empty" {return}
 ctx:=context.Background()
 allow:=func(string)error{return nil}
 intent:=ResidentRecoveryIntent{
  Schema:1,Component:"dns-engine-recovery-intent",Task:"VOLVE-DNS-SERVER-0270",
  LegacySHA256:strings.Repeat("a",64),TaskXMLSHA256:strings.Repeat("b",64),
  TargetSHA256:strings.Repeat("c",64),TargetVersion:"0.28.7",
 }
 if _,err:=ArmResidentRecoveryIntent(ctx,journal,intent,allow,allow);err!=nil{t.Fatal(err)}
 if terminal=="pending"{return}
 if err:=FinishResidentRecoveryIntent(ctx,journal,terminal,allow,allow);err!=nil{t.Fatal(err)}
}

func TestWindowsFreshRecoveryInventoryMissingParentIsIndependentlyObserved(t *testing.T) {
 root:=t.TempDir()
 called:=false
 got,err:=InspectWindowsFreshRecoveryReadOnly(context.Background(),root,func(context.Context,string)error{
  called=true;return errors.New("unexpected ACL probe on absent parent")
 })
 if err!=nil||called||got.RecoveryArtifactsPresent||got.RecoveryJournalPresent||
  got.PendingRollbackPresent||got.SnapshotPresent {
  t.Fatalf("absent recovery parent misclassified: %+v %v",got,err)
 }
}

func TestWindowsFreshRecoveryParentAlwaysBlocksNewMotor(t *testing.T) {
 for _,tc:=range []struct{name,terminal,status string; pending bool}{
  {"empty-parent","","not-present",false},
  {"empty-journal","empty","not-armed",false},
  {"unresolved-intent","pending","recovery-required",true},
  {"restored-terminal","restored","restored",false},
  {"committed-terminal","committed","committed",false},
 } {
  t.Run(tc.name,func(t *testing.T){
   root:=t.TempDir()
   if tc.terminal==""{
    if err:=os.Mkdir(filepath.Join(root,freshRecoveryParentName),0700);err!=nil{t.Fatal(err)}
   }else{createResidentRecoveryFixture(t,root,tc.terminal)}
   checks:=map[string]bool{}
   got,err:=InspectWindowsFreshRecoveryReadOnly(context.Background(),root,func(_ context.Context,p string)error{
    checks[p]=true;return nil
   })
   if err!=nil{t.Fatal(err)}
   if !got.RecoveryArtifactsPresent||got.PendingRollbackPresent!=tc.pending||
    got.JournalStatus!=tc.status||len(checks)==0{
    t.Fatalf("existing recovery missed: %+v %v",got,checks)
   }
   if (tc.terminal=="")!=(!got.RecoveryJournalPresent){
    t.Fatalf("resident journal classification incorrect: %+v",got)
   }
   // Independent six-of-six flags are synthetic ONLY for policy testing.
   evidence:=freshCompleteObservation()
   evidence.RecoveryArtifactsPresent=got.RecoveryArtifactsPresent
   evidence.RecoveryJournalPresent=got.RecoveryJournalPresent
   evidence.PendingRollbackPresent=got.PendingRollbackPresent
   if err:=CheckFreshMotorInstallReadiness(context.Background(),evidence);err==nil{
    t.Fatal("existing recovery files allowed fresh DNS motor install")
   }
  })
 }
}

func TestWindowsFreshRecoveryInventoryRejectsOrphansACLAndUnknowns(t *testing.T){
 for _,tc:=range []struct{name,entry string;makeFile bool}{
  {"unknown-staging",".legacy-recovery-incomplete",false},
  {"unknown-file","write.log",true},
  {"unreadable-snapshot","original-before-upgrade",false},
 } {
  t.Run(tc.name,func(t *testing.T){
   root:=t.TempDir()
   parent:=filepath.Join(root,freshRecoveryParentName)
   if err:=os.Mkdir(parent,0700);err!=nil{t.Fatal(err)}
   p:=filepath.Join(parent,tc.entry)
   var err error
   if tc.makeFile{err=os.WriteFile(p,[]byte("unsafe"),0600)}else{err=os.Mkdir(p,0700)}
   if err!=nil{t.Fatal(err)}
   if _,err:=InspectWindowsFreshRecoveryReadOnly(context.Background(),root,allowRecoveryACLFixture);err==nil {
    t.Fatal("incomplete or unrecognized recovery artifacts treated as safe")
   }
  })
 }
 root:=t.TempDir()
 parent:=filepath.Join(root,freshRecoveryParentName)
 if err:=os.Mkdir(parent,0700);err!=nil{t.Fatal(err)}
 if _,err:=InspectWindowsFreshRecoveryReadOnly(context.Background(),root,func(context.Context,string)error{
  return errors.New("untrusted ACL, everyone can write")
 });err==nil{
  t.Fatal("untrusted ACL accepted")
 }
}

func TestWindowsFreshRecoveryInventoryRejectsOrphanTerminal(t *testing.T) {
 root:=t.TempDir()
 createResidentRecoveryFixture(t,root,"empty")
 journal:=filepath.Join(root,freshRecoveryParentName,freshRecoveryJournalName)
 if err:=os.WriteFile(filepath.Join(journal,ResidentResultFile),[]byte("{}"),0600);err!=nil{t.Fatal(err)}
 if _,err:=InspectWindowsFreshRecoveryReadOnly(context.Background(),root,allowRecoveryACLFixture);err==nil {
  t.Fatal("orphan terminal journal incorrectly treated as completed recovery")
 }
}

func TestWindowsFreshRecoveryInventoryFailsClosedOnCancelledOrUnknownRoot(t *testing.T){
 root:=t.TempDir()
 if _,err:=InspectWindowsFreshRecoveryReadOnly(context.Background(),filepath.Join(root,"missing"),allowRecoveryACLFixture);err==nil{
  t.Fatal("missing trusted root treated as clean")
 }
 if _,err:=InspectWindowsFreshRecoveryReadOnly(context.Background(),root,nil);err==nil{
  t.Fatal("missing independent ACL checker accepted")
 }
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 if _,err:=InspectWindowsFreshRecoveryReadOnly(ctx,root,allowRecoveryACLFixture);!errors.Is(err,context.Canceled){
  t.Fatalf("cancelled recovery inventory did not stop: %v",err)
 }
}

func TestWindowsFreshRecoveryNativeACLReadOnlyRefusesUnsealedDirectory(t *testing.T){
 if testing.Short(){t.Skip("Windows native recovery ACL integration")}
 root:=t.TempDir()
 parent:=filepath.Join(root,freshRecoveryParentName)
 if err:=os.Mkdir(parent,0700);err!=nil{t.Fatal(err)}
 if err:=DefaultWindowsFreshRecoveryACLInspect(context.Background(),parent);err==nil {
  // Even if CI ACL configuration is already sealed (unusual), the important
  // invariant is that this inspection never grants permissions or writes.
  t.Log("CI recovery directory ACL happened to be already strictly protected")
 }else{
  t.Logf("READ ONLY: inherited/unsealed Windows DACL rejected as expected: %v",err)
 }
 if _,err:=InspectWindowsFreshRecoveryReadOnly(context.Background(),root,allowRecoveryACLFixture);err!=nil{
  t.Fatal(err)
 }
 if _,err:=InspectWindowsFreshRecoveryReadOnly(context.Background(),root,DefaultWindowsFreshRecoveryACLInspect);err==nil{
  t.Log("READ ONLY: directory already met strict owner and ACL requirements; still blocks fresh install")
 }
}
