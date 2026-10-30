package motorupdate

import (
 "bytes"
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func residentFixture() ResidentRecoveryIntent {
 h:=func(v string)string{s:=sha256.Sum256([]byte(v));return hex.EncodeToString(s[:])}
 return ResidentRecoveryIntent{
  Schema:1,Component:"dns-engine-recovery-intent",Task:"VOLVE-DNS-SERVER-0270",
  LegacySHA256:h("old"),TaskXMLSHA256:h("system-xml"),
  TargetSHA256:h("new-signed-executable"),TargetVersion:"0.28.7",
 }
}
func residentLabACL(string)error{return nil} // TEST ONLY, no Windows ACL assertion

func TestResidentJournalInterruptedTransactionSurvivesReopen(t *testing.T) {
 dir:=t.TempDir()
 j,e:=ArmResidentRecoveryIntent(context.Background(),dir,residentFixture(),residentLabACL,residentLabACL)
 if e!=nil{t.Fatal(e)}
 if len(j.Nonce)!=32{t.Fatal("missing unpredictable intent nonce")}
 // New invocation has no in-memory state from its writer.
 state,e:=InspectResidentRecoveryJournal(context.Background(),dir,residentLabACL)
 if e!=nil||state.Status!="recovery-required"||state.Intent!=j{
  t.Fatalf("reopened armed intent not preserved: %+v %v",state,e)
 }
 if _,e=ArmResidentRecoveryIntent(context.Background(),dir,residentFixture(),residentLabACL,residentLabACL);e==nil{
  t.Fatal("existing armed transaction was overwritten")
 }
 if e=FinishResidentRecoveryIntent(context.Background(),dir,"committed",residentLabACL,residentLabACL);e!=nil{
  t.Fatal(e)
 }
 state,e=InspectResidentRecoveryJournal(context.Background(),dir,residentLabACL)
 if e!=nil||state.Status!="committed"{t.Fatalf("committed journal not durable: %+v %v",state,e)}
 if e=FinishResidentRecoveryIntent(context.Background(),dir,"restored",residentLabACL,residentLabACL);e==nil{
  t.Fatal("terminal outcome was overwritten")
 }
}

func TestResidentJournalRecoveryResultAfterRestoration(t *testing.T){
 dir:=t.TempDir()
 if _,e:=ArmResidentRecoveryIntent(context.Background(),dir,residentFixture(),residentLabACL,residentLabACL);e!=nil{t.Fatal(e)}
 if e:=FinishResidentRecoveryIntent(context.Background(),dir,"restored",residentLabACL,residentLabACL);e!=nil{t.Fatal(e)}
 s,e:=InspectResidentRecoveryJournal(context.Background(),dir,residentLabACL)
 if e!=nil||s.Status!="restored"{t.Fatalf("restoration result unavailable: %v %+v",e,s)}
}

func TestResidentJournalRejectsTornAndForgedTerminal(t *testing.T){
 for _,kind:=range []string{"truncated","wrong-hash","wrong-nonce","duplicate-field","extra-field","replaced-intent"}{
  t.Run(kind,func(t *testing.T){
   dir:=t.TempDir()
   _,e:=ArmResidentRecoveryIntent(context.Background(),dir,residentFixture(),residentLabACL,residentLabACL)
   if e!=nil{t.Fatal(e)}
   intentPath:=filepath.Join(dir,ResidentIntentFile)
   resultPath:=filepath.Join(dir,ResidentResultFile)
   raw,e:=os.ReadFile(intentPath);if e!=nil{t.Fatal(e)}
   var intent ResidentRecoveryIntent
   if e=json.Unmarshal(raw,&intent);e!=nil{t.Fatal(e)}
   h:=sha256.Sum256(bytes.TrimSpace(raw))
   result:=ResidentRecoveryResult{Schema:1,Component:"dns-engine-recovery-result",
    IntentSHA256:hex.EncodeToString(h[:]),IntentNonce:intent.Nonce,Outcome:"committed"}
   switch kind {
   case "wrong-hash":result.IntentSHA256=strings.Repeat("0",64)
   case "wrong-nonce":result.IntentNonce=strings.Repeat("0",32)
   case "replaced-intent":
     altered:=intent;altered.TargetVersion="0.28.8"
     next,e:=json.Marshal(altered);if e!=nil{t.Fatal(e)}
     if e=os.WriteFile(intentPath,next,0600);e!=nil{t.Fatal(e)}
   }
   data,e:=json.Marshal(result);if e!=nil{t.Fatal(e)}
   switch kind{
   case "truncated":data=[]byte(`{"schema":1`)
   case "duplicate-field":data=bytes.Replace(data,[]byte(`"schema":1`),[]byte(`"schema":1,"schema":1`),1)
   case "extra-field":data=bytes.Replace(data,[]byte(`"schema":1`),[]byte(`"schema":1,"extra":true`),1)
   }
   if e=os.WriteFile(resultPath,data,0600);e!=nil{t.Fatal(e)}
   if s,e:=InspectResidentRecoveryJournal(context.Background(),dir,residentLabACL);e==nil{
    t.Fatalf("forged or partial terminal accepted: %+v",s)
   }
  })
 }
}

func TestResidentJournalFailedSealNeverClaimsSuccess(t *testing.T){
 dir:=t.TempDir()
 failSeal:=func(path string)error{
  if filepath.Base(path)==ResidentIntentFile{return errors.New("simulated NTFS ACL failure")}
  return nil
 }
 if _,e:=ArmResidentRecoveryIntent(context.Background(),dir,residentFixture(),failSeal,residentLabACL);e==nil{
  t.Fatal("failed ACL seal incorrectly armed")
 }
 if s,e:=InspectResidentRecoveryJournal(context.Background(),dir,residentLabACL);e!=nil||s.Status!="recovery-required"{
  t.Fatalf("failed sealing should leave conservative intent evidence: %+v %v",s,e)
 }
 // An untrusted journal must NEVER be used by a production watcher.
 reject:=func(string)error{return errors.New("untrusted owner/DACL")}
 if _,e:=InspectResidentRecoveryJournal(context.Background(),dir,reject);e==nil{
  t.Fatal("unsafe owner allowed recovery decision")
 }
}

func TestResidentJournalRejectedInputsAndCancel(t *testing.T){
 for _,kind:=range []string{"invalid-task","invalid-sha","bad-version","missing-acl","cancel","non-empty","relative"}{
  t.Run(kind,func(t *testing.T){
   dir:=t.TempDir()
   original:=residentFixture()
   seal,protect:=residentLabACL,residentLabACL
   ctx:=context.Background()
   switch kind {
   case "invalid-task":original.Task="OTHER-SYSTEM-TASK"
   case "invalid-sha":original.LegacySHA256="garbage"
   case "bad-version":original.TargetVersion="0.28.6-pre"
   case "missing-acl":protect=nil
   case "cancel":c,cancel:=context.WithCancel(ctx);cancel();ctx=c
   case "non-empty":if e:=os.WriteFile(filepath.Join(dir,"stranger"),[]byte("x"),0600);e!=nil{t.Fatal(e)}
   case "relative":dir="relative-path"
   }
   if _,e:=ArmResidentRecoveryIntent(ctx,dir,original,seal,protect);e==nil{
    t.Fatalf("unsafe %s armed",kind)
   }
  })
 }
 dir:=t.TempDir()
 if e:=FinishResidentRecoveryIntent(context.Background(),dir,"committed",residentLabACL,residentLabACL);e==nil{
  t.Fatal("terminal without intent accepted")
 }
 if e:=os.WriteFile(filepath.Join(dir,ResidentResultFile),[]byte("{}"),0600);e!=nil{t.Fatal(e)}
 if _,e:=InspectResidentRecoveryJournal(context.Background(),dir,residentLabACL);e==nil{
  t.Fatal("orphan result accepted")
 }
}

func TestResidentJournalDisallowsModifiedOrExtraFiles(t *testing.T){
 dir:=t.TempDir()
 if _,e:=ArmResidentRecoveryIntent(context.Background(),dir,residentFixture(),residentLabACL,residentLabACL);e!=nil{t.Fatal(e)}
 if e:=os.WriteFile(filepath.Join(dir,"unexpected"),[]byte("x"),0600);e!=nil{t.Fatal(e)}
 if _,e:=InspectResidentRecoveryJournal(context.Background(),dir,residentLabACL);e==nil{t.Fatal("unknown journal file accepted")}
}
