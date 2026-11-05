//go:build windows

package main

import (
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"

 "volve-browser-protection/motorupdate"
)

func TestInstalledUnsignedMigrationDraftBindsFourLiveSYSTEMObservationsAndNeverAuthorizes(t *testing.T){
 f,p,calls:=reviewInstalledFixture(t)
 before,err:=os.ReadFile(filepath.Join(f.root,dnsServiceFile));if err!=nil{t.Fatal(err)}
 report,err:=buildInstalledUnsignedMigrationDraftReadOnly(context.Background(),
  f.root,f.candidate,"0.28.7",f.pub,true,p,time.Now().UTC())
 if err!=nil{t.Fatal(err)}
 if calls[0]!=4||calls[1]!=4||calls[2]!=4{
  t.Fatalf("missing independent live task/port/owner observations: %v",calls)
 }
 if !report.NoInstallPermission||report.Component!="dns-engine-offline-publisher-draft-only"||
  report.Draft.MigrationAuthorized||report.Draft.ReadyToSwitch||report.Draft.SignaturePresent{
  t.Fatalf("unsigned publisher draft was presented as executable permission: %+v",report)
 }
 raw,err:=base64.StdEncoding.Strict().DecodeString(report.ExactUnsignedPermitBase64)
 if err!=nil{t.Fatal(err)}
 expected,err:=motorupdate.DraftPermitBytesReadOnly(report.Draft);if err!=nil{t.Fatal(err)}
 if string(raw)!=string(expected){t.Fatal("offline signing copy differs from canonical permit")}
 sum:=sha256.Sum256(raw)
 if hex.EncodeToString(sum[:])!=report.Draft.PermitJSONSHA256{
  t.Fatal("offline signing bytes not pinned by SHA256")
 }
 if _,err:=motorupdate.VerifySignedUnversionedLegacyMigration(context.Background(),
  filepath.Join(f.root,dnsServiceFile),f.backup,f.candidate,"0.28.7",
  raw,nil,f.pub,func(string)error{return nil},func()error{return nil});err==nil{
  t.Fatal("unsigned handoff became an actual production permit")
 }
 serialized,err:=json.Marshal(report);if err!=nil{t.Fatal(err)}
 for _,private:=range []string{f.root,f.backup,f.candidate}{
  if strings.Contains(string(serialized),private){t.Fatal("private Windows path leaked into publisher handoff")}
 }
 after,err:=os.ReadFile(filepath.Join(f.root,dnsServiceFile));if err!=nil{t.Fatal(err)}
 if string(before)!=string(after){t.Fatal("read-only CLI bridge changed the original motor")}
}

func TestInstalledUnsignedMigrationDraftRejectsHostDriftBetweenReviewAndDraft(t *testing.T){
 for _,scenario:=range []string{
  "lost-administrator","wrong-key","missing-backup-verifier","candidate-unsigned",
  "task-changed-after-first-review","motor-owner-disappeared","preflight-drift",
  "expired-draft-timestamp","cancelled",
 }{
  t.Run(scenario,func(t *testing.T){
   f,p,calls:=reviewInstalledFixture(t)
   admin:=true
   pub:=f.pub
   issued:=time.Now().UTC()
   ctx:=context.Background()
   switch scenario{
   case "lost-administrator":admin=false
   case "wrong-key":pub,_,_=ed25519.GenerateKey(rand.Reader)
   case "missing-backup-verifier":p.ProtectBackup=nil
   case "candidate-unsigned":if err:=os.Remove(f.candidate+".sig");err!=nil{t.Fatal(err)}
   case "task-changed-after-first-review":
    original:=p.TaskXML
    p.TaskXML=func(ctx context.Context,exe string)([]byte,error){
     calls[2]++
     b,e:=os.ReadFile(filepath.Join(f.backup,"VOLVE_DNS_Legacy_Task.xml"))
     if e!=nil{return nil,e}
     if calls[2]>2 {return append(b,[]byte("modified task")...),nil}
     // Original callback is bypassed to avoid double-counting.
     _=original
     return b,nil
    }
   case "motor-owner-disappeared":
    p.RunningMotor=func(context.Context,string,string)error{
     calls[1]++
     if calls[1]>2{return errors.New("SYSTEM motor no longer owns port53")}
     return nil
    }
   case "preflight-drift":
    p.Preflight=func()(string,error){
     calls[0]++
     if calls[0]>2{return "",errors.New("task unavailable on second check")}
     return "OK",nil
    }
   case "expired-draft-timestamp":issued=issued.Add(-time.Hour)
   case "cancelled":var cancel context.CancelFunc;ctx,cancel=context.WithCancel(ctx);cancel()
   }
   output,err:=buildInstalledUnsignedMigrationDraftReadOnly(ctx,f.root,f.candidate,
    "0.28.7",pub,admin,p,issued)
   if err==nil||output.Component!=""||output.ExactUnsignedPermitBase64!=""{
    t.Fatalf("unsafe publisher draft accepted: %s %+v %v",scenario,output,err)
   }
  })
 }
}
