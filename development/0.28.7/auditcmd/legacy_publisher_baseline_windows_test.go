//go:build windows

package main

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "os"
 "path/filepath"
 "strings"
 "testing"

 "volve-browser-protection/motorupdate"
)

func baselineFixture(t *testing.T)(string,legacyBaselineReaders){
 t.Helper()
 root:=t.TempDir()
 if err:=os.WriteFile(filepath.Join(root,legacyExpectedExe),[]byte(strings.Repeat("MZ_ONLY_A_TEST_IMAGE",30)),0600);err!=nil{t.Fatal(err)}
 inventory:=[]map[string]any{{
  "Name":legacyExpectedTask,"TaskPath":"\\","Principal":"SYSTEM",
  "DefinitionSHA256":strings.Repeat("a",64),
  "Actions":[]map[string]any{{"Execute":filepath.Join(root,legacyExpectedExe),"Arguments":"--dns-service","WorkingDirectory":""}},
 }}
 taskRaw,err:=json.Marshal(inventory);if err!=nil{t.Fatal(err)}
 owner:=DNSOwnerReport{
  Status:"EXACT_LEGACY_SYSTEM_PROCESS_ON_BOTH_UDP53_SOCKETS_NOT_SIGNED",
  Evidence:&DNSOwnerEvidence{
   Schema:1,ExactIPv4Socket:true,ExactIPv6Socket:true,SameNonzeroPID:true,
   ProcessObserved:true,SystemOwner:true,LegacyExecutablePathMatch:true,DNSServiceArgsMatch:true,
  },
 }
 return root,legacyBaselineReaders{
  Tasks:func(context.Context,string)([]byte,error){return taskRaw,nil},
  XML:func(context.Context)([]byte,error){return []byte("<Task><Actions>LABONLY</Actions></Task>"),nil},
  Owner:func(context.Context)DNSOwnerReport{return owner},
 }
}

func TestUnsignedLegacyBaselineProducesExactHashesButNEVERMigrationPermission(t *testing.T){
 root,readers:=baselineFixture(t)
 before,err:=os.ReadFile(filepath.Join(root,legacyExpectedExe));if err!=nil{t.Fatal(err)}
 got:=buildUnsignedLegacyPublisherBaseline(context.Background(),root,readers)
 actualHash:=sha256.Sum256(before)
 xmlHash:=sha256.Sum256([]byte("<Task><Actions>LABONLY</Actions></Task>"))
 if got.Status!="UNSIGNED_LEGACY_IDENTITY_FOR_PUBLISHER_REVIEW_ONLY"||
  got.FromSHA256!=hex.EncodeToString(actualHash[:])||
  got.FromTaskXMLSHA256!=hex.EncodeToString(xmlHash[:])||
  got.FromSize!=int64(len(before))||got.FromTask!=legacyExpectedTask||
  got.FromArguments!="--dns-service"||got.FromExecutable!=legacyExpectedExe||
  got.SignatureVerified||got.MigrationAuthorized||got.ReadyToSwitch{
  t.Fatalf("unsigned host report wrong or unsafe: %+v",got)
 }
 after,err:=os.ReadFile(filepath.Join(root,legacyExpectedExe));if err!=nil{t.Fatal(err)}
 if string(before)!=string(after){t.Fatal("read-only baseline changed motor bytes")}
 raw,err:=json.Marshal(got);if err!=nil{t.Fatal(err)}
 if strings.Contains(string(raw),root)||strings.Contains(string(raw),"C:\\")||
  strings.Contains(string(raw),"LABONLY"){t.Fatal("task XML or local installation path leaked")}
}

func TestUnsignedLegacyBaselineRejectsAlteredTaskOrUnsafeOwner(t *testing.T){
 root,readers:=baselineFixture(t)
 baseline:=readers.Tasks
 for _,tc:=range []struct{name,taskRaw string}{
  {"wrong-task",strings.Replace(string(mustTaskRaw(t,baseline)),legacyExpectedTask,"VOLVE-DNS-SERVER-0999",1)},
  {"wrong-args",strings.Replace(string(mustTaskRaw(t,baseline)),"--dns-service","--refresh",1)},
  {"wrong-exe",strings.Replace(string(mustTaskRaw(t,baseline)),legacyExpectedExe,"OtherProgram.exe",1)},
  {"wrong-principal",strings.Replace(string(mustTaskRaw(t,baseline)),`"Principal":"SYSTEM"`,`"Principal":"USER"`,1)},
  {"extra-action",strings.Replace(string(mustTaskRaw(t,baseline)),`"Actions":[{`,`"Actions":[{}, {`,1)},
  {"unknown-field",strings.Replace(string(mustTaskRaw(t,baseline)),`"Name":`,`"InjectedSecret":"oops","Name":`,1)},
  {"missing-entries","[]"},
 }{
  t.Run(tc.name,func(t *testing.T){
   c:=readers;c.Tasks=func(context.Context,string)([]byte,error){return []byte(tc.taskRaw),nil}
   result:=buildUnsignedLegacyPublisherBaseline(context.Background(),root,c)
   if result.Status!="NOT_VERIFIED_NO_CHANGES"||result.FromSHA256!=""||
    result.MigrationAuthorized||result.FromTaskXMLSHA256!=""{
    t.Fatalf("unsafe task records produced identity: %+v",result)
   }
  })
 }
 c:=readers;c.Owner=func(context.Context)DNSOwnerReport{return DNSOwnerReport{Status:"SOCKET_OWNER_OBSERVED_READ_ONLY"}}
 got:=buildUnsignedLegacyPublisherBaseline(context.Background(),root,c)
 if got.Status!="NOT_VERIFIED_NO_CHANGES"||got.FromSHA256!=""{t.Fatal("foreign DNS owner yielded publisher baseline")}
}

func mustTaskRaw(t *testing.T,read motorupdate.WindowsFreshTaskInspect)[]byte{
 t.Helper()
 raw,err:=read(context.Background(),motorupdate.WindowsVOLVETaskInventoryQuery)
 if err!=nil{t.Fatal(err)}
 return raw
}

func TestUnsignedLegacyBaselineRejectsChangingTaskXMLAndMotorDuringScan(t *testing.T){
 root,readers:=baselineFixture(t)
 calls:=0
 readers.XML=func(context.Context)([]byte,error){
  calls++;if calls==1{return []byte("<Task><Actions>First</Actions></Task>"),nil}
  return []byte("<Task><Actions>Changed</Actions></Task>"),nil
 }
 got:=buildUnsignedLegacyPublisherBaseline(context.Background(),root,readers)
 if got.Status!="NOT_VERIFIED_NO_CHANGES"||got.FromSHA256!=""||calls!=2{
  t.Fatalf("changing Task Scheduler XML was accepted: %+v",got)
 }
 root,readers=baselineFixture(t)
 reads:=0
 original:=readers.Tasks
 readers.Tasks=func(ctx context.Context,q string)([]byte,error){
  reads++
  if reads==2 {
   if err:=os.WriteFile(filepath.Join(root,legacyExpectedExe),[]byte(strings.Repeat("MZ_CHANGED_TEST_IMAGE",30)),0600);err!=nil{t.Fatal(err)}
  }
  return original(ctx,q)
 }
 got=buildUnsignedLegacyPublisherBaseline(context.Background(),root,readers)
 if got.Status!="NOT_VERIFIED_NO_CHANGES"||got.FromSHA256!=""{t.Fatalf("changing motor accepted: %+v",got)}
}

func TestUnsignedLegacyBaselineFailsClosedOnReadErrorOrCancellation(t *testing.T){
 root,readers:=baselineFixture(t)
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 got:=buildUnsignedLegacyPublisherBaseline(ctx,root,readers)
 if got.Status!="NOT_VERIFIED_NO_CHANGES"{t.Fatal("cancelled source inspection returned publisher identity")}
 readers.XML=func(context.Context)([]byte,error){return nil,errors.New("Task Scheduler blocked")}
 got=buildUnsignedLegacyPublisherBaseline(context.Background(),root,readers)
 if got.Status!="NOT_VERIFIED_NO_CHANGES"||got.FromSHA256!=""{t.Fatal("XML read failure was treated as identity")}
}
