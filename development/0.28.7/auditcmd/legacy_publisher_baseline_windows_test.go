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


func TestUnsignedLegacyBaselineStageCodesAreSafeAndPreciselyClassified(t *testing.T){
 root,readers:=baselineFixture(t)
 original:=string(mustTaskRaw(t,readers.Tasks))
 cases:=[]struct{name,raw,want string}{
  {"wrong-principal",strings.Replace(original,`"Principal":"SYSTEM"`,`"Principal":"USER"`,1),"FIRST_TASK_OWNER_MISMATCH"},
  {"wrong-action-path",strings.Replace(original,legacyExpectedExe,"another.exe",1),"FIRST_TASK_ACTION_PATH_MISMATCH"},
  {"wrong-arguments",strings.Replace(original,"--dns-service","--refresh",1),"FIRST_TASK_ARGUMENTS_MISMATCH"},
  {"working-directory-nonempty",strings.Replace(original,`"WorkingDirectory":""`,`"WorkingDirectory":"DIR_NOT_EMPTY"`,1),"FIRST_TASK_WORKING_DIR_MISMATCH"},
  {"working-directory-null",strings.Replace(original,`"WorkingDirectory":""`,`"WorkingDirectory":null`,1),"FIRST_TASK_WORKING_DIR_MISSING"},
  {"unexpected-field",strings.Replace(original,`"Name":`,`"secret":"SHOULD_NOT_LEAK","Name":`,1),"FIRST_TASK_RESPONSE_INVALID"},
  {"task-missing","[]","FIRST_TASK_RESPONSE_INVALID"},
 }
 for _,tc:=range cases{
  t.Run(tc.name,func(t *testing.T){
   c:=readers
   c.Tasks=func(context.Context,string)([]byte,error){return []byte(tc.raw),nil}
   got:=buildUnsignedLegacyPublisherBaseline(context.Background(),root,c)
   if got.Status!="NOT_VERIFIED_NO_CHANGES"||got.FailureStage!=tc.want ||
    got.FromSHA256!=""||got.FromTaskXMLSHA256!=""||got.MigrationAuthorized ||
    got.SignatureVerified||got.ReadyToSwitch{
    t.Fatalf("bad diagnostic stage/authorization: %+v (want %s)",got,tc.want)
   }
   data,err:=json.Marshal(got);if err!=nil{t.Fatal(err)}
   if strings.Contains(string(data),root)||strings.Contains(string(data),"SHOULD_NOT_LEAK"){
    t.Fatalf("failure stage leaked private task details")
   }
  })
 }
}

func TestUnsignedLegacyBaselineStageDetectsXMLOrRuntimeDrift(t *testing.T){
 root,readers:=baselineFixture(t)
 xmlReads:=0
 readers.XML=func(context.Context)([]byte,error){
  xmlReads++
  if xmlReads==1{return []byte("<Task><Actions>First</Actions></Task>"),nil}
  return []byte("<Task><Actions>Changed</Actions></Task>"),nil
 }
 got:=buildUnsignedLegacyPublisherBaseline(context.Background(),root,readers)
 if got.FailureStage!="TASK_XML_CHANGED_BETWEEN_READS"||got.FromSHA256!="" {
  t.Fatalf("XML changed but accepted or wrong stage: %+v",got)
 }
 root,readers=baselineFixture(t)
 owners:=0
 original:=readers.Owner
 readers.Owner=func(ctx context.Context)DNSOwnerReport{
  owners++
  o:=original(ctx)
  // The native Windows inspector returns a newly-decoded evidence object
  // each time. The fixture shares a pointer; copy it to simulate snapshots
  // without retroactively changing the first observation.
  cloned:=*o.Evidence
  o.Evidence=&cloned
  if owners==2{o.Evidence.SystemOwner=false}
  return o
 }
 got=buildUnsignedLegacyPublisherBaseline(context.Background(),root,readers)
 if got.FailureStage!="DNS_OWNER_CHANGED_OR_UNVERIFIED"||got.FromSHA256!=""||
  got.ReadyToSwitch{t.Fatalf("change of native owner evidence was ignored: %+v",got)}
}

func TestUnsignedLegacyBaselineStageNoHashOnMissingXML(t *testing.T){
 root,readers:=baselineFixture(t)
 readers.XML=func(context.Context)([]byte,error){return nil,errors.New("PRIVATE_INTERNAL_PATH")}
 got:=buildUnsignedLegacyPublisherBaseline(context.Background(),root,readers)
 if got.FailureStage!="TASK_XML_FIRST_FAILED"||got.FromSHA256!=""||
  strings.Contains(got.FailureStage,"PRIVATE_INTERNAL_PATH"){
  t.Fatalf("XML read error leaked path or was misclassified: %+v",got)
 }
}


func TestLegacyTaskActionPathSourceExactEquivalenceAndUnsafeRejection(t *testing.T){
 expected:=filepath.Join(`C:\ProgramData\VOLVE-Browser-Filter`,legacyExpectedExe)
 for _,tc:=range []struct{name,actual,form string;allow bool}{
  {"exact",expected,"EXACT_EXPECTED_PATH",true},
  {"quoted",`"`+expected+`"`,"SOURCE_EQUIVALENT_OUTER_QUOTES",true},
  {"forward-slashes",strings.ReplaceAll(expected,`\`,"/"),"SOURCE_EQUIVALENT_SEPARATOR",true},
  {"extended-dos",`\\?\`+expected,"SOURCE_EQUIVALENT_EXTENDED_DOS_PATH",true},
  {"dot-segment",filepath.Dir(expected)+`\.\`+legacyExpectedExe,"SOURCE_EQUIVALENT_DOT_SEGMENT",true},
  {"different-root",filepath.Join(`D:\OtherInstall`,legacyExpectedExe),"SAME_EXECUTABLE_NAME_DIFFERENT_LOCATION",false},
  {"relative",legacyExpectedExe,"ACTION_NOT_ABSOLUTE",false},
  {"unbalanced-quote",`"`+expected,"MALFORMED_OUTER_QUOTES",false},
  {"environment-expansion",`%ProgramData%\VOLVE-Browser-Filter\`+legacyExpectedExe,"UNSAFE_EXECUTE_SYNTAX",false},
  {"parent-traversal",filepath.Dir(expected)+`\..\VOLVE-Browser-Filter\`+legacyExpectedExe,"PARENT_TRAVERSAL_REJECTED",false},
  {"different-name",filepath.Join(filepath.Dir(expected),"other.exe"),"DIFFERENT_EXECUTABLE",false},
  {"embedded-quotes",`"`+expected+`" --other"`,"UNSAFE_EXECUTE_SYNTAX",false},
 }{
  t.Run(tc.name,func(t *testing.T){
   ok,form:=compareLegacyTaskActionPath(tc.actual,expected)
   if ok!=tc.allow||form!=tc.form{t.Fatalf("got ok=%v form=%s expected ok=%v form=%s",ok,form,tc.allow,tc.form)}
  })
 }
}

func TestUnsignedLegacyPublisherBaselineAcceptsOnlySourceCompatibleQuotedTaskAction(t *testing.T){
 root,readers:=baselineFixture(t)
 original:=mustTaskRaw(t,readers.Tasks)
 var tasks []publisherTaskEntry
 if err:=json.Unmarshal(original,&tasks);err!=nil{t.Fatal(err)}
 if len(tasks)!=1||len(tasks[0].Actions)!=1{t.Fatal("bad baseline fixture")}
 tasks[0].Actions[0].Execute=`"`+filepath.Join(root,legacyExpectedExe)+`"`
 encoded,err:=json.Marshal(tasks);if err!=nil{t.Fatal(err)}
 readers.Tasks=func(context.Context,string)([]byte,error){return encoded,nil}
 got:=buildUnsignedLegacyPublisherBaseline(context.Background(),root,readers)
 if got.Status!="UNSIGNED_LEGACY_IDENTITY_FOR_PUBLISHER_REVIEW_ONLY"||
  got.FailureStage!=""||got.FromSHA256==""||
  got.TaskActionPathForm!="SOURCE_EQUIVALENT_OUTER_QUOTES"||
  got.SignatureVerified||got.MigrationAuthorized||got.ReadyToSwitch{
  t.Fatalf("original quoted scheduled command refused or upgrade improperly authorized: %+v",got)
 }
 tasks[0].Actions[0].Execute=filepath.Join(t.TempDir(),legacyExpectedExe)
 foreign,err:=json.Marshal(tasks);if err!=nil{t.Fatal(err)}
 readers.Tasks=func(context.Context,string)([]byte,error){return foreign,nil}
 denied:=buildUnsignedLegacyPublisherBaseline(context.Background(),root,readers)
 if denied.Status!="NOT_VERIFIED_NO_CHANGES"||
  denied.FailureStage!="FIRST_TASK_ACTION_PATH_MISMATCH"||
  denied.TaskActionPathForm!="SAME_EXECUTABLE_NAME_DIFFERENT_LOCATION"||
  denied.FromSHA256!=""||denied.MigrationAuthorized{
  t.Fatalf("different executable location incorrectly accepted: %+v",denied)
 }
}
