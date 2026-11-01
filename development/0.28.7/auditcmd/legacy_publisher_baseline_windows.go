//go:build windows

package main

// A minimal unsigned publisher identity REQUEST for the exact installed
// VOLVE 0.28.6 DNS motor. Does not back up, install, replace, stop, start,
// switch, sign or publish anything. It cannot authorize a migration.
// Neither XML bytes nor task commands/paths/PIDs are exposed to the report.
import (
 "bytes"
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "io"
 "os"
 "os/exec"
 "path/filepath"
 "strings"

 "volve-browser-protection/motorupdate"
)

const legacyExpectedExe="VOLVE_DNS_Server_0270.exe"
const legacyExpectedTask="VOLVE-DNS-SERVER-0270"

type LegacyPublisherBaseline struct {
 Status string `json:"status"`
 FailureStage string `json:"failure_stage,omitempty"`
 Schema int `json:"schema"`
 FromTask string `json:"from_task,omitempty"`
 FromExecutable string `json:"from_executable,omitempty"`
 FromArguments string `json:"from_arguments,omitempty"`
 FromSHA256 string `json:"from_sha256,omitempty"`
 FromSize int64 `json:"from_size,omitempty"`
 FromTaskXMLSHA256 string `json:"from_task_xml_sha256,omitempty"`
 SignatureVerified bool `json:"signature_verified"`
 MigrationAuthorized bool `json:"migration_authorized"`
 ReadyToSwitch bool `json:"ready_to_switch"`
}

type publisherTaskEntry struct {
 Name string `json:"Name"`
 TaskPath string `json:"TaskPath"`
 Principal string `json:"Principal"`
 DefinitionSHA256 string `json:"DefinitionSHA256"`
 Actions []struct{
  Execute string `json:"Execute"`
  Arguments string `json:"Arguments"`
  WorkingDirectory *string `json:"WorkingDirectory"`
 } `json:"Actions"`
}

type legacyBaselineReaders struct {
 Tasks motorupdate.WindowsFreshTaskInspect
 XML func(context.Context)([]byte,error)
 Owner func(context.Context)DNSOwnerReport
}

func defaultLegacyTaskXML(ctx context.Context)([]byte,error){
 if err:=ctx.Err();err!=nil{return nil,err}
 root:=os.Getenv("SystemRoot")
 if root==""||!filepath.IsAbs(root){return nil,errors.New("Windows SystemRoot unavailable")}
 exe:=filepath.Join(root,"System32","schtasks.exe")
 // Query only, no /Create, /Change, /Delete, /Run or /End commands.
 out,err:=exec.CommandContext(ctx,exe,"/Query","/TN",legacyExpectedTask,"/XML").Output()
 if err!=nil{return nil,err}
 return out,nil
}

// inspectVerifiedLegacyTaskStage returns a finite diagnostic code. No path,
// principal, task XML or query errors are propagated to the exported JSON.
// A mismatch never grants authority to install or repair the 0.28.6 motor.
func inspectVerifiedLegacyTaskStage(ctx context.Context,root string,inspect motorupdate.WindowsFreshTaskInspect)string{
 if ctx.Err()!=nil{return "CANCELLED"}
 if inspect==nil{return "TASK_READER_MISSING"}
 raw,err:=inspect(ctx,motorupdate.WindowsVOLVETaskInventoryQuery)
 if err!=nil{return "TASK_QUERY_FAILED"}
 if len(raw)<2||len(raw)>1<<20{return "TASK_RESPONSE_INVALID"}
 dec:=json.NewDecoder(bytes.NewReader(raw));dec.DisallowUnknownFields()
 var records []publisherTaskEntry
 if err:=dec.Decode(&records);err!=nil{return "TASK_RESPONSE_INVALID"}
 var trailing any
 if err:=dec.Decode(&trailing);err!=io.EOF{return "TASK_RESPONSE_INVALID"}
 if len(records)==0||len(records)>64{return "TASK_RESPONSE_INVALID"}
 matches:=0
 expected:=filepath.Join(root,legacyExpectedExe)
 for _,task:=range records{
  if task.Name!=legacyExpectedTask{continue}
  matches++
  if task.TaskPath!="\\"{return "TASK_FOLDER_MISMATCH"}
  if task.Principal!="SYSTEM"&&task.Principal!="S-1-5-18"{return "TASK_OWNER_MISMATCH"}
  if len(task.Actions)!=1{return "TASK_ACTION_COUNT_MISMATCH"}
  a:=task.Actions[0]
  if !filepath.IsAbs(a.Execute)||!strings.EqualFold(filepath.Clean(a.Execute),expected){
   return "TASK_ACTION_PATH_MISMATCH"
  }
  if a.Arguments!="--dns-service"{return "TASK_ARGUMENTS_MISMATCH"}
  if a.WorkingDirectory==nil{return "TASK_WORKING_DIR_MISSING"}
  if *a.WorkingDirectory!=""{return "TASK_WORKING_DIR_MISMATCH"}
 }
 if matches!=1{return "TASK_MISSING_OR_DUPLICATED"}
 if ctx.Err()!=nil{return "CANCELLED"}
 return ""
}

func digestLegacyInstalledMotor(ctx context.Context,root string)(string,int64,error){
 if err:=ctx.Err();err!=nil{return "",0,err}
 path:=filepath.Join(root,legacyExpectedExe)
 stat,err:=os.Lstat(path)
 if err!=nil{return "",0,err}
 if !stat.Mode().IsRegular()||stat.Size()<128||stat.Size()>80<<20{
  return "",0,errors.New("motor executable missing/unsafe")
 }
 f,err:=os.Open(path);if err!=nil{return "",0,err}
 hash:=sha256.New()
 n,copyErr:=io.Copy(hash,io.LimitReader(f,80<<20+1))
 closeErr:=f.Close()
 if copyErr!=nil{return "",0,copyErr}
 if closeErr!=nil{return "",0,closeErr}
 if n!=stat.Size()||ctx.Err()!=nil{return "",0,errors.New("motor size drift")}
 again,err:=os.Lstat(path)
 if err!=nil||!again.Mode().IsRegular()||again.Size()!=stat.Size()||
  !again.ModTime().Equal(stat.ModTime()) {
  return "",0,errors.New("motor changed while hashing")
 }
 return hex.EncodeToString(hash.Sum(nil)),n,nil
}

func digestOriginalTaskXML(ctx context.Context,read func(context.Context)([]byte,error))(string,error){
 if read==nil{return "",errors.New("legacy Task Scheduler XML reader missing")}
 data,err:=read(ctx)
 if err!=nil{return "",err}
 if len(data)<32||len(data)>1<<20{return "",errors.New("task XML unavailable or too large")}
 if err:=ctx.Err();err!=nil{return "",err}
 sum:=sha256.Sum256(data)
 return hex.EncodeToString(sum[:]),nil
}

// Identity for editorial comparison ONLY. It rechecks the task, its XML,
// disk bytes and the SYSTEM PID owning both loopback UDP/53 listeners.
// Incomplete checks return no hashes and no authorizations.
func buildUnsignedLegacyPublisherBaseline(ctx context.Context,root string,readers legacyBaselineReaders)LegacyPublisherBaseline{
 denied:=LegacyPublisherBaseline{Schema:1,Status:"NOT_VERIFIED_NO_CHANGES"}
 fail:=func(stage string)LegacyPublisherBaseline{
  denied.FailureStage=stage
  return denied
 }
 if ctx.Err()!=nil{return fail("CANCELLED")}
 if root==""||!filepath.IsAbs(root)||filepath.Clean(root)!=root||
  readers.Tasks==nil||readers.XML==nil||readers.Owner==nil{
  return fail("REQUIRED_INSPECTOR_MISSING")
 }
 owner:=readers.Owner(ctx)
 if owner.Status!="EXACT_LEGACY_SYSTEM_PROCESS_ON_BOTH_UDP53_SOCKETS_NOT_SIGNED"||
  owner.Evidence==nil||!owner.Safe(){return fail("DNS_OWNER_FIRST_UNVERIFIED")}
 if stage:=inspectVerifiedLegacyTaskStage(ctx,root,readers.Tasks);stage!=""{
  return fail("FIRST_"+stage)
 }
 hash1,size1,err:=digestLegacyInstalledMotor(ctx,root)
 if err!=nil{return fail("MOTOR_DIGEST_FIRST_FAILED")}
 xml1,err:=digestOriginalTaskXML(ctx,readers.XML)
 if err!=nil{return fail("TASK_XML_FIRST_FAILED")}
 if stage:=inspectVerifiedLegacyTaskStage(ctx,root,readers.Tasks);stage!=""{
  return fail("SECOND_"+stage)
 }
 hash2,size2,err:=digestLegacyInstalledMotor(ctx,root)
 if err!=nil{return fail("MOTOR_DIGEST_SECOND_FAILED")}
 xml2,err:=digestOriginalTaskXML(ctx,readers.XML)
 if err!=nil{return fail("TASK_XML_SECOND_FAILED")}
 owner2:=readers.Owner(ctx)
 if ctx.Err()!=nil{return fail("CANCELLED")}
 if owner2.Status!=owner.Status||owner2.Evidence==nil||!owner2.Safe()||
  *owner2.Evidence!=*owner.Evidence{
  return fail("DNS_OWNER_CHANGED_OR_UNVERIFIED")
 }
 if hash1!=hash2||size1!=size2{return fail("MOTOR_CHANGED_BETWEEN_READS")}
 if xml1!=xml2{return fail("TASK_XML_CHANGED_BETWEEN_READS")}
 return LegacyPublisherBaseline{
  Schema:1,Status:"UNSIGNED_LEGACY_IDENTITY_FOR_PUBLISHER_REVIEW_ONLY",
  FromTask:legacyExpectedTask,FromExecutable:legacyExpectedExe,
  FromArguments:"--dns-service",
  FromSHA256:hash1,FromSize:size1,FromTaskXMLSHA256:xml1,
 }
}
