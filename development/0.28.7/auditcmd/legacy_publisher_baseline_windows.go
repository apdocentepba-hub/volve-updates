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

func inspectVerifiedLegacyTask(ctx context.Context,root string,inspect motorupdate.WindowsFreshTaskInspect)error{
 if inspect==nil{return errors.New("no Windows task inventory observer")}
 raw,err:=inspect(ctx,motorupdate.WindowsVOLVETaskInventoryQuery)
 if err!=nil{return err}
 if len(raw)<2||len(raw)>1<<20{return errors.New("Windows task inventory invalid")}
 dec:=json.NewDecoder(bytes.NewReader(raw));dec.DisallowUnknownFields()
 var records []publisherTaskEntry
 if err:=dec.Decode(&records);err!=nil{return err}
 var trailing any
 if err:=dec.Decode(&trailing);err!=io.EOF{return errors.New("trailing task inventory")}
 if len(records)==0||len(records)>64{return errors.New("Windows VOLVE task inventory empty/oversized")}
 matches:=0
 expected:=filepath.Join(root,legacyExpectedExe)
 for _,task:=range records {
  if task.Name!=legacyExpectedTask {continue}
  matches++
  if task.TaskPath!="\\"||
   (task.Principal!="SYSTEM"&&task.Principal!="S-1-5-18")||
   len(task.Actions)!=1{return errors.New("legacy SYSTEM task identity differs")}
  a:=task.Actions[0]
  if !filepath.IsAbs(a.Execute) ||
   !strings.EqualFold(filepath.Clean(a.Execute),expected) ||
   a.Arguments!="--dns-service" || a.WorkingDirectory==nil||
   *a.WorkingDirectory!="" {return errors.New("legacy SYSTEM task action differs")}
 }
 if matches!=1{return errors.New("legacy SYSTEM task missing/duplicated")}
 return ctx.Err()
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
 if err:=ctx.Err();err!=nil{return denied}
 if root==""||!filepath.IsAbs(root)||filepath.Clean(root)!=root||
  readers.Tasks==nil||readers.XML==nil||readers.Owner==nil{return denied}
 owner:=readers.Owner(ctx)
 if owner.Status!="EXACT_LEGACY_SYSTEM_PROCESS_ON_BOTH_UDP53_SOCKETS_NOT_SIGNED"||
  owner.Evidence==nil||!owner.Safe(){return denied}
 if err:=inspectVerifiedLegacyTask(ctx,root,readers.Tasks);err!=nil{return denied}
 hash1,size1,err:=digestLegacyInstalledMotor(ctx,root);if err!=nil{return denied}
 xml1,err:=digestOriginalTaskXML(ctx,readers.XML);if err!=nil{return denied}
 if err:=inspectVerifiedLegacyTask(ctx,root,readers.Tasks);err!=nil{return denied}
 hash2,size2,err:=digestLegacyInstalledMotor(ctx,root);if err!=nil{return denied}
 xml2,err:=digestOriginalTaskXML(ctx,readers.XML);if err!=nil{return denied}
 owner2:=readers.Owner(ctx)
 if ctx.Err()!=nil||owner2.Status!=owner.Status||owner2.Evidence==nil||!owner2.Safe()||
  hash1!=hash2||size1!=size2||xml1!=xml2{return denied}
 return LegacyPublisherBaseline{
  Schema:1,Status:"UNSIGNED_LEGACY_IDENTITY_FOR_PUBLISHER_REVIEW_ONLY",
  FromTask:legacyExpectedTask,FromExecutable:legacyExpectedExe,
  FromArguments:"--dns-service",
  FromSHA256:hash1,FromSize:size1,FromTaskXMLSHA256:xml1,
 }
}
