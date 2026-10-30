package motorupdate

// Create-only recovery journal. This does NOT authorize or switch a DNS motor.
// A missing terminal receipt leaves the transaction requiring independent
// recovery. Nothing here constitutes a real Windows reboot test.
import (
 "bytes"
 "context"
 "crypto/rand"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "regexp"
)

const ResidentIntentFile="resident-intent.json"
const ResidentResultFile="resident-result.json"
const residentJournalLimit=4096
var residentSHA=regexp.MustCompile("^[a-f0-9]{64}$")
var residentVersion=regexp.MustCompile("^[0-9]+\\.[0-9]+\\.[0-9]+$")
var residentNonce=regexp.MustCompile("^[a-f0-9]{32}$")

type ResidentRecoveryIntent struct {
 Schema int `json:"schema"`
 Component string `json:"component"`
 Task string `json:"task"`
 LegacySHA256 string `json:"legacy_sha256"`
 TaskXMLSHA256 string `json:"task_xml_sha256"`
 TargetSHA256 string `json:"target_sha256"`
 TargetVersion string `json:"target_version"`
 Nonce string `json:"nonce"`
}
type ResidentRecoveryResult struct {
 Schema int `json:"schema"`
 Component string `json:"component"`
 IntentSHA256 string `json:"intent_sha256"`
 IntentNonce string `json:"intent_nonce"`
 Outcome string `json:"outcome"`
}
type ResidentRecoveryJournalState struct {
 Status string // not-armed, recovery-required, committed, restored
 Intent ResidentRecoveryIntent
}

func validResidentIntent(j ResidentRecoveryIntent) error {
 if j.Schema!=1||j.Component!="dns-engine-recovery-intent"||
 j.Task!="VOLVE-DNS-SERVER-0270"||!residentSHA.MatchString(j.LegacySHA256)||
 !residentSHA.MatchString(j.TaskXMLSHA256)||!residentSHA.MatchString(j.TargetSHA256)||
 !residentVersion.MatchString(j.TargetVersion)||!residentNonce.MatchString(j.Nonce) {
  return errors.New("invalid resident recovery journal identity")
 }
 return nil
}
func residentDir(dir string) error {
 if !filepath.IsAbs(dir){return errors.New("journal directory must be absolute")}
 s,e:=os.Lstat(dir)
 if e!=nil{return e}
 if !s.IsDir()||s.Mode()&os.ModeSymlink!=0{return errors.New("journal directory is redirected")}
 return nil
}
func residentFile(path string)([]byte,error){
 s,e:=os.Lstat(path);if e!=nil{return nil,e}
 if !s.Mode().IsRegular()||s.Size()<2||s.Size()>residentJournalLimit{
  return nil,errors.New("journal file is linked, empty or too large")
 }
 b,e:=os.ReadFile(path);if e!=nil{return nil,e}
 if len(b)<2||len(b)>residentJournalLimit{return nil,errors.New("journal file changed size")}
 return b,nil
}
func residentCanonical(raw []byte,out any)error{
 d:=json.NewDecoder(bytes.NewReader(raw));d.DisallowUnknownFields()
 if e:=d.Decode(out);e!=nil{return e}
 var extra any
 if e:=d.Decode(&extra);e!=io.EOF{return errors.New("trailing JSON")}
 canonical,e:=json.Marshal(out);if e!=nil{return e}
 // Exact canonical encoding also rejects duplicate keys.
 if !bytes.Equal(bytes.TrimSpace(raw),canonical){return errors.New("noncanonical or duplicate JSON")}
 return nil
}
func residentCreate(path string, data []byte,seal,protect func(string)error)error{
 if seal==nil||protect==nil{return errors.New("no trusted recovery ACL services")}
 f,e:=os.OpenFile(path,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
 if e!=nil{return e}
 // Preserve incomplete files so a crash cannot silently be interpreted as
 // success. Future attempts must fail closed rather than overwrite them.
 _,writeErr:=f.Write(append(data,'\n'))
 if writeErr==nil{writeErr=f.Sync()}
 closeErr:=f.Close()
 if writeErr!=nil{return writeErr};if closeErr!=nil{return closeErr}
 if e=seal(path);e!=nil{return fmt.Errorf("cannot seal recovery journal: %w",e)}
 return protect(path)
}

// ArmResidentRecoveryIntent requires an EMPTY protected directory, then
// writes a nonce-bound intent using O_EXCL and fsync before acknowledging it.
// A future Windows driver MUST verify independent SYSTEM recovery readiness
// and signed migration permission before any actual motor mutation.
func ArmResidentRecoveryIntent(ctx context.Context,dir string,intent ResidentRecoveryIntent,
 seal,protect func(string)error)(ResidentRecoveryIntent,error){
 var zero ResidentRecoveryIntent
 if e:=ctx.Err();e!=nil{return zero,e}
 if e:=residentDir(dir);e!=nil{return zero,e}
 if seal==nil||protect==nil{return zero,errors.New("missing ACL services")}
 if e:=protect(dir);e!=nil{return zero,e}
 entries,e:=os.ReadDir(dir);if e!=nil{return zero,e}
 if len(entries)!=0{return zero,errors.New("existing journal cannot be rearmed")}
 nonce:=make([]byte,16)
 if _,e=rand.Read(nonce);e!=nil{return zero,e}
 intent.Nonce=hex.EncodeToString(nonce)
 if e=validResidentIntent(intent);e!=nil{return zero,e}
 raw,e:=json.Marshal(intent);if e!=nil{return zero,e}
 if e=ctx.Err();e!=nil{return zero,e}
 if e=residentCreate(filepath.Join(dir,ResidentIntentFile),raw,seal,protect);e!=nil{return zero,e}
 state,e:=InspectResidentRecoveryJournal(ctx,dir,protect)
 if e!=nil||state.Status!="recovery-required"||state.Intent!=intent{
  return zero,fmt.Errorf("written intent cannot be verified: %v",e)
 }
 return intent,nil
}

// InspectResidentRecoveryJournal never modifies files, tasks or DNS. An
// unsafe, truncated or orphaned terminal record causes an ERROR, not commit.
func InspectResidentRecoveryJournal(ctx context.Context,dir string,
 protect func(string)error)(ResidentRecoveryJournalState,error){
 var zero ResidentRecoveryJournalState
 if e:=ctx.Err();e!=nil{return zero,e}
 if protect==nil{return zero,errors.New("missing ACL verifier")}
 if e:=residentDir(dir);e!=nil{return zero,e}
 if e:=protect(dir);e!=nil{return zero,e}
 entries,e:=os.ReadDir(dir);if e!=nil{return zero,e}
 if len(entries)>2{return zero,errors.New("unexpected journal files")}
 present:=map[string]bool{}
 for _,x:=range entries{
  if x.Name()!=ResidentIntentFile&&x.Name()!=ResidentResultFile{
   return zero,errors.New("unexpected journal entry")
  }
  present[x.Name()]=true
 }
 if !present[ResidentIntentFile]{
  if present[ResidentResultFile]{return zero,errors.New("orphan terminal receipt")}
  return ResidentRecoveryJournalState{Status:"not-armed"},nil
 }
 intentPath:=filepath.Join(dir,ResidentIntentFile)
 if e=protect(intentPath);e!=nil{return zero,e}
 raw,e:=residentFile(intentPath);if e!=nil{return zero,e}
 var intent ResidentRecoveryIntent
 if e=residentCanonical(raw,&intent);e!=nil{return zero,e}
 if e=validResidentIntent(intent);e!=nil{return zero,e}
 if e=ctx.Err();e!=nil{return zero,e}
 if !present[ResidentResultFile]{
  return ResidentRecoveryJournalState{Status:"recovery-required",Intent:intent},nil
 }
 terminalPath:=filepath.Join(dir,ResidentResultFile)
 if e=protect(terminalPath);e!=nil{return zero,e}
 terminal,e:=residentFile(terminalPath);if e!=nil{return zero,e}
 var result ResidentRecoveryResult
 if e=residentCanonical(terminal,&result);e!=nil{return zero,e}
 hash:=sha256.Sum256(bytes.TrimSpace(raw))
 if result.Schema!=1||result.Component!="dns-engine-recovery-result"||
  result.IntentNonce!=intent.Nonce||result.IntentSHA256!=hex.EncodeToString(hash[:])||
  (result.Outcome!="committed"&&result.Outcome!="restored"){
  return zero,errors.New("terminal receipt not tied to immutable intent")
 }
 if e=protect(intentPath);e!=nil{return zero,e}
 now,e:=residentFile(intentPath)
 if e!=nil||!bytes.Equal(now,raw){return zero,errors.New("journal changed during verification")}
 return ResidentRecoveryJournalState{Status:result.Outcome,Intent:intent},nil
}

// FinishResidentRecoveryIntent is only for a future driver AFTER it has
// independently confirmed DNS/network health (committed) or full recovery
// (restored). It cannot prove that health by itself; no production caller yet.
func FinishResidentRecoveryIntent(ctx context.Context,dir,outcome string,
 seal,protect func(string)error)error{
 if outcome!="committed"&&outcome!="restored"{return errors.New("invalid terminal outcome")}
 if e:=ctx.Err();e!=nil{return e}
 if seal==nil||protect==nil{return errors.New("missing ACL services")}
 state,e:=InspectResidentRecoveryJournal(ctx,dir,protect);if e!=nil{return e}
 if state.Status!="recovery-required"{return errors.New("journal not armed or already finalized")}
 raw,e:=residentFile(filepath.Join(dir,ResidentIntentFile));if e!=nil{return e}
 digest:=sha256.Sum256(bytes.TrimSpace(raw))
 result:=ResidentRecoveryResult{Schema:1,Component:"dns-engine-recovery-result",
  IntentSHA256:hex.EncodeToString(digest[:]),IntentNonce:state.Intent.Nonce,Outcome:outcome}
 output,e:=json.Marshal(result);if e!=nil{return e}
 if e=ctx.Err();e!=nil{return e}
 if e=residentCreate(filepath.Join(dir,ResidentResultFile),output,seal,protect);e!=nil{return e}
 after,e:=InspectResidentRecoveryJournal(ctx,dir,protect)
 if e!=nil||after.Status!=outcome{return fmt.Errorf("terminal result not verifiable: %v",e)}
 return nil
}
