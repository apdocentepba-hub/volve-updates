package motorupdate

// Recovery journal prototype for an eventual Windows task switchover.
// It is deliberately independent of any Windows API and never executes paths,
// changes DNS, or alters a scheduled task. A future privileged driver must
// authenticate task ownership, validate backup ACLs, and implement recovery.

import (
    "bytes"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "strings"
    "time"
)
const RecoveryJournalSchema = 1
const recoveryJournalMaxBytes = 4096
const (
 PhasePrepared = "prepared"
 PhaseSwitching = "switching"
 PhaseProving = "proving"
 PhaseCommitted = "committed"
 PhaseRestoring = "restoring"
 PhaseRestored = "restored"
)
type RecoveryJournal struct {
 Schema int `json:"schema"`
 Component string `json:"component"`
 Phase string `json:"phase"`
 PreviousEngineSHA string `json:"previous_engine_sha256"`
 CandidateEngineSHA string `json:"candidate_engine_sha256"`
 OriginalTaskXMLSHA string `json:"original_task_xml_sha256"`
 StartedUTC string `json:"started_utc"`
 CandidateVersion string `json:"candidate_version"`
}
func NewRecoveryJournal(version string, oldEngine, newEngine, originalTaskXML []byte, now time.Time) (RecoveryJournal, error) {
 oldHash:=sha256.Sum256(oldEngine)
 newHash:=sha256.Sum256(newEngine)
 taskHash:=sha256.Sum256(originalTaskXML)
 j:=RecoveryJournal{Schema:RecoveryJournalSchema,Component:"dns-engine",Phase:PhasePrepared,PreviousEngineSHA:hex.EncodeToString(oldHash[:]),CandidateEngineSHA:hex.EncodeToString(newHash[:]),OriginalTaskXMLSHA:hex.EncodeToString(taskHash[:]),StartedUTC:now.UTC().Format(time.RFC3339Nano),CandidateVersion:version}
 return j,j.Validate()
}
func (j RecoveryJournal) Validate() error {
 if j.Schema!=RecoveryJournalSchema || j.Component!="dns-engine" || !versionRe.MatchString(j.CandidateVersion) {return errors.New("registro de recuperación con esquema o componente inválido")}
 if !hexRe.MatchString(j.PreviousEngineSHA)|| !hexRe.MatchString(j.CandidateEngineSHA)|| !hexRe.MatchString(j.OriginalTaskXMLSHA) {return errors.New("registro con huellas inválidas")}
 if j.PreviousEngineSHA==j.CandidateEngineSHA {return errors.New("el motor nuevo no debe ser idéntico al anterior")}
 switch j.Phase {case PhasePrepared,PhaseSwitching,PhaseProving,PhaseCommitted,PhaseRestoring,PhaseRestored: default: return errors.New("fase de recuperación desconocida")}
 if _,err:=time.Parse(time.RFC3339Nano,j.StartedUTC);err!=nil||!strings.HasSuffix(j.StartedUTC,"Z"){return errors.New("fecha de transacción no es UTC")}
 return nil
}
func (j RecoveryJournal) NeedsRollback() bool {return j.Phase==PhaseSwitching||j.Phase==PhaseProving||j.Phase==PhaseRestoring}
func validTransition(from,to string)bool{
 switch from {case PhasePrepared:return to==PhaseSwitching||to==PhaseRestored
 case PhaseSwitching:return to==PhaseProving||to==PhaseRestoring
 case PhaseProving:return to==PhaseCommitted||to==PhaseRestoring
 case PhaseRestoring:return to==PhaseRestored
 default:return false}
}
func (j RecoveryJournal) Next(phase string)(RecoveryJournal,error){
 if e:=j.Validate();e!=nil{return RecoveryJournal{},e}
 if !validTransition(j.Phase,phase){return RecoveryJournal{},fmt.Errorf("transición de recuperación prohibida: %s -> %s",j.Phase,phase)}
 j.Phase=phase;return j,nil
}
func ReadRecoveryJournal(path string)(RecoveryJournal,error){
 var j RecoveryJournal
 st,e:=os.Lstat(path);if e!=nil{return j,e}
 if !st.Mode().IsRegular()||st.Size()<=0||st.Size()>recoveryJournalMaxBytes{return j,errors.New("registro de recuperación no regular o de tamaño inválido")}
 raw,e:=os.ReadFile(path);if e!=nil{return j,e}
 dec:=json.NewDecoder(bytes.NewReader(raw));dec.DisallowUnknownFields()
 if e:=dec.Decode(&j);e!=nil{return RecoveryJournal{},e}
 var trailing any
 if dec.Decode(&trailing)!=io.EOF{return RecoveryJournal{},errors.New("datos sobrantes en registro")}
 return j,j.Validate()
}
// The caller must verify SYSTEM+Administrators-only directory ACLs on Windows.
// A startup watchdog in a separate process is required for post-crash recovery.
func WriteRecoveryJournalDurable(path string,next RecoveryJournal)error{
 if e:=next.Validate();e!=nil{return e}
 dir:=filepath.Dir(path);st,e:=os.Lstat(dir);if e!=nil{return e}
 if !st.IsDir()||st.Mode()&os.ModeSymlink!=0{return errors.New("directorio de journal no autorizado")}
 if curr,e:=ReadRecoveryJournal(path);e==nil{
  if curr.Phase!=next.Phase {
   allowed,er:=curr.Next(next.Phase);if er!=nil{return er}
   if allowed!=next{return errors.New("cambio no permitido de identidad de la transacción")}
  }else if curr!=next{return errors.New("no se puede reescribir identidad de transacción")}
 }else if !errors.Is(e,os.ErrNotExist){return e}
 raw,e:=json.Marshal(next);if e!=nil{return e}
 if len(raw)>recoveryJournalMaxBytes{return errors.New("registro de recuperación excesivo")}
 f,e:=os.CreateTemp(dir,".volve-recovery-");if e!=nil{return e}
 defer os.Remove(f.Name())
 if e=f.Chmod(0600);e!=nil{f.Close();return e}
 if _,e=f.Write(raw);e!=nil{f.Close();return e}
 if e=f.Sync();e!=nil{f.Close();return e}
 if e=f.Close();e!=nil{return e}
 return os.Rename(f.Name(),path)
}
