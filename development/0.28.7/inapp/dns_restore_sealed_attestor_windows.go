//go:build windows

package motorupdate

// Read-only, FAIL-CLOSED adapter that binds a proposed DNS recovery to an
// independently protected resident journal AND an immutable DNS snapshot.
// No production attestor, signature permit or Windows DNS writer is wired.
// A future signed SYSTEM controller must supply non-mock ACL, permit and
// process-state verifiers and pin the snapshot digest BEFORE a motor switch.
import (
 "bytes"
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "os/user"
 "path/filepath"
 "reflect"
 "strings"
)

const WindowsDNSRecoverySnapshotName="dns-restore-snapshot.json"
const windowsDNSRecoverySnapshotLimit=32<<10

type WindowsSealedDNSRecoverySnapshot struct {
 Schema int `json:"schema"`
 Component string `json:"component"`
 IntentNonce string `json:"intent_nonce"`
 OriginalMotorSHA256 string `json:"original_motor_sha256"`
 CandidateMotorSHA256 string `json:"candidate_motor_sha256"`
 Records []DNSRestoreRecord `json:"records"`
}

// WindowsSealedDNSRecoveryAttestor supplies one actual filesystem/journal
// implementation of the abstract attestor. External verification callbacks
// MUST enforce NTFS SYSTEM/Administrators-only ACLs, a publisher-signed
// unexpired permit, stopped failed motor and trusted SYSTEM identity.
// A boolean from the panel can NEVER serve as a callback implementation.
// A zero-value attestor is always denied.
type WindowsSealedDNSRecoveryAttestor struct {
 JournalDir string
 SnapshotPath string
 PinnedSnapshotSHA256 string
 Protect func(string) error
 VerifyPublisherPermit func(context.Context, ResidentRecoveryIntent) error
 VerifySYSTEMAndFailedMotor func(context.Context, ResidentRecoveryIntent) error
}

// VerifyWindowsCurrentSystemSIDReadOnly inspects the real current Windows
// user SID. Unlike names, SID S-1-5-18 is locale independent. A successful
// check alone does not prove the publisher permit, journal or task identity.
func VerifyWindowsCurrentSystemSIDReadOnly() error {
 current,err:=user.Current()
 if err!=nil{return fmt.Errorf("cannot inspect current Windows token: %w",err)}
 if current.Uid!="S-1-5-18" {
  return errors.New("DNS recovery must execute as Windows LocalSystem")
 }
 return nil
}

func (a WindowsSealedDNSRecoveryAttestor) Verify(ctx context.Context, proposed []DNSRestoreRecord) error {
 if err:=ctx.Err();err!=nil{return err}
 if a.Protect==nil||a.VerifyPublisherPermit==nil||a.VerifySYSTEMAndFailedMotor==nil{
  return errors.New("DNS recovery has no trusted ACL, publisher permit or SYSTEM/process verification")
 }
 if !filepath.IsAbs(a.JournalDir)||
    filepath.Base(a.JournalDir)!="motor-recovery-transaction"||
    filepath.Base(filepath.Dir(a.JournalDir))!="legacy-engine-recovery" {
  return errors.New("DNS recovery journal path outside allowlisted protected tree")
 }
 expected:=filepath.Join(filepath.Dir(a.JournalDir),WindowsDNSRecoverySnapshotName)
 if a.SnapshotPath!=expected {
  return errors.New("DNS recovery snapshot not at protected sibling path")
 }
 if len(a.PinnedSnapshotSHA256)!=64||
    !isResidentLowerSHA(a.PinnedSnapshotSHA256){
  return errors.New("no trusted snapshot SHA-256 pin")
 }
 if len(proposed)==0||len(proposed)>16 {
  return errors.New("DNS recovery contains an invalid number of adapter families")
 }
 if err:=a.Protect(filepath.Dir(a.JournalDir));err!=nil{return fmt.Errorf("untrusted DNS recovery parent: %w",err)}
 if err:=a.Protect(a.SnapshotPath);err!=nil{return fmt.Errorf("untrusted sealed DNS snapshot ACL: %w",err)}
 first,err:=InspectResidentRecoveryJournal(ctx,a.JournalDir,a.Protect)
 if err!=nil{return fmt.Errorf("resident journal not trusted: %w",err)}
 if first.Status!="recovery-required" {
  return fmt.Errorf("resident journal not pending: %s",first.Status)
 }
 if err:=a.VerifyPublisherPermit(ctx,first.Intent);err!=nil{return fmt.Errorf("publisher authorization rejected: %w",err)}
 if err:=a.VerifySYSTEMAndFailedMotor(ctx,first.Intent);err!=nil{return fmt.Errorf("SYSTEM/failed motor not verified: %w",err)}
 stat,err:=os.Lstat(a.SnapshotPath)
 if err!=nil{return err}
 if !stat.Mode().IsRegular()||stat.Size()<2||stat.Size()>windowsDNSRecoverySnapshotLimit {
  return errors.New("protected DNS snapshot linked, empty or oversized")
 }
 raw,err:=os.ReadFile(a.SnapshotPath)
 if err!=nil{return err}
 if len(raw)<2||len(raw)>windowsDNSRecoverySnapshotLimit || int64(len(raw))!=stat.Size(){
  return errors.New("protected DNS snapshot changed size during read")
 }
 digest:=sha256.Sum256(raw)
 if hex.EncodeToString(digest[:])!=a.PinnedSnapshotSHA256 {
  return errors.New("DNS recovery snapshot digest no longer matches sealed preflight")
 }
 dec:=json.NewDecoder(bytes.NewReader(raw))
 dec.DisallowUnknownFields()
 var snapshot WindowsSealedDNSRecoverySnapshot
 if err:=dec.Decode(&snapshot);err!=nil{return fmt.Errorf("invalid DNS recovery snapshot: %w",err)}
 var tail any
 if dec.Decode(&tail)!=io.EOF{return errors.New("DNS recovery snapshot contains trailing JSON")}
 canonical,err:=json.Marshal(snapshot)
 if err!=nil{return err}
 if !bytes.Equal(bytes.TrimSpace(raw),canonical){
  return errors.New("noncanonical or duplicate DNS recovery snapshot keys")
 }
 if snapshot.Schema!=1||snapshot.Component!="volve-dns-restore-snapshot"||
    snapshot.IntentNonce!=first.Intent.Nonce||
    snapshot.OriginalMotorSHA256!=first.Intent.LegacySHA256||
    snapshot.CandidateMotorSHA256!=first.Intent.TargetSHA256{
  return errors.New("DNS snapshot not bound to exact pending resident transaction")
 }
 if len(snapshot.Records)!=len(proposed) || len(snapshot.Records)==0 || len(snapshot.Records)>16{
  return errors.New("proposed DNS records differ from sealed preflight count")
 }
 seen:=map[string]bool{}
 for _,record:=range snapshot.Records{
  if err:=validateWindowsStaticRecoveryRecord(record);err!=nil{return err}
  key:=strings.ToLower(record.Original.InterfaceGUID)+string(record.Original.Family)
  if seen[key]{return errors.New("duplicate adapter family in sealed snapshot")}
  seen[key]=true
 }
 if !reflect.DeepEqual(snapshot.Records,proposed){
  return errors.New("DNS restore records changed since sealed snapshot")
 }
 // Recheck OS-level ACLs and the journal after reading the snapshot. A
 // future production OS driver also requires open-handle identity binding
 // against reparse-point or filesystem replacement races.
 if err:=a.Protect(a.SnapshotPath);err!=nil{return err}
 after,err:=InspectResidentRecoveryJournal(ctx,a.JournalDir,a.Protect)
 if err!=nil||after!=first{return errors.New("pending resident journal changed during DNS attestation")}
 latest,err:=os.ReadFile(a.SnapshotPath)
 if err!=nil||!bytes.Equal(raw,latest){
  return errors.New("protected DNS snapshot changed during attestation")
 }
 if err:=a.VerifySYSTEMAndFailedMotor(ctx,first.Intent);err!=nil{
  return fmt.Errorf("SYSTEM/process identity changed during DNS attestation: %w",err)
 }
 if err:=a.VerifyPublisherPermit(ctx,first.Intent);err!=nil{
  return fmt.Errorf("signed permit invalidated during DNS attestation: %w",err)
 }
 return ctx.Err()
}
