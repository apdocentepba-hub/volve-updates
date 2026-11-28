//go:build windows

package motorupdate

// Fresh-install one-use reservation, not a migration receipt. This
// private primitive requires an independently authenticated admission,
// actual protected recovery parent and a controller already holding
// the shared native lease. It creates no task and performs no DNS writes.
// An administrator who can delete the entire protected transaction tree
// is outside this primitive's replay threat model.
import(
 "bytes"
 "context"
 "crypto/ed25519"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "io"
 "os"
 "path/filepath"
 "strings"
 "time"
)

const freshReservationName="fresh-activation-reserved.json"
type freshActivationReservation struct{
 Schema int `json:"schema"`
 Component string `json:"component"`
 Evidence freshActivationEvidence `json:"evidence"`
 AdmissionSHA256 string `json:"admission_sha256"`
 ReservedAtUnix int64 `json:"reserved_at_unix"`
}

// Independent reattestation must check actual protected original archives,
// owner approval and boot watchdog before the first durable reservation.
// Host readiness refers to the pre-staging snapshot, not to a host that
// already has its newly installed motor running. The trusted controller
// must independently verify all expected staging changes.
func reserveFreshActivationUnderHeldLease(ctx context.Context,root string,raw,sig []byte,key ed25519.PublicKey,pins freshActivationEvidence,host FreshMotorInstallEvidence,held *exclusiveDNSActivationGuard)(freshActivationReservation,error){
 var denied freshActivationReservation
 if ctx==nil||held==nil{return denied,errors.New("fresh admission requires protected lease")}
 if err:=ctx.Err();err!=nil{return denied,err}
 if !filepath.IsAbs(root)||filepath.Clean(root)!=root||strings.HasPrefix(root,string(filepath.Separator)+string(filepath.Separator))||filepath.Base(root)!=pins.TransactionID{return denied,errors.New("fresh activation requires exact local transaction directory")}
 if _,err:=originalRecoveryEvidencePath(root,pins.TransactionID);err!=nil{return denied,err}
 raw=append([]byte(nil),raw...);sig=append([]byte(nil),sig...);key=append(ed25519.PublicKey(nil),key...)
 verify:=func()(freshActivationAdmission,error){return verifyFreshActivationAdmission(ctx,raw,sig,key,pins,host,time.Now())}
 if _,err:=verify();err!=nil{return denied,err}
 if err:=held.VerifyArmed(ctx,pins.OriginalDNSJournalSHA256);err!=nil{return denied,err}
 check:=func(p string)error{return nativeDNSOriginalBackupACL(ctx,p)}
 if err:=verifyOriginalHostsBackupNode(root,true,check);err!=nil{return denied,err}
 // Match the archive review to the independent admission pin. This
 // historical evidence is necessary but never a sufficient watchdog proof.
 if err:=loadOriginalRecoveryReviewEvidenceUnarmed(ctx,root,pins.TransactionID,pins.OriginalReviewSHA256,check);err!=nil{return denied,err}
 admitted,err:=verify();if err!=nil{return denied,err}
 now:=time.Now()
 if !now.Before(time.Unix(admitted.ExpiresAtUnix,0)){return denied,errors.New("fresh activation admission expired")}
 digest:=sha256.Sum256(raw)
 receipt:=freshActivationReservation{1,"volve-fresh-activation-once-v1",pins,hex.EncodeToString(digest[:]),now.Unix()}
 encoded,err:=json.Marshal(receipt);if err!=nil{return denied,err}
 destination:=filepath.Join(root,freshReservationName)
 if err:=ctx.Err();err!=nil{return denied,err}
 file,err:=os.OpenFile(destination,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
 if err!=nil{return denied,err}
 n,writeErr:=file.Write(encoded)
 if writeErr==nil&&n!=len(encoded){writeErr=io.ErrShortWrite}
 if writeErr==nil{writeErr=file.Sync()}
 closeErr:=file.Close()
 if writeErr!=nil||closeErr!=nil{return denied,errors.Join(writeErr,closeErr)}
 // Never remove or reuse the marker, even if sealing/readback fails.
 if err:=nativeSealApprovedOriginalBackupNode(ctx,destination);err!=nil{return denied,err}
 before,err:=os.Lstat(destination);if err!=nil{return denied,err}
 if err:=verifyOriginalHostsBackupNode(destination,false,check);err!=nil{return denied,err}
 got,err:=os.ReadFile(destination)
 if err!=nil||!bytes.Equal(encoded,got){return denied,errors.New("fresh reservation readback mismatch")}
 after,err:=os.Lstat(destination)
 if err!=nil||!os.SameFile(before,after)||before.Size()!=after.Size()||!before.ModTime().Equal(after.ModTime()){return denied,errors.New("fresh reservation identity changed")}
 if err:=verifyOriginalHostsBackupNode(root,true,check);err!=nil{return denied,err}
 if err:=held.VerifyArmed(ctx,pins.OriginalDNSJournalSHA256);err!=nil{return denied,err}
 if _,err:=verify();err!=nil{return denied,err}
 return receipt,nil
}
