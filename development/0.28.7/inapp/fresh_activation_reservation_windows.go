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


// This private controller joins the previously isolated fresh admission,
// signed original archives and durable reservation to the existing DNS
// transaction coordinator. No product entrypoint calls it yet. The caller
// must supply an independently authenticated actual SYSTEM watchdog guard,
// trusted host observations and native backend; the CI test supplies memory
// DNS and a simulated guard. The native mutex itself is not simulated.
type freshAdmissionGuard struct{
 inner DNSActivationSafetyGuard
 verify func(context.Context,string)error
 review func(context.Context)error
}
func(g *freshAdmissionGuard)VerifyArmed(ctx context.Context,pin string)error{
 if err:=g.verify(ctx,pin);err!=nil{return err}
 if err:=g.inner.VerifyArmed(ctx,pin);err!=nil{return err}
 return g.verify(ctx,pin)
}
func(g *freshAdmissionGuard)VerifyLiveProtection(ctx context.Context,pin string)error{
 if err:=g.verify(ctx,pin);err!=nil{return err}
 if err:=g.inner.VerifyLiveProtection(ctx,pin);err!=nil{return err}
 return g.verify(ctx,pin)
}
func(g *freshAdmissionGuard)CommitActive(ctx context.Context,pin string)error{
 if err:=g.verify(ctx,pin);err!=nil{return err}
 if err:=g.review(ctx);err!=nil{return err}
 if err:=g.VerifyArmed(ctx,pin);err!=nil{return err}
 return g.inner.CommitActive(ctx,pin)
}
func(g *freshAdmissionGuard)RecoverIndependently(ctx context.Context,pin string)error{
 // Expired admission or damaged review must not suppress emergency rescue.
 return g.inner.RecoverIndependently(ctx,pin)
}

func activateFreshDNSUnderProtectedLease(ctx context.Context,root string,raw,sig []byte,key ed25519.PublicKey,pins freshActivationEvidence,host FreshMotorInstallEvidence,baseline ProtectionSnapshot,browser WindowsBrowserPolicyEvidence,inventory WindowsFreshVOLVETaskInventory,originalJournal []byte,inner DNSActivationSafetyGuard,factory dnsActivationBackendFactory)error{
 if ctx==nil||inner==nil||factory==nil{return errors.New("fresh controller missing context, independent watchdog or backend")}
 raw=append([]byte(nil),raw...);sig=append([]byte(nil),sig...);key=append(ed25519.PublicKey(nil),key...)
 originalJournal=append([]byte(nil),originalJournal...)
 if _,err:=verifyFreshActivationAdmission(ctx,raw,sig,key,pins,host,time.Now());err!=nil{return err}
 if inventory.VOLVETaskCount!=0||inventory.VerifiedCatalogTask!=nil||len(inventory.UnknownTaskNames)!=0{return errors.New("fresh controller requires absence of original VOLVE tasks")}
 reviewPin,err:=originalRecoveryReviewPin(pins.TransactionID,baseline,pins.OriginalDNSJournalSHA256)
 if err!=nil||reviewPin!=pins.OriginalReviewSHA256{return errors.New("fresh admission not bound to original protection census")}
 records,err:=VerifyDNSOriginalJournal(ctx,originalJournal,pins.OriginalDNSJournalSHA256)
 if err!=nil{return err}
 review:=func(c context.Context)error{
  r,err:=inspectPersistedSignedReviewUnderLease(c,root,pins.TransactionID,key,baseline,browser,inventory,pins.OriginalDNSJournalSHA256)
  if err!=nil||r.Status!="SIGNED_BOUND_FOUR_ARCHIVES_VERIFIED_READ_ONLY"||!r.HostsVerified||r.BrowserKeysVerified!=3||!r.DNSBackupVerified||!r.CatalogBackupVerified||r.CompleteRecoverySnapshot||r.InstallAuthorized||r.RestoreAuthorized{return errors.New("fresh controller requires intact signed four-archive review")}
  return c.Err()
 }
 guard:=&freshAdmissionGuard{inner:inner,review:review,verify:func(c context.Context,pin string)error{
  if pin!=pins.OriginalDNSJournalSHA256{return errors.New("fresh activation journal changed")}
  _,err:=verifyFreshActivationAdmission(c,raw,sig,key,pins,host,time.Now())
  return err
 }}
 return activateVOLVEDNSUnderProtectedLease(ctx,originalJournal,pins.OriginalDNSJournalSHA256,guard,AcquireProtectedResidentTransitionLease,func(c context.Context,held DNSActivationSafetyGuard)(DNSAdapterBackend,error){
  exclusive,ok:=held.(*exclusiveDNSActivationGuard)
  if !ok{return nil,errors.New("fresh controller lost shared native lease")}
  if err:=held.VerifyArmed(c,pins.OriginalDNSJournalSHA256);err!=nil{return nil,err}
  if err:=review(c);err!=nil{return nil,err}
  // Refuse replays before calling even the read-only backend factory.
  if _,err:=os.Lstat(filepath.Join(root,freshReservationName));!errors.Is(err,os.ErrNotExist){return nil,errors.New("fresh activation reservation already exists or is inaccessible")}
  backend,err:=factory(c,held)
  if err!=nil||backend==nil{return nil,errors.New("fresh controller backend unavailable")}
  if err:=verifyDNSActivationTransition(c,records,backend,0);err!=nil{return nil,err}
  if _,err:=reserveFreshActivationUnderHeldLease(c,root,raw,sig,key,pins,host,exclusive);err!=nil{return nil,err}
  return backend,nil
 })
}
