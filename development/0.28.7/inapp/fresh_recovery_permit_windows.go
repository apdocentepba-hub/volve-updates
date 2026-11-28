//go:build windows

package motorupdate

// Separate authorization for a fresh installation's original DNS rescue.
// No legacy motor is required. No activation grant expiry, reservation
// readback, or running candidate can substitute for this signed permit.
// This is a private DNS recovery slice, not a complete boot watchdog:
// the caller must independently fence the exact candidate and startup task,
// authenticate the pending recovery state and later verify full OS recovery.
import(
 "bytes"
 "context"
 "crypto/ed25519"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "reflect"
)

const freshRecoveryPermitName="fresh-recovery-permit.json"
const freshRecoveryPermitComponent="volve-publisher-fresh-recovery-permit-v1"
const freshRecoveryOperation="restore-exact-original-dns-only"

type freshRecoveryPermit struct{
 Schema int `json:"schema"`
 Component string `json:"component"`
 Operation string `json:"operation"`
 Evidence freshActivationEvidence `json:"evidence"`
}
type freshRecoveryEnvelope struct{
 Payload []byte `json:"payload"`
 Signature []byte `json:"signature"`
}

func verifyFreshRecoveryPermit(ctx context.Context,raw,sig []byte,key ed25519.PublicKey,pins freshActivationEvidence)(freshRecoveryPermit,error){
 var denied freshRecoveryPermit
 if ctx==nil{return denied,errors.New("fresh rescue requires context")}
 if err:=ctx.Err();err!=nil{return denied,err}
 if err:=validateFreshActivationEvidence(pins);err!=nil{return denied,err}
 if len(raw)<2||len(raw)>4096||len(key)!=ed25519.PublicKeySize||len(sig)!=ed25519.SignatureSize||!ed25519.Verify(key,raw,sig){return denied,errors.New("fresh rescue publisher signature invalid")}
 var got freshRecoveryPermit
 if err:=json.Unmarshal(raw,&got);err!=nil{return denied,err}
 canonical,err:=json.Marshal(got)
 if err!=nil||!bytes.Equal(raw,canonical)||got!=(freshRecoveryPermit{1,freshRecoveryPermitComponent,freshRecoveryOperation,pins}){return denied,errors.New("fresh rescue scope or independent evidence mismatch")}
 return got,ctx.Err()
}

func loadFreshRecoveryPermitUnderLease(ctx context.Context,root string,key ed25519.PublicKey,pins freshActivationEvidence)(freshRecoveryEnvelope,error){
 var denied freshRecoveryEnvelope
 if ctx==nil{return denied,errors.New("fresh rescue context required")}
 if _,err:=originalRecoveryEvidencePath(root,pins.TransactionID);err!=nil{return denied,err}
 check:=func(p string)error{return nativeDNSOriginalBackupACL(ctx,p)}
 path:=filepath.Join(root,freshRecoveryPermitName)
 verify:=func()error{
  if err:=verifyOriginalHostsBackupNode(root,true,check);err!=nil{return err}
  return verifyOriginalHostsBackupNode(path,false,check)
 }
 if err:=verify();err!=nil{return denied,err}
 before,err:=os.Lstat(path)
 if err!=nil||before.Size()<2||before.Size()>8192{return denied,errors.New("fresh rescue envelope missing or oversized")}
 file,err:=os.Open(path);if err!=nil{return denied,err}
 opened,err:=file.Stat()
 if err!=nil||!os.SameFile(before,opened){file.Close();return denied,errors.New("fresh rescue envelope replaced")}
 raw,readErr:=io.ReadAll(io.LimitReader(file,8193))
 closeErr:=file.Close()
 if readErr!=nil||closeErr!=nil{return denied,errors.Join(readErr,closeErr)}
 var envelope freshRecoveryEnvelope
 if err:=residentCanonical(raw,&envelope);err!=nil{return denied,err}
 canonical,err:=json.Marshal(envelope)
 if err!=nil||!bytes.Equal(append(canonical,'\n'),raw)||int64(len(raw))!=before.Size(){return denied,errors.New("fresh rescue envelope is not exact canonical bytes")}
 if _,err:=verifyFreshRecoveryPermit(ctx,envelope.Payload,envelope.Signature,key,pins);err!=nil{return denied,err}
 if err:=verify();err!=nil{return denied,err}
 after,err:=os.Lstat(path)
 if err!=nil||!os.SameFile(before,after)||before.Size()!=after.Size()||!before.ModTime().Equal(after.ModTime()){return denied,errors.New("fresh rescue envelope changed during verification")}
 return envelope,ctx.Err()
}

// Stage only an externally signed rescue permit, under the same native
// mutex and existing protected original review. Never overwrite a partial
// permit and never treat staging as proof of a running watchdog.
func persistFreshRecoveryPermitNative(ctx context.Context,root string,raw,sig []byte,key ed25519.PublicKey,pins freshActivationEvidence)error{
 if _,err:=verifyFreshRecoveryPermit(ctx,raw,sig,key,pins);err!=nil{return err}
 if _,err:=originalRecoveryEvidencePath(root,pins.TransactionID);err!=nil{return err}
 release,err:=AcquireProtectedResidentTransitionLease(ctx)
 if err!=nil{return err}
 if release==nil{return errors.New("fresh rescue staging requires native mutex")}
 defer release()
 check:=func(p string)error{return nativeDNSOriginalBackupACL(ctx,p)}
 if err:=verifyOriginalHostsBackupNode(root,true,check);err!=nil{return err}
 if err:=loadOriginalRecoveryReviewEvidenceUnarmed(ctx,root,pins.TransactionID,pins.OriginalReviewSHA256,check);err!=nil{return err}
 // Require intact DNS archive before writing this authorization.
 if _,err:=ReadDNSOriginalBackupNativeWindows(ctx,filepath.Join(root,"legacy-engine-recovery"),pins.OriginalDNSJournalSHA256);err!=nil{return err}
 encoded,err:=json.Marshal(freshRecoveryEnvelope{raw,sig});if err!=nil{return err}
 path:=filepath.Join(root,freshRecoveryPermitName)
 if err:=residentCreate(path,encoded,func(p string)error{return nativeSealApprovedOriginalBackupNode(ctx,p)},check);err!=nil{return err}
 _,err=loadFreshRecoveryPermitUnderLease(ctx,root,key,pins)
 return err
}

// The independently started watchdog must establish exact pending state
// and fence candidate/task writers, under the same lease, before every
// command. Never use activation expiry or the consumed marker as a rescue
// precondition; a corrupted marker must not prevent restoration.
type freshRecoveryFence func(context.Context,freshActivationEvidence)error

func restoreFreshOriginalDNSAsSYSTEM(ctx context.Context,root string,key ed25519.PublicKey,pins freshActivationEvidence,fence freshRecoveryFence)error{
 if ctx==nil||fence==nil{return errors.New("fresh SYSTEM rescue requires authenticated pending-state and candidate fence")}
 if err:=VerifyWindowsCurrentSystemSIDReadOnly();err!=nil{return err}
 release,err:=AcquireProtectedResidentTransitionLease(ctx)
 if err!=nil{return err}
 if release==nil{return errors.New("fresh rescue mutex unavailable")}
 defer release()
 return restoreFreshOriginalDNSUnderLease(ctx,root,key,pins,fence,DefaultWindowsReadOnlyPowerShell,runPinnedWindowsNativeDNS)
}

func restoreFreshOriginalDNSUnderLease(ctx context.Context,root string,key ed25519.PublicKey,pins freshActivationEvidence,fence freshRecoveryFence,inspect WindowsReadOnlyPowerShell,invoke WindowsDNSNativeInvoke)error{
 if ctx==nil||fence==nil||inspect==nil||invoke==nil{return errors.New("fresh original DNS rescue dependencies missing")}
 first,err:=loadFreshRecoveryPermitUnderLease(ctx,root,key,pins)
 if err!=nil{return err}
 records,err:=ReadDNSOriginalBackupNativeWindows(ctx,filepath.Join(root,"legacy-engine-recovery"),pins.OriginalDNSJournalSHA256)
 if err!=nil{return err}
 reattest:=func(c context.Context)error{
  if err:=fence(c,pins);err!=nil{return err}
  again,err:=loadFreshRecoveryPermitUnderLease(c,root,key,pins)
  if err!=nil||!bytes.Equal(first.Payload,again.Payload)||!bytes.Equal(first.Signature,again.Signature){return errors.New("fresh rescue permit changed")}
  current,err:=ReadDNSOriginalBackupNativeWindows(c,filepath.Join(root,"legacy-engine-recovery"),pins.OriginalDNSJournalSHA256)
  if err!=nil||!reflect.DeepEqual(records,current){return errors.New("fresh rescue original journal changed")}
  return c.Err()
 }
 if err:=reattest(ctx);err!=nil{return err}
 if err:=verifySignedDNSBootRestoreCensus(ctx,records,inspect,false);err!=nil{return err}
 writer,err:=NewWindowsPinnedDNSRecoveryWriter(ctx,records,inspect,invoke)
 if err!=nil{return err}
 if err:=ExecuteWindowsDNSRestoreBatch(ctx,records,inspect,func(c context.Context,cmd WindowsDNSCommand)error{
  if err:=reattest(c);err!=nil{return err}
  if err:=verifySignedDNSBootRestoreCensus(c,records,inspect,false);err!=nil{return err}
  return writer(c,cmd)
 });err!=nil{return fmt.Errorf("fresh DNS rescue incomplete: %w",err)}
 if err:=reattest(ctx);err!=nil{return err}
 // This is only DNS readback; caller must not mark full recovery here.
 return verifySignedDNSBootRestoreCensus(ctx,records,inspect,true)
}
