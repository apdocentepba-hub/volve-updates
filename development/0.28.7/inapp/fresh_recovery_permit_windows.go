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
 "crypto/sha256"
 "encoding/hex"
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
 pending,err:=expectedFreshRecoveryPending(pins,first)
 if err!=nil{return err}
 if err:=verifyFreshRecoveryPendingUnderLease(ctx,root,pending);err!=nil{return fmt.Errorf("fresh DNS rescue has no verified pending state: %w",err)}
 records,err:=ReadDNSOriginalBackupNativeWindows(ctx,filepath.Join(root,"legacy-engine-recovery"),pins.OriginalDNSJournalSHA256)
 if err!=nil{return err}
 reattest:=func(c context.Context)error{
  if err:=fence(c,pins);err!=nil{return err}
  if err:=verifyFreshRecoveryPendingUnderLease(c,root,pending);err!=nil{return err}
  again,err:=loadFreshRecoveryPermitUnderLease(c,root,key,pins)
  if err!=nil||!bytes.Equal(first.Payload,again.Payload)||!bytes.Equal(first.Signature,again.Signature){return errors.New("fresh rescue permit changed")}
  current,err:=ReadDNSOriginalBackupNativeWindows(c,filepath.Join(root,"legacy-engine-recovery"),pins.OriginalDNSJournalSHA256)
  if err!=nil||!reflect.DeepEqual(records,current){return errors.New("fresh rescue original journal changed")}
  return c.Err()
 }
 if err:=reattest(ctx);err!=nil{return err}
 result,err:=expectedFreshDNSRestored(pending)
 if err!=nil{return err}
 resultPath:=filepath.Join(root,freshDNSRestoredName)
 if _,err:=os.Lstat(resultPath);err==nil{
  // A completed DNS-only rescue is read-only on subsequent boots. Never
  // overwrite its record or interpret it as full machine recovery.
  if err:=verifyFreshDNSRestoredUnderLease(ctx,root,pending,result);err!=nil{return err}
  if err:=verifySignedDNSBootRestoreCensus(ctx,records,inspect,true);err!=nil{return fmt.Errorf("DNS drift after completed fresh rescue requires separate diagnosis: %w",err)}
  return reattest(ctx)
 }else if !errors.Is(err,os.ErrNotExist){return err}
 if err:=verifySignedDNSBootRestoreCensus(ctx,records,inspect,false);err!=nil{return err}
 writer,err:=NewWindowsPinnedDNSRecoveryWriter(ctx,records,inspect,invoke)
 if err!=nil{return err}
 if err:=ExecuteWindowsDNSRestoreBatch(ctx,records,inspect,func(c context.Context,cmd WindowsDNSCommand)error{
  if err:=reattest(c);err!=nil{return err}
  if err:=verifySignedDNSBootRestoreCensus(c,records,inspect,false);err!=nil{return err}
  return writer(c,cmd)
 });err!=nil{return fmt.Errorf("fresh DNS rescue incomplete: %w",err)}
 if err:=reattest(ctx);err!=nil{return err}
 if err:=verifySignedDNSBootRestoreCensus(ctx,records,inspect,true);err!=nil{return err}
 // Record ONLY the verified original DNS result. This does not authorize
 // removing the watchdog, committing installation or claiming full rescue.
 if err:=reattest(ctx);err!=nil{return err}
 if err:=verifySignedDNSBootRestoreCensus(ctx,records,inspect,true);err!=nil{return err}
 if err:=persistFreshDNSRestoredUnderLease(ctx,root,pending,result);err!=nil{return err}
 if err:=reattest(ctx);err!=nil{return err}
 return verifySignedDNSBootRestoreCensus(ctx,records,inspect,true)
}


// Pending DNS recovery is separate from both admission consumption and the
// recovery-only permit. Only the trusted controller, after validating all
// signed original archives and the independent watchdog, may arm it under
// the shared native lease. A partial marker is never accepted or overwritten.
// This record is NOT a terminal receipt or permission to remove a watchdog.
const freshRecoveryPendingName="fresh-dns-recovery-pending.json"
type freshRecoveryPending struct{
 Schema int `json:"schema"`
 Component string `json:"component"`
 Evidence freshActivationEvidence `json:"evidence"`
 PermitEnvelopeSHA256 string `json:"permit_envelope_sha256"`
}
func expectedFreshRecoveryPending(pins freshActivationEvidence,envelope freshRecoveryEnvelope)(freshRecoveryPending,error){
 var denied freshRecoveryPending
 if err:=validateFreshActivationEvidence(pins);err!=nil{return denied,err}
 encoded,err:=json.Marshal(envelope);if err!=nil{return denied,err}
 digest:=sha256.Sum256(encoded)
 return freshRecoveryPending{1,"volve-fresh-dns-recovery-pending-v1",pins,hex.EncodeToString(digest[:])},nil
}

// Caller owns native lease; only fixed exact transaction child is read.
// The trusted permit is reopened by the caller, never inferred from this
// unsigned NTFS-protected pending record.
func verifyFreshRecoveryPendingUnderLease(ctx context.Context,root string,expected freshRecoveryPending)error{
 if ctx==nil{return errors.New("fresh recovery pending context required")}
 if err:=ctx.Err();err!=nil{return err}
 if expected.Schema!=1||expected.Component!="volve-fresh-dns-recovery-pending-v1"||verifyCanonicalLowerSHA256(expected.PermitEnvelopeSHA256)!=nil{return errors.New("fresh recovery pending evidence invalid")}
 if err:=validateFreshActivationEvidence(expected.Evidence);err!=nil{return err}
 if _,err:=originalRecoveryEvidencePath(root,expected.Evidence.TransactionID);err!=nil{return err}
 return verifyFreshFixedRecordUnderLease(ctx,root,freshRecoveryPendingName,expected)
}

// Shared bounded native reader for these two fixed protected records.
// Never allow a caller to nominate an arbitrary file.
func verifyFreshFixedRecordUnderLease(ctx context.Context,root,name string,expected any)error{
 data,err:=readFreshFixedRecordUnderLease(ctx,root,name)
 if err!=nil{return err}
 canonical,err:=json.Marshal(expected)
 if err!=nil||!bytes.Equal(data,append(canonical,'\n')){return errors.New("fresh protected record differs from authenticated evidence")}
 return ctx.Err()
}
func readFreshFixedRecordUnderLease(ctx context.Context,root,name string)([]byte,error){
 if ctx==nil{return nil,errors.New("fresh record context required")}
 if name!=freshRecoveryPendingName&&name!=freshDNSRestoredName&&name!=freshProvisionalName{return nil,errors.New("unsupported fresh recovery record")}
 path:=filepath.Join(root,name)
 check:=func(p string)error{return nativeDNSOriginalBackupACL(ctx,p)}
 verify:=func()error{
  if err:=verifyOriginalHostsBackupNode(root,true,check);err!=nil{return err}
  return verifyOriginalHostsBackupNode(path,false,check)
 }
 if err:=verify();err!=nil{return nil,err}
 before,err:=os.Lstat(path)
 if err!=nil||before.Size()<2||before.Size()>4096{return nil,errors.New("fresh recovery pending record missing or malformed")}
 file,err:=os.Open(path);if err!=nil{return nil,err}
 opened,err:=file.Stat()
 if err!=nil||!os.SameFile(before,opened){file.Close();return nil,errors.New("fresh pending recovery record replaced")}
 data,readErr:=io.ReadAll(io.LimitReader(file,4097))
 closeErr:=file.Close()
 if readErr!=nil||closeErr!=nil{return nil,errors.Join(readErr,closeErr)}
 if int64(len(data))!=before.Size(){return nil,errors.New("fresh protected record length changed during read")}
 if err:=verify();err!=nil{return nil,err}
 after,err:=os.Lstat(path)
 if err!=nil||!os.SameFile(before,after)||before.Size()!=after.Size()||!before.ModTime().Equal(after.ModTime()){return nil,errors.New("fresh pending recovery record changed during readback")}
 return data,ctx.Err()
}

func armFreshRecoveryPendingUnderLease(ctx context.Context,root string,key ed25519.PublicKey,pins freshActivationEvidence,held *exclusiveDNSActivationGuard)(freshRecoveryPending,error){
 var denied freshRecoveryPending
 if ctx==nil||held==nil{return denied,errors.New("fresh pending arming requires protected lease and independent watchdog")}
 if err:=held.VerifyArmed(ctx,pins.OriginalDNSJournalSHA256);err!=nil{return denied,err}
 envelope,err:=loadFreshRecoveryPermitUnderLease(ctx,root,key,pins)
 if err!=nil{return denied,err}
 expected,err:=expectedFreshRecoveryPending(pins,envelope)
 if err!=nil{return denied,err}
 if _,err:=ReadDNSOriginalBackupNativeWindows(ctx,filepath.Join(root,"legacy-engine-recovery"),pins.OriginalDNSJournalSHA256);err!=nil{return denied,err}
 check:=func(p string)error{return nativeDNSOriginalBackupACL(ctx,p)}
 if err:=verifyOriginalHostsBackupNode(root,true,check);err!=nil{return denied,err}
 if err:=requireFreshDNSRestoredAbsent(ctx,root);err!=nil{return denied,err}
 raw,err:=json.Marshal(expected);if err!=nil{return denied,err}
 if err:=ctx.Err();err!=nil{return denied,err}
 if err:=residentCreate(filepath.Join(root,freshRecoveryPendingName),raw,func(p string)error{return nativeSealApprovedOriginalBackupNode(ctx,p)},check);err!=nil{return denied,err}
 if err:=verifyFreshRecoveryPendingUnderLease(ctx,root,expected);err!=nil{return denied,err}
 return expected,nil
}


// A DNS-only completion record is distinct from a successful installation
// or full rollback. No timestamp or mutable flags are used as authority.
// It binds the exact independently verified pending record. Full recovery
// and an active post-boot installation need different lifecycle evidence.
const freshDNSRestoredName="fresh-dns-original-restored.json"
type freshDNSRestored struct{
 Schema int `json:"schema"`
 Component string `json:"component"`
 PendingSHA256 string `json:"pending_sha256"`
 OriginalDNSJournalSHA256 string `json:"original_dns_journal_sha256"`
}
func expectedFreshDNSRestored(pending freshRecoveryPending)(freshDNSRestored,error){
 var denied freshDNSRestored
 if pending.Schema!=1||pending.Component!="volve-fresh-dns-recovery-pending-v1"||verifyCanonicalLowerSHA256(pending.PermitEnvelopeSHA256)!=nil{return denied,errors.New("fresh DNS restored result requires verified pending record")}
 if err:=validateFreshActivationEvidence(pending.Evidence);err!=nil{return denied,err}
 raw,err:=json.Marshal(pending);if err!=nil{return denied,err}
 digest:=sha256.Sum256(raw)
 return freshDNSRestored{1,"volve-fresh-dns-original-restored-only-v1",hex.EncodeToString(digest[:]),pending.Evidence.OriginalDNSJournalSHA256},nil
}
func requireFreshDNSRestoredAbsent(ctx context.Context,root string)error{
 if err:=ctx.Err();err!=nil{return err}
 if _,err:=os.Lstat(filepath.Join(root,freshDNSRestoredName));!errors.Is(err,os.ErrNotExist){return errors.New("fresh DNS completion slot already exists or cannot be observed")}
 return nil
}
func verifyFreshDNSRestoredUnderLease(ctx context.Context,root string,pending freshRecoveryPending,result freshDNSRestored)error{
 expected,err:=expectedFreshDNSRestored(pending)
 if err!=nil||expected!=result{return errors.New("foreign fresh DNS completion result")}
 if err:=verifyFreshRecoveryPendingUnderLease(ctx,root,pending);err!=nil{return err}
 return verifyFreshFixedRecordUnderLease(ctx,root,freshDNSRestoredName,result)
}
// Internal caller must have proved exact live original DNS and retained the
// same independent recovery lease; this helper alone proves no OS outcome.
func persistFreshDNSRestoredUnderLease(ctx context.Context,root string,pending freshRecoveryPending,result freshDNSRestored)error{
 expected,err:=expectedFreshDNSRestored(pending)
 if err!=nil||expected!=result{return errors.New("invalid fresh DNS completion result")}
 if err:=verifyFreshRecoveryPendingUnderLease(ctx,root,pending);err!=nil{return err}
 if err:=requireFreshDNSRestoredAbsent(ctx,root);err!=nil{return err}
 raw,err:=json.Marshal(result);if err!=nil{return err}
 check:=func(p string)error{return nativeDNSOriginalBackupACL(ctx,p)}
 if err:=ctx.Err();err!=nil{return err}
 if err:=residentCreate(filepath.Join(root,freshDNSRestoredName),raw,func(p string)error{return nativeSealApprovedOriginalBackupNode(ctx,p)},check);err!=nil{return err}
 return verifyFreshDNSRestoredUnderLease(ctx,root,pending,result)
}
