//go:build windows

package motorupdate

// Reboot-ready authorization adapter for the independent Windows watchdog.
// It rereads the publisher-signed permit from sealed NTFS on each privileged
// operation, under the existing protected kernel lease. No permission to
// switch or install any production motor is granted by this adapter.
import (
 "bytes"
 "context"
 "crypto/ed25519"
 "errors"
 "fmt"
 "path/filepath"
 "reflect"
)

type durablePublisherBootDriver struct{
 ResidentBootRecoveryDriver
 root string
 publisher ed25519.PublicKey
 protectGrant func(string)error
 protectJournal func(string)error
 protectBackup func(string)error
 firstPermit []byte
 firstSignature []byte
}

// NewDurablePublisherBoundProtectedResidentBootDriver can be constructed on
// EVERY boot, even if there was never a recovery journal or the last attempt
// already committed. Only a PENDING journal triggers reads of the durable
// publisher grant through VerifySealedOriginal/RestoreOriginal.
//
// The caller MUST supply the PUBLIC key embedded in the distributed watchdog,
// not a key read from the journal or the filesystem.
func NewDurablePublisherBoundProtectedResidentBootDriver(
 operations ResidentOriginalRecoveryOps, root string, publisherKey ed25519.PublicKey,
 protectGrant,protectJournal,protectBackup func(string)error,
)(ResidentBootRecoveryDriver,error){
 if operations==nil||root==""||len(publisherKey)!=ed25519.PublicKeySize||
  protectGrant==nil||protectJournal==nil||protectBackup==nil{
  return nil,errors.New("boot rescue requires original operations, pinned publisher key and three protected ACL verifiers")
 }
 if _,_,_,_,err:=residentGrantPaths(root);err!=nil{return nil,err}
 protected,err:=NewProtectedResidentBootDriver(operations)
 if err!=nil{return nil,err}
 return &durablePublisherBootDriver{
  ResidentBootRecoveryDriver:protected,
  root:root,publisher:append(ed25519.PublicKey(nil),publisherKey...),
  protectGrant:protectGrant,protectJournal:protectJournal,protectBackup:protectBackup,
 },nil
}
func(d *durablePublisherBootDriver)verifyDurableEvidence(ctx context.Context,intent ResidentRecoveryIntent)error{
 if d==nil||d.ResidentBootRecoveryDriver==nil{return errors.New("no durable SYSTEM recovery driver")}
 if err:=ctx.Err();err!=nil{return err}
 // This call verifies the exact NTFS path and ACLs of the grant AND
 // independently binds its authentic Ed25519 signature to the pending
 // journal nonce/target and sealed original. It accepts a previously valid
 // expired grant for recovery ONLY.
 grant,err:=LoadResidentDurablePublisherGrant(ctx,d.root,d.publisher,
  d.protectGrant,d.protectJournal,d.protectBackup)
 if err!=nil{return fmt.Errorf("pending boot rescue lacks trusted on-disk signed grant: %w",err)}
 state,err:=InspectResidentRecoveryJournal(ctx,grant.JournalDir,d.protectJournal)
 if err!=nil||state.Status!="recovery-required"||state.Intent!=intent{
  return errors.New("protected pending journal changed or does not match boot recovery intent")
 }
 // A change to signed grant contents *between* verifying the sealed original
 // and restoring the task is forbidden, even if both grants are individually
 // valid. This is separate from the immutable kernel-mutex requirement.
 if d.firstPermit==nil{
  d.firstPermit=append([]byte(nil),grant.Permit...)
  d.firstSignature=append([]byte(nil),grant.Signature...)
 }else if !bytes.Equal(d.firstPermit,grant.Permit)||
  !bytes.Equal(d.firstSignature,grant.Signature){
  return errors.New("publisher signed grant changed during independent boot recovery")
 }
 return nil
}
// The durable grant, exact pending intent, and privileged original are
// protected by one continuous kernel-lease interval. Never read a signed
// recovery file before establishing the local + Windows mutex gate.
func(d *durablePublisherBootDriver)withDurableSignedLease(
 ctx context.Context,intent ResidentRecoveryIntent,restore bool,
)error{
 if d==nil||d.ResidentBootRecoveryDriver==nil{return errors.New("missing protected durable SYSTEM recovery adapter")}
 protected,ok:=d.ResidentBootRecoveryDriver.(*protectedResidentBootDriver)
 if !ok||protected==nil{return errors.New("durable SYSTEM recovery lacks native protected Windows mutex")}
 return protected.underProtectedLease(ctx,func()error{
  if err:=d.verifyDurableEvidence(ctx,intent);err!=nil{return err}
  if restore{return protected.operations.RestoreOriginal(ctx,intent)}
  return protected.operations.VerifySealedOriginal(ctx,intent)
 })
}
func(d *durablePublisherBootDriver)VerifySealedOriginal(ctx context.Context,intent ResidentRecoveryIntent)error{
 return d.withDurableSignedLease(ctx,intent,false)
}
func(d *durablePublisherBootDriver)RestoreOriginal(ctx context.Context,intent ResidentRecoveryIntent)error{
 return d.withDurableSignedLease(ctx,intent,true)
}


// DNS-aware adapter for the new boot policy. Not registered as a task,
// exported as a product command, or called by the installer.
// A future trusted Windows motor driver must prove that the failed candidate
// and its restart mechanisms cannot write DNS; never use a UI flag or a
// success-only callback for this proof.
type residentFailedCandidateFence func(context.Context,ResidentRecoveryIntent)error

type durablePublisherDNSBootDriver struct {
 *durablePublisherBootDriver
 verifySystem func()error
 verifyCandidateStopped residentFailedCandidateFence
 inspect WindowsReadOnlyPowerShell
 invoke WindowsDNSNativeInvoke
 firstBinding []byte
 firstBindingSignature []byte
}

var _ ResidentDNSBootRecoveryDriver = (*durablePublisherDNSBootDriver)(nil)

// Native bridge, deliberately private until exact task/process fencing and
// real reboot/network tests are certified. The public key is supplied by
// the trusted watchdog binary, never read from mutable disk configuration.
func newNativeDurablePublisherDNSBootDriver(
 ops ResidentOriginalRecoveryOps, root string, key ed25519.PublicKey,
 fence residentFailedCandidateFence,
)(ResidentDNSBootRecoveryDriver,error){
 return newDurablePublisherDNSBootDriver(ops,root,key,fence,
  VerifyWindowsCurrentSystemSIDReadOnly,DefaultWindowsReadOnlyPowerShell,runPinnedWindowsNativeDNS)
}

func newDurablePublisherDNSBootDriver(
 ops ResidentOriginalRecoveryOps, root string,key ed25519.PublicKey,
 fence residentFailedCandidateFence,system func()error,
 inspect WindowsReadOnlyPowerShell,invoke WindowsDNSNativeInvoke,
)(ResidentDNSBootRecoveryDriver,error){
 if fence==nil||system==nil||inspect==nil||invoke==nil{
  return nil,errors.New("DNS boot driver requires trusted SYSTEM, stopped candidate, inspector and native writer")
 }
 // Fail closed before privileged operations, even when constructed by an
 // elevated administrator who does not possess the actual SYSTEM token.
 if err:=system();err!=nil{return nil,fmt.Errorf("DNS recovery requires LocalSystem: %w",err)}
 // ACL callbacks must remain native and cannot be supplied by the caller.
 acl:=func(path string)error{return nativeDNSOriginalBackupACL(context.Background(),path)}
 base,err:=NewDurablePublisherBoundProtectedResidentBootDriver(ops,root,key,acl,acl,acl)
 if err!=nil{return nil,err}
 durable,ok:=base.(*durablePublisherBootDriver)
 if !ok{return nil,errors.New("unexpected boot authorization adapter")}
 return &durablePublisherDNSBootDriver{
  durablePublisherBootDriver:durable,verifySystem:system,
  verifyCandidateStopped:fence,inspect:inspect,invoke:invoke,
 },nil
}

func(d *durablePublisherDNSBootDriver)AcquireExclusive(ctx context.Context)(func(),error){
 if ctx==nil{return nil,errors.New("missing DNS boot lease context")}
 if err:=d.verifySystem();err!=nil{return nil,err}
 return d.durablePublisherBootDriver.AcquireExclusive(ctx)
}

// All reads and writes below use the outer resident lease; never call the
// DNS-only public-lease entry here (would reacquire the same mutex).
func(d *durablePublisherDNSBootDriver)withOriginalDNS(
 ctx context.Context,intent ResidentRecoveryIntent,
 work func(*protectedResidentBootDriver,[]byte,[]byte,[]DNSRestoreRecord)error,
)error{
 if ctx==nil{return errors.New("missing DNS boot context")}
 protected,ok:=d.ResidentBootRecoveryDriver.(*protectedResidentBootDriver)
 if !ok||protected==nil{return errors.New("DNS boot recovery lacks native resident lease")}
 return protected.underProtectedLease(ctx,func()error{
  if err:=d.verifySystem();err!=nil{return err}
  if err:=d.verifyDurableEvidence(ctx,intent);err!=nil{return err}
  // DNS restoration is a distinct publisher-authorized scope. A valid
  // motor-only permit must never authorize adapter writes or DNS terminal
  // recovery, even when all file hashes and task identities match.
  if len(d.firstPermit)==0||len(d.firstSignature)==0{
   return errors.New("missing durable publisher permit for motor-and-DNS recovery")
  }
  if err:=VerifyExplicitResidentRecoveryScope(
   ctx,d.firstPermit,d.firstSignature,d.publisher,
   ResidentRecoveryScopeMotorAndDNS,intent.Nonce,
  );err!=nil{
   return fmt.Errorf("publisher permit does not authorize exact MotorAndDNS recovery scope: %w",err)
  }
  raw,sig,err:=loadSignedOriginalDNSEvidenceUnderLeaseWindows(ctx,d.root,d.publisher)
  if err!=nil{return err}
  receipt,err:=VerifySignedDNSOriginalBinding(ctx,raw,sig,d.publisher,intent,d.firstPermit)
  if err!=nil{return err}
  if d.firstBinding!=nil&&(!bytes.Equal(raw,d.firstBinding)||!bytes.Equal(sig,d.firstBindingSignature)){
   return errors.New("signed DNS binding changed within resident recovery")
  }
  records,err:=ReadDNSOriginalBackupNativeWindows(ctx,filepath.Join(d.root,"legacy-engine-recovery"),receipt.OriginalDNSJournalSHA256)
  if err!=nil{return err}
  if err:=validateDNSRecoveryRecords(records);err!=nil{return err}
  if d.firstBinding==nil{
   d.firstBinding=append([]byte(nil),raw...)
   d.firstBindingSignature=append([]byte(nil),sig...)
  }
  return work(protected,raw,sig,records)
 })
}

// Before any motor change, authenticate the DNS snapshot and verify every
// live adapter is at an allowed recovery stage. Do not require that the
// failed candidate has stopped yet: motor restoration follows this check.
func(d *durablePublisherDNSBootDriver)VerifySealedOriginal(ctx context.Context,intent ResidentRecoveryIntent)error{
 return d.withOriginalDNS(ctx,intent,func(p *protectedResidentBootDriver,_ ,_ []byte,records []DNSRestoreRecord)error{
  if err:=verifySignedDNSBootRestoreCensus(ctx,records,d.inspect,false);err!=nil{return err}
  return p.operations.VerifySealedOriginal(ctx,intent)
 })
}

func(d *durablePublisherDNSBootDriver)RestoreOriginal(ctx context.Context,intent ResidentRecoveryIntent)error{
 return d.withOriginalDNS(ctx,intent,func(p *protectedResidentBootDriver,_ ,_ []byte,records []DNSRestoreRecord)error{
  if err:=verifySignedDNSBootRestoreCensus(ctx,records,d.inspect,false);err!=nil{return err}
  return p.operations.RestoreOriginal(ctx,intent)
 })
}

func(d *durablePublisherDNSBootDriver)RestoreOriginalDNS(ctx context.Context,intent ResidentRecoveryIntent)error{
 return d.withOriginalDNS(ctx,intent,func(_ *protectedResidentBootDriver,raw,sig []byte,records []DNSRestoreRecord)error{
  if err:=d.verifyCandidateStopped(ctx,intent);err!=nil{return fmt.Errorf("failed candidate not fenced: %w",err)}
  return restoreSignedOriginalDNSUnderHeldLeaseWindows(ctx,d.root,d.publisher,raw,sig,d.inspect,
   func(ctx context.Context,args []string)error{
    if err:=d.verifySystem();err!=nil{return err}
    if err:=d.verifyCandidateStopped(ctx,intent);err!=nil{return err}
    // Reopen the sealed binding before EVERY actual native DNS command.
    now,signature,err:=loadSignedOriginalDNSEvidenceUnderLeaseWindows(ctx,d.root,d.publisher)
    if err!=nil||!bytes.Equal(now,raw)||!bytes.Equal(signature,sig){return errors.New("signed DNS authorization drift before native write")}
    return d.invoke(ctx,args)
   })
 })
}

func(d *durablePublisherDNSBootDriver)VerifyOriginalDNS(ctx context.Context,intent ResidentRecoveryIntent)error{
 return d.withOriginalDNS(ctx,intent,func(_ *protectedResidentBootDriver,raw,sig []byte,records []DNSRestoreRecord)error{
  if err:=d.verifyCandidateStopped(ctx,intent);err!=nil{return err}
  if err:=verifySignedDNSBootRestoreCensus(ctx,records,d.inspect,true);err!=nil{return err}
  after,signature,err:=loadSignedOriginalDNSEvidenceUnderLeaseWindows(ctx,d.root,d.publisher)
  if err!=nil||!bytes.Equal(after,raw)||!bytes.Equal(signature,sig){return errors.New("signed DNS evidence changed during independent readback")}
  receipt,err:=VerifySignedDNSOriginalBinding(ctx,after,signature,d.publisher,intent,d.firstPermit)
  if err!=nil{return err}
  again,err:=ReadDNSOriginalBackupNativeWindows(ctx,filepath.Join(d.root,"legacy-engine-recovery"),receipt.OriginalDNSJournalSHA256)
  if err!=nil||!reflect.DeepEqual(records,again){return errors.New("original DNS snapshot drifted during readback")}
  return d.verifyCandidateStopped(ctx,intent)
 })
}

// StartOriginal is the final activation phase of DNS-aware recovery. It
// reopens the durable publisher grant and original DNS binding under the
// SAME protected lease, rechecks the candidate fence and original adapter
// census, and delegates only to a bound original-task starter. It must not
// be called until RestoreOriginalDNS and VerifyOriginalDNS have succeeded.
func(d *durablePublisherDNSBootDriver)StartOriginal(ctx context.Context,intent ResidentRecoveryIntent)error{
 return d.withOriginalDNS(ctx,intent,func(protected *protectedResidentBootDriver,raw,sig []byte,records []DNSRestoreRecord)error{
  if err:=d.verifyCandidateStopped(ctx,intent);err!=nil{return err}
  if err:=verifySignedDNSBootRestoreCensus(ctx,records,d.inspect,true);err!=nil{return err}
  after,signature,err:=loadSignedOriginalDNSEvidenceUnderLeaseWindows(ctx,d.root,d.publisher)
  if err!=nil||!bytes.Equal(after,raw)||!bytes.Equal(signature,sig){
   return errors.New("signed original DNS evidence changed before original motor start")
  }
  starter,ok:=protected.operations.(interface{
   StartOriginal(context.Context,ResidentRecoveryIntent)error
  })
  if !ok{return errors.New("protected original recovery operations lack the separate original-task starter")}
  if err:=d.verifySystem();err!=nil{return err}
  if err:=d.verifyCandidateStopped(ctx,intent);err!=nil{return err}
  if err:=starter.StartOriginal(ctx,intent);err!=nil{return fmt.Errorf("publisher-bound original motor start refused: %w",err)}
  return ctx.Err()
 })
}


// StartOriginal is the final activation phase of DNS-aware recovery. It
// reopens the durable publisher grant and original DNS binding under the
// SAME protected lease, rechecks the candidate fence and original adapter
// census, and delegates only to a bound original-task starter. It must not
// be called until RestoreOriginalDNS and VerifyOriginalDNS have succeeded.
func(d *durablePublisherDNSBootDriver)StartOriginal(ctx context.Context,intent ResidentRecoveryIntent)error{
 return d.withOriginalDNS(ctx,intent,func(protected *protectedResidentBootDriver,raw,sig []byte,records []DNSRestoreRecord)error{
  if err:=d.verifyCandidateStopped(ctx,intent);err!=nil{return err}
  if err:=verifySignedDNSBootRestoreCensus(ctx,records,d.inspect,true);err!=nil{return err}
  after,signature,err:=loadSignedOriginalDNSEvidenceUnderLeaseWindows(ctx,d.root,d.publisher)
  if err!=nil||!bytes.Equal(after,raw)||!bytes.Equal(signature,sig){
   return errors.New("signed original DNS evidence changed before original motor start")
  }
  starter,ok:=protected.operations.(interface{
   StartOriginal(context.Context,ResidentRecoveryIntent)error
  })
  if !ok{return errors.New("protected original recovery operations lack the separate original-task starter")}
  if err:=d.verifySystem();err!=nil{return err}
  if err:=d.verifyCandidateStopped(ctx,intent);err!=nil{return err}
  if err:=starter.StartOriginal(ctx,intent);err!=nil{return fmt.Errorf("publisher-bound original motor start refused: %w",err)}
  return ctx.Err()
 })
}

