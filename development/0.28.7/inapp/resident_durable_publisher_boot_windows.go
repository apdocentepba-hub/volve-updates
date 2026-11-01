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
func(d *durablePublisherBootDriver)VerifySealedOriginal(ctx context.Context,intent ResidentRecoveryIntent)error{
 if err:=d.verifyDurableEvidence(ctx,intent);err!=nil{return err}
 return d.ResidentBootRecoveryDriver.VerifySealedOriginal(ctx,intent)
}
func(d *durablePublisherBootDriver)RestoreOriginal(ctx context.Context,intent ResidentRecoveryIntent)error{
 if err:=d.verifyDurableEvidence(ctx,intent);err!=nil{return err}
 return d.ResidentBootRecoveryDriver.RestoreOriginal(ctx,intent)
}
