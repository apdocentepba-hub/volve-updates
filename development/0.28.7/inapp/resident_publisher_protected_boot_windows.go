//go:build windows

package motorupdate

// This is the production-oriented, FAIL-CLOSED publisher authorization layer
// for the already implemented protected Win32 boot-recovery driver. It does
// not switch, schedule, start, stop or edit the installed DNS service.
import (
 "context"
 "crypto/ed25519"
 "errors"
 "fmt"
)

type PublisherBoundResidentRecoveryEvidence struct{
 JournalDir string
 BackupDir string
 SignedPermit []byte
 Signature []byte
 PublisherKey ed25519.PublicKey
 ProtectJournal func(string)error
 ProtectBackup func(string)error
}

type publisherBoundResidentBootDriver struct{
 ResidentBootRecoveryDriver
 evidence PublisherBoundResidentRecoveryEvidence
}

// NewPublisherBoundProtectedResidentBootDriver requires signed publisher
// evidence, not only a locally hashed original. Operations are never called
// until the complete permit/journal/sealed-backup chain has been checked.
// The caller must pin the editor public key in the distributed binary.
func NewPublisherBoundProtectedResidentBootDriver(
 operations ResidentOriginalRecoveryOps, evidence PublisherBoundResidentRecoveryEvidence,
)(ResidentBootRecoveryDriver,error){
 if operations==nil||len(evidence.PublisherKey)!=ed25519.PublicKeySize||
  len(evidence.SignedPermit)==0||len(evidence.Signature)==0||
  evidence.ProtectJournal==nil||evidence.ProtectBackup==nil||
  evidence.JournalDir==""||evidence.BackupDir==""{
  return nil,errors.New("SYSTEM recovery needs real operations and publisher-signed protected original evidence")
 }
 protected,err:=NewProtectedResidentBootDriver(operations)
 if err!=nil{return nil,err}
 // Defensively copy editor identity and grant bytes: the caller cannot
 // mutate the authorization after construction while the mutex is held.
 evidence.PublisherKey=append(ed25519.PublicKey(nil),evidence.PublisherKey...)
 evidence.SignedPermit=append([]byte(nil),evidence.SignedPermit...)
 evidence.Signature=append([]byte(nil),evidence.Signature...)
 return &publisherBoundResidentBootDriver{ResidentBootRecoveryDriver:protected,evidence:evidence},nil
}

func(d *publisherBoundResidentBootDriver) verify(ctx context.Context,intent ResidentRecoveryIntent)error{
 if d==nil||d.ResidentBootRecoveryDriver==nil{return errors.New("no signed SYSTEM boot recovery driver")}
 if err:=ctx.Err();err!=nil{return err}
 _,err:=VerifyResidentPublisherRecoveryBinding(ctx,
  d.evidence.JournalDir,d.evidence.BackupDir,d.evidence.SignedPermit,
  d.evidence.Signature,d.evidence.PublisherKey,d.evidence.ProtectJournal,d.evidence.ProtectBackup)
 if err!=nil{return fmt.Errorf("publisher-authorized recovery denied: %w",err)}
 state,err:=InspectResidentRecoveryJournal(ctx,d.evidence.JournalDir,d.evidence.ProtectJournal)
 if err!=nil||state.Status!="recovery-required"||state.Intent!=intent{
  return errors.New("signed recovery journal does not match exact caller intent")
 }
 return nil
}
// Keep publisher permit/journal reads AND the privileged original operation
// inside ONE protected kernel-lease interval. The underlying protected
// adapter's stateMu prevents a concurrent finalizer from dropping the lease
// between the signature validation and the actual recovery call.
func(d *publisherBoundResidentBootDriver)withSignedLease(
 ctx context.Context,intent ResidentRecoveryIntent,restore bool,
)error{
 if d==nil||d.ResidentBootRecoveryDriver==nil{return errors.New("missing protected signed recovery adapter")}
 protected,ok:=d.ResidentBootRecoveryDriver.(*protectedResidentBootDriver)
 if !ok||protected==nil{return errors.New("signed recovery lacks the required native Windows mutex adapter")}
 return protected.underProtectedLease(ctx,func()error{
  if err:=d.verify(ctx,intent);err!=nil{return err}
  if restore{return protected.operations.RestoreOriginal(ctx,intent)}
  return protected.operations.VerifySealedOriginal(ctx,intent)
 })
}
func(d *publisherBoundResidentBootDriver)VerifySealedOriginal(ctx context.Context,intent ResidentRecoveryIntent)error{
 return d.withSignedLease(ctx,intent,false)
}
func(d *publisherBoundResidentBootDriver)RestoreOriginal(ctx context.Context,intent ResidentRecoveryIntent)error{
 return d.withSignedLease(ctx,intent,true)
}
