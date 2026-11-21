//go:build windows

package motorupdate

// Private DNS-only slice of a future independently installed SYSTEM watchdog.
// It does NOT restore the legacy motor or its tasks, does not register a
// watchdog, and MUST NOT be used as proof of post-reboot recovery. It never
// writes a terminal restored receipt: the motor and network probes of
// RecoverPendingResidentAfterBoot remain separate mandatory checks.
import (
 "bytes"
 "context"
 "crypto/ed25519"
 "errors"
 "fmt"
 "path/filepath"
 "reflect"
 "strings"
)

type dnsBootRecoveryLease func(context.Context)(func(),error)

// Private and NOT wired to product, updater or NSIS. Future signed watchdog
// must pin its Ed25519 key and original-DNS receipt; never from mutable UI.
func restoreSignedOriginalDNSAsSYSTEM(
 ctx context.Context,root string,publisherKey ed25519.PublicKey,
 originalBindingJSON,originalBindingSignature []byte,
)error{
 if ctx==nil{return errors.New("SYSTEM DNS recovery context missing")}
 if err:=VerifyWindowsCurrentSystemSIDReadOnly();err!=nil{
  return fmt.Errorf("original DNS recovery requires actual LocalSystem token: %w",err)
 }
 return restoreSignedOriginalDNSUnderProtectedLeaseWindows(
  ctx,root,publisherKey,originalBindingJSON,originalBindingSignature,
  DefaultWindowsReadOnlyPowerShell,runPinnedWindowsNativeDNS,
  AcquireProtectedResidentTransitionLease,
 )
}

// Tested with real Windows NTFS and Win32 mutex, but memory-only DNS commands.
// Only a caller that has already stopped the failed motor and authenticated
// the watchdog boot transaction may safely invoke the production bridge.
func restoreSignedOriginalDNSUnderProtectedLeaseWindows(
 ctx context.Context,root string,publisherKey ed25519.PublicKey,
 originalBindingJSON,originalBindingSignature []byte,
 inspect WindowsReadOnlyPowerShell,invoke WindowsDNSNativeInvoke,
 acquire dnsBootRecoveryLease,
)error{
 if ctx==nil||inspect==nil||invoke==nil||acquire==nil{
  return errors.New("signed SYSTEM DNS recovery requires trusted inspector, writer and mutex")
 }
 if err:=ctx.Err();err!=nil{return err}
 if len(publisherKey)!=ed25519.PublicKeySize||len(originalBindingJSON)==0||
  len(originalBindingSignature)==0{return errors.New("missing publisher-signed original DNS recovery authorization")}
 if !filepath.IsAbs(root)||filepath.Clean(root)!=root||
  strings.HasPrefix(root,string(filepath.Separator)+string(filepath.Separator)){
  return errors.New("signed DNS recovery must use canonical local protected root")
 }
 release,err:=acquire(ctx)
 if err!=nil{return fmt.Errorf("recovery protected Windows kernel mutex not acquired: %w",err)}
 if release==nil{return errors.New("recovery mutex acquired without owner release")}
 defer release()
 return restoreSignedOriginalDNSUnderHeldLeaseWindows(
  ctx,root,publisherKey,originalBindingJSON,originalBindingSignature,inspect,invoke)
}

// This core must run ONLY while holding the protected Windows kernel mutex.
// Separating ownership from execution lets the restarted SYSTEM watchdog
// reopen persisted signed evidence without reacquiring the same mutex.
func restoreSignedOriginalDNSUnderHeldLeaseWindows(
 ctx context.Context,root string,publisherKey ed25519.PublicKey,
 originalBindingJSON,originalBindingSignature []byte,
 inspect WindowsReadOnlyPowerShell,invoke WindowsDNSNativeInvoke,
)error{
 verifyACL:=func(path string)error{return nativeDNSOriginalBackupACL(ctx,path)}
 grant,err:=LoadResidentDurablePublisherGrant(
  ctx,root,publisherKey,verifyACL,verifyACL,verifyACL,
 )
 if err!=nil{return fmt.Errorf("sealed signed publisher permit unavailable: %w",err)}
 pending,err:=InspectResidentRecoveryJournal(ctx,grant.JournalDir,verifyACL)
 if err!=nil||pending.Status!="recovery-required"{
  return errors.New("protected original DNS recovery requires exact pending motor transaction")
 }
 receipt,err:=VerifySignedDNSOriginalBinding(
  ctx,originalBindingJSON,originalBindingSignature,publisherKey,
  pending.Intent,grant.Permit,
 )
 if err!=nil{return fmt.Errorf("publisher-signed original DNS snapshot rejected: %w",err)}
 parent:=filepath.Join(root,"legacy-engine-recovery")
 records,err:=ReadDNSOriginalBackupNativeWindows(
  ctx,parent,receipt.OriginalDNSJournalSHA256,
 )
 if err!=nil{return fmt.Errorf("NTFS-sealed original DNS snapshot unsafe: %w",err)}
 if err:=validateDNSRecoveryRecords(records);err!=nil{return err}
 // Refuse before any netsh if a VPN, virtual adapter or unexpected
 // family exists outside the publisher-signed original DNS inventory.
 if err:=verifySignedDNSBootRestoreCensus(ctx,records,inspect,false);err!=nil{
  return fmt.Errorf("original DNS recovery full-adapter preflight refused: %w",err)
 }
 writer,err:=NewWindowsPinnedDNSRecoveryWriter(ctx,records,inspect,invoke)
 if err!=nil{return fmt.Errorf("pinned native DNS restore writer rejected: %w",err)}
 if err:=ExecuteWindowsDNSRestoreBatch(ctx,records,inspect,func(
  ctx context.Context,cmd WindowsDNSCommand,
 )error{
  // Independently inspect the entire host inventory before every mutation,
  // not only the requested GUID. Caller retains the same Win32 lease.
  if err:=verifySignedDNSBootRestoreCensus(ctx,records,inspect,false);err!=nil{return err}
  return writer(ctx,cmd)
 });err!=nil{
  return fmt.Errorf("SYSTEM original DNS restoration incomplete; pending recovery receipt preserved: %w",err)
 }
 if err:=verifySignedDNSBootRestoreCensus(ctx,records,inspect,true);err!=nil{
  return fmt.Errorf("original IPv4/IPv6 readback not proven: %w",err)
 }
 // No terminal success from this DNS-only stage. Reopen signer, pending
 // journal and snapshot under the SAME mutex to detect ACL/content drift.
 again,err:=LoadResidentDurablePublisherGrant(
  ctx,root,publisherKey,verifyACL,verifyACL,verifyACL,
 )
 if err!=nil||grant.JournalDir!=again.JournalDir||grant.BackupDir!=again.BackupDir||
  !bytes.Equal(grant.Permit,again.Permit)||!bytes.Equal(grant.Signature,again.Signature){
  return errors.New("signed publisher grant changed during DNS restoration")
 }
 current,err:=InspectResidentRecoveryJournal(ctx,grant.JournalDir,verifyACL)
 if err!=nil||current!=pending{
  return errors.New("pending motor recovery journal changed during DNS restoration")
 }
 reloaded,err:=ReadDNSOriginalBackupNativeWindows(ctx,parent,receipt.OriginalDNSJournalSHA256)
 if err!=nil||!reflect.DeepEqual(records,reloaded){
  return errors.New("sealed original DNS backup changed during recovery")
 }
 if _,err:=VerifySignedDNSOriginalBinding(
  ctx,originalBindingJSON,originalBindingSignature,publisherKey,
  current.Intent,again.Permit,
 );err!=nil{return fmt.Errorf("original DNS publisher signature invalid at final readback: %w",err)}
 return verifySignedDNSBootRestoreCensus(ctx,records,inspect,true)
}

// This is the only boot-time DNS restoration entry that does not need signed
// receipt bytes passed in memory by the installer. It reopens the already
// sealed receipt and verifies it against the independently durable publisher
// grant, pending motor journal and DNS snapshot, under ONE protected mutex.
// Still private: no task or product command calls this without a verified
// motor-stop / SYSTEM watchdog transaction.
func restorePersistedSignedOriginalDNSAsSYSTEM(
 ctx context.Context,root string,key ed25519.PublicKey,
)error{
 if ctx==nil{return errors.New("boot DNS recovery context unavailable")}
 if err:=VerifyWindowsCurrentSystemSIDReadOnly();err!=nil{
  return fmt.Errorf("boot original DNS recovery requires LocalSystem: %w",err)
 }
 return restorePersistedSignedOriginalDNSUnderProtectedLeaseWindows(
  ctx,root,key,DefaultWindowsReadOnlyPowerShell,
  runPinnedWindowsNativeDNS,AcquireProtectedResidentTransitionLease)
}

func restorePersistedSignedOriginalDNSUnderProtectedLeaseWindows(
 ctx context.Context,root string,key ed25519.PublicKey,
 inspect WindowsReadOnlyPowerShell,invoke WindowsDNSNativeInvoke,
 acquire dnsBootRecoveryLease,
)error{
 if ctx==nil||inspect==nil||invoke==nil||acquire==nil{
  return errors.New("persisted signed DNS recovery missing protected Windows services")
 }
 if err:=ctx.Err();err!=nil{return err}
 if _,_,_,err:=dnsOriginalBindingEvidencePaths(root);err!=nil{return err}
 release,err:=acquire(ctx)
 if err!=nil{return fmt.Errorf("cannot obtain original DNS boot kernel mutex: %w",err)}
 if release==nil{return errors.New("DNS recovery lease has no owner release")}
 defer release()
 raw,signature,err:=loadSignedOriginalDNSEvidenceUnderLeaseWindows(ctx,root,key)
 if err!=nil{return fmt.Errorf("durable publisher signed original DNS binding rejected: %w",err)}
 return restoreSignedOriginalDNSUnderHeldLeaseWindows(
  ctx,root,key,raw,signature,inspect,invoke)
}

func verifySignedDNSBootRestoreCensus(
 ctx context.Context,records []DNSRestoreRecord,
 inspect WindowsReadOnlyPowerShell,requireOriginal bool,
)error{
 if ctx==nil||inspect==nil{return errors.New("DNS census verification unavailable")}
 if err:=ctx.Err();err!=nil{return err}
 evidence,err:=InspectWindowsDNSAssignmentProvenanceReadOnly(ctx,inspect)
 if err!=nil{return err}
 if len(evidence.States)!=len(records){
  return errors.New("original recovery journal does not cover full live Windows adapter/family census")
 }
 historical:=make(map[string]DNSRestoreRecord,len(records))
 for _,record:=range records{
  key:=strings.ToLower(record.Original.InterfaceGUID)+"|"+string(record.Original.Family)
  if _,exists:=historical[key];exists{return errors.New("duplicate original DNS journal family")}
  historical[key]=record
 }
 for _,state:=range evidence.States{
  key:=strings.ToLower(state.InterfaceGUID)+"|"+string(state.Family)
  record,ok:=historical[key]
  if !ok{return errors.New("foreign DNS adapter or protocol outside signed original recovery snapshot")}
  if requireOriginal&&!sameDNSState(state,record.Original){
   return errors.New("readback still differs from exact protected original DNS")
  }
 }
 for _,record:=range records{
  if _,_,err:=observeWindowsDNSRestoreStage(ctx,record,inspect);err!=nil{
   return fmt.Errorf("untrusted live adapter restore stage: %w",err)
  }
 }
 return nil
}
