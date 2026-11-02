//go:build windows

package main

// First real filesystem recovery primitive for a MISSING legacy motor.
// Intentionally NOT exposed as a CLI / installer / update-button action.
// It publishes only the exact original from a sealed NTFS snapshot when
// the recovery intent, genuine publisher grant and live SYSTEM/DNS53
// quiescence are all reverified under ONE protected OS-wide mutex.
//
// This intentionally DOES NOT overwrite an already-present candidate,
// stop a service/process, touch Task Scheduler, change DNS, or finalize
// a recovery receipt. The future SYSTEM restorer must handle those other
// phases separately after reboot and full integration testing.
import (
 "context"
 "crypto/ed25519"
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"

 "volve-browser-protection/motorupdate"
)

type residentMissingOriginalRestoreDeps struct{
 VerifySystem func(context.Context)error
 VerifyACL func(string)error
 SealNew func(string)error
 ProbeQuiescence func(context.Context,string)(residentQuiescenceDecision,error)
}

// restoreSignedMissingOriginalWindows is intentionally package-local and
// REQUIRES an external SYSTEM attestor. No executor can pass an absent probe
// as a harmless no-op: every dependency is required. Tests use a disposable
// NTFS fixture and a synthetic publisher key; no real product files are read.
func restoreSignedMissingOriginalWindows(ctx context.Context,root string,
 publisherKey ed25519.PublicKey, deps residentMissingOriginalRestoreDeps,
)error{
 if err:=ctx.Err();err!=nil{return err}
 if deps.VerifySystem==nil||deps.VerifyACL==nil||deps.SealNew==nil||
  deps.ProbeQuiescence==nil{
  return errors.New("missing privileged identity, ACL, sealing or live DNS gate")
 }
 if err:=deps.VerifySystem(ctx);err!=nil{
  return fmt.Errorf("independent restorer is not SYSTEM: %w",err)
 }
 if !filepath.IsAbs(root)||filepath.Clean(root)!=root||
  len(publisherKey)!=ed25519.PublicKeySize{
  return errors.New("untrusted root or publisher identity")
 }
 lease,err:=motorupdate.AcquireProtectedResidentTransitionLease(ctx)
 if err!=nil{return fmt.Errorf("cannot acquire protected recovery mutex: %w",err)}
 if lease==nil{return errors.New("recovery mutex returned no release function")}
 defer lease()

 admission,err:=auditResidentSignedBootAdmissionLocked(ctx,root,publisherKey,
  deps.VerifyACL,deps.VerifyACL,deps.VerifyACL,deps.ProbeQuiescence)
 if err!=nil{return fmt.Errorf("signed boot recovery rejected: %w",err)}
 if !admission.PublisherVerified||!admission.QuiescenceVerified||
  admission.Action!="signed-evidence-verified-read-only"{
  return errors.New("signed recovery not fully authorized and quiescent")
 }
 if admission.OriginalFileState!="missing-original"{
  // Never overwrite a candidate or rewrite an intact original through this
  // primitive. They require different, explicit recovery operations.
  return errors.New("missing-only recovery refuses to replace an existing motor")
 }
 original:=filepath.Join(root,residentLegacyExe)
 snapshot:=filepath.Join(root,residentRecoveryParent,residentRecoveryFolder,residentRecoveryExe)
 if err:=deps.VerifyACL(root);err!=nil{return fmt.Errorf("untrusted installation directory: %w",err)}
 if err:=deps.VerifyACL(snapshot);err!=nil{return fmt.Errorf("untrusted original snapshot: %w",err)}
 info,err:=os.Lstat(snapshot)
 if err!=nil{return err}
 if !info.Mode().IsRegular()||info.Size()<1||info.Size()>chainLegacyMax{
  return errors.New("sealed original snapshot is not regular or bounded")
 }
 if _,err:=os.Lstat(original);err==nil{return errors.New("original file unexpectedly appeared")}
 if !errors.Is(err,os.ErrNotExist){return fmt.Errorf("original cannot be safely checked: %w",err)}

 input,err:=os.Open(snapshot)
 if err!=nil{return err}
 defer input.Close()
 stage,err:=os.CreateTemp(root,".volve-signed-original-recovery-*")
 if err!=nil{return fmt.Errorf("cannot stage original on same volume: %w",err)}
 stagePath:=stage.Name()
 defer os.Remove(stagePath)
 hash:=sha256.New()
 copied,copyErr:=io.Copy(io.MultiWriter(stage,hash),io.LimitReader(input,chainLegacyMax+1))
 if copyErr!=nil{stage.Close();return copyErr}
 if err:=stage.Sync();err!=nil{stage.Close();return err}
 if err:=stage.Close();err!=nil{return err}
 if copied!=info.Size()||copied>chainLegacyMax||
  hex.EncodeToString(hash.Sum(nil))!=admission.OriginalSHA256{
  return errors.New("staged original differs from signed/sealed recovery intent")
 }
 // Never expose a potentially user-writable executable. Fail closed if
 // installing the protected ACL on the NEW file is unavailable.
 if err:=deps.SealNew(stagePath);err!=nil{return fmt.Errorf("cannot seal staged original: %w",err)}
 if err:=deps.VerifyACL(stagePath);err!=nil{return fmt.Errorf("staged original ACL not trusted: %w",err)}

 // Repeat ALL signed grant/rollback/journal and live Task Scheduler/process/
 // DNS-port checks under the SAME lease, after staging and before publishing.
 again,err:=auditResidentSignedBootAdmissionLocked(ctx,root,publisherKey,
  deps.VerifyACL,deps.VerifyACL,deps.VerifyACL,deps.ProbeQuiescence)
 if err!=nil||again!=admission{
  return fmt.Errorf("signed recovery evidence changed before no-clobber publish: %w",err)
 }
 if err:=deps.VerifySystem(ctx);err!=nil{return err}
 if err:=ctx.Err();err!=nil{return err}
 // NTFS hard link is a CREATE-ONLY publish: if another process races to
 // create the old path, Link fails rather than overwrite an unknown motor.
 if err:=os.Link(stagePath,original);err!=nil{
  return fmt.Errorf("original create-only NTFS publish refused: %w",err)
 }
 // Leave the original installed if later evidence becomes unsafe, but NEVER
 // issue a false recovery success or a terminal journal receipt. The future
 // SYSTEM watchdog must inspect and repair with an explicit transaction.
 actual,err:=digestResidentLive(ctx,original)
 if err!=nil||actual!=admission.OriginalSHA256{
  return errors.New("published original checksum not verified")
 }
 if err:=deps.VerifyACL(original);err!=nil{return fmt.Errorf("original restored with untrusted ACL: %w",err)}
 if _,err:=auditPostSwitchResidentRecovery(ctx,root);err!=nil{
  return fmt.Errorf("signed original published but recovery journal/backup changed: %w",err)
 }
 return nil
}
