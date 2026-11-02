//go:build windows

package main

// Publisher-signed rollback of an EXACT, already-installed candidate to the
// sealed old motor. This is private to the lock-held recovery coordinator:
// NO CLI, installed task or release channel can invoke it today.
//
// An existing UNKNOWN/linked executable is never eligible. Neither a signed
// journal alone nor the lab CI recovery path is enough: a real durable
// publisher grant, protected NTFS, LocalSystem and actual DNS53/process
// quiescence must all be true under the updater's shared Win32 kernel mutex.
// Do not publish a terminal receipt until a separate DNS/Internet boot proof.
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
)

func restoreSignedExactCandidateLockedWindows(ctx context.Context,root string,
 publisher ed25519.PublicKey,deps residentMissingOriginalRestoreDeps)error{
 if err:=ctx.Err();err!=nil{return err}
 if len(publisher)!=ed25519.PublicKeySize||
  !filepath.IsAbs(root)||filepath.Clean(root)!=root||
  deps.VerifySystem==nil||deps.VerifyACL==nil||
  deps.SealNew==nil||deps.ProbeQuiescence==nil {
  return errors.New("signed exact-target rollback requires pinned publisher and all SYSTEM/NTFS/DNS guards")
 }
 if err:=deps.VerifySystem(ctx);err!=nil{return fmt.Errorf("candidate rollback requires SYSTEM: %w",err)}
 admit,err:=auditResidentSignedBootAdmissionLocked(ctx,root,publisher,
  deps.VerifyACL,deps.VerifyACL,deps.VerifyACL,deps.ProbeQuiescence)
 if err!=nil{return fmt.Errorf("signed candidate rollback admission rejected: %w",err)}
 if !admit.PublisherVerified||!admit.QuiescenceVerified||
  admit.Status!="recovery-required"||
  admit.Action!="signed-evidence-verified-read-only"||
  admit.OriginalFileState!="exact-pinned-target-still-present"{
  return errors.New("signed rollback refuses an original, missing file or unrecognized live candidate")
 }
 old:=filepath.Join(root,residentLegacyExe)
 snapshot:=filepath.Join(root,residentRecoveryParent,residentRecoveryFolder,residentRecoveryExe)
 if err:=deps.VerifyACL(root);err!=nil{return err}
 if err:=deps.VerifyACL(old);err!=nil{return fmt.Errorf("candidate file ACL not sealed: %w",err)}
 if err:=deps.VerifyACL(snapshot);err!=nil{return fmt.Errorf("old backup ACL not sealed: %w",err)}
 info,err:=os.Lstat(snapshot)
 if err!=nil{return err}
 if !info.Mode().IsRegular()||info.Size()<1||info.Size()>chainLegacyMax{
  return errors.New("publisher-sealed original snapshot is not regular and bounded")
 }
 source,err:=os.Open(snapshot)
 if err!=nil{return err}
 defer source.Close()
 stage,err:=os.CreateTemp(root,".volve-signed-candidate-rollback-*")
 if err!=nil{return fmt.Errorf("cannot stage original on protected same-volume NTFS: %w",err)}
 staged:=stage.Name()
 defer os.Remove(staged)
 hash:=sha256.New()
 count,copyErr:=io.Copy(io.MultiWriter(stage,hash),io.LimitReader(source,chainLegacyMax+1))
 if copyErr!=nil{stage.Close();return copyErr}
 if err:=stage.Sync();err!=nil{stage.Close();return err}
 if err:=stage.Close();err!=nil{return err}
 if count!=info.Size()||count>chainLegacyMax||
  hex.EncodeToString(hash.Sum(nil))!=admit.OriginalSHA256{
  return errors.New("staged old motor differs from signed original")
 }
 if err:=deps.SealNew(staged);err!=nil{return fmt.Errorf("cannot seal stage DACL: %w",err)}
 if err:=deps.VerifyACL(staged);err!=nil{return fmt.Errorf("staged original has untrusted NTFS DACL: %w",err)}

 // An exact candidate is the ONLY file we may replace. Revalidate its
 // identity, signed editorial authorization, task state, running processes,
 // IPv4/IPv6 DNS53 and immutable backups UNDER THE SAME HELD mutex.
 again,err:=auditResidentSignedBootAdmissionLocked(ctx,root,publisher,
  deps.VerifyACL,deps.VerifyACL,deps.VerifyACL,deps.ProbeQuiescence)
 if err!=nil||again!=admit{
  return fmt.Errorf("signed publisher grant or live candidate changed before rollback: %w",err)
 }
 now,err:=os.Lstat(old)
 if err!=nil||!now.Mode().IsRegular()||now.Size()<1||now.Size()>chainLegacyMax{
  return errors.New("candidate absent, linked or changed at final replacement boundary")
 }
 if err:=deps.VerifyACL(old);err!=nil{return fmt.Errorf("candidate DACL changed: %w",err)}
 // Last hash check must bind to the journal's signed TARGET and not merely
 // accept a binary with an EXE filename or a matching displayed version.
 pinned,err:=auditPostSwitchResidentRecovery(ctx,root)
 if err!=nil{return err}
 candidateHash,err:=digestResidentLive(ctx,old)
 if err!=nil||candidateHash!=pinned.TargetSHA256||
  candidateHash==pinned.LegacySHA256{
  return errors.New("existing motor no longer equals the exact signed target")
 }
 if err:=deps.VerifySystem(ctx);err!=nil{return err}
 if err:=ctx.Err();err!=nil{return err}
 // Windows MoveFileEx(REPLACE_EXISTING) from os.Rename is a single same-volume
 // replacement. An executable in use normally prevents this operation.
 // Failure preserves the candidate and keeps the recovery journal PENDING.
 if err:=os.Rename(staged,old);err!=nil{
  return fmt.Errorf("atomic exact-candidate to original replacement refused: %w",err)
 }
 restored,err:=digestResidentLive(ctx,old)
 if err!=nil||restored!=admit.OriginalSHA256{
  return errors.New("signed old motor hash cannot be proven after replacement")
 }
 if err:=deps.VerifyACL(old);err!=nil{return fmt.Errorf("restored original NTFS ACL changed: %w",err)}
 after,err:=auditPostSwitchResidentRecovery(ctx,root)
 if err!=nil||after!=pinned{
  return errors.New("signed recovery journal/backup changed after candidate rollback")
 }
 // Task Scheduler restore MUST follow this file replacement under the
 // caller's same protected mutex. Never record a DNS-health success here.
 return nil
}
