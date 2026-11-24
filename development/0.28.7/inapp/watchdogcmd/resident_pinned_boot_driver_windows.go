//go:build windows

package main

// Production-identity construction ONLY, not a production entrypoint.
// A future independently installed LocalSystem startup watchdog can use
// this driver through RecoverPendingResidentAfterBoot once real post-boot
// task/DNS/Internet health and a persistent reboot have been proven.
// NO CLI, scheduled task registration, panel button or release enables it.
import (
 "context"
 "crypto/ed25519"
 "encoding/base64"
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "strings"
 "time"

 "volve-browser-protection/motorupdate"
)

// newPinnedResidentBootRecoveryDriverWindows cannot accept a caller-supplied
// signing key, a substitute mutex or a simulated identity. It deliberately
// requires the actual Windows LocalSystem access token before returning a
// driver, and the resulting operations re-attest SYSTEM under the lock.
func newPinnedResidentBootRecoveryDriverWindows(
 ctx context.Context,root string,
)(motorupdate.ResidentBootRecoveryDriver,error){
 if err:=ctx.Err();err!=nil{return nil,err}
 if !filepath.IsAbs(root)||filepath.Clean(root)!=root{
  return nil,errors.New("signed resident boot driver requires canonical absolute installation root")
 }
 if err:=verifyResidentActualSYSTEM(ctx);err!=nil{
  return nil,fmt.Errorf("signed resident boot recovery requires actual SYSTEM identity: %w",err)
 }
 key,err:=base64.StdEncoding.DecodeString(pinnedPublicKeyB64)
 if err!=nil||len(key)!=ed25519.PublicKeySize{
  return nil,errors.New("watchdog embedded editor key is invalid")
 }
 // A boot controller may be constructed before its first journal recovery.
 // Never retain the constructor context: it can already have expired when a
 // future boot event requests ACL verification. Each operation has its OWN
 // bounded context and continues to fail closed on PowerShell/NTFS errors.
 acl:=func(path string)error{
  checkCtx,cancel:=context.WithTimeout(context.Background(),30*time.Second)
  defer cancel()
  return checkResidentJournalNTFS(checkCtx,path)
 }
 deps:=residentSignedCombinedRecoveryDeps{
  File:residentMissingOriginalRestoreDeps{
   VerifySystem:verifyResidentActualSYSTEM,
   VerifyACL:acl,
   SealNew:func(path string)error{
    sealCtx,cancel:=context.WithTimeout(context.Background(),30*time.Second)
    defer cancel()
    return sealResidentOriginalRecoveryStageNTFS(sealCtx,root,path)
   },
   ProbeQuiescence:auditResidentQuiescenceReadOnly,
  },
  Task:residentSignedTaskRestoreDeps{
   VerifySystem:verifyResidentActualSYSTEM,
   VerifyACL:acl,
   ProbeQuiescence:auditResidentQuiescenceReadOnly,
   RunWindowsTask:ps,
  },
 }
 ops,err:=newResidentSignedBootOriginalOps(root,ed25519.PublicKey(key),deps)
 if err!=nil{return nil,err}
 // This is THE OS-wide Windows kernel lease, not a local test lock. The
 // inner operations are explicitly lock-held, avoiding double acquisition.
 // Never let this motor-only entry finalize a transaction that has
 // staged DNS evidence. The separate DNS-aware driver remains disabled
 // until the actual candidate fence and reboot/network tests pass.
 return motorupdate.NewProtectedResidentBootDriver(&motorOnlyPinnedBootOps{root:root,original:ops})
}


// This gate executes inside the native resident lease, before BOTH original
// verification and mutation. Partial or corrupt DNS staging is evidence
// enough to REFUSE the motor-only path, not a reason to silently fall back.
// Absence cannot prove that DNS was never changed if a privileged actor
// deleted all evidence: a production DNS transaction must additionally bind
// its scope in the immutable signed intent before making any DNS writes.
type motorOnlyPinnedBootOps struct {
 root string
 original motorupdate.ResidentOriginalRecoveryOps
}

func rejectDNSStagingForMotorOnlyBoot(ctx context.Context,root string)error{
 if ctx==nil{return errors.New("motor-only recovery requires context")}
 if err:=ctx.Err();err!=nil{return err}
 if !filepath.IsAbs(root)||filepath.Clean(root)!=root||strings.HasPrefix(root,`\\`){
  return errors.New("motor-only recovery requires canonical local root")
 }
 parent:=filepath.Join(root,residentRecoveryParent)
 for _,path:=range []string{root,parent}{
  info,err:=os.Lstat(path)
  if err!=nil{return fmt.Errorf("cannot inspect motor-only recovery ancestry: %w",err)}
  if !info.IsDir()||info.Mode()&os.ModeSymlink!=0{return errors.New("motor-only recovery ancestry is redirected")}
 }
 for _,name:=range []string{motorupdate.DNSOriginalBackupDirectoryName,"dns-original-binding.json","dns-original-binding.sig"}{
  _,err:=os.Lstat(filepath.Join(parent,name))
  if err==nil{return errors.New("DNS evidence present: motor-only boot recovery forbidden; require DNS-aware recovery")}
  if !errors.Is(err,os.ErrNotExist){return fmt.Errorf("cannot prove absence of DNS recovery evidence: %w",err)}
 }
 return ctx.Err()
}

func(o *motorOnlyPinnedBootOps)VerifySealedOriginal(ctx context.Context,intent motorupdate.ResidentRecoveryIntent)error{
 if o==nil||o.original==nil{return errors.New("missing motor-only original verifier")}
 if err:=rejectDNSStagingForMotorOnlyBoot(ctx,o.root);err!=nil{return err}
 if err:=o.original.VerifySealedOriginal(ctx,intent);err!=nil{return err}
 return rejectDNSStagingForMotorOnlyBoot(ctx,o.root)
}
func(o *motorOnlyPinnedBootOps)RestoreOriginal(ctx context.Context,intent motorupdate.ResidentRecoveryIntent)error{
 if o==nil||o.original==nil{return errors.New("missing motor-only original restorer")}
 if err:=rejectDNSStagingForMotorOnlyBoot(ctx,o.root);err!=nil{return err}
 if err:=o.original.RestoreOriginal(ctx,intent);err!=nil{return err}
 return rejectDNSStagingForMotorOnlyBoot(ctx,o.root)
}
