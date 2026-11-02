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
 "path/filepath"
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
 return motorupdate.NewProtectedResidentBootDriver(ops)
}
