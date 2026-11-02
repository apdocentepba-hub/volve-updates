//go:build windows

package main

// Production-identity binding for a future independent SYSTEM watchdog.
// Deliberately NOT connected to main(), Windows startup, launcher buttons,
// update manifests or any published version. It cannot operate as an
// administrator or an interactive user: only the Windows SYSTEM SID can
// pass the initial barrier, and all subsequent signed/NTFS/DNS gates remain.
import (
 "context"
 "crypto/ed25519"
 "encoding/base64"
 "errors"
 "fmt"
)

func verifyResidentActualSYSTEM(ctx context.Context)error{
 if err:=ctx.Err();err!=nil{return err}
 evidence,err:=ps(ctx,
  "$ErrorActionPreference='Stop';"+
  "$id=[Security.Principal.WindowsIdentity]::GetCurrent();"+
  "if($null -eq $id -or $null -eq $id.User -or $id.User.Value -cne 'S-1-5-18'){throw 'VOLVE SYSTEM SID required'};"+
  "Write-Output 'VOLVE_VERIFIED_SYSTEM_SID'")
 if err!=nil{return fmt.Errorf("actual SYSTEM token could not be verified: %w",err)}
 if evidence!="VOLVE_VERIFIED_SYSTEM_SID"{
  return errors.New("ambiguous Windows identity evidence")
 }
 return ctx.Err()
}

func restoreSignedOriginalSYSTEMTaskWithPinnedPublisherWindows(
 ctx context.Context,root string,
)error{
 if err:=ctx.Err();err!=nil{return err}
 // An explicit OS token check precedes even reading the private recovery
 // journal. An admin may inspect but may NOT perform this restore.
 if err:=verifyResidentActualSYSTEM(ctx);err!=nil{return err}
 pub,err:=base64.StdEncoding.DecodeString(pinnedPublicKeyB64)
 if err!=nil||len(pub)!=ed25519.PublicKeySize{
  return errors.New("pinned editorial public key is malformed")
 }
 acl:=func(path string)error{return checkResidentJournalNTFS(ctx,path)}
 return restoreSignedOriginalSYSTEMTaskWindows(ctx,root,
  ed25519.PublicKey(pub),residentSignedTaskRestoreDeps{
   VerifySystem:verifyResidentActualSYSTEM,
   VerifyACL:acl,
   ProbeQuiescence:auditResidentQuiescenceReadOnly,
   RunWindowsTask:ps,
  })
}
