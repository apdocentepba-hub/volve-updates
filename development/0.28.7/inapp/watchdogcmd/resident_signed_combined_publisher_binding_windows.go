//go:build windows

package main

// Restricted identity/ACL binding for future independently installed SYSTEM
// watchdog. This file creates NO CLI handler, task, update release or GUI
// action. A valid staged recovery still needs persistent reboot/DNS proof.
import (
 "context"
 "crypto/ed25519"
 "encoding/base64"
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "strings"
)

func sealResidentOriginalRecoveryStageNTFS(ctx context.Context, root, staged string) error {
 if err:=ctx.Err();err!=nil{return err}
 if err:=verifyResidentActualSYSTEM(ctx);err!=nil{return err}
 if !filepath.IsAbs(root)||filepath.Clean(root)!=root||
    !filepath.IsAbs(staged)||filepath.Clean(staged)!=staged||
    !strings.EqualFold(filepath.Dir(staged),root)||
    !strings.HasPrefix(filepath.Base(staged),".volve-signed-original-recovery-"){
  return errors.New("stage is outside exact original recovery install root")
 }
 fi,err:=os.Lstat(staged)
 if err!=nil{return err}
 if !fi.Mode().IsRegular()||fi.Size()<1||fi.Size()>chainLegacyMax{
  return errors.New("staged original motor is not a bounded regular EXE")
 }
 script:="$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';"+
   "$p="+q(staged)+";"+
   "$sys=[Security.Principal.SecurityIdentifier]::new('S-1-5-18');"+
   "$adm=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544');"+
   "$attr=[IO.File]::GetAttributes($p);"+
   "if(($attr -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Linked recovery stage forbidden'};"+
   "$d=[Security.AccessControl.FileSecurity]::new();"+
   "$d.SetAccessRuleProtection($true,$false);"+
   "$d.SetOwner($sys);"+
   "$full=[Security.AccessControl.FileSystemRights]::FullControl;"+
   "$allow=[Security.AccessControl.AccessControlType]::Allow;"+
   "$d.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sys,$full,$allow));"+
   "$d.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($adm,$full,$allow));"+
   "Set-Acl -LiteralPath $p -AclObject $d -ErrorAction Stop;"+
   "Write-Output 'VOLVE_PROTECTED_ORIGINAL_STAGE'"
 out,err:=ps(ctx,script)
 if err!=nil{return fmt.Errorf("SYSTEM recovery stage NTFS sealing rejected: %w",err)}
 if out!="VOLVE_PROTECTED_ORIGINAL_STAGE"{
  return fmt.Errorf("uncertain NTFS stage sealing output: %q",out)
 }
 return checkResidentJournalNTFS(ctx,staged)
}

func recoverSignedOriginalAndSYSTEMTaskWithPublisherBindingWindows(
 ctx context.Context,root string,
)error{
 if err:=ctx.Err();err!=nil{return err}
 if err:=verifyResidentActualSYSTEM(ctx);err!=nil{return err}
 key,err:=base64.StdEncoding.DecodeString(pinnedPublicKeyB64)
 if err!=nil||len(key)!=ed25519.PublicKeySize{
  return errors.New("editor public key embedded in watchdog is invalid")
 }
 verifyACL:=func(p string)error{return checkResidentJournalNTFS(ctx,p)}
 deps:=residentSignedCombinedRecoveryDeps{
  File:residentMissingOriginalRestoreDeps{
   VerifySystem:verifyResidentActualSYSTEM,
   VerifyACL:verifyACL,
   SealNew:func(p string)error{return sealResidentOriginalRecoveryStageNTFS(ctx,root,p)},
   ProbeQuiescence:auditResidentQuiescenceReadOnly,
  },
  Task:residentSignedTaskRestoreDeps{
   VerifySystem:verifyResidentActualSYSTEM,
   VerifyACL:verifyACL,
   ProbeQuiescence:auditResidentQuiescenceReadOnly,
   RunWindowsTask:ps,
  },
 }
 return recoverSignedLegacyOriginalAndSYSTEMTaskWindows(ctx,root,
  ed25519.PublicKey(key),deps)
}
