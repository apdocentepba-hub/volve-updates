//go:build windows

package main

// PRIVATE production-identity finalization for an independently installed
// SYSTEM boot watchdog. The ordinary GUI cannot invoke this routine.
// No CLI, startup task, release switch, or motor activation is registered.
//
// The signed boot policy owns the real Windows mutex, authenticates the
// immutable original and publisher grant, restores/starts only that original
// if required, verifies real DNS v4/v6 and external Internet, and ONLY THEN
// requests this create-only terminal receipt. A successful Start-ScheduledTask
// alone is never a recovery success.
import (
 "context"
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "strings"

 "volve-browser-protection/motorupdate"
)

func pinnedResidentTerminalReceiptPath(root,path string) bool {
 if root==""||!filepath.IsAbs(root)||filepath.Clean(root)!=root||
  !filepath.IsAbs(path)||filepath.Clean(path)!=path||
  strings.HasPrefix(root,`\\`)||
  strings.HasPrefix(path,`\\`){
  return false
 }
 expected:=filepath.Join(root,residentRecoveryParent,residentJournalDirName,motorupdate.ResidentResultFile)
 return strings.EqualFold(expected,path)
}

// This callback MUST run under actual LocalSystem after residentCreate used
// O_EXCL to make the one terminal receipt. It may change the DACL of that
// EXACT NEW result file only; never the install directory or task/engine.
// A pre-existing result is rejected by the journal writer, not overwritten.
func sealPinnedResidentTerminalReceiptNTFS(ctx context.Context,root,path string)error{
 if err:=ctx.Err();err!=nil{return err}
 if !pinnedResidentTerminalReceiptPath(root,path){
  return errors.New("signed recovery seal refuses any path except exact terminal receipt")
 }
 if err:=verifyResidentActualSYSTEM(ctx);err!=nil{
  return fmt.Errorf("terminal recovery receipt sealing requires SYSTEM: %w",err)
 }
 dir:=filepath.Dir(path)
 parent:=filepath.Dir(dir)
 for _,p:=range []string{root,parent,dir}{
  info,err:=os.Lstat(p)
  if err!=nil{return err}
  if !info.IsDir()||info.Mode()&os.ModeSymlink!=0 {
   return errors.New("recovery receipt directory is redirected or not ordinary")
  }
  if err:=checkResidentJournalNTFS(ctx,p);err!=nil{
   return fmt.Errorf("terminal receipt ancestor ACL rejected: %w",err)
  }
 }
 file,err:=os.Lstat(path);if err!=nil{return err}
 if !file.Mode().IsRegular()||file.Mode()&os.ModeSymlink!=0||
  file.Size()<2||file.Size()>4096{
  return errors.New("terminal recovery receipt is not bounded canonical JSON file")
 }
 script:="$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';"+
  "$p="+q(path)+";"+
  "$identity=[Security.Principal.WindowsIdentity]::GetCurrent();"+
  "if($identity.User.Value -cne 'S-1-5-18'){throw 'SYSTEM required to seal boot result'};"+
  "$attr=[IO.File]::GetAttributes($p);"+
  "if(($attr -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'terminal is a reparse point'};"+
  "$sys=[Security.Principal.SecurityIdentifier]::new('S-1-5-18');"+
  "$adm=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544');"+
  "$d=[Security.AccessControl.FileSecurity]::new();"+
  "$d.SetAccessRuleProtection($true,$false);$d.SetOwner($sys);"+
  "$rights=[Security.AccessControl.FileSystemRights]::FullControl;"+
  "$allow=[Security.AccessControl.AccessControlType]::Allow;"+
  "$d.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sys,$rights,$allow));"+
  "$d.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($adm,$rights,$allow));"+
  "Set-Acl -LiteralPath $p -AclObject $d -ErrorAction Stop;"+
  "Write-Output 'VOLVE_SIGNED_RECOVERY_RESULT_SEALED'"
 got,err:=ps(ctx,script)
 if err!=nil{return fmt.Errorf("Windows terminal receipt NTFS sealing rejected: %w",err)}
 if got!="VOLVE_SIGNED_RECOVERY_RESULT_SEALED"{
  return fmt.Errorf("ambiguous terminal receipt seal response: %q",got)
 }
 if err:=checkResidentJournalNTFS(ctx,path);err!=nil{return err}
 return checkResidentJournalNTFS(ctx,dir)
}

// A complete private bridge already connects the genuine pinned SYSTEM
// original-driver and real Windows DNS/Internet probes. No task registration,
// install hook, update button or command invokes this function yet. Its
// only mutation, if all signed gates pass, is a separately authorized old
// motor restoration and the final O_EXCL journal receipt.
func runPinnedResidentBootRecoveryWindows(ctx context.Context,installedRoot string)(string,error){
 if err:=ctx.Err();err!=nil{return "",err}
 if !filepath.IsAbs(installedRoot)||filepath.Clean(installedRoot)!=installedRoot||
  strings.HasPrefix(installedRoot,`\\`){
  return "",errors.New("pinned signed SYSTEM boot root must be canonical and local")
 }
 if err:=verifyResidentActualSYSTEM(ctx);err!=nil{return "",err}
 components,err:=newPinnedResidentBootComponentsWindows(ctx,installedRoot)
 if err!=nil{return "",err}
 if components.Driver==nil||components.Health==nil{
  return "",errors.New("pinned original driver or DNS/Internet health is missing")
 }
 parent:=filepath.Dir(components.JournalDir)
 for _,p:=range []string{installedRoot,parent,components.JournalDir}{
  if err:=checkResidentJournalNTFS(ctx,p);err!=nil{
   return "",fmt.Errorf("signed boot recovery journal ancestry unsafe: %w",err)
  }
 }
 protect:=func(path string)error{return checkResidentJournalNTFS(ctx,path)}
 seal:=func(path string)error{
  return sealPinnedResidentTerminalReceiptNTFS(ctx,installedRoot,path)
 }
 return motorupdate.RecoverPendingResidentAfterBoot(
  ctx,components.JournalDir,seal,protect,components.Health,components.Driver)
}
