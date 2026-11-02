//go:build windows

package main

// Private construction of a *matched* signed boot driver, SYSTEM-only health
// verifier, and canonical journal path. This creates no startup trigger,
// scheduled task, service, UI action, DNS setting or recovery receipt.
// Production recovery remains DISABLED pending a persistent VM reboot and
// authentic publisher grant for the installed legacy engine.
import (
 "context"
 "errors"
 "fmt"
 "path/filepath"

 "volve-browser-protection/motorupdate"
)

type residentPinnedBootComponentsWindows struct {
 Driver motorupdate.ResidentBootRecoveryDriver
 Health motorupdate.ResidentCompletionChecks
 JournalDir string
}

// The journal path and recovery/health roots must come from ONE canonical,
// trusted installation root. Never let untrusted journal JSON supply a
// different executable path, health callback or publisher public key.
func newPinnedResidentBootComponentsWindows(
 ctx context.Context,root string,
)(residentPinnedBootComponentsWindows,error){
 var empty residentPinnedBootComponentsWindows
 if err:=ctx.Err();err!=nil{return empty,err}
 if !filepath.IsAbs(root)||filepath.Clean(root)!=root{
  return empty,errors.New("boot recovery requires canonical absolute root")
 }
 if err:=verifyResidentActualSYSTEM(ctx);err!=nil{
  return empty,fmt.Errorf("matched recovery and health require actual SYSTEM: %w",err)
 }
 driver,err:=newPinnedResidentBootRecoveryDriverWindows(ctx,root)
 if err!=nil{return empty,fmt.Errorf("pinned rollback driver not constructed: %w",err)}
 health,err:=newPinnedResidentBootHealthWindows(ctx,root)
 if err!=nil{return empty,fmt.Errorf("pinned original health not constructed: %w",err)}
 if driver==nil||health==nil{
  return empty,errors.New("matched signed boot components incomplete")
 }
 return residentPinnedBootComponentsWindows{
  Driver:driver,
  Health:health,
  JournalDir:filepath.Join(root,residentRecoveryParent,residentJournalDirName),
 },nil
}
