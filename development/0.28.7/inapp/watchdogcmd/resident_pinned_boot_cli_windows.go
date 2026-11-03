//go:build windows

package main

// SYSTEM-only entrypoint intended for the watchdog packaged INSIDE a future
// single-file installer. NOT registered in Task Scheduler or a stable release.
// All editorial signing, DACL, kernel lease and DNS/Internet health guards
// reside in runPinnedResidentBootRecoveryWindows. No user-supplied root.
import (
 "context"
 "errors"
 "fmt"
 "path/filepath"
 "strings"
)

func pinnedRecoveryInstalledRootWindows(ctx context.Context)(string,error){
 if err:=ctx.Err();err!=nil{return "",err}
 // Even installed-root discovery requires the actual LocalSystem SID.
 if err:=verifyResidentActualSYSTEM(ctx);err!=nil{
  return "",fmt.Errorf("independent boot recovery requires actual LocalSystem: %w",err)
 }
 result,err:=ps(ctx,
  "$ErrorActionPreference='Stop';"+
  "$base=[Environment]::GetFolderPath('CommonApplicationData');"+
  "if([string]::IsNullOrWhiteSpace($base)){throw 'Windows common application data unavailable'};"+
  "Write-Output $base")
 if err!=nil{return "",err}
 if result==""||strings.ContainsAny(result,"\r\n\x00")||
  !filepath.IsAbs(result)||filepath.Clean(result)!=result||
  strings.HasPrefix(result,"\\\\"){
  return "",errors.New("Windows common application data is not a canonical local directory")
 }
 path:=filepath.Join(result,"VOLVE-Browser-Filter")
 if !filepath.IsAbs(path)||filepath.Clean(path)!=path{
  return "",errors.New("fixed VOLVE root is not canonical")
 }
 return path,ctx.Err()
}

func runPinnedResidentBootRecoveryCLIWindows(ctx context.Context)(string,error){
 // Only one fixed installation root is allowed. Neither signing key nor
 // task/executable/journal paths can be chosen by the process caller.
 root,err:=pinnedRecoveryInstalledRootWindows(ctx)
 if err!=nil{return "",err}
 result,err:=runPinnedResidentBootRecoveryWindows(ctx,root)
 if err!=nil{return "",err}
 // "committed" is an already-terminal journal, NOT a proof this invocation
 // started a motor. The caller must only print the reported journal phase.
 if result!="restored"&&result!="committed"{
  return "",errors.New("independent boot recovery has no signed terminal journal")
 }
 return result,nil
}
