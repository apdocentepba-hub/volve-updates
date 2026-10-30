//go:build windows

package main

// Read-only integration of all step-2 recovery evidence: NTFS protected
// journal, independently observed SYSTEM task/process/PID/dual UDP53 owners,
// publisher-signed target (for commit), DNS v4/v6 responses and direct TCP.
// This does not install a watchdog, authorize a switch, write a receipt,
// change the network or publish a release.
import (
 "context"
 "crypto/ed25519"
 "errors"
 "fmt"
 "os"
 "path/filepath"

 "volve-browser-protection/motorupdate"
)

func auditWindowsResidentRecoveryHealthReadOnly(
 ctx context.Context,root,outcome string,key ed25519.PublicKey,
) (motorupdate.ResidentRecoveryIntent,error) {
 var empty motorupdate.ResidentRecoveryIntent
 if err:=ctx.Err();err!=nil{return empty,err}
 if outcome!="restored" && outcome!="committed"{
  return empty,errors.New("unknown resident health outcome")
 }
 if !isAdmin(){return empty,errors.New("read-only SYSTEM health audit requires Administrator")}
 if !filepath.IsAbs(root){return empty,errors.New("invalid resident recovery installation root")}
 stat,err:=os.Lstat(root)
 if err!=nil{return empty,err}
 if !stat.IsDir()||stat.Mode()&os.ModeSymlink!=0{
  return empty,errors.New("resident install root is not an ordinary directory")
 }
 dir:=filepath.Join(root,localRecoveryFolder,localRecoveryJournal)
 if err:=checkSealedResidentJournalACL(dir);err!=nil{
  return empty,fmt.Errorf("protected recovery journal rejected: %w",err)
 }
 checks:=newResidentWindowsHealthChecks(root,key)
 return motorupdate.AuditResidentRecoveryOutcome(ctx,dir,outcome,
  checkSealedResidentJournalACL,checks)
}
