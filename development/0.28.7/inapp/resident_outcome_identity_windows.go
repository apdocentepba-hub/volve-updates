//go:build windows

package main

// Read-only Windows identity stage of the future resident recovery health
// gate. No call from the installed panel or production task switch exists.
// This DOES NOT prove reboot durability, process ancestry or signed migration
// permission, and does not yet authorize writing a terminal receipt.
import (
 "context"
 "crypto/ed25519"
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "regexp"
 "strings"

 "volve-browser-protection/motorupdate"
)

var residentOutcomeVersion=regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

func residentOutcomeCandidatePath(root,version string)(string,error){
 if !filepath.IsAbs(root)||!residentOutcomeVersion.MatchString(version){
  return "",errors.New("unrecognized resident version/root")
 }
 name:="VOLVE_DNS_Motor_"+strings.ReplaceAll(version,".","_")+".exe"
 return filepath.Join(root,"motor-"+version,name),nil
}

// verifyResidentOutcomeIdentityReadOnly makes an independent re-read of the
// original backup AND observes both the scheduler action and a live SYSTEM
// process. For a new motor it also requires the publisher-signed installed
// manifest and executable, not just a journal-provided hash.
func verifyResidentOutcomeIdentityReadOnly(ctx context.Context,root string,
 intent motorupdate.ResidentRecoveryIntent,outcome string,key ed25519.PublicKey)error{
 if err:=ctx.Err();err!=nil{return err}
 if !isAdmin(){return errors.New("Windows motor identity inspection needs Administrator")}
 if outcome!="committed" && outcome!="restored"{
  return errors.New("unexpected recovery result")
 }
 if !filepath.IsAbs(root) || !residentOutcomeVersion.MatchString(intent.TargetVersion) {
  return errors.New("untrusted resident install root/version")
 }
 stat,err:=os.Lstat(root)
 if err!=nil{return err}
 if !stat.IsDir() || stat.Mode()&os.ModeSymlink!=0 {
  return errors.New("resident install root redirected")
 }
 parent:=filepath.Join(root,localRecoveryFolder)
 if err:=checkSealedLegacyRecoveryACL(parent);err!=nil{
  return fmt.Errorf("unprotected recovery parent: %w",err)
 }
 backupDir:=filepath.Join(parent,localRecoverySnapshot)
 record,err:=motorupdate.VerifyUnversionedLegacyRecovery(backupDir,checkSealedLegacyRecoveryACL)
 if err!=nil{return fmt.Errorf("original backup no longer verified: %w",err)}
 if record.ExeSHA256!=intent.LegacySHA256 || record.XMLSHA256!=intent.TaskXMLSHA256 ||
  intent.Task!="VOLVE-DNS-SERVER-0270"{
  return errors.New("active recovery journal disagrees with sealed original")
 }
 if err:=ctx.Err();err!=nil{return err}
 expected:=filepath.Join(root,dnsServiceFile)
 sha:=record.ExeSHA256
 if outcome=="committed" {
  if len(key)!=ed25519.PublicKeySize{return errors.New("missing pinned publisher key")}
  exe,err:=residentOutcomeCandidatePath(root,intent.TargetVersion)
  if err!=nil{return err}
  manifest,err:=motorupdate.VerifyStaged(exe,key)
  if err!=nil{return fmt.Errorf("installed candidate has no valid publisher signature: %w",err)}
  if manifest.Version!=intent.TargetVersion || manifest.SHA256!=intent.TargetSHA256 {
   return errors.New("installed signed motor no longer matches armed recovery intent")
  }
  expected=exe;sha=manifest.SHA256
 }
 return verifyResidentRunningMotorReadOnly(ctx,expected,sha)
}

// This health-check object can only be used by a future privileged recovery
// controller. The callback deliberately does not accept a spoofed test result
// or infer that a matching process alone proves recovery completed.
func newResidentWindowsHealthChecks(root string,key ed25519.PublicKey)motorupdate.ResidentActiveHealthChecks{
 return motorupdate.NewResidentNetworkHealth(
  func(ctx context.Context,j motorupdate.ResidentRecoveryIntent,outcome string)error{
   return verifyResidentOutcomeIdentityReadOnly(ctx,root,j,outcome,key)
  },
 )
}
