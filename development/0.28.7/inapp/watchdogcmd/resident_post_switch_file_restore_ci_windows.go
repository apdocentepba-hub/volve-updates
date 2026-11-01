//go:build windows

package main

// Windows CI-ONLY file-level rehearsal for a missing legacy DNS executable.
// This cannot be invoked from the installed app, has no CLI, requires a
// disposable pilot task and GitHub Actions' temporary sandbox, never changes
// Task Scheduler/DNS and never restores from a journal without a sealed copy.
//
// The real privileged SYSTEM controller is NOT implemented by this function.
// It may replace ONLY a byte-exact, pending-journal-pinned candidate inside
// an isolated CI directory. It rejects unknown binaries. The journal's hash
// is NOT a valid publisher signature: production remains forbidden.
import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "strings"
)

func restoreMissingLegacyExecutableCILab(ctx context.Context,root,pilotTask string)error{
 if err:=ctx.Err();err!=nil{return err}
 if os.Getenv("GITHUB_ACTIONS")!="true"||
  os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"||
  !pilotTaskPattern.MatchString(pilotTask)||
  !filepath.IsAbs(root)||filepath.Clean(root)!=root{
  return errors.New("file restoration is restricted to a disposable Windows CI sandbox")
 }
 relative,err:=filepath.Rel(filepath.Clean(os.TempDir()),root)
 if err!=nil||relative=="."||relative==".."||
  strings.HasPrefix(relative,".."+string(filepath.Separator))||
  filepath.IsAbs(relative){
  return errors.New("CI recovery root outside the disposable temp hierarchy")
 }
 // The live EXE is deliberately NOT used as proof of the old version:
 // it may have been replaced or disappeared in an interrupted upgrade.
 pinned,err:=auditPostSwitchResidentRecovery(ctx,root)
 if err!=nil{return fmt.Errorf("post-switch sealed fallback not trusted: %w",err)}
 original:=filepath.Join(root,residentLegacyExe)
 // A new candidate is an acceptable lab occupant ONLY when its exact bytes
 // match the pending recovery intent. This is not publisher authorization.
 // In particular, never overwrite an unknown or symlinked executable.
 replacedPinnedCandidate:=false
 if info,err:=os.Lstat(original);err==nil{
  if !info.Mode().IsRegular() || info.Size()<1 || info.Size()>chainLegacyMax {
   return errors.New("existing installed executable is linked or not a regular bounded file")
  }
  actual,hashErr:=digestResidentLive(ctx,original)
  if hashErr!=nil{return fmt.Errorf("existing legacy motor unsafe: %w",hashErr)}
  if actual==pinned.LegacySHA256{
   return nil // Already restored: never rewrite an otherwise healthy original.
  }
  if actual!=pinned.TargetSHA256 || pinned.TargetSHA256==pinned.LegacySHA256{
   return errors.New("different installed executable requires a separate locked replacement transaction")
  }
  replacedPinnedCandidate=true
 }else if !errors.Is(err,os.ErrNotExist){return err}

 snapshot:=filepath.Join(root,residentRecoveryParent,residentRecoveryFolder,residentRecoveryExe)
 info,err:=os.Lstat(snapshot)
 if err!=nil{return err}
 if !info.Mode().IsRegular()||info.Size()<1||info.Size()>chainLegacyMax{
  return errors.New("recovery source is linked, empty or outside limits")
 }
 source,err:=os.Open(snapshot)
 if err!=nil{return err}
 defer source.Close()
 staged,err:=os.CreateTemp(root,".volve-ci-recovery-*")
 if err!=nil{return err}
 stagePath:=staged.Name()
 defer os.Remove(stagePath)
 hasher:=sha256.New()
 amount,err:=io.Copy(io.MultiWriter(staged,hasher),io.LimitReader(source,chainLegacyMax+1))
 if err!=nil{staged.Close();return err}
 if err:=staged.Sync();err!=nil{staged.Close();return err}
 if err:=staged.Close();err!=nil{return err}
 if amount!=info.Size()||amount>chainLegacyMax||
  hex.EncodeToString(hasher.Sum(nil))!=pinned.LegacySHA256{
  return errors.New("original changed while staging CI recovery")
 }
 // Re-read protected ACLs, XML, journal and both SHA-256 hashes immediately
 // before creating a new link. Do not guess the version from filename.
 last,err:=auditPostSwitchResidentRecovery(ctx,root)
 if err!=nil||last!=pinned{
  return errors.New("sealed backup or journal changed before CI original restoration")
 }
 if err:=ctx.Err();err!=nil{return err}
 if replacedPinnedCandidate {
  // A bounded lab file-level transaction: the original is staged and synced
  // before any replacement, and the currently installed bytes are checked
  // AGAIN at the last boundary. Never stop a running product motor; Windows
  // atomically refuses renaming over an executable that is still in use.
  current,err:=digestResidentLive(ctx,original)
  if err!=nil || current!=pinned.TargetSHA256 {
   return errors.New("CI candidate changed before byte-exact replacement")
  }
  if err:=os.Rename(stagePath,original);err!=nil{
   return fmt.Errorf("atomic CI replacement of the exact pinned candidate failed: %w",err)
  }
 }else{
  // NTFS hard-link creation is no-clobber: if another actor creates the old
  // filename concurrently, Link fails. Stage and installed path share bytes
  // on the same volume; removing stagePath does not remove the installed file.
  if err:=os.Link(stagePath,original);err!=nil{
   return fmt.Errorf("cannot exclusively publish restored CI original: %w",err)
  }
 }
 runningHash,err:=digestResidentLive(ctx,original)
 if err!=nil||runningHash!=pinned.LegacySHA256{
  return errors.New("published CI legacy copy not verifiable")
 }
 final,err:=auditPostSwitchResidentRecovery(ctx,root)
 if err!=nil||final!=pinned{
  return errors.New("sealed recovery provenance changed after file restoration")
 }
 return nil
}
