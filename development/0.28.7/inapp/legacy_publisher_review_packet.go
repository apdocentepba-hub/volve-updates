package motorupdate

// A read-only, deterministic REVIEW packet for the legitimate VOLVE publisher.
// This is NOT a migration permit, provenance attestation, signed release,
// installation marker, or consent to switch the production DNS task.
import (
 "context"
 "crypto/ed25519"
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "fmt"
 "os"
 "path/filepath"
)

// LegacyPublisherReviewPacket contains only the exact evidence the editor
// needs to authorize a specific unversioned -> signed motor transition.
// FromVersion is deliberately absent: the historical version is unknown.
// No private key and no user-specific file path is serialized.
type LegacyPublisherReviewPacket struct {
 Schema int `json:"schema"`
 Component string `json:"component"`
 Disposition string `json:"disposition"`
 FromTask string `json:"from_task"`
 FromArgs string `json:"from_args"`
 FromExecutable string `json:"from_executable"`
 FromSHA256 string `json:"from_sha256"`
 FromSize int64 `json:"from_size"`
 FromTaskXMLSHA256 string `json:"from_task_xml_sha256"`
 ToVersion string `json:"to_version"`
 ToSHA256 string `json:"to_sha256"`
 ToSize int64 `json:"to_size"`
 MinPanelVersion string `json:"min_panel_version"`
 InspectedPanelVersion string `json:"inspected_panel_version"`
 PublisherPublicKeySHA256 string `json:"publisher_public_key_sha256"`
}

const LegacyPublisherReviewComponent="dns-engine-migration-review-only"

// BuildLegacyPublisherReviewPacketReadOnly requires an independently secured
// local rollback snapshot, live SYSTEM/rescue/DNS preflight, installed old
// bytes and a publisher-signed candidate. It RECHECKS both live state and
// hashes after preparing the packet. An editor must review this data offline,
// issue a one-time permit using the authentic release key and publish it via
// the verified channel; the program NEVER signs a permit in this function.
func BuildLegacyPublisherReviewPacketReadOnly(
 ctx context.Context, liveExe, backupDir, candidate, panelVersion string,
 publisherKey ed25519.PublicKey, protectBackup func(string) error,
 livePreflight func() error,
)(LegacyPublisherReviewPacket,error){
 var zero LegacyPublisherReviewPacket
 if err:=ctx.Err();err!=nil{return zero,err}
 if len(publisherKey)!=ed25519.PublicKeySize{return zero,errors.New("editor public key missing")}
 if protectBackup==nil||livePreflight==nil{
  return zero,errors.New("independent ACL verifier or live SYSTEM/DNS preflight missing")
 }
 if !filepath.IsAbs(liveExe)||filepath.Base(liveExe)!=legacyServiceName||
  !filepath.IsAbs(backupDir)||!filepath.IsAbs(candidate)||
  !versionRe.MatchString(panelVersion){
  return zero,errors.New("installed legacy paths or panel version unrecognized")
 }
 if err:=safeInventoryDirectory(filepath.Dir(liveExe));err!=nil{return zero,err}
 if err:=safeInventoryDirectory(filepath.Dir(backupDir));err!=nil{return zero,err}
 if err:=protectBackup(filepath.Dir(backupDir));err!=nil{
  return zero,fmt.Errorf("recovery parent ACL untrusted: %w",err)
 }
 if err:=ctx.Err();err!=nil{return zero,err}
 for _,node:=range []string{backupDir,
  filepath.Join(backupDir,legacyBackupExe),
  filepath.Join(backupDir,legacyBackupXML),
  filepath.Join(backupDir,legacyBackupReceipt),
 }{
  if err:=protectBackup(node);err!=nil{return zero,fmt.Errorf("original backup not protected: %w",err)}
 }
 original,err:=VerifyUnversionedLegacyRecovery(backupDir,protectBackup)
 if err!=nil{return zero,fmt.Errorf("original rollback backup not verifiable: %w",err)}
 // Never prepare a legacy bridge for an installation already registered as
 // a managed engine. This is a one-time transition, not a downgrade path.
 installDir:=filepath.Dir(liveExe)
 for _,node:=range []string{
  filepath.Join(installDir,"installed-engines",installedReceiptName),
  filepath.Join(installDir,installedReceiptName),
 }{
  if _,err:=os.Lstat(node);err==nil{
   return zero,errors.New("managed engine already registered")
  }else if !errors.Is(err,os.ErrNotExist){return zero,err}
 }
 manifest,err:=VerifyStaged(candidate,publisherKey)
 if err!=nil{return zero,fmt.Errorf("candidate publisher signature missing or invalid: %w",err)}
 cmp,err:=compareVersions(manifest.Version,"0.28.7")
 if err!=nil||cmp<0{return zero,errors.New("signed migration destination below supported generation")}
 panelCmp,err:=compareVersions(panelVersion,manifest.MinPanelVersion)
 if err!=nil||panelCmp<0{return zero,errors.New("installed panel incompatible with signed candidate")}
 if err:=ctx.Err();err!=nil{return zero,err}
 if err:=livePreflight();err!=nil{return zero,fmt.Errorf("live task, rescue or DNS state invalid: %w",err)}
 oldHash,oldSize,err:=legacyDigest(liveExe,legacyBackupMaxExe)
 if err!=nil{return zero,err}
 if oldHash!=original.ExeSHA256||oldSize!=original.ExeSize{
  return zero,errors.New("installed motor does not match original sealed rollback")
 }
 if err:=ctx.Err();err!=nil{return zero,err}
 // Minimize TOCTOU: recheck active state, bytes, sealed snapshot and candidate.
 // Still require OS-level exclusive mutex for any future real installation.
 if err:=livePreflight();err!=nil{return zero,fmt.Errorf("live state changed during review: %w",err)}
 again,err:=VerifyUnversionedLegacyRecovery(backupDir,protectBackup)
 if err!=nil||again!=original{return zero,errors.New("rollback snapshot changed during review")}
 secondHash,secondSize,err:=legacyDigest(liveExe,legacyBackupMaxExe)
 if err!=nil||oldHash!=secondHash||oldSize!=secondSize{
  return zero,errors.New("old motor changed during review")
 }
 secondManifest,err:=VerifyStaged(candidate,publisherKey)
 if err!=nil||secondManifest!=manifest{return zero,errors.New("signed candidate changed during review")}
 if err:=ctx.Err();err!=nil{return zero,err}
 keyFingerprint:=sha256.Sum256(publisherKey)
 return LegacyPublisherReviewPacket{
  Schema:1,Component:LegacyPublisherReviewComponent,Disposition:"REVIEW_ONLY_UNSIGNED_NOT_A_PERMIT",
  FromTask:legacySystemTask,FromArgs:legacyServiceArg,
  FromExecutable:legacyServiceName,FromSHA256:original.ExeSHA256,FromSize:original.ExeSize,
  FromTaskXMLSHA256:original.XMLSHA256,
  ToVersion:manifest.Version,ToSHA256:manifest.SHA256,ToSize:manifest.Size,
  MinPanelVersion:manifest.MinPanelVersion,InspectedPanelVersion:panelVersion,
  PublisherPublicKeySHA256:hex.EncodeToString(keyFingerprint[:]),
 },nil
}
