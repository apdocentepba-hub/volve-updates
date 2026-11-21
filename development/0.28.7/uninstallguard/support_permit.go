package uninstallguard

// VOLVE support release permit: CRYPTOGRAPHIC PRECHECK ONLY.
// This verifies a signed, short-lived, installation-specific request to
// begin a future authorized restore-and-remove flow. This package NEVER
// grants permission to edit DNS, stop the motor, delete files or uninstall.
// One-time redemption still requires a protected atomic nonce ledger, live
// SYSTEM owner proof, an intact original DNS/task snapshot and user approval.
// Neither the signing private key nor an operational uninstaller belongs here.
import (
 "bytes"
 "context"
 "crypto/ed25519"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "strings"
 "time"
)

const maxSupportPermitBytes=4096
const supportReleaseComponent="volve-support-release-authorization-v1"
const supportReleaseAction="restore-original-configuration-and-uninstall"

type SupportReleasePermit struct{
 Schema int `json:"schema"`
 Component string `json:"component"`
 InstallationID string `json:"installation_id"`
 OriginalDNSSnapshotSHA256 string `json:"original_dns_snapshot_sha256"`
 RecoveryJournalSHA256 string `json:"recovery_journal_sha256"`
 Action string `json:"action"`
 CaseID string `json:"case_id"`
 Nonce string `json:"nonce"`
 IssuedUTC string `json:"issued_utc"`
 ExpiresUTC string `json:"expires_utc"`
 RequiresUserApproval bool `json:"requires_user_approval"`
 RequiresOriginalRecovery bool `json:"requires_original_recovery"`
}

type SupportRemovalReview struct{
 Schema int `json:"schema"`
 Component string `json:"component"`
 VerifiedPublisherReceipt bool `json:"verified_publisher_receipt"`
 VerifiedIndependentSupportSignature bool `json:"verified_independent_support_signature"`
 BoundToInstallationAndOriginalDNS bool `json:"bound_to_installation_and_original_dns"`
 OneTimeNonceConsumed bool `json:"one_time_nonce_consumed"`
 UserApproved bool `json:"user_approved"`
 OriginalDNSRestored bool `json:"original_dns_restored"`
 CanUninstall bool `json:"can_uninstall"`
 CanChangeDNS bool `json:"can_change_dns"`
 CanDeleteTasks bool `json:"can_delete_tasks"`
}

func isLowerHex32(s string)bool{
 if len(s)!=32||strings.ToLower(s)!=s{return false}
 _,err:=hex.DecodeString(s)
 return err==nil
}

// VerifySignedSupportReleasePermit rejects expired or unscoped support permits,
// explicitly needs a DIFFERENT Ed25519 public key from the release publisher,
// and compares signed data with an independently verified installation receipt.
// The caller must NOT use the returned value as a removal authorization.
func VerifySignedSupportReleasePermit(
 ctx context.Context,raw,signature []byte,supportKey,publisherKey ed25519.PublicKey,
 installed InstalledReceipt,now time.Time,
)(SupportReleasePermit,error){
 var denied SupportReleasePermit
 if ctx==nil{return denied,errors.New("missing support release context")}
 if err:=ctx.Err();err!=nil{return denied,err}
 if err:=validateReceipt(installed);err!=nil{return denied,err}
 if len(supportKey)!=ed25519.PublicKeySize||
  len(publisherKey)!=ed25519.PublicKeySize||
  bytes.Equal(supportKey,publisherKey)||
  len(signature)!=ed25519.SignatureSize||
  len(raw)<2||len(raw)>maxSupportPermitBytes{
  return denied,errors.New("a distinct, pinned support signing identity is required")
 }
 if !ed25519.Verify(supportKey,raw,signature){
  return denied,errors.New("support approval signature invalid")
 }
 dec:=json.NewDecoder(bytes.NewReader(raw))
 dec.DisallowUnknownFields()
 var permit SupportReleasePermit
 if err:=dec.Decode(&permit);err!=nil{return denied,fmt.Errorf("support release JSON invalid: %w",err)}
 var extra any
 if err:=dec.Decode(&extra);err!=io.EOF{return denied,errors.New("support release has trailing content")}
 canonical,err:=json.Marshal(permit)
 if err!=nil||!bytes.Equal(raw,canonical){return denied,errors.New("support approval noncanonical or duplicate JSON")}
 if permit.Schema!=1||permit.Component!=supportReleaseComponent||
  permit.Action!=supportReleaseAction||
  !permit.RequiresUserApproval||!permit.RequiresOriginalRecovery||
  !isLowerHex32(permit.CaseID)||!isLowerHex32(permit.Nonce)||
  permit.InstallationID!=installed.InstallationID||
  permit.OriginalDNSSnapshotSHA256!=installed.OriginalDNSSnapshotSHA256||
  permit.RecoveryJournalSHA256!=installed.RecoveryJournalSHA256{
  return denied,errors.New("support approval not bound to exact installation, original configuration and recovery")
 }
 issued,err:=time.Parse(time.RFC3339,permit.IssuedUTC)
 if err!=nil{return denied,errors.New("invalid support authorization issuance")}
 expiry,err:=time.Parse(time.RFC3339,permit.ExpiresUTC)
 if err!=nil{return denied,errors.New("invalid support authorization expiry")}
 if now.IsZero(){return denied,errors.New("current system clock not verified")}
 now=now.UTC()
 if issued.After(now.Add(5*time.Minute))||expiry.Before(now)||
  !expiry.After(issued)||expiry.Sub(issued)>24*time.Hour{
  return denied,errors.New("support authorization not yet valid, expired or lifetime too long")
 }
 if err:=ctx.Err();err!=nil{return denied,err}
 return permit,nil
}

// ReviewSupportRemovalOnly tests BOTH independent signatures on read-only
// evidence. A valid token cannot bypass a pre-existing active recovery,
// legacy tasks, a missing owner receipt, consent or nonce consumption.
func ReviewSupportRemovalOnly(
 ctx context.Context,e Evidence,installedRaw,installedSig []byte,
 publisherKey ed25519.PublicKey,permitRaw,permitSig []byte,
 supportKey ed25519.PublicKey,now time.Time,
)(SupportRemovalReview,error){
 var denied SupportRemovalReview
 if ctx==nil{return denied,errors.New("missing removal review context")}
 if _,err:=Review(e);err!=nil{return denied,err}
 receipt,err:=VerifySignedInstalledReceipt(installedRaw,installedSig,publisherKey)
 if err!=nil{return denied,err}
 if _,err:=VerifySignedSupportReleasePermit(ctx,permitRaw,permitSig,supportKey,publisherKey,receipt,now);err!=nil{
  return denied,err
 }
 if e.LegacyTasks>0||e.RecoveryJournalPresent{
  return denied,errors.New("unresolved legacy tasks or pending recovery prevent support removal review")
 }
 return SupportRemovalReview{
  Schema:1,Component:"VOLVE-SUPPORT-RELEASE-REVIEW-ONLY",
  VerifiedPublisherReceipt:true,VerifiedIndependentSupportSignature:true,
  BoundToInstallationAndOriginalDNS:true,OneTimeNonceConsumed:false,
  UserApproved:false,OriginalDNSRestored:false,CanUninstall:false,
  CanChangeDNS:false,CanDeleteTasks:false,
 },nil
}
