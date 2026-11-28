package motorupdate

// Separate fresh-install admission contract. It cannot arm recovery, write
// DNS, or issue permission from a preview. Its pins MUST come from an
// independently authenticated controller and durable original archives, never
// from the grant itself. The real SYSTEM caller and one-use reservation are
// separate mandatory dependencies; this verifier is intentionally private.
import (
 "bytes"
 "context"
 "crypto/ed25519"
 "encoding/base64"
 "encoding/json"
 "errors"
 "strings"
 "time"
)

const freshActivationComponent="volve-publisher-fresh-activation-admission-v2"
const freshActivationOperation="fresh-motor-install-and-local-dns"

type freshActivationEvidence struct {
 TransactionID string `json:"transaction_id"`
 SignedPackageSHA256 string `json:"signed_package_sha256"`
 MotorSHA256 string `json:"motor_sha256"`
 OriginalReviewSHA256 string `json:"original_review_sha256"`
 OriginalDNSJournalSHA256 string `json:"original_dns_journal_sha256"`
 WatchdogTaskXMLSHA256 string `json:"watchdog_task_xml_sha256"`
 OwnerApprovalSHA256 string `json:"owner_approval_sha256"`
 WatchdogExecutableSHA256 string `json:"watchdog_executable_sha256"`
 WatchdogSecurityDescriptorSHA256 string `json:"watchdog_security_descriptor_sha256"`
}
type freshActivationAdmission struct {
 Schema int `json:"schema"`
 Component string `json:"component"`
 Operation string `json:"operation"`
 Evidence freshActivationEvidence `json:"evidence"`
 IssuedAtUnix int64 `json:"issued_at_unix"`
 ExpiresAtUnix int64 `json:"expires_at_unix"`
}

func validateFreshActivationEvidence(e freshActivationEvidence)error{
 if err:=verifyDNSActivationEvidencePins(DNSActivationExternallyPinnedEvidence{
 IntentNonce:e.TransactionID,OriginalDNSJournalSHA256:e.OriginalDNSJournalSHA256,
 TargetMotorSHA256:e.MotorSHA256,WatchdogTaskXMLSHA256:e.WatchdogTaskXMLSHA256});err!=nil{return err}
 if e.TransactionID==strings.Repeat("0",32){return errors.New("fresh transaction ID is zero")}
 for _,v:=range []string{e.SignedPackageSHA256,e.MotorSHA256,e.OriginalReviewSHA256,e.OriginalDNSJournalSHA256,e.WatchdogTaskXMLSHA256,e.OwnerApprovalSHA256,e.WatchdogExecutableSHA256,e.WatchdogSecurityDescriptorSHA256}{
  if err:=verifyCanonicalLowerSHA256(v);err!=nil||v==strings.Repeat("0",64){return errors.New("fresh activation evidence pin invalid")}
 }
 return nil
}

// This contract deliberately admits only a CLEAN installation, not a catalog
// preservation or legacy migration. A verified backup rehearsal alone does
// not constitute durable recovery. No caller may use this return value to
// skip native SYSTEM/ACL/boot-watchdog/nonce and live-health reattestation.
func verifyFreshActivationAdmission(ctx context.Context,raw,signature []byte,key ed25519.PublicKey,pins freshActivationEvidence,host FreshMotorInstallEvidence,now time.Time)(freshActivationAdmission,error){
 var denied freshActivationAdmission
 if ctx==nil{return denied,errors.New("fresh activation context missing")}
 if err:=ctx.Err();err!=nil{return denied,err}
 if err:=CheckFreshMotorInstallReadiness(ctx,host);err!=nil{return denied,err}
 if host.VOLVETaskCount!=0{return denied,errors.New("catalog-preserving installation requires a separate admission")}
 if err:=validateFreshActivationEvidence(pins);err!=nil{return denied,err}
 if len(raw)<2||len(raw)>dnsActivationGrantMaxBytes||len(key)!=ed25519.PublicKeySize||len(signature)!=base64.StdEncoding.EncodedLen(ed25519.SignatureSize)||now.IsZero(){return denied,errors.New("fresh signed admission inputs invalid")}
 sig,err:=base64.StdEncoding.Strict().DecodeString(string(signature))
 if err!=nil||len(sig)!=ed25519.SignatureSize||base64.StdEncoding.EncodeToString(sig)!=string(signature)||!ed25519.Verify(key,raw,sig){return denied,errors.New("fresh publisher admission signature invalid")}
 var got freshActivationAdmission
 if err:=json.Unmarshal(raw,&got);err!=nil{return denied,err}
 canonical,err:=json.Marshal(got)
 if err!=nil||!bytes.Equal(raw,canonical){return denied,errors.New("fresh admission must be exact canonical JSON")}
 if got.Schema!=2||got.Component!=freshActivationComponent||got.Operation!=freshActivationOperation||got.Evidence!=pins{return denied,errors.New("fresh admission scope or independent evidence mismatch")}
 issued,expires:=time.Unix(got.IssuedAtUnix,0),time.Unix(got.ExpiresAtUnix,0)
 life:=expires.Sub(issued)
 if life<=0||life>dnsActivationGrantMaxLifetime||issued.After(now.Add(dnsActivationGrantMaxClockSkew))||!now.Before(expires){return denied,errors.New("fresh admission outside valid time window")}
 if err:=ctx.Err();err!=nil{return denied,err}
 return got,nil
}
