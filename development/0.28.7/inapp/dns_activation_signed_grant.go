package motorupdate

// DNS activation has a distinct publisher authorization from migration and
// DNS RESTORE receipts. A receipt that proves an original backup exists is
// NOT an authorization to change the machine's current DNS configuration.
//
// These pure cryptographic admission checks deliberately contain NO OS write
// and create NO installer route. A future SYSTEM controller MUST obtain all
// expected SHA-256 values and nonce from independently authenticated, sealed,
// current on-disk evidence, and enforce one-use nonce consumption under the
// shared protected Windows mutex. Supplying self-declared values is unsafe.
import (
 "bytes"
 "context"
 "crypto/ed25519"
 "crypto/subtle"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "time"
)

const dnsActivationGrantComponent="volve-publisher-dns-activation-grant-v1"
const dnsActivationGrantOperation="activate-local-dns-only"
const dnsActivationGrantMaxBytes=4096
const dnsActivationGrantMaxLifetime=15*time.Minute
const dnsActivationGrantMaxClockSkew=2*time.Minute

type SignedDNSActivationGrant struct {
 Schema int `json:"schema"`
 Component string `json:"component"`
 Operation string `json:"operation"`
 IntentNonce string `json:"intent_nonce"`
 OriginalDNSJournalSHA256 string `json:"original_dns_journal_sha256"`
 TargetMotorSHA256 string `json:"target_motor_sha256"`
 WatchdogTaskXMLSHA256 string `json:"watchdog_task_xml_sha256"`
 IssuedAtUnix int64 `json:"issued_at_unix"`
 ExpiresAtUnix int64 `json:"expires_at_unix"`
}

type DNSActivationExternallyPinnedEvidence struct {
 IntentNonce string
 OriginalDNSJournalSHA256 string
 TargetMotorSHA256 string
 WatchdogTaskXMLSHA256 string
}

// verifyCanonicalLowerSHA256 forbids noncanonical hashes that can produce
// different signed JSON or ambiguous comparisons for the same 32 bytes.
func verifyCanonicalLowerSHA256(s string)error{
 if len(s)!=64{return errors.New("not a 64-character SHA-256")}
 raw,err:=hex.DecodeString(s)
 if err!=nil||len(raw)!=32||hex.EncodeToString(raw)!=s{
  return errors.New("SHA-256 must be exactly 32 lowercase hexadecimal bytes")
 }
 return nil
}
func verifyDNSActivationEvidencePins(e DNSActivationExternallyPinnedEvidence)error{
 if len(e.IntentNonce)!=32{
  return errors.New("activation intent nonce must be exactly 32 hexadecimal characters")
 }
 nonce,err:=hex.DecodeString(e.IntentNonce)
 if err!=nil||len(nonce)!=16||hex.EncodeToString(nonce)!=e.IntentNonce{
  return errors.New("activation intent nonce must be canonical lowercase hexadecimal")
 }
 for _,s:=range []string{e.OriginalDNSJournalSHA256,e.TargetMotorSHA256,e.WatchdogTaskXMLSHA256}{
  if err:=verifyCanonicalLowerSHA256(s);err!=nil{return err}
 }
 return nil
}

// VerifyPublisherSignedDNSActivationGrant checks an exact, time-limited,
// Ed25519 publisher grant for ONE already authenticated pending transaction.
// It does NOT prove current LocalSystem identity, task registration, motor
// health, NTFS ACLs, UAC authorization or replay consumption. Those remain
// mandatory checks of the real SYSTEM installer; this result is never a
// boolean permission from the client UI or a recovery receipt.
func VerifyPublisherSignedDNSActivationGrant(
 ctx context.Context, raw,signature []byte,publisherKey ed25519.PublicKey,
 pinned DNSActivationExternallyPinnedEvidence,now time.Time,
)(SignedDNSActivationGrant,error){
 var refused SignedDNSActivationGrant
 if ctx==nil{return refused,errors.New("publisher grant requires context")}
 if err:=ctx.Err();err!=nil{return refused,err}
 if len(publisherKey)!=ed25519.PublicKeySize||len(raw)<2||
  len(raw)>dnsActivationGrantMaxBytes||len(signature)<64||len(signature)>256{
  return refused,errors.New("publisher DNS activation grant missing or excessive")
 }
 if err:=verifyDNSActivationEvidencePins(pinned);err!=nil{
  return refused,fmt.Errorf("no independently authenticated DNS activation evidence: %w",err)
 }
 if now.IsZero(){return refused,errors.New("trusted activation time missing")}
 decoded,err:=base64.StdEncoding.Strict().DecodeString(string(bytes.TrimSpace(signature)))
 if err!=nil||len(decoded)!=ed25519.SignatureSize||!ed25519.Verify(publisherKey,raw,decoded){
  return refused,errors.New("DNS activation publisher signature invalid")
 }
 decoder:=json.NewDecoder(bytes.NewReader(raw))
 decoder.DisallowUnknownFields()
 var grant SignedDNSActivationGrant
 if err:=decoder.Decode(&grant);err!=nil{return refused,fmt.Errorf("invalid signed DNS activation payload: %w",err)}
 var extra any
 if err:=decoder.Decode(&extra);err!=io.EOF{return refused,errors.New("signed activation grant has trailing JSON")}
 canonical,err:=json.Marshal(grant)
 if err!=nil||!bytes.Equal(raw,canonical){return refused,errors.New("DNS activation grant is not canonical JSON")}
 if grant.Schema!=1||grant.Component!=dnsActivationGrantComponent||grant.Operation!=dnsActivationGrantOperation{
  return refused,errors.New("signed grant is not explicitly scoped to activation of VOLVE localhost DNS")
 }
 if err:=verifyDNSActivationEvidencePins(DNSActivationExternallyPinnedEvidence{
  IntentNonce:grant.IntentNonce,OriginalDNSJournalSHA256:grant.OriginalDNSJournalSHA256,
  TargetMotorSHA256:grant.TargetMotorSHA256,WatchdogTaskXMLSHA256:grant.WatchdogTaskXMLSHA256,
 });err!=nil{return refused,fmt.Errorf("signed activation grant contains invalid bound identity: %w",err)}
 for _,pair:=range [][2]string{
  {grant.IntentNonce,pinned.IntentNonce},
  {grant.OriginalDNSJournalSHA256,pinned.OriginalDNSJournalSHA256},
  {grant.TargetMotorSHA256,pinned.TargetMotorSHA256},
  {grant.WatchdogTaskXMLSHA256,pinned.WatchdogTaskXMLSHA256},
 }{
  if subtle.ConstantTimeCompare([]byte(pair[0]),[]byte(pair[1]))!=1{
   return refused,errors.New("publisher signed grant does not match exact authenticated DNS/motor/watchdog/nonce")
  }
 }
 issued:=time.Unix(grant.IssuedAtUnix,0)
 expiry:=time.Unix(grant.ExpiresAtUnix,0)
 lifetime:=expiry.Sub(issued)
 if lifetime<=0||lifetime>dnsActivationGrantMaxLifetime||
  issued.After(now.Add(dnsActivationGrantMaxClockSkew))||!now.Before(expiry){
  return refused,errors.New("DNS activation grant expired, future dated or outside short validity window")
 }
 if err:=ctx.Err();err!=nil{return refused,err}
 return grant,nil
}
