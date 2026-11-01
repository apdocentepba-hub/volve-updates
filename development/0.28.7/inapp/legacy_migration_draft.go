package motorupdate

// Read-only preparation of the publisher's exact one-time migration permit.
// The PRIVATE publisher key is deliberately not available to this process.
// This does not sign, publish, install, change DNS or authorize a transition.
import (
 "context"
 "crypto/ed25519"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "path/filepath"
 "time"
)

// UnsignedLegacyMigrationDraft can be reviewed on an offline signing station.
// Its permit is a DRAFT even though it has the same shape as an authorized
// permit: VerifySignedUnversionedLegacyMigration still demands a separate
// Ed25519 signature from the existing, pinned release publisher.
type UnsignedLegacyMigrationDraft struct {
 Schema int `json:"schema"`
 Component string `json:"component"`
 Disposition string `json:"disposition"`
 Review LegacyPublisherReviewPacket `json:"review"`
 Permit LegacyMigrationPermit `json:"permit"`
 PermitJSONSHA256 string `json:"permit_json_sha256"`
 ReviewJSONSHA256 string `json:"review_json_sha256"`
 SignaturePresent bool `json:"signature_present"`
 MigrationAuthorized bool `json:"migration_authorized"`
 ReadyToSwitch bool `json:"ready_to_switch"`
}

const UnsignedLegacyDraftComponent="dns-engine-legacy-offline-approval-draft"
const UnsignedLegacyDraftDisposition="PUBLISHER_REVIEW_REQUIRED_UNSIGNED_NO_INSTALL_PERMISSION"

// PrepareLegacyMigrationDraftReadOnly reconstructs the complete publisher
// review from a protected local snapshot and TWO live state probes. It binds
// the draft to a signed staged target, but leaves publisher authorization
// entirely absent. Never promote its JSON or SHA into a signed permit.
func PrepareLegacyMigrationDraftReadOnly(
 ctx context.Context,
 liveExe,backupDir,candidate,panelVersion string,
 publisherKey ed25519.PublicKey,
 protectBackup func(string)error,livePreflight func()error,
 issuedAt time.Time,
)(UnsignedLegacyMigrationDraft,error){
 var empty UnsignedLegacyMigrationDraft
 if err:=ctx.Err();err!=nil{return empty,err}
 if len(publisherKey)!=ed25519.PublicKeySize ||
  protectBackup==nil||livePreflight==nil||
  !filepath.IsAbs(candidate)||filepath.Clean(candidate)!=candidate {
  return empty,errors.New("publisher identity, signed candidate or independent recovery checks missing")
 }
 now:=time.Now().UTC()
 if issuedAt.IsZero()||issuedAt.After(now.Add(5*time.Minute))||
  issuedAt.Before(now.Add(-5*time.Minute)){
  return empty,errors.New("offline approval draft issuance must use the current UTC time")
 }
 review,err:=BuildLegacyPublisherReviewPacketReadOnly(
  ctx,liveExe,backupDir,candidate,panelVersion,
  publisherKey,protectBackup,livePreflight)
 if err!=nil{return empty,fmt.Errorf("live publisher review refused: %w",err)}
 // Explicitly check the schema, disposition and key fingerprint: neither an
 // untrusted uploaded diagnostic nor a synthetic lab signature can be
 // silently promoted into a permission.
 pubFingerprint:=sha256.Sum256(publisherKey)
 if review.Schema!=1||
  review.Component!=LegacyPublisherReviewComponent||
  review.Disposition!="REVIEW_ONLY_UNSIGNED_NOT_A_PERMIT"||
  review.PublisherPublicKeySHA256!=hex.EncodeToString(pubFingerprint[:])||
  review.FromTask!=legacySystemTask||
  review.FromArgs!=legacyServiceArg||
  review.FromExecutable!=legacyServiceName||
  !hexRe.MatchString(review.FromSHA256)||
  !hexRe.MatchString(review.FromTaskXMLSHA256)||
  review.FromSize<=0||
  review.FromSize>legacyBackupMaxExe {
  return empty,errors.New("protected original, publisher key or read-only review mismatched")
 }
 if err:=ctx.Err();err!=nil{return empty,err}
 // The signed new candidate may change after the first protected review.
 // Reinspect its signature, SHA, size and compatibility before returning.
 manifest,err:=VerifyStaged(candidate,publisherKey)
 if err!=nil{return empty,fmt.Errorf("signed release changed during draft creation: %w",err)}
 if manifest.Version!=review.ToVersion||manifest.SHA256!=review.ToSHA256||
  manifest.Size!=review.ToSize||
  manifest.MinPanelVersion!=review.MinPanelVersion||
  review.InspectedPanelVersion!=panelVersion {
  return empty,errors.New("candidate no longer matches the live protected review")
 }
 issued:=issuedAt.UTC().Truncate(time.Second)
 permit:=LegacyMigrationPermit{
  Schema:1,Component:"dns-engine-legacy-migration",
  FromTask:review.FromTask,FromArgs:review.FromArgs,
  FromExecutable:review.FromExecutable,
  FromSHA256:review.FromSHA256,FromSize:review.FromSize,
  FromTaskXMLSHA256:review.FromTaskXMLSHA256,
  ToVersion:review.ToVersion,ToSHA256:review.ToSHA256,
  ToSize:review.ToSize,MinPanelVersion:review.MinPanelVersion,
  IssuedUTC:issued.Format(time.RFC3339),
  ExpiresUTC:issued.Add(24*time.Hour).Format(time.RFC3339),
 }
 raw,err:=json.Marshal(permit)
 if err!=nil{return empty,err}
 // Internally confirm the unsigned bytes are a well-formed, but NOT signed,
 // authorization shape; the production verifier must reject this draft until
 // an independently generated signature is checked against publisherKey.
 if _,err:=parseSignedMigrationPermit(raw,nil,publisherKey);err==nil{
  return empty,errors.New("unsigned migration draft improperly accepted as signed")
 }
 digest:=sha256.Sum256(raw)
 reviewBytes,err:=json.Marshal(review);if err!=nil{return empty,err}
 reviewDigest:=sha256.Sum256(reviewBytes)
 if err:=ctx.Err();err!=nil{return empty,err}
 return UnsignedLegacyMigrationDraft{
  Schema:1,Component:UnsignedLegacyDraftComponent,
  Disposition:UnsignedLegacyDraftDisposition,
  Review:review,Permit:permit,PermitJSONSHA256:hex.EncodeToString(digest[:]),
  ReviewJSONSHA256:hex.EncodeToString(reviewDigest[:]),
  SignaturePresent:false,MigrationAuthorized:false,ReadyToSwitch:false,
 },nil
}

// DraftPermitBytesReadOnly returns the exact canonical bytes an offline
// publisher could separately sign after independent editorial review.
// This function neither sees nor creates a publisher private key.
func DraftPermitBytesReadOnly(draft UnsignedLegacyMigrationDraft)([]byte,error){
 if draft.Schema!=1||draft.Component!=UnsignedLegacyDraftComponent||
  draft.Disposition!=UnsignedLegacyDraftDisposition||
  draft.SignaturePresent||draft.MigrationAuthorized||draft.ReadyToSwitch||
  draft.Review.Disposition!="REVIEW_ONLY_UNSIGNED_NOT_A_PERMIT"||
  draft.Permit.Schema!=1||
  draft.Permit.Component!="dns-engine-legacy-migration" {
  return nil,errors.New("not a nonauthorizing publisher review draft")
 }
 p:=draft.Permit
 r:=draft.Review
 reviewBytes,err:=json.Marshal(r);if err!=nil{return nil,err}
 reviewDigest:=sha256.Sum256(reviewBytes)
 if hex.EncodeToString(reviewDigest[:])!=draft.ReviewJSONSHA256||
  !hexRe.MatchString(r.PublisherPublicKeySHA256){
  return nil,errors.New("original editor review or publisher fingerprint altered")
 }
 if p.FromTask!=r.FromTask||p.FromArgs!=r.FromArgs||
  p.FromExecutable!=r.FromExecutable||
  p.FromSHA256!=r.FromSHA256||p.FromSize!=r.FromSize||
  p.FromTaskXMLSHA256!=r.FromTaskXMLSHA256||
  p.ToVersion!=r.ToVersion||p.ToSHA256!=r.ToSHA256||
  p.ToSize!=r.ToSize||p.MinPanelVersion!=r.MinPanelVersion{
  return nil,errors.New("draft permit no longer matches the protected review")
 }
 raw,err:=json.Marshal(p);if err!=nil{return nil,err}
 sha:=sha256.Sum256(raw)
 if hex.EncodeToString(sha[:])!=draft.PermitJSONSHA256{
  return nil,errors.New("unsigned permit draft bytes or digest changed")
 }
 return raw,nil
}
