package motorupdate

// This package binds an UNTRUSTED user-provided Windows diagnostic snapshot to
// an independently publisher-SIGNED staged candidate for editorial REVIEW.
// A JSON report is not a live Windows attestation, a recovery receipt, proof
// of user consent, a release, or permission to alter any productive motor.
// No machine mutation, network calls, or signing operations occur here.
import (
 "bytes"
 "context"
 "crypto/ed25519"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "io"
 "path/filepath"
)

const maxObservedHostReviewJSON=32<<10

type observedHostCandidateInput struct {
 Schema int `json:"schema"`
 Component string `json:"component"`
 Mode string `json:"mode"`
 Result string `json:"result"`
 Route struct {
  InventoriesChecked int `json:"inventories_checked"`
  SignedUpgradeAuthorized bool `json:"signed_upgrade_authorized"`
  FreshInstallAuthorized bool `json:"fresh_install_authorized"`
  CanModifyDNS bool `json:"can_modify_dns"`
 } `json:"route"`
 HostEvidence struct {
  InventoriesObserved int `json:"inventories_observed"`
  LegacyDNSTaskSeen bool `json:"legacy_dns_task_seen"`
  LegacyDNSMotorFileSeen bool `json:"legacy_dns_motor_file_seen"`
  LocalDNSIPv4Seen bool `json:"local_dns_ipv4_seen"`
  LocalDNSIPv6Seen bool `json:"local_dns_ipv6_seen"`
  UDP53IPv4Listeners int `json:"udp53_ipv4_listeners"`
  UDP53IPv6Listeners int `json:"udp53_ipv6_listeners"`
  SignedUpgradeAuthorized bool `json:"signed_upgrade_authorized"`
  CanModifyDNS bool `json:"can_modify_dns"`
 } `json:"host_evidence"`
 DNSOwner struct {
  Status string `json:"status"`
  Evidence struct {
   ExactIPv4Socket bool `json:"exact_ipv4_socket"`
   ExactIPv6Socket bool `json:"exact_ipv6_socket"`
   SameNonzeroPID bool `json:"same_nonzero_pid"`
   ProcessObserved bool `json:"process_observed"`
   SystemOwner bool `json:"system_owner"`
   LegacyExecutablePathMatch bool `json:"legacy_executable_path_match"`
   DNSServiceArgsMatch bool `json:"dns_service_args_match"`
  } `json:"evidence"`
  RunningMotorConfirmed bool `json:"running_motor_confirmed"`
  SignedMigrationAuthorized bool `json:"signed_migration_authorized"`
  CanModifyDNS bool `json:"can_modify_dns"`
 } `json:"dns_udp53_owner"`
 Legacy struct {
  Schema int `json:"schema"`
  Status string `json:"status"`
  TaskActionPathForm string `json:"task_action_path_form"`
  FromTask string `json:"from_task"`
  FromExecutable string `json:"from_executable"`
  FromArguments string `json:"from_arguments"`
  FromSHA256 string `json:"from_sha256"`
  FromSize int64 `json:"from_size"`
  FromTaskXMLSHA256 string `json:"from_task_xml_sha256"`
  SignatureVerified bool `json:"signature_verified"`
  MigrationAuthorized bool `json:"migration_authorized"`
  ReadyToSwitch bool `json:"ready_to_switch"`
 } `json:"legacy_identity_for_publisher"`
}

// This response is explicitly NOT a LegacyPublisherReviewPacket: that stronger
// type requires a sealed snapshot, ACLs, live Windows inspection and two reads.
type UnsignedObservedCandidateReview struct {
 Schema int `json:"schema"`
 Component string `json:"component"`
 Disposition string `json:"disposition"`
 FromTask string `json:"from_task"`
 FromExecutable string `json:"from_executable"`
 FromArguments string `json:"from_args"`
 FromSHA256 string `json:"from_sha256"`
 FromSize int64 `json:"from_size"`
 FromTaskXMLSHA256 string `json:"from_task_xml_sha256"`
 ToVersion string `json:"to_version"`
 ToSHA256 string `json:"to_sha256"`
 ToSize int64 `json:"to_size"`
 MinPanelVersion string `json:"min_panel_version"`
 InspectedPanelVersion string `json:"inspected_panel_version"`
 PublisherPublicKeySHA256 string `json:"publisher_public_key_sha256"`
 RequiresProtectedRollback bool `json:"requires_protected_rollback"`
 SignatureVerifiedForCandidate bool `json:"signature_verified_for_candidate"`
 LegacyIdentityIndependentlyVerified bool `json:"legacy_identity_independently_verified"`
 MigrationAuthorized bool `json:"migration_authorized"`
 ReadyToSwitch bool `json:"ready_to_switch"`
}

func acceptedTaskPathForm(v string)bool{
 switch v {
 case "EXACT_EXPECTED_PATH", "SOURCE_EQUIVALENT_OUTER_QUOTES",
  "SOURCE_EQUIVALENT_EXTENDED_DOS_PATH", "SOURCE_EQUIVALENT_SEPARATOR",
  "SOURCE_EQUIVALENT_DOT_SEGMENT":return true
 default:return false
 }
}

// BindUnsignedHostReportToSignedCandidateReadOnly is a RESEARCH/REVIEW
// operation, not a grant. This parser intentionally ignores unrelated
// browser-policy counts while requiring enough positive independent-looking
// indicators to prevent an accidental 'clean install' classification.
// A caller must NEVER promote this output to a migration permit.
func BindUnsignedHostReportToSignedCandidateReadOnly(
 ctx context.Context, reportJSON []byte, candidate,panelVersion string,
 publisherKey ed25519.PublicKey,
)(UnsignedObservedCandidateReview,error){
 var zero UnsignedObservedCandidateReview
 if err:=ctx.Err();err!=nil{return zero,err}
 if len(reportJSON)<2||len(reportJSON)>maxObservedHostReviewJSON||
  len(publisherKey)!=ed25519.PublicKeySize||
  !filepath.IsAbs(candidate)||filepath.Clean(candidate)!=candidate||
  !versionRe.MatchString(panelVersion){
  return zero,errors.New("missing or invalid observed review, candidate or publisher identity")
 }
 // We cannot use DisallowUnknownFields for the complete standalone report,
 // because it also contains anonymous catalog and browser-policy telemetry.
 // Decode the full report into raw fields, then STRICTLY decode critical
 // subobjects; reject duplicate keys in those subobjects.
 if err:=rejectDuplicateHostJSONKeys(reportJSON);err!=nil{return zero,errors.New("invalid or duplicate host JSON fields")}
 var root map[string]json.RawMessage
 if err:=json.Unmarshal(reportJSON,&root);err!=nil{return zero,errors.New("invalid review JSON")}
 var v observedHostCandidateInput
 if err:=json.Unmarshal(reportJSON,&v);err!=nil{return zero,errors.New("invalid review shape")}
 if v.Schema!=1||v.Component!="volve-dns-readonly-host-diagnosis"||
  v.Mode!="READ_ONLY_NOT_AN_INSTALLER"||v.Result!="REVIEW_ONLY"||
  v.Route.InventoriesChecked!=6||v.HostEvidence.InventoriesObserved!=6||
  v.Route.SignedUpgradeAuthorized||v.Route.FreshInstallAuthorized||v.Route.CanModifyDNS||
  v.HostEvidence.SignedUpgradeAuthorized||v.HostEvidence.CanModifyDNS||
  !v.HostEvidence.LegacyDNSTaskSeen||!v.HostEvidence.LegacyDNSMotorFileSeen||
  !v.HostEvidence.LocalDNSIPv4Seen||!v.HostEvidence.LocalDNSIPv6Seen||
  v.HostEvidence.UDP53IPv4Listeners!=1||v.HostEvidence.UDP53IPv6Listeners!=1||
  v.DNSOwner.Status!="EXACT_LEGACY_SYSTEM_PROCESS_ON_BOTH_UDP53_SOCKETS_NOT_SIGNED"||
  !v.DNSOwner.Evidence.ExactIPv4Socket||!v.DNSOwner.Evidence.ExactIPv6Socket||
  !v.DNSOwner.Evidence.SameNonzeroPID||!v.DNSOwner.Evidence.ProcessObserved||
  !v.DNSOwner.Evidence.SystemOwner||!v.DNSOwner.Evidence.LegacyExecutablePathMatch||
  !v.DNSOwner.Evidence.DNSServiceArgsMatch||
  v.DNSOwner.RunningMotorConfirmed||v.DNSOwner.SignedMigrationAuthorized||
  v.DNSOwner.CanModifyDNS ||
  v.Legacy.Schema!=1||
  v.Legacy.Status!="UNSIGNED_LEGACY_IDENTITY_FOR_PUBLISHER_REVIEW_ONLY"||
  !acceptedTaskPathForm(v.Legacy.TaskActionPathForm)||
  v.Legacy.FromTask!=legacySystemTask||v.Legacy.FromExecutable!=legacyServiceName||
  v.Legacy.FromArguments!=legacyServiceArg||
  !hexRe.MatchString(v.Legacy.FromSHA256)||v.Legacy.FromSize<=0||
  v.Legacy.FromSize>legacyBackupMaxExe||
  !hexRe.MatchString(v.Legacy.FromTaskXMLSHA256)||
  v.Legacy.SignatureVerified||v.Legacy.MigrationAuthorized||v.Legacy.ReadyToSwitch{
  return zero,errors.New("observed report does not prove a review-only legacy layout")
 }
 for _,key:=range []string{"route","host_evidence","dns_udp53_owner","legacy_identity_for_publisher"}{
  if len(root[key])<2{return zero,errors.New("required Windows evidence missing")}
 }
 // Independently verify candidate signature twice; no 'new version' inferred
 // from the filename. A real signed release can be reviewed later without
 // taking the old task down.
 manifest,err:=VerifyStaged(candidate,publisherKey)
 if err!=nil{return zero,errors.New("candidate is not signed by selected publisher")}
 cmp,err:=compareVersions(manifest.Version,"0.28.7")
 if err!=nil||cmp<0{return zero,errors.New("unsupported migration destination")}
 cmp,err=compareVersions(panelVersion,manifest.MinPanelVersion)
 if err!=nil||cmp<0{return zero,errors.New("signed candidate requires a newer Centro")}
 if err:=ctx.Err();err!=nil{return zero,err}
 again,err:=VerifyStaged(candidate,publisherKey)
 if err!=nil||again!=manifest{return zero,errors.New("signed candidate changed while inspecting")}
 if err:=ctx.Err();err!=nil{return zero,err}
 pubSHA:=sha256.Sum256(publisherKey)
 return UnsignedObservedCandidateReview{
  Schema:1,Component:"dns-engine-observed-candidate-review-only",
  Disposition:"UNTRUSTED_HOST_REPORT_PLUS_SIGNED_CANDIDATE_NOT_A_PERMIT",
  FromTask:legacySystemTask,FromExecutable:legacyServiceName,FromArguments:legacyServiceArg,
  FromSHA256:v.Legacy.FromSHA256,FromSize:v.Legacy.FromSize,
  FromTaskXMLSHA256:v.Legacy.FromTaskXMLSHA256,
  ToVersion:manifest.Version,ToSHA256:manifest.SHA256,ToSize:manifest.Size,
  MinPanelVersion:manifest.MinPanelVersion,InspectedPanelVersion:panelVersion,
  PublisherPublicKeySHA256:hex.EncodeToString(pubSHA[:]),
  RequiresProtectedRollback:true,SignatureVerifiedForCandidate:true,
  LegacyIdentityIndependentlyVerified:false,MigrationAuthorized:false,ReadyToSwitch:false,
 },nil
}

// RequireObservedCandidateReviewOnly is intentionally fail-closed for any
// consumer accidentally treating this as an installation authorization.
func RequireObservedCandidateReviewOnly(p UnsignedObservedCandidateReview)error{
 if p.Schema!=1||p.Component!="dns-engine-observed-candidate-review-only"||
  p.Disposition!="UNTRUSTED_HOST_REPORT_PLUS_SIGNED_CANDIDATE_NOT_A_PERMIT"||
  !p.RequiresProtectedRollback||!p.SignatureVerifiedForCandidate||
  p.LegacyIdentityIndependentlyVerified||p.MigrationAuthorized||p.ReadyToSwitch{
  return errors.New("observed host/candidate evidence is not a migration authorization")
 }
 return nil
}

// Reject duplicate keys anywhere, not just on the top-level JSON object.
// Otherwise JSON producers and consumers could select different task hashes
// from the same purported review packet. Never log the rejected JSON.
func rejectDuplicateHostJSONKeys(raw []byte)error{
 dec:=json.NewDecoder(bytes.NewReader(raw))
 if err:=walkUniqueHostJSON(dec,0);err!=nil{return err}
 var trailing any
 if err:=dec.Decode(&trailing);err!=io.EOF{return errors.New("trailing JSON payload")}
 return nil
}

func walkUniqueHostJSON(dec *json.Decoder,depth int)error{
 if depth>16{return errors.New("JSON nesting too deep")}
 tok,err:=dec.Token()
 if err!=nil{return err}
 delim,ok:=tok.(json.Delim)
 if !ok{return nil}
 switch delim{
 case '{':
  seen:=map[string]bool{}
  for dec.More(){
   k,err:=dec.Token()
   if err!=nil{return err}
   key,ok:=k.(string)
   if !ok{return errors.New("invalid JSON property name")}
   if seen[key]{return errors.New("duplicate JSON property")}
   seen[key]=true
   if err:=walkUniqueHostJSON(dec,depth+1);err!=nil{return err}
  }
  end,err:=dec.Token()
  if err!=nil||end!=json.Delim('}'){return errors.New("unclosed JSON object")}
 case '[':
  for dec.More(){
   if err:=walkUniqueHostJSON(dec,depth+1);err!=nil{return err}
  }
  end,err:=dec.Token()
  if err!=nil||end!=json.Delim(']'){return errors.New("unclosed JSON array")}
 default:return errors.New("invalid JSON delimiter")
 }
 return nil
}
