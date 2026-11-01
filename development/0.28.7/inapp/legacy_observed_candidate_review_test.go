package motorupdate

import (
 "bytes"
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "encoding/json"
 "os"
 "strings"
 "testing"
)

func syntheticWindowsHostDiagnosticForBridge(f *signedBridgeFixture)[]byte {
 // These are synthetic test fingerprints: NEVER the private user's upload.
 payload:=map[string]any{
  "schema":1,"component":"volve-dns-readonly-host-diagnosis",
  "mode":"READ_ONLY_NOT_AN_INSTALLER","result":"REVIEW_ONLY",
  "explanation":"No changes applied",
  "route":map[string]any{
   "route":"contradictory-installed-protection-no-write",
   "reason":"existing protection present",
   "inventories_checked":6,"signed_upgrade_authorized":false,
   "fresh_install_authorized":false,"can_modify_dns":false,
  },
  "host_evidence":map[string]any{
   "inventories_observed":6,"volve_tasks":3,
   "legacy_dns_task_seen":true,"legacy_dns_motor_file_seen":true,
   "local_dns_ipv4_seen":true,"local_dns_ipv6_seen":true,
   "udp53_ipv4_listeners":1,"udp53_ipv6_listeners":1,
   "tcp53_ipv6_listeners":1,
   "signed_upgrade_authorized":false,"can_modify_dns":false,
  },
  "dns_udp53_owner":map[string]any{
   "status":"EXACT_LEGACY_SYSTEM_PROCESS_ON_BOTH_UDP53_SOCKETS_NOT_SIGNED",
   "evidence":map[string]any{
    "exact_ipv4_socket":true,"exact_ipv6_socket":true,
    "same_nonzero_pid":true,"process_observed":true,"system_owner":true,
    "legacy_executable_path_match":true,"dns_service_args_match":true,
   },
   "running_motor_confirmed":false,"signed_migration_authorized":false,
   "can_modify_dns":false,
  },
  "legacy_identity_for_publisher":map[string]any{
   "schema":1,"status":"UNSIGNED_LEGACY_IDENTITY_FOR_PUBLISHER_REVIEW_ONLY",
   "task_action_path_form":"SOURCE_EQUIVALENT_OUTER_QUOTES",
   "from_task":legacySystemTask,"from_executable":legacyServiceName,
   "from_arguments":legacyServiceArg,
   "from_sha256":f.permit.FromSHA256,"from_size":f.permit.FromSize,
   "from_task_xml_sha256":f.permit.FromTaskXMLSHA256,
   "signature_verified":false,"migration_authorized":false,"ready_to_switch":false,
  },
  "browser_policies":map[string]any{
   "total_numbered_entries":160,"browser_enforcement_verified":false,
  },
 }
 b,err:=json.Marshal(payload)
 if err!=nil{panic(err)}
 return b
}

func TestUnsignedObservedHostBindsSignedCandidateButCannotAuthorizeSwitch(t *testing.T){
 f:=newSignedBridge(t)
 report:=syntheticWindowsHostDiagnosticForBridge(f)
 got,err:=BindUnsignedHostReportToSignedCandidateReadOnly(context.Background(),
  report,f.candidate,"0.28.7",f.pub)
 if err!=nil{t.Fatal(err)}
 if got.Component!="dns-engine-observed-candidate-review-only"||
  got.Disposition!="UNTRUSTED_HOST_REPORT_PLUS_SIGNED_CANDIDATE_NOT_A_PERMIT"||
  got.FromSHA256!=f.permit.FromSHA256||got.FromTaskXMLSHA256!=f.permit.FromTaskXMLSHA256||
  got.ToSHA256!=f.permit.ToSHA256||got.ToVersion!="0.28.7"||
  got.InspectedPanelVersion!="0.28.7"||
  !got.SignatureVerifiedForCandidate||!got.RequiresProtectedRollback||
  got.LegacyIdentityIndependentlyVerified||got.MigrationAuthorized||got.ReadyToSwitch {
  t.Fatalf("signed candidate and untrusted host were confused with permission: %+v",got)
 }
 if err:=RequireObservedCandidateReviewOnly(got);err!=nil{t.Fatal(err)}
 b,err:=json.Marshal(got);if err!=nil{t.Fatal(err)}
 for _,secret:=range []string{f.root,f.live,f.backup,f.candidate,"ProgramData","--dns-service --steal"}{
  if strings.Contains(string(b),secret){t.Fatalf("local path/secret leaked in review result")}
 }
 // NO signing key is held in the review response. A valid synthetic
 // candidate + host pairing is still rejected by a real migration verifier.
 _,err=VerifySignedUnversionedLegacyMigration(context.Background(),f.live,f.backup,f.candidate,"0.28.7",
  b,nil,f.pub,testSecureLabFolderBridge,func()error{return nil})
 if err==nil{t.Fatal("unsigned candidate review incorrectly accepted as signed permit")}
}

func TestUnsignedObservedHostReviewRejectsSpoofedIdentityAndSignature(t *testing.T){
 for _,tc:=range []struct{
  name string
  mutate func(map[string]any)
 }{
  {"legacy-ready",func(m map[string]any){m["legacy_identity_for_publisher"].(map[string]any)["ready_to_switch"]=true}},
  {"pretend-legacy-signed",func(m map[string]any){m["legacy_identity_for_publisher"].(map[string]any)["signature_verified"]=true}},
  {"fake-migration-permission",func(m map[string]any){m["legacy_identity_for_publisher"].(map[string]any)["migration_authorized"]=true}},
  {"old-task-name",func(m map[string]any){m["legacy_identity_for_publisher"].(map[string]any)["from_task"]="DIFFERENT"}},
  {"old-args",func(m map[string]any){m["legacy_identity_for_publisher"].(map[string]any)["from_arguments"]="--refresh"}},
  {"old-sha-malformed",func(m map[string]any){m["legacy_identity_for_publisher"].(map[string]any)["from_sha256"]="not-a-hash"}},
  {"xml-sha-malformed",func(m map[string]any){m["legacy_identity_for_publisher"].(map[string]any)["from_task_xml_sha256"]="missing"}},
  {"legacy-size-too-big",func(m map[string]any){m["legacy_identity_for_publisher"].(map[string]any)["from_size"]=1000000000}},
  {"unaccepted-task-path",func(m map[string]any){m["legacy_identity_for_publisher"].(map[string]any)["task_action_path_form"]="SAME_EXECUTABLE_NAME_DIFFERENT_LOCATION"}},
  {"no-legacy-dns-task",func(m map[string]any){m["host_evidence"].(map[string]any)["legacy_dns_task_seen"]=false}},
  {"no-legacy-motor",func(m map[string]any){m["host_evidence"].(map[string]any)["legacy_dns_motor_file_seen"]=false}},
  {"different-port-count",func(m map[string]any){m["host_evidence"].(map[string]any)["udp53_ipv6_listeners"]=2}},
  {"not-system-owner",func(m map[string]any){m["dns_udp53_owner"].(map[string]any)["evidence"].(map[string]any)["system_owner"]=false}},
  {"fake-owner-migration",func(m map[string]any){m["dns_udp53_owner"].(map[string]any)["signed_migration_authorized"]=true}},
  {"fake-route-permission",func(m map[string]any){m["route"].(map[string]any)["can_modify_dns"]=true}},
  {"incomplete-inventory",func(m map[string]any){m["host_evidence"].(map[string]any)["inventories_observed"]=5}},
  {"wrong-component",func(m map[string]any){m["component"]="other-product"}},
 }{
  t.Run(tc.name,func(t *testing.T){
   f:=newSignedBridge(t)
   var decoded map[string]any
   if err:=json.Unmarshal(syntheticWindowsHostDiagnosticForBridge(f),&decoded);err!=nil{t.Fatal(err)}
   tc.mutate(decoded)
   raw,err:=json.Marshal(decoded);if err!=nil{t.Fatal(err)}
   got,err:=BindUnsignedHostReportToSignedCandidateReadOnly(context.Background(),raw,f.candidate,"0.28.7",f.pub)
   if err==nil||got.Component!=""||got.MigrationAuthorized||got.ReadyToSwitch{
    t.Fatalf("unsafe report %q yielded review: %+v err=%v",tc.name,got,err)
   }
  })
 }
}

func TestUnsignedObservedHostReviewRejectsUnsignedChangedOrForeignPublisherCandidate(t *testing.T){
 f:=newSignedBridge(t)
 raw:=syntheticWindowsHostDiagnosticForBridge(f)
 otherPublic,_,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 for _,tc:=range []struct{name string;candidate string;pub ed25519.PublicKey;panel string}{
  {"foreign-publisher",f.candidate,otherPublic,"0.28.7"},
  {"panel-too-old",f.candidate,f.pub,"0.28.6"},
  {"relative-candidate","relative.exe",f.pub,"0.28.7"},
  {"no-publisher",f.candidate,nil,"0.28.7"},
 }{
  t.Run(tc.name,func(t *testing.T){
   got,err:=BindUnsignedHostReportToSignedCandidateReadOnly(context.Background(),raw,tc.candidate,tc.panel,tc.pub)
   if err==nil||got.Component!=""{t.Fatalf("unsafe candidate accepted: %+v",got)}
  })
 }
 if err:=os.WriteFile(f.candidate,[]byte("tampered"),0600);err!=nil{t.Fatal(err)}
 got,err:=BindUnsignedHostReportToSignedCandidateReadOnly(context.Background(),raw,f.candidate,"0.28.7",f.pub)
 if err==nil||got.Component!=""{t.Fatal("tampered candidate passed signature check")}
}

func TestUnsignedObservedHostReviewRejectsDuplicateKeysAndTrailingContent(t *testing.T){
 f:=newSignedBridge(t)
 raw:=syntheticWindowsHostDiagnosticForBridge(f)
 cases:=[][]byte{
  append(bytes.TrimSpace(raw),[]byte(" {}")...),
  []byte("{}"),
  []byte("null"),
  []byte(`{"schema":1,"schema":1}`),
  []byte(`{"dns_udp53_owner":{"status":"valid","status":"spoofed"}}`),
  []byte(`{"schema":1,"a":{"nested":3,"nested":4}}`),
 }
 for i,input:=range cases{
  got,err:=BindUnsignedHostReportToSignedCandidateReadOnly(context.Background(),input,f.candidate,"0.28.7",f.pub)
  if err==nil||got.Component!=""{t.Fatalf("malformed JSON test %d passed: %+v",i,got)}
 }
}

func TestObservedCandidateReviewFlagsCanNeverBePromoted(t *testing.T){
 f:=newSignedBridge(t)
 raw:=syntheticWindowsHostDiagnosticForBridge(f)
 got,err:=BindUnsignedHostReportToSignedCandidateReadOnly(context.Background(),raw,f.candidate,"0.28.7",f.pub)
 if err!=nil{t.Fatal(err)}
 got.MigrationAuthorized=true
 if err:=RequireObservedCandidateReviewOnly(got);err==nil{t.Fatal("review permitted installation")}
 got.MigrationAuthorized=false
 got.LegacyIdentityIndependentlyVerified=true
 if err:=RequireObservedCandidateReviewOnly(got);err==nil{t.Fatal("untrusted report mistaken for live attestation")}
}
