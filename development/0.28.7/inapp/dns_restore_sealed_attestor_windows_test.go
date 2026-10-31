//go:build windows

package motorupdate

import (
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "os"
 "path/filepath"
 "reflect"
 "strings"
 "testing"
)

type windowsDNSSnapshotFixture struct {
 gate WindowsSealedDNSRecoveryAttestor
 records []DNSRestoreRecord
 intent ResidentRecoveryIntent
 raw []byte
 checks *int
}
func fixtureWindowsSealedSnapshot(t *testing.T) windowsDNSSnapshotFixture {
 t.Helper()
 ctx:=context.Background()
 root:=t.TempDir()
 dir:=filepath.Join(root,"legacy-engine-recovery","motor-recovery-transaction")
 if err:=os.MkdirAll(dir,0700);err!=nil{t.Fatal(err)}
 protected:=func(string)error{return nil} // Test double only; NEVER use as a production ACL verifier.
 initial:=ResidentRecoveryIntent{
  Schema:1,Component:"dns-engine-recovery-intent",Task:"VOLVE-DNS-SERVER-0270",
  LegacySHA256:strings.Repeat("a",64),TaskXMLSHA256:strings.Repeat("b",64),
  TargetSHA256:strings.Repeat("c",64),TargetVersion:"0.28.7",
 }
 intent,err:=ArmResidentRecoveryIntent(ctx,dir,initial,protected,protected)
 if err!=nil{t.Fatal(err)}
 v4,v6,_:=batchFixture()
 records:=[]DNSRestoreRecord{v4,v6}
 snapshot:=WindowsSealedDNSRecoverySnapshot{
  Schema:1,Component:"volve-dns-restore-snapshot",
  IntentNonce:intent.Nonce,
  OriginalMotorSHA256:intent.LegacySHA256,CandidateMotorSHA256:intent.TargetSHA256,
  Records:cloneWindowsDNSRecoveryRecords(records),
 }
 raw,err:=json.Marshal(snapshot)
 if err!=nil{t.Fatal(err)}
 path:=filepath.Join(filepath.Dir(dir),WindowsDNSRecoverySnapshotName)
 if err:=os.WriteFile(path,raw,0600);err!=nil{t.Fatal(err)}
 hash:=sha256.Sum256(raw)
 pub,private,err:=ed25519.GenerateKey(rand.Reader)
 if err!=nil{t.Fatal(err)}
 permit:=[]byte("CI-only exact signed permit "+intent.Nonce+" "+intent.TargetSHA256)
 signature:=ed25519.Sign(private,permit)
 checks:=new(int)
 gate:=WindowsSealedDNSRecoveryAttestor{
  JournalDir:dir,SnapshotPath:path,PinnedSnapshotSHA256:hex.EncodeToString(hash[:]),
  Protect:protected,
  VerifyPublisherPermit:func(_ context.Context,got ResidentRecoveryIntent)error{
   if got!=intent||!ed25519.Verify(pub,permit,signature){return errors.New("test publisher permit rejected")}
   return nil
  },
  VerifySYSTEMAndFailedMotor:func(_ context.Context,got ResidentRecoveryIntent)error{
   *checks++
   if got!=intent{return errors.New("test SYSTEM process binding rejected")}
   return nil
  },
 }
 return windowsDNSSnapshotFixture{gate:gate,records:records,intent:intent,raw:raw,checks:checks}
}
func TestSealedDNSAttestorChecksRealJournalAndSignedTestPermit(t *testing.T){
 fixture:=fixtureWindowsSealedSnapshot(t)
 if err:=fixture.gate.Verify(context.Background(),fixture.records);err!=nil{t.Fatal(err)}
 if *fixture.checks!=2{t.Fatalf("SYSTEM verifier not checked both before and after: %d",*fixture.checks)}
 // Successful independent preflight must not issue a terminal journal receipt.
 state,err:=InspectResidentRecoveryJournal(context.Background(),fixture.gate.JournalDir,fixture.gate.Protect)
 if err!=nil||state.Status!="recovery-required"{
  t.Fatalf("read-only attestation altered pending journal: %+v, %v",state,err)
 }
}
func TestSealedDNSAttestorDeniesTamperedOrReorderedRestoreRecords(t *testing.T){
 fixture:=fixtureWindowsSealedSnapshot(t)
 records:=cloneWindowsDNSRecoveryRecords(fixture.records)
 records[0].Original.Servers[0]="8.8.8.8"
 if err:=fixture.gate.Verify(context.Background(),records);err==nil{
  t.Fatal("changed DNS source was accepted")
 }
 reversed:=[]DNSRestoreRecord{fixture.records[1],fixture.records[0]}
 if err:=fixture.gate.Verify(context.Background(),reversed);err==nil{
  t.Fatal("reordered restored DNS adapter families were accepted")
 }
 if err:=os.WriteFile(fixture.gate.SnapshotPath,[]byte(`{"schema":1,"schema":1}`),0600);err!=nil{t.Fatal(err)}
 if err:=fixture.gate.Verify(context.Background(),fixture.records);err==nil{
  t.Fatal("modified protected DNS snapshot was accepted")
 }
}
func TestSealedDNSAttestorDeniesMismatchedJournalNonceAndTerminalState(t *testing.T){
 fixture:=fixtureWindowsSealedSnapshot(t)
 var snapshot WindowsSealedDNSRecoverySnapshot
 if err:=json.Unmarshal(fixture.raw,&snapshot);err!=nil{t.Fatal(err)}
 snapshot.IntentNonce=strings.Repeat("d",32)
 changed,err:=json.Marshal(snapshot)
 if err!=nil{t.Fatal(err)}
 digest:=sha256.Sum256(changed)
 if err:=os.WriteFile(fixture.gate.SnapshotPath,changed,0600);err!=nil{t.Fatal(err)}
 fixture.gate.PinnedSnapshotSHA256=hex.EncodeToString(digest[:])
 if err:=fixture.gate.Verify(context.Background(),fixture.records);err==nil{
  t.Fatal("DNS snapshot bound to another resident transaction accepted")
 }
 // Restore exact snapshot, then deliberately finalize the journal. An old
 // signed permit cannot authorize new DNS writes after terminal state.
 if err:=os.WriteFile(fixture.gate.SnapshotPath,fixture.raw,0600);err!=nil{t.Fatal(err)}
 sha:=sha256.Sum256(fixture.raw)
 fixture.gate.PinnedSnapshotSHA256=hex.EncodeToString(sha[:])
 if err:=FinishResidentRecoveryIntent(context.Background(),fixture.gate.JournalDir,"restored",fixture.gate.Protect,fixture.gate.Protect);err!=nil{t.Fatal(err)}
 if err:=fixture.gate.Verify(context.Background(),fixture.records);err==nil{
  t.Fatal("terminal resident journal accepted as pending")
 }
}
func TestSealedDNSAttestorDeniesMissingACLPermitAndSYSTEMIdentity(t *testing.T){
 fixture:=fixtureWindowsSealedSnapshot(t)
 cases:=[]struct{
  name string
  change func(*WindowsSealedDNSRecoveryAttestor)
 }{
  {"missing acl",func(a *WindowsSealedDNSRecoveryAttestor){a.Protect=nil}},
  {"acl denied",func(a *WindowsSealedDNSRecoveryAttestor){a.Protect=func(string)error{return errors.New("untrusted owner")}}},
  {"missing permit",func(a *WindowsSealedDNSRecoveryAttestor){a.VerifyPublisherPermit=nil}},
  {"permit expired",func(a *WindowsSealedDNSRecoveryAttestor){a.VerifyPublisherPermit=func(context.Context,ResidentRecoveryIntent)error{return errors.New("expired")}}},
  {"missing SYSTEM verifier",func(a *WindowsSealedDNSRecoveryAttestor){a.VerifySYSTEMAndFailedMotor=nil}},
  {"motor still running",func(a *WindowsSealedDNSRecoveryAttestor){a.VerifySYSTEMAndFailedMotor=func(context.Context,ResidentRecoveryIntent)error{return errors.New("motor still running")}}},
  {"wrong digest",func(a *WindowsSealedDNSRecoveryAttestor){a.PinnedSnapshotSHA256=strings.Repeat("f",64)}},
 }
 for _,tc:=range cases{t.Run(tc.name,func(t *testing.T){
  g:=fixture.gate
  tc.change(&g)
  if err:=g.Verify(context.Background(),fixture.records);err==nil{t.Fatal("invalid security attestor accepted")}
 })}
}
func TestSealedDNSAttestorDetectsChangesBetweenProtectedReads(t *testing.T){
 fixture:=fixtureWindowsSealedSnapshot(t)
 original:=fixture.gate.Protect
 count:=0
 fixture.gate.Protect=func(path string)error{
  count++
  if path==fixture.gate.SnapshotPath && count>2 {
   if err:=os.WriteFile(path,[]byte("{}"),0600);err!=nil{return err}
  }
  return original(path)
 }
 if err:=fixture.gate.Verify(context.Background(),fixture.records);err==nil{
  t.Fatal("protected snapshot replacement during attestation was accepted")
 }
}
func TestSealedDNSAttestorCompatibleWithAuthenticatedBatchAndLease(t *testing.T){
 fixture:=fixtureWindowsSealedSnapshot(t)
 _,_,h:=batchFixture()
 name:=testWindowsDNSLeaseName()
 totalWrites:=0
 err:=runAttestedWindowsStaticDNSRecovery(context.Background(),fixture.records,h.inspect,fixture.gate,
  func(ctx context.Context,args []string)error{
   totalWrites++
   return h.write(ctx,WindowsDNSCommand{Program:"netsh.exe",Args:args})
  },name)
 if err!=nil{t.Fatal(err)}
 if totalWrites!=3||!reflect.DeepEqual(h.live[DNSIPv4],fixture.records[0].Original.Servers)||
   !reflect.DeepEqual(h.live[DNSIPv6],fixture.records[1].Original.Servers){
  t.Fatalf("real-file journal verifier failed simulated rollback: writes=%d",totalWrites)
 }
 if *fixture.checks<10{t.Fatal("attestor did not recheck sealed journal and SYSTEM state around every write")}
}
func TestWindowsRealCurrentTokenNeverImplicitlyAuthorizesDNSRecovery(t *testing.T){
 if os.Getenv("VOLVE_CI_READONLY_ADAPTER_INSPECTION")!="1"{t.Skip("CI read-only token check")}
 // GitHub-hosted Windows runs as an admin account, not LocalSystem.
 if err:=VerifyWindowsCurrentSystemSIDReadOnly();err==nil{
  t.Fatal("interactive CI user was treated as SYSTEM")
 }
}
