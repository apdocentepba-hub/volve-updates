//go:build windows

package motorupdate

import(
 "bytes"
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "crypto/sha256"
 "encoding/hex"
 "encoding/base64"
 "encoding/json"
 "errors"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"
)

func TestWindowsFreshReservationNativeCreateOnly(t *testing.T){
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{t.Skip("hosted NTFS only")}
 ctx,cancel:=context.WithTimeout(context.Background(),60*time.Second);defer cancel()
 pins:=freshActivationEvidence{strings.Repeat("a",32),strings.Repeat("1",64),strings.Repeat("2",64),strings.Repeat("3",64),strings.Repeat("4",64),strings.Repeat("5",64),strings.Repeat("6",64)}
 root:=filepath.Join(t.TempDir(),pins.TransactionID)
 if err:=os.Mkdir(root,0700);err!=nil{t.Fatal(err)}
 if err:=nativeSealApprovedOriginalBackupNode(ctx,root);err!=nil{t.Fatal(err)}
 // Synthetic historical review, not a real recovery authorization. The
 // test's guard is in-memory; native NTFS and named mutex are real.
 historical,err:=json.Marshal(originalRecoveryReviewEvidence{1,"original-recovery-review-unarmed",pins.TransactionID,pins.OriginalReviewSHA256});if err!=nil{t.Fatal(err)}
 reviewPath:=filepath.Join(root,originalRecoveryReviewFile)
 if err:=residentCreate(reviewPath,historical,func(p string)error{return nativeSealApprovedOriginalBackupNode(ctx,p)},func(p string)error{return nativeDNSOriginalBackupACL(ctx,p)});err!=nil{t.Fatal(err)}
 pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 now:=time.Now()
 raw,err:=json.Marshal(freshActivationAdmission{1,freshActivationComponent,freshActivationOperation,pins,now.Add(-time.Minute).Unix(),now.Add(5*time.Minute).Unix()});if err!=nil{t.Fatal(err)}
 sig:=[]byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv,raw)))
 host:=FreshMotorInstallEvidence{InspectedAsAdministrator:true,InspectedMotorFiles:true,InspectedTaskScheduler:true,InspectedServices:true,InspectedDNSAdapters:true,InspectedPort53Listeners:true,InspectedRecoveryState:true}
 release,err:=AcquireProtectedResidentTransitionLease(ctx);if err!=nil{t.Fatal(err)}
 held:=&exclusiveDNSActivationGuard{inner:&freshReservationFixtureGuard{},acquire:AcquireProtectedResidentTransitionLease,release:release}
 defer held.close()
 marker:=filepath.Join(root,freshReservationName)
 bad:=append([]byte(nil),sig...);bad[0]='!'
 if _,err:=reserveFreshActivationUnderHeldLease(ctx,root,raw,bad,pub,pins,host,held);err==nil{t.Fatal("invalid signature reserved marker")}
 if _,err:=os.Lstat(marker);!os.IsNotExist(err){t.Fatal("invalid admission created marker")}
 first,err:=reserveFreshActivationUnderHeldLease(ctx,root,raw,sig,pub,pins,host,held)
 if err!=nil||first.Evidence!=pins{t.Fatal("fresh reservation failed",err)}
 initial,err:=os.ReadFile(marker);if err!=nil{t.Fatal(err)}
 if _,err:=reserveFreshActivationUnderHeldLease(ctx,root,raw,sig,pub,pins,host,held);!errors.Is(err,os.ErrExist){t.Fatal("fresh admission replay accepted or unexpected refusal",err)}
 after,err:=os.ReadFile(marker);if err!=nil||!bytes.Equal(initial,after){t.Fatal("replay modified reservation")}
 if err:=nativeDNSOriginalBackupACL(ctx,marker);err!=nil{t.Fatal(err)}
 if err:=verifyFreshReservationNative(ctx,root,first);err!=nil{t.Fatal("intact receipt refused",err)}
 wrong:=first;wrong.AdmissionSHA256=strings.Repeat("9",64)
 if err:=verifyFreshReservationNative(ctx,root,wrong);err==nil{t.Fatal("foreign reservation accepted")}
 if err:=os.WriteFile(marker,[]byte("{"),0600);err!=nil{t.Fatal(err)}
 if err:=verifyFreshReservationNative(ctx,root,first);err==nil{t.Fatal("partial reservation accepted")}
 if _,err:=reserveFreshActivationUnderHeldLease(ctx,root,raw,sig,pub,pins,host,held);!errors.Is(err,os.ErrExist){t.Fatal("partial reservation reused",err)}
 t.Log("PASS VOLVE_FRESH_NATIVE_RESERVATION_CREATE_ONLY_ACL_REPLAY_REFUSED_NO_DNS")
 t.Log("PASS VOLVE_FRESH_RESERVATION_REOPEN_REFUSES_FOREIGN_PARTIAL")
}

type freshReservationFixtureGuard struct{}
func(*freshReservationFixtureGuard)VerifyArmed(context.Context,string)error{return nil}
func(*freshReservationFixtureGuard)VerifyLiveProtection(context.Context,string)error{return errors.New("fixture cannot verify live protection")}
func(*freshReservationFixtureGuard)RecoverIndependently(context.Context,string)error{return errors.New("fixture cannot restore DNS")}
func(*freshReservationFixtureGuard)CommitActive(context.Context,string)error{return errors.New("fixture cannot commit activation")}


func TestWindowsFreshControllerSignedArchivesAndRecovery(t *testing.T){
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{t.Skip("hosted NTFS only")}
 ctx,cancel:=context.WithTimeout(context.Background(),240*time.Second);defer cancel()
 _,snap,browser,hosts,policies:=makeOriginalProtectionPairFixture(t)
 id:=strings.Repeat("b",32)
 root:=filepath.Join(t.TempDir(),id)
 parent:=filepath.Join(root,"original-protection-recovery")
 dnsParent:=filepath.Join(root,"legacy-engine-recovery")
 seal:=func(p string)error{return nativeSealApprovedOriginalBackupNode(ctx,p)}
 check:=func(p string)error{return nativeDNSOriginalBackupACL(ctx,p)}
 for _,dir:=range []string{root,parent,dnsParent}{if err:=os.Mkdir(dir,0700);err!=nil{t.Fatal(err)};if err:=seal(dir);err!=nil{t.Fatal(err)}}
 observed,err:=InspectWindowsDNSAssignmentProvenanceReadOnly(ctx,protectionSnapshotDNSInspect)
 if err!=nil{t.Fatal(err)}
 journal,dnsPin,err:=BuildDNSOriginalJournal(ctx,observed.States)
 if err!=nil{t.Fatal(err)}
 snap.DNSAdaptersSHA256=observed.SHA256
 sum:=sha256.Sum256([]byte(catalogTaskAbsentMarker))
 snap.CatalogTaskDefinitionSHA256=hex.EncodeToString(sum[:])
 inv:=WindowsFreshVOLVETaskInventory{}
 if err:=storeOriginalWindowsHostsBackupUnarmed(ctx,parent,hosts,WindowsHostsFileEvidence{SHA256:snap.HostsSHA256,BlockedRuleCount:snap.HostsBlockedRuleCount},seal,check);err!=nil{t.Fatal(err)}
 if err:=storeBrowserOriginalArchiveUnarmed(ctx,parent,browser,policies,seal,check);err!=nil{t.Fatal(err)}
 if _,err:=StoreDNSOriginalBackupUnarmed(ctx,dnsParent,journal,dnsPin,seal,check);err!=nil{t.Fatal(err)}
 if err:=storeOriginalCatalogArchiveUnarmed(ctx,parent,snap,inv,originalCatalogDefinition{},seal,check);err!=nil{t.Fatal(err)}
 pin,err:=originalRecoveryReviewPin(id,snap,dnsPin);if err!=nil{t.Fatal(err)}
 if err:=PersistBoundOriginalRecoveryNativeUnarmed(ctx,root,id,pin,snap,browser,inv,dnsPin);err!=nil{t.Fatal(err)}
 pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 reviewRaw,err:=json.Marshal(SignedOriginalRecoveryReview{1,signedOriginalRecoveryReviewComponent,id,pin});if err!=nil{t.Fatal(err)}
 pins:=freshActivationEvidence{id,strings.Repeat("1",64),strings.Repeat("2",64),pin,dnsPin,strings.Repeat("5",64),strings.Repeat("6",64)}
 now:=time.Now()
 raw,err:=json.Marshal(freshActivationAdmission{1,freshActivationComponent,freshActivationOperation,pins,now.Add(-time.Minute).Unix(),now.Add(5*time.Minute).Unix()});if err!=nil{t.Fatal(err)}
 sig:=[]byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv,raw)))
 host:=FreshMotorInstallEvidence{InspectedAsAdministrator:true,InspectedMotorFiles:true,InspectedTaskScheduler:true,InspectedServices:true,InspectedDNSAdapters:true,InspectedPort53Listeners:true,InspectedRecoveryState:true}
 backend:=&activationTestBackend{current:map[string]DNSServerState{}}
 for _,state:=range observed.States{backend.current[activationKey(state.InterfaceGUID,state.Family)]=copyActivationState(state)}
 guard:=&activationTestGuard{backend:backend,originals:observed.States}
 calls:=0
 marker:=filepath.Join(root,freshReservationName)
 corrupted:=&freshReservationCorruptingBackend{activationTestBackend:backend,marker:marker}
 run:=func()error{return activateFreshDNSUnderProtectedLease(ctx,root,raw,sig,pub,pins,host,snap,browser,inv,journal,guard,func(context.Context,DNSActivationSafetyGuard)(DNSAdapterBackend,error){calls++;return corrupted,nil})}
 if err:=run();err==nil||calls!=0||backend.writes!=0{t.Fatal("unsigned historical review reached backend")}
 if _,err:=os.Lstat(marker);!os.IsNotExist(err){t.Fatal("unsigned review consumed reservation")}
 if err:=PersistSignedOriginalRecoveryNativeUnarmed(ctx,root,id,reviewRaw,ed25519.Sign(priv,reviewRaw),pub,snap,browser,inv,dnsPin);err!=nil{t.Fatal(err)}
 // Real protected files + lease, simulated successful first DNS write
 // followed by deliberate damage to the consumed receipt.
 if err:=run();err==nil||!strings.Contains(err.Error(),"recovery attestation lost")||calls!=1||backend.writes!=1||guard.recoverCalls!=1||guard.commitCalls!=0||!corrupted.corrupted{t.Fatal("damaged reservation did not prevent next write and request rescue",err)}
 records,err:=VerifyDNSOriginalJournal(ctx,journal,dnsPin);if err!=nil{t.Fatal(err)}
 if err:=verifyDNSActivationTransition(ctx,records,backend,0);err!=nil{t.Fatal("original readback differs",err)}
 before,err:=os.ReadFile(marker);if err!=nil{t.Fatal(err)}
 if err:=run();err==nil||calls!=1||backend.writes!=1||guard.commitCalls!=0{t.Fatal("replay reached backend",err)}
 after,err:=os.ReadFile(marker);if err!=nil||!bytes.Equal(before,after){t.Fatal("replay modified durable marker")}
 if string(before)!="{"{t.Fatal("partial consumed receipt not preserved")}
 t.Log("PASS VOLVE_FRESH_SIGNED_ARCHIVES_RESERVATION_RECOVERY_CHAIN_MEMORY_DNS_ONLY")
 t.Log("PASS VOLVE_FRESH_RESERVATION_DRIFT_STOPS_NEXT_WRITE_AND_RECOVERS")
}

type freshReservationCorruptingBackend struct{
 *activationTestBackend
 marker string
 corrupted bool
}
func(b *freshReservationCorruptingBackend)Apply(ctx context.Context,next DNSServerState)error{
 if err:=b.activationTestBackend.Apply(ctx,next);err!=nil{return err}
 if b.writes==1{
  if err:=os.WriteFile(b.marker,[]byte("{"),0600);err!=nil{return err}
  b.corrupted=true
 }
 return nil
}
