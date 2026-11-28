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
 pins:=freshActivationEvidence{strings.Repeat("a",32),strings.Repeat("1",64),strings.Repeat("2",64),strings.Repeat("3",64),strings.Repeat("4",64),strings.Repeat("5",64),strings.Repeat("6",64),strings.Repeat("7",64),strings.Repeat("8",64)}
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
 raw,err:=json.Marshal(freshActivationAdmission{2,freshActivationComponent,freshActivationOperation,pins,now.Add(-time.Minute).Unix(),now.Add(5*time.Minute).Unix()});if err!=nil{t.Fatal(err)}
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
 runFreshControllerSignedArchives(t,true)
}

func TestWindowsFreshControllerSignedArchivesSuccessfulCommit(t *testing.T){
 runFreshControllerSignedArchives(t,false)
}

func runFreshControllerSignedArchives(t *testing.T, corrupt bool){
 t.Helper()
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{t.Skip("hosted NTFS only")}
 ctx,cancel:=context.WithTimeout(context.Background(),240*time.Second);defer cancel()
 _,snap,browser,hosts,policies:=makeOriginalProtectionPairFixture(t)
 id:=strings.Repeat("b",32)
 if !corrupt{id=strings.Repeat("d",32)}
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
 pins:=freshActivationEvidence{id,strings.Repeat("1",64),strings.Repeat("2",64),pin,dnsPin,strings.Repeat("5",64),strings.Repeat("6",64),strings.Repeat("7",64),strings.Repeat("8",64)}
 now:=time.Now()
 raw,err:=json.Marshal(freshActivationAdmission{2,freshActivationComponent,freshActivationOperation,pins,now.Add(-time.Minute).Unix(),now.Add(5*time.Minute).Unix()});if err!=nil{t.Fatal(err)}
 sig:=[]byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv,raw)))
 host:=FreshMotorInstallEvidence{InspectedAsAdministrator:true,InspectedMotorFiles:true,InspectedTaskScheduler:true,InspectedServices:true,InspectedDNSAdapters:true,InspectedPort53Listeners:true,InspectedRecoveryState:true}
 backend:=&activationTestBackend{current:map[string]DNSServerState{}}
 for _,state:=range observed.States{backend.current[activationKey(state.InterfaceGUID,state.Family)]=copyActivationState(state)}
 guard:=&activationTestGuard{backend:backend,originals:observed.States}
 calls:=0
 marker:=filepath.Join(root,freshReservationName)
 corrupted:=&freshReservationCorruptingBackend{activationTestBackend:backend,marker:marker}
 run:=func()error{return activateFreshDNSUnderProtectedLease(ctx,root,raw,sig,pub,pins,host,snap,browser,inv,journal,guard,func(context.Context,DNSActivationSafetyGuard)(DNSAdapterBackend,error){calls++;if corrupt{return corrupted,nil};return backend,nil})}
 if err:=run();err==nil||calls!=0||backend.writes!=0{t.Fatal("unsigned historical review reached backend")}
 if _,err:=os.Lstat(marker);!os.IsNotExist(err){t.Fatal("unsigned review consumed reservation")}
 if err:=PersistSignedOriginalRecoveryNativeUnarmed(ctx,root,id,reviewRaw,ed25519.Sign(priv,reviewRaw),pub,snap,browser,inv,dnsPin);err!=nil{t.Fatal(err)}
 if !corrupt{
  // Successful DNS coordinator path, real protected archives/reservation
  // but memory-only backend and simulated health/commit callback.
  // This deliberately is NOT a durable product installation commit.
  if err:=run();err!=nil{t.Fatal("signed fresh healthy path refused",err)}
  records,err:=VerifyDNSOriginalJournal(ctx,journal,dnsPin);if err!=nil{t.Fatal(err)}
  if calls!=1||backend.writes!=len(records)||guard.healthCalls!=1||guard.commitCalls!=1||guard.recoverCalls!=0{t.Fatal("successful transaction did not reach exactly one health/commit callback")}
  if err:=verifyDNSActivationTransition(ctx,records,backend,len(records));err!=nil{t.Fatal("active DNS readback differs",err)}
  before,err:=os.ReadFile(marker);if err!=nil{t.Fatal(err)}
  var receipt freshActivationReservation
  if err:=json.Unmarshal(before,&receipt);err!=nil{t.Fatal(err)}
  sum:=sha256.Sum256(raw)
  if receipt.Evidence!=pins||receipt.AdmissionSHA256!=hex.EncodeToString(sum[:]){t.Fatal("consumed receipt does not bind admission")}
  release,err:=AcquireProtectedResidentTransitionLease(ctx);if err!=nil{t.Fatal(err)}
  checkErr:=verifyFreshReservationNative(ctx,root,receipt)
  release()
  if checkErr!=nil{t.Fatal(checkErr)}
  if err:=run();err==nil||calls!=1||backend.writes!=len(records)||guard.commitCalls!=1||guard.recoverCalls!=0{t.Fatal("successful admission replay reached backend or repeated commit",err)}
  after,err:=os.ReadFile(marker);if err!=nil||!bytes.Equal(before,after){t.Fatal("successful replay modified durable receipt")}
  t.Log("PASS VOLVE_FRESH_SIGNED_ARCHIVES_HEALTH_COMMIT_ONCE_MEMORY_DNS_ONLY")
  return
 }
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


func TestWindowsFreshWatchdogNativeRegistrationAttestation(t *testing.T){
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{t.Skip("hosted inert task only")}
 ctx,cancel:=context.WithTimeout(context.Background(),90*time.Second);defer cancel()
 name:="VOLVE-CI-FreshWatchdog-"+os.Getenv("GITHUB_RUN_ID")+"00000"
 if !freshWatchdogLabName.MatchString(name){t.Fatal("invalid lab task name")}
 root:=t.TempDir()
 if err:=nativeSealApprovedOriginalBackupNode(ctx,root);err!=nil{t.Fatal(err)}
 exe:=filepath.Join(root,"VOLVE-FreshWatchdog.exe")
 original,err:=os.ReadFile(filepath.Join(os.Getenv("SystemRoot"),"System32","cmd.exe"));if err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(exe,original,0600);err!=nil{t.Fatal(err)}
 if err:=nativeSealApprovedOriginalBackupNode(ctx,exe);err!=nil{t.Fatal(err)}
 args:="/D /C exit 0"
 // Never start this inert task. Its disposable startup trigger and identity
 // are native Scheduler observations; there is no real watchdog here.
 q:=windowsSYSDNSQuote
 script:=`$ErrorActionPreference='Stop';$n=`+q(name)+`;
 if(Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue){throw 'task collision'};
 $a=New-ScheduledTaskAction -Execute `+q(exe)+` -Argument `+q(args)+`;
 $p=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest;
 $b=New-ScheduledTaskTrigger -AtStartup;
 Register-ScheduledTask -TaskPath '\' -TaskName $n -Action $a -Principal $p -Trigger $b -ErrorAction Stop|Out-Null`
 if err:=windowsSYSDNSShell(ctx,script);err!=nil{t.Fatal(err)}
 defer func(){
  cleanup,cancel:=context.WithTimeout(context.Background(),20*time.Second);defer cancel()
  if err:=windowsSYSDNSShell(cleanup,`$ErrorActionPreference='Stop';Unregister-ScheduledTask -TaskPath '\' -TaskName `+q(name)+` -Confirm:$false -ErrorAction Stop`);err!=nil{t.Error("inert watchdog task cleanup failed",err)}
 }()
 release,err:=AcquireProtectedResidentTransitionLease(ctx);if err!=nil{t.Fatal(err)};defer release()
 observed,err:=observeFreshWatchdogTaskNative(ctx,name);if err!=nil{t.Fatal(err)}
 sum:=sha256.Sum256(original)
 pin:=freshWatchdogTaskPin{name,exe,args,"",hex.EncodeToString(sum[:]),observed.DefinitionSHA256,observed.SecurityDescriptorSHA256}
 if err:=verifyFreshWatchdogRegistrationNative(ctx,pin);err!=nil{t.Fatal("native inert watchdog identity refused",err)}
 evidence:=freshActivationEvidence{
  TransactionID:strings.Repeat("a",32),SignedPackageSHA256:strings.Repeat("1",64),
  MotorSHA256:strings.Repeat("2",64),OriginalReviewSHA256:strings.Repeat("3",64),
  OriginalDNSJournalSHA256:strings.Repeat("4",64),OwnerApprovalSHA256:strings.Repeat("5",64),
  WatchdogTaskXMLSHA256:pin.DefinitionSHA256,WatchdogExecutableSHA256:pin.ExecutableSHA256,
  WatchdogSecurityDescriptorSHA256:pin.SecurityDescriptorSHA256}
 if err:=bindFreshWatchdogAdmission(evidence,pin);err!=nil{t.Fatal("matching signed watchdog pins refused",err)}
 for _,variant:=range []string{"xml","exe","acl"}{
  wrong:=pin
  switch variant{case "xml":wrong.DefinitionSHA256=strings.Repeat("f",64);case "exe":wrong.ExecutableSHA256=strings.Repeat("f",64);case "acl":wrong.SecurityDescriptorSHA256=strings.Repeat("f",64)}
  if err:=bindFreshWatchdogAdmission(evidence,wrong);err==nil{t.Fatal("foreign watchdog evidence accepted",variant)}
 }
 t.Log("PASS VOLVE_FRESH_WATCHDOG_ADMISSION_BINDS_XML_EXE_DACL")
 bad:=pin;bad.Arguments="/D /C exit 1"
 if err:=verifyFreshWatchdogRegistrationNative(ctx,bad);err==nil{t.Fatal("wrong watchdog command accepted")}
 bad=pin;bad.ExecutableSHA256=strings.Repeat("f",64)
 if err:=verifyFreshWatchdogRegistrationNative(ctx,bad);err==nil{t.Fatal("wrong watchdog executable digest accepted")}
 bad=pin;bad.SecurityDescriptorSHA256=strings.Repeat("f",64)
 if err:=verifyFreshWatchdogRegistrationNative(ctx,bad);err==nil{t.Fatal("wrong watchdog security descriptor accepted")}
 if err:=windowsSYSDNSShell(ctx,`$ErrorActionPreference='Stop';Disable-ScheduledTask -TaskPath '\' -TaskName `+q(name)+` -ErrorAction Stop|Out-Null`);err!=nil{t.Fatal(err)}
 if err:=verifyFreshWatchdogRegistrationNative(ctx,pin);err==nil{t.Fatal("disabled watchdog accepted")}
 t.Log("PASS VOLVE_FRESH_NATIVE_WATCHDOG_REGISTRATION_PINNED_INERT_NO_START_NO_DNS")
}


func TestWindowsFreshNativeActivationRejectsNonSYSTEM(t *testing.T){
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{t.Skip("hosted native refusal only")}
 if VerifyWindowsCurrentSystemSIDReadOnly()==nil{t.Fatal("expected non-SYSTEM hosted test process")}
 err:=activateFreshDNSAsSYSTEM(context.Background(),"",nil,nil,nil,freshActivationEvidence{},FreshMotorInstallEvidence{},ProtectionSnapshot{},WindowsBrowserPolicyEvidence{},WindowsFreshVOLVETaskInventory{},nil,freshWatchdogTaskPin{},WindowsDNSOverrideCensus{},&freshReservationFixtureGuard{})
 if err==nil||!strings.Contains(err.Error(),"actual LocalSystem"){t.Fatal("native route did not reject non-SYSTEM first",err)}
 t.Log("PASS VOLVE_FRESH_NATIVE_ROUTE_REFUSES_NON_SYSTEM_NO_WRITES")
}
