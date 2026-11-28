//go:build windows

package motorupdate

import(
 "bytes"
 "context"
 "crypto/sha256"
 "crypto/ed25519"
 "crypto/rand"
 "encoding/json"
 "encoding/hex"
 "errors"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"
)

func TestFreshBootIdentityRejectsSameBootAndInconsistentEvidence(t *testing.T){
 before:=freshBootIdentity{1800000000000,123,1800000001000}
 after:=freshBootIdentity{1800000300000,234,1800000301000}
 wall:=before.BootUnixMilli+900000
 if err:=validateFreshBootSample(before,wall,wall+2000,900000,902000);err!=nil{t.Fatal(err)}
 if err:=verifyFreshLaterBoot(before,after);err!=nil{t.Fatal(err)}
 for _,b:=range []freshBootIdentity{before,{before.BootUnixMilli,234,before.StartEventUnixMilli},{after.BootUnixMilli,123,after.StartEventUnixMilli},{after.BootUnixMilli,234,after.BootUnixMilli-600000},{0,234,0},{after.BootUnixMilli,0,after.StartEventUnixMilli}}{
  if err:=verifyFreshLaterBoot(before,b);err==nil{t.Fatal("same/ambiguous boot accepted",b)}
 }
 if err:=validateFreshBootSample(before,wall,wall+2000,1000,3000);err==nil{t.Fatal("wall-clock evidence accepted despite incompatible kernel uptime")}
 if err:=validateFreshBootSample(before,wall,wall+2000,900000,899999);err==nil{t.Fatal("backwards kernel uptime accepted")}
 t.Log("PASS VOLVE_FRESH_BOOT_IDENTITY_REFUSES_SAME_BOOT_CLOCK_ONLY")
}
func TestWindowsFreshNativeBootObservationReadOnly(t *testing.T){
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{t.Skip("hosted native boot observation only")}
 first,err:=observeFreshBootNative(context.Background());if err!=nil{t.Fatal(err)}
 second,err:=observeFreshBootNative(context.Background());if err!=nil{t.Fatal(err)}
 if first!=second{t.Fatal("native boot identity not stable within same boot")}
 if err:=verifyFreshLaterBoot(first,second);err==nil{t.Fatal("same Windows session accepted as reboot")}
 t.Log("PASS VOLVE_FRESH_NATIVE_BOOT_WMI_EVENT_KERNEL_UPTIME_READ_ONLY")
}


func TestWindowsFreshProvisionalNativeStorageAndPostBootGate(t *testing.T){
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{t.Skip("hosted protected file test only")}
 ctx,cancel:=context.WithTimeout(context.Background(),180*time.Second);defer cancel()
 // Reuse the sealed DNS-only lab fixture, without a scheduled task, DNS
 // writes or a real reboot. Only storage/authority gates are under test.
 root,pins,pub,raw,sig:=prepareFreshSYSTEMRecoveryLab(t,ctx,t.TempDir(),windowsDNSCrashRecords(activationTestGUID))
 release,err:=AcquireProtectedResidentTransitionLease(ctx);if err!=nil{t.Fatal(err)}
 held:=&exclusiveDNSActivationGuard{inner:&freshReservationFixtureGuard{},acquire:AcquireProtectedResidentTransitionLease,release:release}
 defer held.close()
 pending,err:=armFreshRecoveryPendingUnderLease(ctx,root,pub,pins,held);if err!=nil{t.Fatal(err)}
 before,err:=observeFreshBootNative(ctx);if err!=nil{t.Fatal(err)}
 sum:=sha256.Sum256(raw);digest:=hex.EncodeToString(sum[:])
 path:=filepath.Join(root,freshProvisionalName)
 if err:=persistFreshActivationProvisionalUnderLease(ctx,root,pending,digest,before,observeFreshBootNative);err==nil{t.Fatal("provisional receipt without consumed admission")}
 if _,err:=os.Lstat(path);!os.IsNotExist(err){t.Fatal("unconsumed admission created provisional receipt")}
 host:=FreshMotorInstallEvidence{InspectedAsAdministrator:true,InspectedMotorFiles:true,InspectedTaskScheduler:true,InspectedServices:true,InspectedDNSAdapters:true,InspectedPort53Listeners:true,InspectedRecoveryState:true}
 if _,err:=reserveFreshActivationUnderHeldLease(ctx,root,raw,sig,pub,pins,host,held);err!=nil{t.Fatal(err)}
 later:=freshBootIdentity{before.BootUnixMilli+600000,before.StartEventRecordID+1,before.StartEventUnixMilli+600000}
 simulatedLater:=func(c context.Context)(freshBootIdentity,error){return later,c.Err()}
 if err:=persistFreshActivationProvisionalUnderLease(ctx,root,pending,digest,before,simulatedLater);err==nil{t.Fatal("changed boot accepted during provisional commit")}
 if _,err:=os.Lstat(path);!os.IsNotExist(err){t.Fatal("changed boot created provisional receipt")}
 if err:=persistFreshActivationProvisionalUnderLease(ctx,root,pending,digest,before,observeFreshBootNative);err!=nil{t.Fatal(err)}
 saved,err:=os.ReadFile(path);if err!=nil{t.Fatal(err)}
 if err:=persistFreshActivationProvisionalUnderLease(ctx,root,pending,digest,before,observeFreshBootNative);!errors.Is(err,os.ErrExist){t.Fatal("provisional slot reused",err)}
 verify:=func(d string,observer func(context.Context)(freshBootIdentity,error))(freshBootIdentity,error){
  return verifyFreshPostBootEvidenceUnderLease(ctx,root,pub,pins,d,observer)
 }
 if _,err:=verify(digest,observeFreshBootNative);err==nil{t.Fatal("same native boot accepted as reboot")}
 if _,err:=verify(strings.Repeat("f",64),simulatedLater);err==nil{t.Fatal("foreign consumed admission accepted")}
 if got,err:=verify(digest,simulatedLater);err!=nil||got!=later{t.Fatal("simulated later observation refused",err)}
 calls:=0
 unstable:=func(c context.Context)(freshBootIdentity,error){calls++;if calls==2{return before,c.Err()};return later,c.Err()}
 if _,err:=verify(digest,unstable);err==nil{t.Fatal("unstable boot observation accepted")}
 after,err:=os.ReadFile(path);if err!=nil||!bytes.Equal(saved,after){t.Fatal("provisional proof mutated record")}
 // Corrupting consumed authorization prevents activation certification,
 // but leaves the independent signed recovery permit readable.
 if err:=os.WriteFile(filepath.Join(root,freshReservationName),[]byte("{"),0600);err!=nil{t.Fatal(err)}
 if _,err:=verify(digest,simulatedLater);err==nil{t.Fatal("damaged consumed admission accepted")}
 if _,err:=loadFreshRecoveryPermitUnderLease(ctx,root,pub,pins);err!=nil{t.Fatal("activation damage suppressed recovery permit",err)}
 if err:=verifyFreshRecoveryPendingUnderLease(ctx,root,pending);err!=nil{t.Fatal("activation damage suppressed pending rescue",err)}
 // A malformed provisional receipt never authorizes a terminal result.
 if err:=os.WriteFile(path,[]byte("{"),0600);err!=nil{t.Fatal(err)}
 if _,err:=verify(digest,simulatedLater);err==nil{t.Fatal("partial provisional receipt accepted")}
 if _,err:=os.Lstat(filepath.Join(root,freshDNSRestoredName));!os.IsNotExist(err){t.Fatal("boot proof created terminal DNS restoration receipt")}
 t.Log("PASS VOLVE_FRESH_PROVISIONAL_NATIVE_NTFS_CONSUMED_ADMISSION_SAME_BOOT_REFUSED_SIMULATED_LATER_BOOT")
}


func TestFreshPostBootActiveCensusRejectsPartialOrForeignFamilies(t *testing.T){
 raw,pin,_,_:=prepareActivationTest(t)
 records,err:=VerifyDNSOriginalJournal(context.Background(),raw,pin)
 if err!=nil{t.Fatal(err)}
 states:=make([]DNSServerState,len(records))
 for i,r:=range records{states[i]=copyWindowsActivationDNSState(r.Expected)}
 if err:=verifyFreshActiveDNSCensus(records,states);err!=nil{t.Fatal(err)}
 reversed:=[]DNSServerState{states[1],states[0]}
 if err:=verifyFreshActiveDNSCensus(records,reversed);err!=nil{t.Fatal("census order incorrectly treated as identity",err)}
 foreign:=copyWindowsActivationDNSState(states[0]);foreign.InterfaceGUID="{11111111-2222-3333-4444-555555555555}"
 original:=copyWindowsActivationDNSState(records[0].Original)
 for _,bad:=range [][]DNSServerState{nil,states[:1],{states[0],states[0]},{foreign,states[1]},{original,states[1]},append(append([]DNSServerState(nil),states...),foreign)}{
  if err:=verifyFreshActiveDNSCensus(records,bad);err==nil{t.Fatal("incomplete, duplicate or unprotected postboot DNS accepted",bad)}
 }
 t.Log("PASS VOLVE_FRESH_POSTBOOT_ALL_ACTIVE_DNS_FAMILIES_READ_ONLY")
}


func TestFreshMotorRuntimeRequiresFourExactSamePIDListeners(t *testing.T){
 pin:=freshMotorRuntimePin{Executable:`C:\VOLVE\motor-0.28.7\VOLVE_DNS_Motor_0_28_7.exe`}
 now:=time.Now().UnixMilli()
 boot:=freshBootIdentity{now-600000,10,now-599000}
 good:=freshMotorRuntimeObservation{PID:123,CreatedUnixMilli:now-500000,Path:pin.Executable,CommandLine:"\""+pin.Executable+"\" --dns-service",OwnerSID:"S-1-5-18",Endpoints:[]windowsFreshPort53Row{{"UDP","127.0.0.1",53,123},{"UDP","::1",53,123},{"TCP","127.0.0.1",53,123},{"TCP","::1",53,123}}}
 if err:=verifyFreshMotorRuntimeObservation(pin,good,boot);err!=nil{t.Fatal(err)}
 for _,mode:=range []string{"other-sid","old-process","wrong-argv","foreign-pid","wildcard","duplicate","missing","extra"}{
  bad:=good;bad.Endpoints=append([]windowsFreshPort53Row(nil),good.Endpoints...)
  switch mode{
  case "other-sid":bad.OwnerSID="S-1-5-19"
  case "old-process":bad.CreatedUnixMilli=boot.BootUnixMilli-1
  case "wrong-argv":bad.CommandLine+=" --unexpected"
  case "foreign-pid":bad.Endpoints[3].PID=124
  case "wildcard":bad.Endpoints[0].Address="0.0.0.0"
  case "duplicate":bad.Endpoints[3]=bad.Endpoints[2]
  case "missing":bad.Endpoints=bad.Endpoints[:3]
  case "extra":bad.Endpoints=append(bad.Endpoints,bad.Endpoints[0])
  }
  if err:=verifyFreshMotorRuntimeObservation(pin,bad,boot);err==nil{t.Fatal("unsafe identity accepted",mode)}
 }
 t.Log("PASS VOLVE_FRESH_RUNTIME_EXACT_FOUR_LISTENERS_SAME_SYSTEM_PID")
}


func TestFreshStagingProofBindsCatalogAndMotorTask(t *testing.T){
 pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 pins:=freshActivationEvidence{strings.Repeat("a",32),strings.Repeat("1",64),strings.Repeat("2",64),strings.Repeat("3",64),strings.Repeat("4",64),strings.Repeat("5",64),strings.Repeat("6",64),strings.Repeat("7",64),strings.Repeat("8",64)}
 admission:=strings.Repeat("9",64)
 root:=`C:\VOLVE`
 motor:=freshMotorRuntimePin{Executable:filepath.Join(root,"motor-0.28.7","VOLVE_DNS_Motor_0_28_7.exe"),TaskXMLSHA256:strings.Repeat("a",64),TaskDaclSHA256:strings.Repeat("b",64)}
 good:=freshStagingProof{1,"volve-fresh-staged-motor-catalog-review-only-v1",pins,admission,motor,root,[4]freshStageFeed{}}
 for i,name:=range freshStageFeedNames{good.Feeds[i].Name=name}
 good.Feeds[0].Bytes=11000000;good.Feeds[0].SHA256=strings.Repeat("c",64)
 raw,err:=json.Marshal(good);if err!=nil{t.Fatal(err)}
 sig:=ed25519.Sign(priv,raw)
 if got,err:=verifyFreshStagingProof(pub,raw,sig,pins,admission,motor);err!=nil||got!=good{t.Fatal("exact staging proof refused",err)}
 for _,mode:=range []string{"foreign-transaction","foreign-admission","other-task","other-root","missing-full","reordered","unbound-optional","scope","tamper"}{
  bad:=good
  switch mode{
  case "foreign-transaction":bad.Evidence.TransactionID=strings.Repeat("b",32)
  case "foreign-admission":bad.AdmissionSHA256=strings.Repeat("a",64)
  case "other-task":bad.Motor.TaskDaclSHA256=strings.Repeat("d",64)
  case "other-root":bad.InstallRoot=`D:\Other`
  case "missing-full":bad.Feeds[0].Bytes=0;bad.Feeds[0].SHA256=""
  case "reordered":bad.Feeds[0],bad.Feeds[1]=bad.Feeds[1],bad.Feeds[0]
  case "unbound-optional":bad.Feeds[1].Bytes=42
  case "scope":bad.Scope="activate"
  case "tamper":bad.Feeds[0].SHA256=strings.Repeat("d",64)
  }
  b,e:=json.Marshal(bad);if e!=nil{t.Fatal(e)}
  s:=ed25519.Sign(priv,b);if mode=="tamper"{s=sig}
  if _,e:=verifyFreshStagingProof(pub,b,s,pins,admission,motor);e==nil{t.Fatal("unsafe staging proof accepted",mode)}
 }

 // The signed metadata alone cannot establish actual feed contents.
 // Use only disposable files on the hosted Windows runner; no motor or
 // task is started and no DNS, installed catalog, or network is changed.
 if os.Getenv("GITHUB_ACTIONS")=="true"&&os.Getenv("RUNNER_ENVIRONMENT")=="github-hosted"{
  t.Run("native_protected_feed_bytes",testFreshStagedCatalogNativeFiles)
 }
 t.Log("PASS VOLVE_FRESH_STAGE_SIGNED_CATALOG_AND_MOTOR_TASK_BOUND")
}

func testFreshStagedCatalogNativeFiles(t *testing.T){
 ctx,cancel:=context.WithTimeout(context.Background(),110*time.Second);defer cancel()
 root:=filepath.Join(t.TempDir(),"catalog-fixture")
 catalog:=filepath.Join(root,"catalog")
 feeds:=filepath.Join(catalog,"feeds")
 for _,dir:=range []string{root,catalog,feeds}{
  if err:=os.Mkdir(dir,0700);err!=nil{t.Fatal(err)}
  if err:=nativeSealApprovedOriginalBackupNode(ctx,dir);err!=nil{t.Fatal(err)}
 }
 stage:=freshStagingProof{InstallRoot:root}
 for i,name:=range freshStageFeedNames{stage.Feeds[i].Name=name}
 payload:=[]byte("example.invalid\n")
 digest:=sha256.Sum256(payload)
 stage.Feeds[0].Bytes=int64(len(payload))
 stage.Feeds[0].SHA256=hex.EncodeToString(digest[:])
 required:=filepath.Join(feeds,stage.Feeds[0].Name)
 if err:=os.WriteFile(required,payload,0600);err!=nil{t.Fatal(err)}
 if err:=nativeSealApprovedOriginalBackupNode(ctx,required);err!=nil{t.Fatal(err)}
 if err:=verifyFreshStagedCatalogNative(ctx,stage);err!=nil{t.Fatal("exact protected feed refused",err)}
 // Unexpected optional data must not be silently accepted.
 optional:=filepath.Join(feeds,stage.Feeds[1].Name)
 if err:=os.WriteFile(optional,payload,0600);err!=nil{t.Fatal(err)}
 if err:=verifyFreshStagedCatalogNative(ctx,stage);err==nil||!strings.Contains(err.Error(),"unsigned optional catalog appeared"){t.Fatal("unexpected optional feed was not specifically refused",err)}
 if err:=os.Remove(optional);err!=nil{t.Fatal(err)}
 // A signed optional slot is allowed only with its exact protected bytes.
 stage.Feeds[1].Bytes=int64(len(payload))
 stage.Feeds[1].SHA256=hex.EncodeToString(digest[:])
 if err:=verifyFreshStagedCatalogNative(ctx,stage);err==nil{t.Fatal("missing signed optional feed accepted")}
 if err:=os.WriteFile(optional,payload,0600);err!=nil{t.Fatal(err)}
 if err:=nativeSealApprovedOriginalBackupNode(ctx,optional);err!=nil{t.Fatal(err)}
 if err:=verifyFreshStagedCatalogNative(ctx,stage);err!=nil{t.Fatal("signed protected optional feed refused",err)}
 // Same byte length, different SHA-256: no size-only false PASS.
 altered:=append([]byte(nil),payload...);altered[0]='X'
 if err:=os.WriteFile(required,altered,0600);err!=nil{t.Fatal(err)}
 if err:=verifyFreshStagedCatalogNative(ctx,stage);err==nil||!strings.Contains(err.Error(),"catalog differs from signed staged content"){t.Fatal("same-size altered catalog was not specifically refused",err)}
 observed,err:=os.ReadFile(required)
 if err!=nil||!bytes.Equal(observed,altered){t.Fatal("read-only audit modified fixture",err)}
 t.Log("PASS VOLVE_FRESH_NATIVE_PROTECTED_CATALOG_BYTES_UNEXPECTED_OPTIONAL_AND_SAME_SIZE_TAMPER_REFUSED")
}
