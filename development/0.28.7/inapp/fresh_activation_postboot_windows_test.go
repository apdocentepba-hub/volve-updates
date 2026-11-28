//go:build windows

package motorupdate

import(
 "bytes"
 "context"
 "crypto/sha256"
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
