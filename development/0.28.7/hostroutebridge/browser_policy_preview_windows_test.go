//go:build windows

package hostroutebridge

import (
 "context"
 "errors"
 "strings"
 "testing"
 "time"

 motorupdate "volve-browser-protection/motorupdate"
)

func fakeBrowserSnapshot(chrome int) motorupdate.WindowsBrowserPolicyEvidence {
 return motorupdate.WindowsBrowserPolicyEvidence{
  Schema:1,Component:"browser-policy-registry-read-only",
  Records:[]motorupdate.WindowsBrowserPolicyRecord{
   {Name:"chrome",Present:true,NumberedEntries:chrome},
   {Name:"edge",Present:true,NumberedEntries:3},
   {Name:"firefox",Present:true,NumberedEntries:2},
  },
  TotalNumberedEntries:chrome+5,NoRegistryValuesCollected:true,
  BrowserEnforcementVerified:false,DNSMotorVerified:false,
 }
}

func TestBrowserCensusStableCountsDoNotCertifyProtection(t *testing.T) {
 original:=fakeBrowserSnapshot(4)
 if err:=validateStableReadOnlyBrowserEvidence(original,original);err!=nil{t.Fatal(err)}
 tampered:=fakeBrowserSnapshot(5)
 if err:=validateStableReadOnlyBrowserEvidence(original,tampered);err==nil{
  t.Fatal("changing browser registry count did not block preflight")
 }
 claimed:=fakeBrowserSnapshot(4)
 claimed.BrowserEnforcementVerified=true
 if err:=validateStableReadOnlyBrowserEvidence(original,claimed);err==nil{
  t.Fatal("reported browser enforcement with no live browser test")
 }
 malformed:=fakeBrowserSnapshot(4)
 malformed.Records=malformed.Records[:2]
 if err:=validateStableReadOnlyBrowserEvidence(original,malformed);err==nil{
  t.Fatal("missing Firefox registry evidence was silently accepted")
 }
}

func TestProtectedBrowserCensusRejectsStalePolicyRegistryWithoutAnyPermit(t *testing.T) {
 fixture:=labEvidence(t)
 ctx,cancel:=context.WithTimeout(context.Background(),120*time.Second)
 defer cancel()
 reads:=0
 policy:=func(ctx context.Context,query string)([]byte,error){
  if query!=motorupdate.WindowsVOLVEBrowserPolicyQuery{
   return nil,errors.New("unsafe browser policy query")
  }
  reads++
  current:=4
  if reads>1{current=6} // Simulate a concurrent policy change.
  return []byte(`[{"Name":"chrome","Present":true,"NumberedEntries":`+
   func()string{if current==4{return "4"};return "6"}()+
   `,"InvalidEntries":0,"UnexpectedEntries":0},`+
   `{"Name":"edge","Present":false,"NumberedEntries":0,"InvalidEntries":0,"UnexpectedEntries":0},`+
   `{"Name":"firefox","Present":false,"NumberedEntries":0,"InvalidEntries":0,"UnexpectedEntries":0}]`),nil
 }
 review,plan,counts,err:=InspectAndPlanWithBrowserCensusUnderProtectedLeaseReadOnly(
  ctx,fixture.exe,fixture.key,fixture.certPin,fixture.exePin,
  t.TempDir(),motorupdate.DefaultWindowsMotorRouteInspectors(),policy,
 )
 if err==nil||!strings.Contains(err.Error(),"changed during preinstallation review")||
  reads!=2||review.Component!=""||plan.Mode!=""||len(counts.Records)!=0{
  t.Fatalf("drifting policies returned trusted preflight: calls=%d review=%+v plan=%+v counts=%+v err=%v",
   reads,review,plan,counts,err)
 }
 // Failure must release the real kernel lease, not strand a future watchdog.
 bounded,done:=context.WithTimeout(context.Background(),2*time.Second)
 defer done()
 release,err:=motorupdate.AcquireProtectedResidentTransitionLease(bounded)
 if err!=nil||release==nil{t.Fatalf("failed browser census left mutex held: %v",err)}
 release()
}

func TestProtectedBrowserCensusRunsNativeRegistryInventoryUnderSameLease(t *testing.T) {
 fixture:=labEvidence(t)
 ctx,cancel:=context.WithTimeout(context.Background(),120*time.Second)
 defer cancel()
 reads:=0
 policy:=func(ctx context.Context,query string)([]byte,error){
  reads++
  otherCtx,finish:=context.WithTimeout(ctx,120*time.Millisecond)
  defer finish()
  done:=make(chan error,1)
  go func(){
   unlock,err:=motorupdate.AcquireProtectedResidentTransitionLease(otherCtx)
   if unlock!=nil{unlock()}
   done<-err
  }()
  if err:=<-done;!errors.Is(err,context.DeadlineExceeded){
   return nil,errors.New("browser policy census ran outside protected OS lease")
  }
  return motorupdate.DefaultWindowsBrowserPolicyInspect(ctx,query)
 }
 review,plan,counts,err:=InspectAndPlanWithBrowserCensusUnderProtectedLeaseReadOnly(
  ctx,fixture.exe,fixture.key,fixture.certPin,fixture.exePin,
  t.TempDir(),motorupdate.DefaultWindowsMotorRouteInspectors(),policy,
 )
 if err!=nil{t.Fatal(err)}
 if reads!=2||review.InventoriesChecked!=6||!plan.SignedPackageVerified||
  len(counts.Records)!=3||!counts.NoRegistryValuesCollected||
  counts.BrowserEnforcementVerified||counts.DNSMotorVerified||
  plan.CanInstall||plan.CanChangeDNS||plan.CanChangeTasks{
  t.Fatalf("registry + signed Windows census was not bounded and review-only: reads=%d review=%+v plan=%+v policy=%+v",
   reads,review,plan,counts)
 }
 t.Logf("PASS VOLVE_PROTECTED_BROWSER_REGISTRY_NATIVE_Windows keys=3 numbered=%d NO_URL_VALUES NO_INSTALL",
  counts.TotalNumberedEntries)
}
