//go:build windows

package hostroutebridge

import (
 "context"
 "errors"
 "testing"
 "time"

 motorupdate "volve-browser-protection/motorupdate"
)

func TestProtectedPreflightRefusesCancelledContextBeforeKernelObject(t *testing.T) {
 ctx,cancel:=context.WithCancel(context.Background())
 cancel()
 report,plan,err:=InspectAndPlanUnderProtectedLeaseReadOnly(ctx,
  "",nil,"","","",motorupdate.WindowsMotorRouteInspectors{})
 if !errors.Is(err,context.Canceled)||report.Component!=""||plan.Mode!="" {
  t.Fatalf("cancelled preflight issued a privileged review: %+v %+v %v",report,plan,err)
 }
}

func TestProtectedPreflightCannotReadHostDuringAnotherTransaction(t *testing.T) {
 fixture:=labEvidence(t) // REAL Windows CI Authenticode lab file
 held,err:=motorupdate.AcquireProtectedResidentTransitionLease(context.Background())
 if err!=nil{t.Fatal(err)}
 defer held()
 readers:=motorupdate.DefaultWindowsMotorRouteInspectors()
 attempts:=0
 original:=readers.Host.Admin
 readers.Host.Admin=func(ctx context.Context,command string)([]byte,error){
  attempts++
  return original(ctx,command)
 }
 blocked,cancel:=context.WithTimeout(context.Background(),180*time.Millisecond)
 defer cancel()
 report,plan,err:=InspectAndPlanUnderProtectedLeaseReadOnly(blocked,
  fixture.exe,fixture.key,fixture.certPin,fixture.exePin,t.TempDir(),readers)
 if !errors.Is(err,context.DeadlineExceeded)||attempts!=0||report.Component!=""||plan.Mode!="" {
  t.Fatalf("second transaction bypassed kernel mutex: calls=%d review=%+v plan=%+v err=%v",attempts,report,plan,err)
 }
}

func TestProtectedPreflightHoldsRealMutexThroughoutSignedWindowsCensus(t *testing.T) {
 fixture:=labEvidence(t)
 readers:=motorupdate.DefaultWindowsMotorRouteInspectors()
 original:=readers.Host.Admin
 if original==nil{t.Fatal("missing real Windows admin inventory inspector")}
 contested:=false
 readers.Host.Admin=func(ctx context.Context,cmd string)([]byte,error){
  attemptCtx,cancel:=context.WithTimeout(ctx,160*time.Millisecond)
  defer cancel()
  done:=make(chan error,1)
  go func(){
   release,err:=motorupdate.AcquireProtectedResidentTransitionLease(attemptCtx)
   if release!=nil{release()}
   done<-err
  }()
  if lockErr:=<-done;!errors.Is(lockErr,context.DeadlineExceeded){
   return nil,errors.New("a separate watchdog bypassed native updater lease during Windows inventory")
  }
  contested=true
  return original(ctx,cmd)
 }
 ctx,cancel:=context.WithTimeout(context.Background(),130*time.Second)
 defer cancel()
 review,plan,err:=InspectAndPlanUnderProtectedLeaseReadOnly(ctx,
  fixture.exe,fixture.key,fixture.certPin,fixture.exePin,
  t.TempDir(),readers)
 if err!=nil{t.Fatal(err)}
 if !contested||!review.WindowsPublisherAndPackageVerified||
  review.InventoriesChecked!=6||plan.CanInstall||plan.CanUpgrade||
  plan.CanChangeDNS||plan.CanChangeTasks||
  plan.Disposition!="READ_ONLY_PLAN_NOT_AN_INSTALLATION_PERMIT"{
  t.Fatalf("protected preflight failed to remain exclusive and read-only: %+v %+v",review,plan)
 }
 // The protected review must have released the same native OS mutex before
 // returning. A second independent operation can acquire it immediately.
 free,done:=context.WithTimeout(context.Background(),2*time.Second)
 defer done()
 unlock,err:=motorupdate.AcquireProtectedResidentTransitionLease(free)
 if err!=nil||unlock==nil{t.Fatalf("preflight leaked updater/watchdog kernel mutex: %v",err)}
 unlock()
 t.Logf("PASS VOLVE_PROTECTED_SIGNED_HOST_6_INVENTORIES route=%s NO_INSTALL_NO_DNS_TASK_WRITES",review.Route)
}
