//go:build windows

package motorupdate

// Publisher-signed end-to-end transaction contract with the ACTUAL protected
// Windows kernel mutex and a no-op motor driver. This is a disposable CI
// simulation, NEVER an installed or productive DNS migration.
import (
 "context"
 "errors"
 "strings"
 "testing"
 "time"
)

type protectedSignedFullTransactionLab struct {
 *managedDriverTest
 delegateLockCalls int
 readyChecks int
 protectedHandoffs int
 preparedChecks int
}

func(d *protectedSignedFullTransactionLab)AcquireExclusiveMigration(context.Context)(func(),error){
 d.delegateLockCalls++
 return nil,errors.New("weaker delegated lease MUST NOT be reached")
}
func(d *protectedSignedFullTransactionLab)IndependentRecoveryReady(ctx context.Context,_ VerifiedLegacyMigrationProof)error{
 d.readyChecks++
 // Use a fresh goroutine + OS thread, not reentrant acquisition by the
 // updater. The watchdog must be excluded until explicit handoff.
 probeCtx,cancel:=context.WithTimeout(ctx,125*time.Millisecond)
 defer cancel()
 unlock,err:=AcquireProtectedResidentTransitionLease(probeCtx)
 if unlock!=nil{unlock()}
 if !errors.Is(err,context.DeadlineExceeded){
  return errors.New("SYSTEM watchdog did not observe exclusive signed updater kernel mutex")
 }
 return nil
}
func(d *protectedSignedFullTransactionLab)VerifyPreparedTarget(_ context.Context,m Manifest)error{
 d.preparedChecks++
 if m.Version!="0.28.7"{return errors.New("unexpected signed motor candidate")}
 return nil
}
func(d *protectedSignedFullTransactionLab)RestoreAfterProtectedHandoff(ctx context.Context)error{
 d.protectedHandoffs++
 // Recovery is a separate owner, after the signed updater has released
 // the OS mutex. The fake driver merely records Restore; no task/DNS writes.
 release,err:=AcquireProtectedResidentTransitionLease(ctx)
 if err!=nil{return err}
 if release==nil{return errors.New("independent watchdog returned no protected kernel lease")}
 defer release()
 return d.managedDriverTest.Restore(ctx)
}

func TestProtectedSignedFullTransactionCommitAndRecoveryUnderNativeMutex(t *testing.T){
 residentProtectedCITest(t)
 for _,mode:=range []string{"commit","switch-failure","cancel-after-switch"}{
  t.Run(mode,func(t *testing.T){
   fixture:=newSignedBridge(t)
   driver:=&protectedSignedFullTransactionLab{managedDriverTest:&managedDriverTest{}}
   var ctx context.Context=context.Background()
   if mode=="switch-failure"{driver.fail="switch"}
   if mode=="cancel-after-switch"{
    var cancel context.CancelFunc
    ctx,cancel=context.WithCancel(context.Background())
    defer cancel()
    driver.cancel=cancel
   }
   wrapped,err:=NewProtectedSignedLegacySwitchDriver(driver)
   if err!=nil{t.Fatal(err)}
   err=runSignedLegacyLab(ctx,fixture,wrapped,testSecureLabFolderBridge,func()error{return nil})
   if driver.delegateLockCalls!=0{
    t.Fatalf("unprotected fake lock was called %d times",driver.delegateLockCalls)
   }
   if driver.readyChecks<2{
    t.Fatalf("native mutex not held across signed boundaries: %d checks",driver.readyChecks)
   }
   if mode=="commit"{
    if err!=nil{t.Fatalf("signed transaction cannot commit under real kernel mutex: %v",err)}
    if driver.readyChecks!=3||driver.preparedChecks!=2||driver.protectedHandoffs!=0{
     t.Fatalf("incomplete signed fences/unsafe restore: ready=%d prepared=%d recovery=%d",
      driver.readyChecks,driver.preparedChecks,driver.protectedHandoffs)
    }
   }else{
    if err==nil||driver.protectedHandoffs!=1{
     t.Fatalf("failed signed transition did not use independent kernel handoff: mode=%s handoffs=%d err=%v",
      mode,driver.protectedHandoffs,err)
    }
    if driver.rollbackCancelled{
     t.Fatal("independent recovery incorrectly inherited cancelled updater context")
    }
    for _,step:=range driver.calls{
     if step=="commit"{t.Fatalf("failed transaction committed in mode %s: %v",mode,driver.calls)}
    }
    if mode=="switch-failure"&&!strings.Contains(err.Error(),"revertida"){
     t.Fatalf("real protected handoff did not validate successful recovery: %v",err)
    }
   }
   // Every success/failure path must let an unrelated Windows thread (or
   // independent SYSTEM watchdog) acquire the same kernel mutex afterwards.
   finishCtx,done:=context.WithTimeout(context.Background(),3*time.Second)
   defer done()
   probe,probeErr:=AcquireProtectedResidentTransitionLease(finishCtx)
   if probeErr!=nil||probe==nil{
    t.Fatalf("signed transaction leaked native kernel mutex: mode=%s err=%v",mode,probeErr)
   }
   probe()
  })
 }
}
