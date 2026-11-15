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
 coverageChecks int
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
func(d *protectedSignedFullTransactionLab)VerifyLegacyTaskRecoveryCoverage(ctx context.Context,proof VerifiedLegacyMigrationProof)(LegacyTaskRecoverySnapshot,error){
 d.coverageChecks++
 probeCtx,cancel:=context.WithTimeout(ctx,125*time.Millisecond)
 defer cancel()
 unlock,err:=AcquireProtectedResidentTransitionLease(probeCtx)
 if unlock!=nil{unlock()}
 if !errors.Is(err,context.DeadlineExceeded){
  return LegacyTaskRecoverySnapshot{},errors.New("task recovery coverage review ran without the protected SYSTEM mutex")
 }
 return testLegacyTaskRecoverySnapshotForProof(completeLegacyTaskRecoverySnapshot(),proof),nil
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

func TestProtectedSignedDriverUsesRecoveryReaderOnlyUnderNativeMutex(t *testing.T) {
 residentProtectedCITest(t)
 operations := &protectedSignedFullTransactionLab{managedDriverTest: &managedDriverTest{}}
 calls := 0
 proof := VerifiedLegacyMigrationProof{
  LegacySHA256: testLegacyActionSHA256,
  LegacyTaskXMLSHA256: testLegacyTaskXMLSHA256,
 }
 reader := ProtectedLegacyTaskRecoveryReader(func(ctx context.Context, got VerifiedLegacyMigrationProof) (LegacyTaskRecoverySnapshot, error) {
  calls++
  if got != proof { return LegacyTaskRecoverySnapshot{}, errors.New("signed proof was not forwarded unchanged") }
  probeCtx, cancel := context.WithTimeout(ctx, 125*time.Millisecond)
  defer cancel()
  unlock, err := AcquireProtectedResidentTransitionLease(probeCtx)
  if unlock != nil { unlock() }
  if !errors.Is(err, context.DeadlineExceeded) {
   return LegacyTaskRecoverySnapshot{}, errors.New("dedicated recovery reader ran without the native migration mutex")
  }
  return testLegacyTaskRecoverySnapshotForProof(completeLegacyTaskRecoverySnapshot(), got), nil
 })
 wrapped, err := NewProtectedSignedLegacySwitchDriverWithRecoveryReader(operations, reader)
 if err != nil { t.Fatal(err) }
 if _, err := wrapped.VerifyLegacyTaskRecoveryCoverage(context.Background(), proof); err == nil {
  t.Fatal("recovery reader was callable before mutex acquisition")
 }
 if calls != 0 { t.Fatal("reader callback ran outside the protected lease") }
 ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
 defer cancel()
 release, err := wrapped.AcquireExclusiveMigration(ctx)
 if err != nil { t.Fatal(err) }
 snapshot, err := wrapped.VerifyLegacyTaskRecoveryCoverage(ctx, proof)
 release()
 if err != nil { t.Fatal(err) }
 if calls != 1 || operations.coverageChecks != 0 {
  t.Fatalf("protected reader did not replace delegated evidence source: callback=%d delegated=%d", calls, operations.coverageChecks)
 }
 if !ReviewLegacyTaskRecoveryCoverage(snapshot).RecoverySetComplete {
  t.Fatal("native protected wrapper returned incomplete recovery evidence")
 }
}

func TestProtectedSignedTransactionBlocksWhenDedicatedReaderLacksDependencyOrRebootEvidence(t *testing.T) {
	residentProtectedCITest(t)
	for _, missing := range []struct {
		name string
		clear func(*LegacyTaskRecoverySnapshot)
		want string
	}{
		{"transitive dependencies", func(s *LegacyTaskRecoverySnapshot) { s.TransitiveDependenciesCertified = false }, "transitive legacy dependencies are not certified"},
		{"recovery after reboot", func(s *LegacyTaskRecoverySnapshot) { s.RecoveryAfterRebootVerified = false }, "recovery after reboot is not verified"},
	} {
		t.Run(missing.name, func(t *testing.T) {
			fixture := newSignedBridge(t)
			operations := &protectedSignedFullTransactionLab{managedDriverTest: &managedDriverTest{}}
			proof := VerifiedLegacyMigrationProof{LegacySHA256: testLegacyActionSHA256, LegacyTaskXMLSHA256: testLegacyTaskXMLSHA256}
			calls := 0
			reader := ProtectedLegacyTaskRecoveryReader(func(_ context.Context, got VerifiedLegacyMigrationProof) (LegacyTaskRecoverySnapshot, error) {
				calls++
				if got != proof { return LegacyTaskRecoverySnapshot{}, errors.New("signed proof was not forwarded unchanged") }
				snapshot := testLegacyTaskRecoverySnapshotForProof(completeLegacyTaskRecoverySnapshot(), got)
				missing.clear(&snapshot)
				return snapshot, nil
			})
			wrapped, err := NewProtectedSignedLegacySwitchDriverWithRecoveryReader(operations, reader)
			if err != nil { t.Fatal(err) }
			err = runSignedLegacyLab(context.Background(), fixture, wrapped, testSecureLabFolderBridge, func() error { return nil })
			if err == nil || !strings.Contains(err.Error(), missing.want) {
				t.Fatalf("protected transaction accepted missing %s evidence: %v", missing.name, err)
			}
			if calls != 1 || operations.coverageChecks != 0 || operations.readyChecks != 0 || len(operations.calls) != 0 {
				t.Fatalf("dedicated reader's negative evidence did not stop before any mutation: reader=%d delegated=%d ready=%d calls=%v", calls, operations.coverageChecks, operations.readyChecks, operations.calls)
			}
		})
	}
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
    if driver.readyChecks!=3||driver.preparedChecks!=2||driver.coverageChecks!=3||driver.protectedHandoffs!=0{
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
