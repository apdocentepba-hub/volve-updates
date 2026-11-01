package motorupdate

import (
    "context"
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "reflect"
    "strings"
    "testing"
)

// All tests use temporary fake binaries, ephemeral Ed25519 publisher keys and
// fake drivers. None launches a DNS service, alters Windows tasks or network.
type signedLegacyDriverLab struct {
    *managedDriverTest
    watchdogCount int
    failWatchdogAt int
    preparedCount int
    failPreparedAt int
    connectivityCount int
    afterConnectivity func()error
    replaceCandidate bool
    replaceOldMotor string
    afterSnapshot func()error
    afterInstall func()error
}
func newSignedLegacyDriverLab()*signedLegacyDriverLab {
    return &signedLegacyDriverLab{managedDriverTest:&managedDriverTest{}}
}
// Override Snapshot so tests can corrupt the real temp-file backup only
// after the independent signed permission and readiness checks succeeded.
func (d *signedLegacyDriverLab) Snapshot(ctx context.Context)error{
 if err:=d.managedDriverTest.Snapshot(ctx);err!=nil{return err}
 if d.afterSnapshot!=nil{return d.afterSnapshot()}
 return nil
}
func (d *signedLegacyDriverLab) IndependentRecoveryReady(_ context.Context, _ VerifiedLegacyMigrationProof)error{
    d.watchdogCount++
    if err:=d.tick("watchdog");err!=nil{return err}
    if d.failWatchdogAt==d.watchdogCount{return errors.New("independent recovery agent unavailable")}
    return nil
}
func (d *signedLegacyDriverLab) VerifyPreparedTarget(_ context.Context, m Manifest) error {
    d.preparedCount++
    if m.Version!="0.28.7" {return errors.New("invalid signed prepared version")}
    if err:=d.tick("prepared");err!=nil{return err}
    if d.preparedCount==d.failPreparedAt{return errors.New("installed target became untrusted")}
    return nil
}
func (d *signedLegacyDriverLab) ProbeConnectivity(ctx context.Context)error{
    if err:=d.managedDriverTest.ProbeConnectivity(ctx);err!=nil{return err}
    d.connectivityCount++
    if d.connectivityCount==1&&d.afterConnectivity!=nil{return d.afterConnectivity()}
    return nil
}
func (d *signedLegacyDriverLab) InstallVersionedCandidate(ctx context.Context,candidate string) error {
    if err:=d.managedDriverTest.InstallVersionedCandidate(ctx,candidate);err!=nil{return err}
    if d.afterInstall!=nil{return d.afterInstall()}
    if d.replaceCandidate{
        return os.WriteFile(candidate,[]byte("MZ_CANDIDATE_MODIFIED_AFTER_FIRST_SIGNATURE"),0600)
    }
    if d.replaceOldMotor!=""{
        return os.WriteFile(d.replaceOldMotor,[]byte("MZ_LEGACY_CHANGED_BEFORE_SWITCH"),0600)
    }
    return nil
}
func runSignedLegacyLab(ctx context.Context,f *signedBridgeFixture,driver SignedLegacySwitchDriver,acl func(string)error,preflight func()error)error{
    return ApplySignedLegacyWithRollback(ctx,f.live,f.backup,f.candidate,"0.28.7",
        f.raw,f.sig,f.pub,acl,preflight,driver)
}
func TestSignedLegacyTransactionRequiresRevalidationAndIndependentWatchdog(t *testing.T){
    f:=newSignedBridge(t)
    d:=newSignedLegacyDriverLab()
    checks:=0
    err:=runSignedLegacyLab(context.Background(),f,d,testSecureLabFolderBridge,
        func()error{checks++;return nil})
    if err!=nil {t.Fatal(err)}
    want:=[]string{"preflight","watchdog","snapshot","install","prepared","watchdog","switch","probe","connectivity","prepared","watchdog","commit"}
    if !reflect.DeepEqual(d.calls,want){t.Fatalf("unexpected signed migration order: %v",d.calls)}
    // Each of the TWO signed-proof boundaries now verifies SYSTEM/DNS twice:
    // initial and final immutable-host checks (4 total). The external
    // watchdog itself is independently checked before and after Snapshot.
    if checks!=4 || d.watchdogCount!=3||d.preparedCount!=2{t.Fatalf("expected 4 SYSTEM/DNS checks, 3 watchdog checks, and 2 installed target checks before commit; got %d/%d/%d",checks,d.watchdogCount,d.preparedCount)}
}
func TestSignedLegacyTransactionBlocksBeforeSnapshotWithoutPermissionOrWatchdog(t *testing.T){
    for _,kind:=range []string{"wrong-publisher","unsafe-parent","no-live-dns","missing-watchdog","no-driver"}{
        t.Run(kind,func(t *testing.T){
            f:=newSignedBridge(t)
            d:=newSignedLegacyDriverLab()
            var driver SignedLegacySwitchDriver=d
            acl:=testSecureLabFolderBridge
            preflight:=func()error{return nil}
            switch kind {
            case "wrong-publisher":
                f.sig=[]byte("not a real signature")
            case "unsafe-parent":
                acl=func(string)error{return errors.New("untrusted ACL")}
            case "no-live-dns":
                preflight=func()error{return errors.New("DNS stopped")}
            case "missing-watchdog":
                d.failWatchdogAt=1
            case "no-driver":
                driver=nil
            }
            err:=runSignedLegacyLab(context.Background(),f,driver,acl,preflight)
            if err==nil{t.Fatal("unsigned or unsafe migration accepted")}
            for _,call:=range d.calls {
                if call=="snapshot"||call=="install"||call=="switch"||call=="commit"{
                    t.Fatalf("unsafe operation %s before readiness: %v",call,d.calls)
                }
            }
        })
    }
}
func TestSignedLegacyTransactionFailsClosedOnRecheckAndRestores(t *testing.T){
    for _,kind:=range []string{"candidate-tamper","legacy-tamper","watchdog-down","prepared-copy-invalid"}{
        t.Run(kind,func(t *testing.T){
            f:=newSignedBridge(t)
            d:=newSignedLegacyDriverLab()
            switch kind{
            case "candidate-tamper":d.replaceCandidate=true
            case "legacy-tamper":d.replaceOldMotor=f.live
            case "watchdog-down":d.failWatchdogAt=2
            case "prepared-copy-invalid":d.fail="prepared"
            }
            err:=runSignedLegacyLab(context.Background(),f,d,testSecureLabFolderBridge,func()error{return nil})
            if err==nil || !strings.Contains(err.Error(),"revertida"){
                t.Fatalf("post-snapshot recheck failure not recovered: %v",err)
            }
            for _,call:=range d.calls {
                if call=="switch"||call=="commit" {t.Fatalf("switch/commit after invalid recheck: %v",d.calls)}
            }
            tail:=d.calls[len(d.calls)-3:]
            if !reflect.DeepEqual(tail,[]string{"restore","probe","connectivity"}){
                t.Fatalf("not independently restored and probed: %v",d.calls)
            }
        })
    }
}
func TestSignedLegacyTransactionNeverCommitsAfterSwitchFailure(t *testing.T){
    f:=newSignedBridge(t)
    for _,step:=range []string{"install","prepared","switch","probe","connectivity","commit"}{
        t.Run(step,func(t *testing.T){
            d:=newSignedLegacyDriverLab()
            d.fail=step
            err:=runSignedLegacyLab(context.Background(),f,d,testSecureLabFolderBridge,func()error{return nil})
            if err==nil{t.Fatalf("failure in %s silently accepted",step)}
            seenRestore:=false
            for _,call:=range d.calls{if call=="restore"{seenRestore=true}}
            if !seenRestore{t.Fatalf("rollback not attempted after %s: %v",step,d.calls)}
        })
    }
}
func TestSignedLegacyTransactionRecoverAfterCancellationWithNewContext(t *testing.T){
    f:=newSignedBridge(t)
    ctx,cancel:=context.WithCancel(context.Background())
    defer cancel()
    d:=newSignedLegacyDriverLab()
    d.cancel=cancel
    err:=runSignedLegacyLab(ctx,f,d,testSecureLabFolderBridge,func()error{return nil})
    if err==nil || d.rollbackCancelled {t.Fatalf("independent recovery context missing: %v",err)}
    seen:=false
    for _,call:=range d.calls{if call=="restore"{seen=true}}
    if !seen {t.Fatalf("cancellation bypassed rollback: %v",d.calls)}
}
func TestSignedLegacyTransactionCannotClaimRecoveryIfInternetStillDown(t *testing.T){
    f:=newSignedBridge(t)
    d:=newSignedLegacyDriverLab()
    d.fail="connectivity"
    err:=runSignedLegacyLab(context.Background(),f,d,testSecureLabFolderBridge,func()error{return nil})
    if err==nil || !strings.Contains(err.Error(),"CRÍTICO"){
        t.Fatalf("false recovery with failed Internet probe: %v",err)
    }
}

func TestSignedLegacyTransactionRejectsBackupModifiedImmediatelyAfterSnapshot(t *testing.T){
 for _,kind:=range []string{"binary-corrupt","xml-removed","receipt-corrupt","acl-revoked"}{
  t.Run(kind,func(t *testing.T){
   f:=newSignedBridge(t)
   d:=newSignedLegacyDriverLab()
   aclBroken:=false
   checkACL:=func(path string)error{
    if aclBroken&&path==f.backup{return errors.New("revoked secure snapshot ACL")}
    return nil // Only the synthetic lab is allowed to assume trusted ACL.
   }
   d.afterSnapshot=func()error{
    switch kind{
    case "binary-corrupt":
     return os.WriteFile(filepath.Join(f.backup,legacyBackupExe),[]byte("MZ_CORRUPT_SNAPSHOT"),0600)
    case "xml-removed":
     return os.Remove(filepath.Join(f.backup,legacyBackupXML))
    case "receipt-corrupt":
     return os.WriteFile(filepath.Join(f.backup,legacyBackupReceipt),[]byte("{}"),0600)
    case "acl-revoked":
     aclBroken=true
    }
    return nil
   }
   err:=runSignedLegacyLab(context.Background(),f,d,checkACL,func()error{return nil})
   if err==nil||!strings.Contains(err.Error(),"CRÍTICO")||
    !strings.Contains(err.Error(),"respaldo alterado tras Snapshot"){
    t.Fatalf("corrupted backup after snapshot was not marked critical: %v",err)
   }
   want:=[]string{"preflight","watchdog","snapshot"}
   if !reflect.DeepEqual(d.calls,want){
    t.Fatalf("modified fallback allowed installation or attempted unsafe restore: %v",d.calls)
   }
  })
 }
}

func TestSignedLegacyTransactionRejectsSealedBackupTamperedAfterTargetPreparation(t *testing.T){
 f:=newSignedBridge(t)
 d:=newSignedLegacyDriverLab()
 d.afterInstall=func()error{
  return os.WriteFile(filepath.Join(f.backup,legacyBackupXML),[]byte("XML_CHANGED_AFTER_PREPARATION"),0600)
 }
 err:=runSignedLegacyLab(context.Background(),f,d,testSecureLabFolderBridge,func()error{return nil})
 if err==nil||!strings.Contains(err.Error(),"CRÍTICO")||
  !strings.Contains(err.Error(),"autorización cambió"){
  t.Fatalf("corrupted rollback after installing target not critical: %v",err)
 }
 want:=[]string{"preflight","watchdog","snapshot","install","prepared"}
 if !reflect.DeepEqual(d.calls,want){
  t.Fatalf("corrupted backup allowed unsafe restore, switch or commit: %v",d.calls)
 }
}

func TestSignedLegacyTransactionRestoresIfLiveSYSTEMChangesAtSecondProof(t *testing.T){
 // First publisher proof: two good OS probes. The second proof happens
 // AFTER the durable snapshot and candidate preparation, and must prevent
 // Switch if either its initial or final OS/DNS observation fails.
 for _,failAt:=range []int{3,4}{
  t.Run(fmt.Sprintf("live-preflight-%d",failAt),func(t *testing.T){
   f:=newSignedBridge(t)
   d:=newSignedLegacyDriverLab()
   checks:=0
   err:=runSignedLegacyLab(context.Background(),f,d,
    testSecureLabFolderBridge,func()error{
     checks++
     if checks==failAt {return errors.New("live SYSTEM DNS identity drift")}
     return nil
    })
   if err==nil||!strings.Contains(err.Error(),"revertida")||checks!=failAt {
    t.Fatalf("stale second signed identity proof was not rolled back: checks=%d, err=%v",checks,err)
   }
   for _,call:=range d.calls{
    if call=="switch"||call=="commit"{
     t.Fatalf("untrusted second preflight allowed %s: %v",call,d.calls)
    }
   }
   tail:=d.calls[len(d.calls)-3:]
   if !reflect.DeepEqual(tail,[]string{"restore","probe","connectivity"}){
    t.Fatalf("recovery after changed SYSTEM identity not independently proved: %v",d.calls)
   }
  })
 }
}

func TestSignedLegacyTransactionPostDNSFenceFailsClosed(t *testing.T){
 // No release or SYSTEM changes: ephemeral Ed25519 fixture and fake
 // driver. These mutations occur AFTER successful local and external
 // connectivity tests, just before Commit.
 for _,kind:=range []string{
  "candidate-replaced-after-DNS",
  "sealed-original-replaced-after-DNS",
  "installed-target-changed-after-DNS",
  "independent-watchdog-down-after-DNS",
 }{
  t.Run(kind,func(t *testing.T){
   f:=newSignedBridge(t)
   d:=newSignedLegacyDriverLab()
   switch kind{
   case "candidate-replaced-after-DNS":
    d.afterConnectivity=func()error{return os.WriteFile(f.candidate,[]byte("MZ_CHANGED_AFTER_DNS"),0600)}
   case "sealed-original-replaced-after-DNS":
    d.afterConnectivity=func()error{
     return os.WriteFile(filepath.Join(f.backup,legacyBackupExe),[]byte("MZ_BAD_BACKUP_AFTER_DNS"),0600)
    }
   case "installed-target-changed-after-DNS":d.failPreparedAt=2
   case "independent-watchdog-down-after-DNS":d.failWatchdogAt=3
   }
   err:=runSignedLegacyLab(context.Background(),f,d,testSecureLabFolderBridge,func()error{return nil})
   if err==nil{t.Fatalf("post-DNS failure %q was committed",kind)}
   seenCommit:=false
   restored:=false
   for _,call:=range d.calls{
    if call=="commit"{seenCommit=true}
    if call=="restore"{restored=true}
   }
   if seenCommit{t.Fatalf("invalid post-DNS state committed: %v",d.calls)}
   if kind=="sealed-original-replaced-after-DNS"{
    // A corrupted backup is untrusted even for recovery. Must raise
    // CRITICAL and leave the pending intent to an independent operator.
    if restored||!strings.Contains(err.Error(),"CRÍTICO"){
     t.Fatalf("corrupt original was restored or not reported critical: %v calls=%v",err,d.calls)
    }
   }else {
    if !restored||!strings.Contains(err.Error(),"revertida"){
     t.Fatalf("valid fallback after post-DNS failure not used: %v calls=%v",err,d.calls)
    }
    if len(d.calls)<3||!reflect.DeepEqual(d.calls[len(d.calls)-3:],
      []string{"restore","probe","connectivity"}){
     t.Fatalf("rollback health not confirmed after DNS success: %v",d.calls)
    }
   }
  })
 }
}

func TestSignedLegacyTransactionLastHealthFenceOccursBeforeCommit(t *testing.T){
 f:=newSignedBridge(t)
 d:=newSignedLegacyDriverLab()
 if err:=runSignedLegacyLab(context.Background(),f,d,
  testSecureLabFolderBridge,func()error{return nil});err!=nil{t.Fatal(err)}
 wantSuffix:=[]string{"switch","probe","connectivity","prepared","watchdog","commit"}
 if !reflect.DeepEqual(d.calls[len(d.calls)-len(wantSuffix):],wantSuffix){
  t.Fatalf("signed target and watchdog were not rechecked AFTER DNS and BEFORE Commit: %v",d.calls)
 }
}
