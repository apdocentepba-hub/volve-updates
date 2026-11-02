//go:build windows

package motorupdate

// Production Windows mutex adapter for the publisher-authorized legacy DNS
// transition. It does not install, switch, stop, restart or restore the actual
// motor: independently verified SYSTEM drivers must supply those operations.
import (
 "context"
 "errors"
 "fmt"
 "sync"
)

// ProtectedSignedRecoveryHandoff is mandatory for a production signed
// migration driver. The caller MUST have already persisted a pending,
// publisher-authorized recovery journal and armed an independent SYSTEM
// watchdog before invoking the handoff. The operation starts and waits for
// recovery WITHOUT trying to reacquire the mutex: the wrapping coordinator
// releases it just before calling, and reacquires it before any health probe.
type ProtectedSignedRecoveryHandoff interface {
 RestoreAfterProtectedHandoff(context.Context) error
}

type protectedSignedLegacyDriver struct {
 SignedLegacySwitchDriver
 handoff ProtectedSignedRecoveryHandoff

 // The Go lock serializes wrapper calls and finalizers; the named Windows
 // kernel mutex is the actual cross-process exclusion mechanism.
 stateMu sync.Mutex
 currentRelease func()
 leaseSerial uint64
}

// NewProtectedSignedLegacySwitchDriver makes the signed transition use the
// same SYSTEM/Admin-only OS kernel mutex as the independent boot watchdog.
// The wrapper does not authorize productive installation or motor changes.
func NewProtectedSignedLegacySwitchDriver(operations SignedLegacySwitchDriver)(SignedLegacySwitchDriver,error){
 if operations==nil{return nil,errors.New("missing trusted signed migration operations")}
 handoff,ok:=operations.(ProtectedSignedRecoveryHandoff)
 if !ok||handoff==nil{
  return nil,errors.New("signed migration driver lacks independent protected watchdog handoff")
 }
 return &protectedSignedLegacyDriver{SignedLegacySwitchDriver:operations,handoff:handoff},nil
}

func(d *protectedSignedLegacyDriver)AcquireExclusiveMigration(ctx context.Context)(func(),error){
 if d==nil||d.SignedLegacySwitchDriver==nil||d.handoff==nil{
  return nil,errors.New("missing protected signed migration adapter")
 }
 d.stateMu.Lock()
 defer d.stateMu.Unlock()
 if d.currentRelease!=nil{return nil,errors.New("signed migration already owns protected system mutex")}
 if err:=ctx.Err();err!=nil{return nil,err}
 release,err:=AcquireProtectedResidentTransitionLease(ctx)
 if err!=nil{return nil,err}
 if release==nil{return nil,errors.New("protected system mutex supplied no release callback")}
 d.leaseSerial++
 serial:=d.leaseSerial
 d.currentRelease=release
 // The finalizer may outlive the transaction: an old finalizer must NEVER
 // release the mutex acquired by a later independent transaction.
 return func(){
  d.stateMu.Lock()
  defer d.stateMu.Unlock()
  if d.leaseSerial!=serial{return}
  if d.currentRelease!=nil{
   d.currentRelease()
   d.currentRelease=nil
  }
 },nil
}

// withProtectedLease holds the local state mutex for the entire delegate
// operation, preventing a concurrent finalizer or rollback handoff from
// releasing the named system mutex in the middle of a write or health probe.
// Embedded driver methods must NOT bypass this gate.
func(d *protectedSignedLegacyDriver)withProtectedLease(ctx context.Context,action func()error)error{
 if d==nil||d.SignedLegacySwitchDriver==nil{return errors.New("missing protected signed migration adapter")}
 d.stateMu.Lock()
 defer d.stateMu.Unlock()
 if d.currentRelease==nil{return errors.New("signed migration operation refused without protected system mutex")}
 if err:=ctx.Err();err!=nil{return err}
 return action()
}

func(d *protectedSignedLegacyDriver)Preflight(ctx context.Context,manifest Manifest)error{
 return d.withProtectedLease(ctx,func()error{return d.SignedLegacySwitchDriver.Preflight(ctx,manifest)})
}
func(d *protectedSignedLegacyDriver)IndependentRecoveryReady(ctx context.Context,proof VerifiedLegacyMigrationProof)error{
 return d.withProtectedLease(ctx,func()error{return d.SignedLegacySwitchDriver.IndependentRecoveryReady(ctx,proof)})
}
func(d *protectedSignedLegacyDriver)Snapshot(ctx context.Context)error{
 return d.withProtectedLease(ctx,func()error{return d.SignedLegacySwitchDriver.Snapshot(ctx)})
}
func(d *protectedSignedLegacyDriver)InstallVersionedCandidate(ctx context.Context,candidate string)error{
 return d.withProtectedLease(ctx,func()error{return d.SignedLegacySwitchDriver.InstallVersionedCandidate(ctx,candidate)})
}
func(d *protectedSignedLegacyDriver)VerifyPreparedTarget(ctx context.Context,manifest Manifest)error{
 return d.withProtectedLease(ctx,func()error{return d.SignedLegacySwitchDriver.VerifyPreparedTarget(ctx,manifest)})
}
func(d *protectedSignedLegacyDriver)Switch(ctx context.Context)error{
 return d.withProtectedLease(ctx,func()error{return d.SignedLegacySwitchDriver.Switch(ctx)})
}
func(d *protectedSignedLegacyDriver)Commit(ctx context.Context,manifest Manifest)error{
 return d.withProtectedLease(ctx,func()error{return d.SignedLegacySwitchDriver.Commit(ctx,manifest)})
}

// Restore hands off the OS mutex to a DIFFERENT SYSTEM watchdog process.
// Hold the local state mutex through the handoff to prevent a second updater
// call from racing with the unprotected recovery interval. Even when the
// watchdog fails, reacquire the exact OS mutex before any health checks.
func(d *protectedSignedLegacyDriver)Restore(ctx context.Context)error{
 if d==nil||d.handoff==nil{return errors.New("missing trusted SYSTEM recovery handoff")}
 d.stateMu.Lock()
 defer d.stateMu.Unlock()
 if d.currentRelease==nil{return errors.New("cannot hand off recovery without protected transition mutex")}
 release:=d.currentRelease
 d.currentRelease=nil
 release()
 recoverErr:=d.handoff.RestoreAfterProtectedHandoff(ctx)
 nextRelease,lockErr:=AcquireProtectedResidentTransitionLease(ctx)
 if lockErr!=nil{
  return errors.Join(recoverErr,fmt.Errorf("CRÍTICO: exclusive mutex could not be reacquired after watchdog: %w",lockErr))
 }
 if nextRelease==nil{
  return errors.Join(recoverErr,errors.New("CRÍTICO: watchdog completed without a protected verification lease"))
 }
 d.currentRelease=nextRelease
 return recoverErr
}

func(d *protectedSignedLegacyDriver)Probe(ctx context.Context)error{
 return d.withProtectedLease(ctx,func()error{return d.SignedLegacySwitchDriver.Probe(ctx)})
}
func(d *protectedSignedLegacyDriver)ProbeConnectivity(ctx context.Context)error{
 return d.withProtectedLease(ctx,func()error{return d.SignedLegacySwitchDriver.ProbeConnectivity(ctx)})
}
