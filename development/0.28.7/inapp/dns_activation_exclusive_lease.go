package motorupdate

// The future privileged installer and the independent SYSTEM boot watchdog
// MUST contend on the SAME protected Windows kernel mutex. Recovery must
// receive that mutex, not deadlock behind the installation coordinator.
//
// This file provides the portable choreography only. The production Windows
// acquirer is AcquireProtectedResidentTransitionLease, never a process mutex.
// No public installer command calls this implementation yet.
import (
 "context"
 "errors"
 "fmt"
 "sync"
)

type dnsActivationLeaseAcquirer func(context.Context)(func(),error)
type dnsActivationBackendFactory func(context.Context,DNSActivationSafetyGuard)(DNSAdapterBackend,error)

type exclusiveDNSActivationGuard struct {
 mu sync.Mutex
 inner DNSActivationSafetyGuard
 acquire dnsActivationLeaseAcquirer
 release func()
}

func(g *exclusiveDNSActivationGuard)VerifyArmed(ctx context.Context,pin string)error{
 g.mu.Lock()
 defer g.mu.Unlock()
 if g.release==nil{return errors.New("DNS activation guard missing protected system lease")}
 return g.inner.VerifyArmed(ctx,pin)
}
func(g *exclusiveDNSActivationGuard)VerifyLiveProtection(ctx context.Context,pin string)error{
 g.mu.Lock()
 defer g.mu.Unlock()
 if g.release==nil{return errors.New("cannot probe active DNS without protected system lease")}
 return g.inner.VerifyLiveProtection(ctx,pin)
}
func(g *exclusiveDNSActivationGuard)CommitActive(ctx context.Context,pin string)error{
 g.mu.Lock()
 defer g.mu.Unlock()
 if g.release==nil{return errors.New("cannot commit active DNS outside protected system lease")}
 return g.inner.CommitActive(ctx,pin)
}

// RecoverIndependently yields the kernel mutex to ANOTHER SYSTEM process.
// It reacquires the same named mutex before the coordinator independently
// rereads the restored original DNS. If reacquisition is impossible, the
// transaction MUST remain a critical unresolved recovery (never success).
func(g *exclusiveDNSActivationGuard)RecoverIndependently(ctx context.Context,pin string)error{
 g.mu.Lock()
 defer g.mu.Unlock()
 if g.release==nil{return errors.New("no protected DNS lease to hand off")}
 release:=g.release
 g.release=nil
 release()
 recoveryErr:=g.inner.RecoverIndependently(ctx,pin)
 // The caller supplies a fresh, bounded recovery context even when the
 // installation context is cancelled. Use the same deadline for reacquire.
 reacquired,err:=g.acquire(ctx)
 if err!=nil{
  if reacquired!=nil{reacquired()}
  return errors.Join(recoveryErr,fmt.Errorf("CRITICAL: cannot reacquire protected Windows lease after independent DNS recovery: %w",err))
 }
 if reacquired==nil{
  return errors.Join(recoveryErr,errors.New("CRITICAL: independent recovery returned without protected kernel lease"))
 }
 if err:=ctx.Err();err!=nil{
  reacquired()
  return errors.Join(recoveryErr,fmt.Errorf("CRITICAL: recovery context expired while reacquiring protected Windows lease: %w",err))
 }
 g.release=reacquired
 return recoveryErr
}
func(g *exclusiveDNSActivationGuard)close(){
 g.mu.Lock()
 defer g.mu.Unlock()
 if g.release!=nil{release:=g.release;g.release=nil;release()}
}

// activateVOLVEDNSUnderProtectedLease coordinates native SYSTEM exclusion,
// construction of a journal-pinned backend, the complete dual-stack switch,
// and independent SYSTEM recovery. The factory must not invoke a DNS writer
// during setup; the coordinator verifies original state first.
func activateVOLVEDNSUnderProtectedLease(
 ctx context.Context, originalJournal []byte, independentSHA256 string,
 guard DNSActivationSafetyGuard, acquire dnsActivationLeaseAcquirer,
 backendFactory dnsActivationBackendFactory,
)error{
 if ctx==nil||guard==nil||acquire==nil||backendFactory==nil{
  return errors.New("protected DNS activation requires SYSTEM lease, verified guard and native backend")
 }
 if err:=ctx.Err();err!=nil{return err}
 release,err:=acquire(ctx)
 if err!=nil{
  if release!=nil{release()}
  return fmt.Errorf("protected resident SYSTEM mutex unavailable: %w",err)
 }
 if release==nil{return errors.New("protected resident mutex yielded no owner release")}
 guarded:=&exclusiveDNSActivationGuard{inner:guard,acquire:acquire,release:release}
 defer guarded.close()
 // The backend factory can consume a one-use signed authorization.
 // Cancellation while acquiring the native mutex must not reach it.
 if err:=ctx.Err();err!=nil{return err}
 backend,err:=backendFactory(ctx,guarded)
 if err!=nil{return fmt.Errorf("protected native DNS adapter refused: %w",err)}
 if backend==nil{return errors.New("protected native DNS adapter absent")}
 return activateVOLVEDNSWithRecovery(ctx,originalJournal,independentSHA256,backend,guarded)
}
