//go:build windows

package motorupdate

// Authorization boundary for the EXPERIMENTAL Windows DNS restore path.
// This package does not authenticate SYSTEM, the publisher or journal ACLs
// itself. It holds only a disposable CI interprocess mutex, NOT a
// production-authorized mutex. A production attestor is NOT implemented and
// no installed product calls this function. Without one it fails closed.
import (
  "context"
  "errors"
  "fmt"
)

// WindowsDNSRecoveryAttestor must independently verify BOTH immutable
// recovery journal + original adapter provenance AND the current Windows
// SYSTEM/lock/failed-motor preconditions at every operation. An attestor
// must bind records to a sealed, authenticated journal and must be
// implemented in a privileged, signed caller; never accept UI booleans.
type WindowsDNSRecoveryAttestor interface {
  Verify(context.Context, []DNSRestoreRecord) error
}

func cloneWindowsDNSRecoveryRecords(records []DNSRestoreRecord) []DNSRestoreRecord {
  out:=make([]DNSRestoreRecord,len(records))
  for i,r:=range records {
    r.Original.Servers=append([]string(nil),r.Original.Servers...)
    r.Expected.Servers=append([]string(nil),r.Expected.Servers...)
    out[i]=r
  }
  return out
}

// runAttestedWindowsStaticDNSRecovery enforces the independent attestor
// before touching live DNS, after pinning adapter identities, before EACH
// possible write, and after the full dual-stack recovery. The attestor is
// injectable only for lab tests; no default production implementation exists.
// If anything fails, the protected recovery journal MUST stay pending.
func runAttestedWindowsStaticDNSRecovery(
  ctx context.Context,
  records []DNSRestoreRecord,
  inspect WindowsReadOnlyPowerShell,
  attestor WindowsDNSRecoveryAttestor,
  invoke WindowsDNSNativeInvoke,
  disposableLabLockName string,
) error {
  if len(records)==0||inspect==nil||attestor==nil||invoke==nil{
    return errors.New("protected DNS recovery has no attested journal, inspector or invoker")
  }
  if err:=ctx.Err();err!=nil{return err}
  // This lab-only namespace cannot be confused with a production motor.
  // The OS-wide mutex is held across attestation, adapter pinning, every
  // IPv4/IPv6 write, independent postchecks, and the final authorization.
  release,err:=acquireWindowsDNSLabRecoveryLease(ctx,disposableLabLockName)
  if err!=nil{return fmt.Errorf("exclusive DNS recovery lease unavailable: %w",err)}
  defer release()
  snapshot:=cloneWindowsDNSRecoveryRecords(records)
  verify:=func(stage string)error{
    if err:=ctx.Err();err!=nil{return err}
    if err:=attestor.Verify(ctx,cloneWindowsDNSRecoveryRecords(snapshot));err!=nil{
      return fmt.Errorf("independent DNS recovery authorization expired at %s: %w",stage,err)
    }
    return nil
  }
  if err:=verify("preflight");err!=nil{return err}
  writer,err:=NewWindowsPinnedStaticDNSWriter(ctx,snapshot,inspect,
    func(ctx context.Context,args []string)error{
      if err:=verify("before write");err!=nil{return err}
      if err:=validatePinnedWindowsDNSArgv(args);err!=nil{return err}
      if err:=invoke(ctx,args);err!=nil{return err}
      return verify("after write")
    })
  if err!=nil{return err}
  if err:=verify("after adapter pinning");err!=nil{return err}
  if err:=ExecuteWindowsStaticDNSRestoreBatch(ctx,snapshot,inspect,writer);err!=nil{return err}
  return verify("after dual-stack recovery")
}

// An explicit native-mutation entrypoint is purposefully NOT exported.
// Only a future sealed-journal SYSTEM controller can supply the OS attestor.
// The native command adapter itself is read-only when called externally.
