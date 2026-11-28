//go:build windows

package hostroutebridge

// A transaction-bound, still NON-AUTHORIZING Windows preinstallation review.
// Both updater and independent SYSTEM recovery share this exact native Windows
// kernel mutex. The check is repeated WHILE HOLDING the mutex, so it cannot
// accidentally rely on a stale unlocked route from the GUI preview.
//
// This is not a release grant, installation API, or recovery controller.
// No task, DNS, firewall, browser or installed component is modified here.
import (
 "context"
 "crypto/ed25519"
 "errors"
 "fmt"

 motorupdate "volve-browser-protection/motorupdate"
)

// acquireReviewLease never returns a partially acquired mutex to the caller.
// It preserves the native owner-thread release contract and refuses a
// successful acquisition that races with context cancellation.
func acquireReviewLease(ctx context.Context, acquire func(context.Context)(func(),error)) (func(),error) {
 if ctx==nil||acquire==nil{return nil,errors.New("review lease requires context and acquisition callback")}
 if err:=ctx.Err();err!=nil{return nil,err}
 release,err:=acquire(ctx)
 if err!=nil {
  if release!=nil{release()}
  return nil,err
 }
 if release==nil{return nil,errors.New("native transition lease did not provide a release callback")}
 if err:=ctx.Err();err!=nil{release();return nil,err}
 return release,nil
}

// InspectAndPlanUnderProtectedLeaseReadOnly is the precursor to a future
// privileged transaction: acquire the real protected OS-wide mutex and
// perform the full dual-signed package and six-inventory Windows inspection
// entirely under that lock. NEVER treat the plan as permission to install.
//
// Release uses the Windows owner-thread-safe callback from motorupdate.
// Failure leaves NO positive partial review or plan for another caller.
func InspectAndPlanUnderProtectedLeaseReadOnly(
 ctx context.Context,
 signedEXE string,
 publisherPublicKey ed25519.PublicKey,
 windowsSignerCertSHA256 string,
 signedEXESHA256 string,
 installedRoot string,
 readers motorupdate.WindowsMotorRouteInspectors,
) (Review,InstallerPlanReadOnly,error) {
 var zeroReview Review
 var zeroPlan InstallerPlanReadOnly
 if ctx==nil{return zeroReview,zeroPlan,errors.New("protected host review needs a context")}
 if err:=ctx.Err();err!=nil{return zeroReview,zeroPlan,err}
 release,err:=acquireReviewLease(ctx,motorupdate.AcquireProtectedResidentTransitionLease)
 if err!=nil{return zeroReview,zeroPlan,fmt.Errorf("cannot obtain privileged SYSTEM/updater transition lease: %w",err)}
 defer release()
 review,plan,err:=InspectAndPlanWindowsHostReadOnly(
  ctx,signedEXE,publisherPublicKey,windowsSignerCertSHA256,
  signedEXESHA256,installedRoot,readers,
 )
 if err!=nil{return zeroReview,zeroPlan,err}
 if review.InstallAuthorized||review.UpgradeAuthorized||review.CanModifyDNS||
  plan.CanInstall||plan.CanUpgrade||plan.CanChangeDNS||plan.CanChangeTasks||
  plan.Disposition!="READ_ONLY_PLAN_NOT_AN_INSTALLATION_PERMIT"{
  return zeroReview,zeroPlan,errors.New("protected Windows preflight unexpectedly authorized mutation")
 }
 if err:=ctx.Err();err!=nil{return zeroReview,zeroPlan,err}
 return review,plan,nil
}
