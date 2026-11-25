// Package installerprogress translates independently verified controller outcomes
// into UI state. It neither authenticates a controller nor authorizes a system operation.
package installerprogress

import (
 "context"
 "errors"
 "sync"
)

type Stage string

const (
 Preflight Stage = "preflight"
 PackageVerified Stage = "package_verified"
 BackupVerified Stage = "backup_verified"
 WatchdogVerified Stage = "watchdog_verified"
 MotorVerified Stage = "motor_verified"
 ConnectivityVerified Stage = "connectivity_verified"
 CommitVerified Stage = "commit_verified"
 PostBootVerified Stage = "post_boot_verified"
)

var order = [...]Stage{Preflight, PackageVerified, BackupVerified, WatchdogVerified, MotorVerified, ConnectivityVerified, CommitVerified, PostBootVerified}

// State must not be copied after first use. UI readers and controller events
// share one synchronized state, not independent progress counters.
type State struct {
 mu sync.Mutex
 next int
 status string
 rebootRequested bool
}
type View struct {
 Percent int
 Status string
 Next Stage
 RebootRequired bool
}
func New() *State { return &State{status:"running"} }

// ResumeVerifiedCommit reconstructs ONLY the UI state after a durable commit.
// The trusted controller must independently verify its authenticated journal
// and current transaction identity. This package does not read a UI-supplied
// checkpoint, trust a stored percentage, authenticate the callback or grant
// any permission. A success is still only 87%, pending post-boot proof.
// A failed verification yields no resumable state.
func ResumeVerifiedCommit(ctx context.Context, verifyCommit func(context.Context) error) (*State,error) {
 if ctx==nil || verifyCommit==nil {return nil,errors.New("verified commit reader required")}
 if err:=ctx.Err();err!=nil{return nil,err}
 if err:=verifyCommit(ctx);err!=nil{return nil,err}
 if err:=ctx.Err();err!=nil{return nil,err}
 return &State{next:len(order)-1,status:"awaiting_reboot"},nil
}

// ResumePostBootVerification allows the UI to resume verification after a
// restart that the authenticated controller has independently observed.
// This is NOT confirmation of healthy protection. It only records the
// pending post-boot check; a failed health check must still enter recovery.
func (s *State) ResumePostBootVerification(ctx context.Context, verifyRestart func(context.Context) error) error {
 if ctx==nil || verifyRestart==nil{return errors.New("verified restart reader required")}
 if err:=ctx.Err();err!=nil{return err}
 // Do not hold the UI mutex across I/O or a controller callback.
 s.mu.Lock()
 eligible:=s.status=="awaiting_reboot" && !s.rebootRequested && s.next==len(order)-1
 s.mu.Unlock()
 if !eligible{return errors.New("restart observation not expected")}
 if err:=verifyRestart(ctx);err!=nil{return err}
 s.mu.Lock()
 defer s.mu.Unlock()
 if err:=ctx.Err();err!=nil{return err}
 if s.status!="awaiting_reboot" || s.rebootRequested || s.next!=len(order)-1{return errors.New("restart observation invalidated during verification")}
 s.rebootRequested=true
 return nil
}

// Confirm is called only by the future authenticated controller adapter
// after a successful independent check. The last stage is deliberately
// unavailable here: a durable activation receipt is NOT a post-boot proof.
func (s *State) Confirm(stage Stage) error {
 s.mu.Lock()
 defer s.mu.Unlock()
 if s.status != "running" || s.next >= len(order)-1 || order[s.next] != stage {
  return errors.New("unexpected stage or terminal state")
 }
 s.next++
 if s.next == len(order)-1 { s.status="awaiting_reboot" }
 return nil
}

// RequireReboot records a request after durable commit, not completion.
// The independent controller must actually initiate/observe the restart.
func (s *State) RequireReboot() error {
 s.mu.Lock()
 defer s.mu.Unlock()
 if s.status != "awaiting_reboot" || s.rebootRequested {
  return errors.New("unexpected or duplicate reboot request")
 }
 s.rebootRequested=true
 return nil
}

// ConfirmReboot requires a controller-supplied verification operation
// that authenticates a new boot and verifies the durable receipt, live
// protection and independent recovery. This package is a UI state machine,
// NOT the authenticating controller. An acknowledgment alone is insufficient.
// The callback runs outside the mutex and may report a recovery requirement.
func (s *State) ConfirmReboot(ctx context.Context, verifyHealth func(context.Context) error) error {
 if ctx==nil || verifyHealth==nil{return errors.New("verified post-boot health reader required")}
 if err:=ctx.Err();err!=nil{return err}
 s.mu.Lock()
 eligible:=s.status=="awaiting_reboot" && s.rebootRequested && s.next==len(order)-1
 s.mu.Unlock()
 if !eligible{return errors.New("post-boot confirmation not expected")}
 if err:=verifyHealth(ctx);err!=nil{return err}
 s.mu.Lock()
 defer s.mu.Unlock()
 if err:=ctx.Err();err!=nil{return err}
 if s.status!="awaiting_reboot" || !s.rebootRequested || s.next!=len(order)-1 {
  return errors.New("post-boot confirmation invalidated during verification")
 }
 s.next++
 s.status="completed"
 s.rebootRequested=false
 return nil
}

// Failure after a durable commit but before post-boot verification is
// still a recovery-required state. Never report protection installed.
func (s *State) Fail() error {
 s.mu.Lock()
 defer s.mu.Unlock()
 if s.status != "running" && s.status != "awaiting_reboot" {
  return errors.New("unexpected failure transition")
 }
 s.rebootRequested=false
 if s.next>=3 { s.status="recovery_required" } else { s.status="failed_before_activation" }
 return nil
}
func (s *State) ConfirmRecovery() error {
 s.mu.Lock()
 defer s.mu.Unlock()
 if s.status != "recovery_required" { return errors.New("no pending recovery") }
 s.status="recovered_not_installed"
 return nil
}
func (s *State) RecoveryFailed() error {
 s.mu.Lock()
 defer s.mu.Unlock()
 if s.status != "recovery_required" { return errors.New("no pending recovery") }
 s.status="recovery_failed"
 return nil
}
func (s *State) View() View {
 s.mu.Lock()
 defer s.mu.Unlock()
 v:=View{Percent:s.next*100/len(order),Status:s.status,RebootRequired:s.status=="awaiting_reboot"}
 if s.status=="running" || s.status=="awaiting_reboot" { v.Next=order[s.next] }
 return v
}
