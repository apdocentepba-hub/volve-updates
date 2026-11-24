// Package installerprogress translates independently verified controller outcomes
// into UI state. It neither authenticates a controller nor authorizes a system operation.
package installerprogress

import (
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

// ConfirmReboot must be called only after authenticating a new boot and
// verifying the durable receipt, live protection and independent recovery.
// An acknowledgment, a timeout, or a successful pre-boot probe is insufficient.
func (s *State) ConfirmReboot() error {
 s.mu.Lock()
 defer s.mu.Unlock()
 if s.status != "awaiting_reboot" || !s.rebootRequested || s.next != len(order)-1 {
  return errors.New("post-boot confirmation not expected")
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
