// Package installerprogress translates verified controller outcomes into UI state.
// It does not authenticate a controller or authorize any system operation.
package installerprogress

import "errors"

type Stage string
const (
 Preflight Stage = "preflight"
 PackageVerified Stage = "package_verified"
 BackupVerified Stage = "backup_verified"
 WatchdogVerified Stage = "watchdog_verified"
 MotorVerified Stage = "motor_verified"
 ConnectivityVerified Stage = "connectivity_verified"
 CommitVerified Stage = "commit_verified"
)
var order = [...]Stage{Preflight, PackageVerified, BackupVerified, WatchdogVerified, MotorVerified, ConnectivityVerified, CommitVerified}
type State struct { next int; status string; pendingReboot bool }
type View struct { Percent int; Status string; Next Stage; RebootRequired bool }
func New() *State { return &State{status:"running"} }
// Confirm is called only by the future authenticated controller adapter after
// a successful independent check, not from installer UI or arbitrary JSON.
func (s *State) Confirm(stage Stage) error {
 if s.status != "running" || s.pendingReboot || s.next >= len(order) || order[s.next] != stage { return errors.New("unexpected stage or terminal state") }
 s.next++
 if s.next == len(order) { s.status="completed" }
 return nil
}
// RequireReboot is only applicable after the motor is independently verified.
func (s *State) RequireReboot() error {
 if s.status != "running" || s.pendingReboot || s.next != 5 { return errors.New("unexpected reboot request") }
 s.pendingReboot=true; return nil
}
// ConfirmReboot does not perform or prove reboot; caller must verify evidence.
func (s *State) ConfirmReboot() error {
 if s.status != "running" || !s.pendingReboot { return errors.New("no pending reboot") }
 s.pendingReboot=false; return nil
}
// Fail stops forward progress. Once backup is verified, retain a distinct
// recovery-required state; the UI must not say protection was installed.
func (s *State) Fail() error {
 if s.status != "running" { return errors.New("unexpected failure transition") }
 s.pendingReboot=false
 if s.next>=3 { s.status="recovery_required" } else { s.status="failed_before_activation" }
 return nil
}
func (s *State) ConfirmRecovery() error {
 if s.status != "recovery_required" { return errors.New("no pending recovery") }
 s.status="recovered_not_installed"; return nil
}
func (s *State) RecoveryFailed() error {
 if s.status != "recovery_required" { return errors.New("no pending recovery") }
 s.status="recovery_failed"; return nil
}
func (s *State) View() View {
 v:=View{Percent:s.next*100/len(order), Status:s.status, RebootRequired:s.pendingReboot}
 if s.status=="running" && s.next<len(order) { v.Next=order[s.next] }
 return v
}
