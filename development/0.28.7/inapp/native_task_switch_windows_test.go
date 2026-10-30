//go:build windows

package main

import (
    "context"
    "strings"
    "testing"
)

// This regression guard is deliberately independent of admin privileges,
// Task Scheduler, network connectivity and file presence. It must reject a
// production switch BEFORE any potentially mutating Windows operation.
// Remove only after the production recovery driver and real-reboot proof have
// both been independently validated and the release gate has been approved.
func TestProductionMotorTaskSwitchRemainsFailClosed(t *testing.T) {
    if !ownedMotorTaskName(dnsServiceTask) {
        t.Fatal("production task identity unexpectedly changed; review gate")
    }
    err := switchVerifiedMotorTaskAction(
        context.Background(), dnsServiceTask,
        `C:\\VOLVE\\VOLVE_DNS_Server_0270.exe`, "--dns-service",
        `C:\\VOLVE\\new\\VOLVE_DNS_Motor.exe`, "--dns-service", nil,
    )
    if err == nil || !strings.Contains(err.Error(), "bloqueado") {
        t.Fatalf("production switch must be blocked before watchdog approval: %v", err)
    }
}

func TestUnknownMotorTaskIsAlwaysRejected(t *testing.T) {
    err := switchVerifiedMotorTaskAction(
        context.Background(), "OTHER-SYSTEM-TASK",
        `C:\\VOLVE\\old.exe`, "", `C:\\VOLVE\\new.exe`, "", nil,
    )
    if err == nil || !strings.Contains(err.Error(), "fuera de lista") {
        t.Fatalf("unowned task must be rejected without side effects: %v", err)
    }
}
