// VOLVÉ 0.28.7 development-only source overlay tool. NOT part of the app.
package main

import (
    "fmt"
    "go/format"
    "os"
    "path/filepath"
    "strings"
)

func patch(path, old, replacement string) error {
    raw, err := os.ReadFile(path)
    if err != nil { return err }
    src := string(raw)
    if strings.Count(src, old) != 1 {
        return fmt.Errorf("refusing to modify %s: expected exactly one insertion marker, got %d", path, strings.Count(src, old))
    }
    src = strings.Replace(src, old, replacement, 1)
    out, err := format.Source([]byte(src))
    if err != nil { return fmt.Errorf("format %s: %w", path, err) }
    return os.WriteFile(path, out, 0600)
}

func main() {
    if len(os.Args) != 2 { panic("usage: go run apply_overlay.go <source-code-dir>") }
    target := os.Args[1]
    if !filepath.IsAbs(target) {
        abs, err := filepath.Abs(target); if err != nil { panic(err) }
        target = abs
    }
    if _, err := os.Stat(filepath.Join(target, "main_windows.go")); err != nil { panic(err) }
    if _, err := os.Stat(filepath.Join(target, "panel_windows.go")); err != nil { panic(err) }
    srcDir := "development/0.28.7/inapp"
    for _, name := range []string{"inapp_motor_update_windows.go", "inapp_motor_update_windows_test.go", "managed_windows_task_lab_test.go", "native_task_switch_windows.go", "independent_watchdog_windows_test.go", "watchdog_system_lab_windows_test.go", "ci_hardened_recovery_windows_test.go", "legacy_upgrade_readiness_windows.go", "legacy_upgrade_readiness_windows_test.go", "complete_binary_action_recovery_windows_test.go", "motor_dns_isolated_probe_windows.go", "motor_dns_isolated_probe_windows_test.go"} {
        data, err := os.ReadFile(filepath.Join(srcDir, name)); if err != nil { panic(err) }
        formatted, err := format.Source(data); if err != nil { panic(err) }
        if err := os.WriteFile(filepath.Join(target, name), formatted, 0600); err != nil { panic(err) }
    }
    for _, name := range []string{"managed_transaction.go", "managed_transaction_test.go", "verified_inventory.go", "verified_inventory_test.go", "internet_proof.go", "internet_proof_test.go", "legacy_motor_attestation.go", "legacy_motor_attestation_test.go"} {
        data, err := os.ReadFile(filepath.Join(srcDir, name)); if err != nil { panic(err) }
        formatted, err := format.Source(data); if err != nil { panic(err) }
        if err := os.WriteFile(filepath.Join(target, "motorupdate", name), formatted, 0600); err != nil { panic(err) }
    }
    watchdogTarget := filepath.Join(target, "cmd", "volve-managed-watchdog")
    if err := os.MkdirAll(watchdogTarget, 0700); err != nil { panic(err) }
    for _, name := range []string{"main_windows.go", "main_windows_test.go", "recovery_acl_windows.go", "recovery_acl_windows_test.go", "programdata_lab_windows_test.go"} {
        data, err := os.ReadFile(filepath.Join(srcDir, "watchdogcmd", name)); if err != nil { panic(err) }
        formatted, err := format.Source(data); if err != nil { panic(err) }
        if err := os.WriteFile(filepath.Join(watchdogTarget, name), formatted, 0600); err != nil { panic(err) }
    }
    const oldMain = "if len(os.Args) == 2 && os.Args[1] == \"--check-app-updates\" {"
    const newMain = `if len(os.Args) == 2 && os.Args[1] == "--motor-dns-isolated-loopback" {
        result, err := runMotorDNSIsolatedLoopbackProof()
        if err != nil {
            fmt.Println("VOLVE_DNS_ISOLATED_LOOPBACK_FAILED:", err)
            os.Exit(1)
        }
        fmt.Println(result)
        return
    }
    if len(os.Args) == 3 && os.Args[1] == "--motor-upgrade-evidence" {
        if err := runMotorUpgradeEvidenceCLI(os.Args[2]); err != nil {
            fmt.Println("MOTOR DNS: identidad no verificable; NO se modificó el equipo:", err)
            os.Exit(1)
        }
        return
    }
    if len(os.Args) == 2 && os.Args[1] == "--check-all-updates" {
        result, err := checkAllUpdates()
        if err != nil {
            fmt.Println("ACTUALIZACIÓN NO REALIZADA:", err)
            os.Exit(1)
        }
        fmt.Println(result)
        return
    }
    ` + oldMain
    if err := patch(filepath.Join(target, "main_windows.go"), oldMain, newMain); err != nil { panic(err) }
    const oldPanel = `result := panelToolBounded("--check-app-updates", 120*time.Second)`
    const newPanel = `result := panelToolBounded("--check-all-updates", 120*time.Second)`
    if err := patch(filepath.Join(target, "panel_windows.go"), oldPanel, newPanel); err != nil { panic(err) }
    const oldNote = "No se modifica el DNS ni se reemplaza el motor residente."
    const newNote = "Consulta el Centro y prepara actualizaciones firmadas del motor sin reemplazar el DNS activo."
    // Replace explanatory UI text only; never alter existing release signature verification.
    if err := patch(filepath.Join(target, "panel_windows.go"), oldNote, newNote); err != nil { panic(err) }
    fmt.Println("PASS: unified signed panel + motor staging is wired into the installed update button; DNS tasks untouched.")
}
