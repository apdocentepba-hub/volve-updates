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

// Preserve the production --dns-service behavior, fixed port 53 and live
// installation root. Move the SAME dual-stack runner into an injected helper
// which CI exercises ONLY with ephemeral loopback ports and temp catalogs.
// Fail closed if the source function shape is not the expected version.
func patchResidentDNSEntry(path string) error {
    raw,err:=os.ReadFile(path)
    if err!=nil{return err}
    src:=string(raw)
    begin:="func runDNSService() error {"
    next:="func checkDNSLocal() error {"
    if strings.Count(src,begin)!=1 || strings.Count(src,next)!=1 {
        return fmt.Errorf("resident DNS service source shape not recognized")
    }
    start:=strings.Index(src,begin)
    end:=strings.Index(src,next)
    if end<=start{return fmt.Errorf("resident DNS service is out of order")}
    old:=src[start:end]
    for _,required:=range []string{
        "engine, e := fullEngine()",
        "sv4.Run(ctx, \"127.0.0.1\", 53)",
        "sv6.Run(ctx, \"::1\", 53)",
        "sv4.SwapRules(updated)",
        "sv6.SwapRules(updated)",
        "last := feedSignature()",
    } {
        if !strings.Contains(old,required) {
            return fmt.Errorf("resident DNS service changed: missing %q",required)
        }
    }
    replacement:=`func runDNSService() error {
        root,err:=installRoot()
        if err!=nil{return err}
        return runDNSServiceAt(context.Background(),root,53,
            []string{"1.1.1.1:53","9.9.9.9:53"},nil)
    }

    `
    updated,err:=format.Source([]byte(src[:start]+replacement+src[end:]))
    if err!=nil{return fmt.Errorf("invalid service runner refactor: %w",err)}
    return os.WriteFile(path,updated,0600)
}

// The pinned base DNS proxy previously closed its TCP connection after
// exactly one query. Reuse must preserve all existing filtering and failure
// behavior. Reject any drift in the original handler before modifying it.
func patchDNSPersistentTCP(path string) error {
    const original = `				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(12 * time.Second))
				var length [2]byte
				if _, e := io.ReadFull(c, length[:]); e != nil {
					return
				}
				n := int(binary.BigEndian.Uint16(length[:]))
				if n < 12 || n > 65500 {
					return
				}
				q := make([]byte, n)
				if _, e := io.ReadFull(c, q); e != nil {
					return
				}
				ans, e := s.handle(q)
				if e != nil {
					ans = SERVFAIL(q)
				}
				if len(ans) < 12 {
					return
				}
				binary.BigEndian.PutUint16(length[:], uint16(len(ans)))
				_, _ = c.Write(length[:])
				_, _ = c.Write(ans)`
    const replacement = `				defer c.Close()
				// A TCP DNS connection can carry multiple framed queries.
				// Keep the original per-frame timeout and bound total lifetime
				// and query count. Closing on cancellation unblocks idle reads.
				stopClose := context.AfterFunc(ctx, func() { _ = c.Close() })
				defer stopClose()
				expires := time.Now().Add(2 * time.Minute)
				for served := 0; served < 128; served++ {
					if ctx.Err() != nil || !time.Now().Before(expires) {
						return
					}
					deadline := time.Now().Add(12 * time.Second)
					if expires.Before(deadline) {
						deadline = expires
					}
					if err := c.SetDeadline(deadline); err != nil {
						return
					}
					var length [2]byte
					if _, e := io.ReadFull(c, length[:]); e != nil {
						return
					}
					n := int(binary.BigEndian.Uint16(length[:]))
					if n < 12 || n > 65500 {
						return
					}
					q := make([]byte, n)
					if _, e := io.ReadFull(c, q); e != nil {
						return
					}
					// Every query, including a reused connection, traverses
					// the same rule engine and upstream/failed-response path.
					ans, e := s.handleTransport(q, true)
					if e != nil {
						ans = SERVFAIL(q)
					}
					if len(ans) < 12 || len(ans) > 65535 {
						return
					}
					frame := make([]byte, 2+len(ans))
					binary.BigEndian.PutUint16(frame[:2], uint16(len(ans)))
					copy(frame[2:], ans)
					for len(frame) > 0 {
						written, err := c.Write(frame)
						if err != nil || written <= 0 {
							return
						}
						frame = frame[written:]
					}
				}`
    return patch(path, original, replacement)
}

// A TCP client retry must not receive the same truncated UDP answer.
// Keep ordinary UDP behavior and the existing block rule path; only a
// truncated response to a TCP client requires an upstream TCP retry.
func patchDNSUpstreamTruncation(path string) error {
    const oldHandle = `func (s *Server) handle(query []byte) ([]byte, error) {`
    const newHandle = `func (s *Server) handle(query []byte) ([]byte, error) {
        return s.handleTransport(query, false)
    }
    func (s *Server) handleTransport(query []byte, tcpClient bool) ([]byte, error) {`
    if err:=patch(path,oldHandle,newHandle);err!=nil{return err}
    const oldReturn = `		return response[:n], nil
	}
	return nil, fmt.Errorf("upstreams failed: %w", last)
}`
    const newReturn = `		if tcpClient && response[2]&0x02 != 0 {
            full,err:=s.completeTruncatedDNSOverTCP(target,query,end)
            if err!=nil {last=err;continue}
            return full,nil
        }
        return response[:n], nil
	}
	return nil, fmt.Errorf("upstreams failed: %w", last)
}
func (s *Server) completeTruncatedDNSOverTCP(target string,query []byte,questionEnd int)([]byte,error){
    if len(query)<12||len(query)>65535||questionEnd<17||questionEnd>len(query){return nil,errors.New("invalid TCP upstream request")}
    conn,err:=net.DialTimeout("tcp",target,s.timeout)
    if err!=nil{return nil,err}
    defer conn.Close()
    if err=conn.SetDeadline(time.Now().Add(s.timeout));err!=nil{return nil,err}
    packet:=make([]byte,2+len(query))
    binary.BigEndian.PutUint16(packet[:2],uint16(len(query)));copy(packet[2:],query)
    for len(packet)>0 {
        n,e:=conn.Write(packet);if e!=nil{return nil,e};if n<=0{return nil,io.ErrShortWrite};packet=packet[n:]
    }
    var length [2]byte
    if _,err=io.ReadFull(conn,length[:]);err!=nil{return nil,err}
    n:=int(binary.BigEndian.Uint16(length[:]))
    if n<questionEnd{return nil,errors.New("short upstream TCP DNS frame")}
    reply:=make([]byte,n)
    if _,err=io.ReadFull(conn,reply);err!=nil{return nil,err}
    if reply[0]!=query[0]||reply[1]!=query[1]||reply[2]&0x80==0||
        reply[2]&0x78!=query[2]&0x78||reply[2]&0x02!=0||
        binary.BigEndian.Uint16(reply[4:6])!=1||
        string(reply[12:questionEnd])!=string(query[12:questionEnd]){
        return nil,errors.New("uncorrelated or truncated upstream TCP DNS response")
    }
    return reply,nil
}`
    return patch(path,oldReturn,newReturn)
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
    for _, name := range []string{"inapp_motor_update_windows.go", "inapp_motor_update_windows_test.go", "managed_windows_task_lab_test.go", "signed_legacy_windows_task_lab_test.go", "native_task_switch_windows.go", "native_task_switch_windows_test.go", "independent_watchdog_windows_test.go", "watchdog_system_lab_windows_test.go", "ci_hardened_recovery_windows_test.go", "legacy_upgrade_readiness_windows.go", "legacy_upgrade_readiness_windows_test.go", "complete_binary_action_recovery_windows_test.go", "motor_dns_isolated_probe_windows.go", "motor_dns_isolated_probe_windows_test.go", "real_catalog_motor_windows_test.go", "production_dns_service_runner_windows.go", "production_dns_service_runner_windows_test.go", "dns_port53_hosted_vm_windows_test.go", "real_binary_system_execution_and_rollback_windows_test.go", "volveci_signed_full_dns53_system_windows_test.go", "motor_migration_status_windows.go", "motor_migration_status_windows_test.go", "legacy_migration_status_windows.go", "legacy_migration_status_windows_test.go", "installed_publisher_review_windows.go", "installed_publisher_review_windows_test.go", "installed_unsigned_migration_draft_windows.go", "installed_unsigned_migration_draft_windows_test.go", "protected_motor_target_windows.go", "protected_motor_target_windows_test.go", "protected_motor_target_ci_windows_test.go", "protected_motor_staging_entry_windows.go", "installed_motor_route_windows.go", "installed_motor_route_windows_test.go", "legacy_recovery_windows.go", "legacy_recovery_windows_test.go", "legacy_recovery_seal_windows.go", "legacy_recovery_seal_windows_test.go", "resident_journal_windows.go", "resident_journal_windows_test.go", "resident_running_identity_windows.go", "resident_running_identity_windows_test.go", "resident_outcome_identity_windows.go", "resident_outcome_identity_windows_test.go", "resident_health_audit_windows.go", "ci_fresh_dns53_windows.go", "ci_failing_candidate_dns53_windows.go", "ci_fresh_dns53_windows_test.go", "ci_fresh_startup_diagnostic_windows_test.go"} {
        data, err := os.ReadFile(filepath.Join(srcDir, name)); if err != nil { panic(err) }
        formatted, err := format.Source(data); if err != nil { panic(err) }
        if err := os.WriteFile(filepath.Join(target, name), formatted, 0600); err != nil { panic(err) }
    }
    for _, name := range []string{"managed_transaction.go", "managed_transaction_test.go", "legacy_managed_transaction.go", "legacy_managed_transaction_test.go", "legacy_task_recovery_coverage.go", "legacy_task_recovery_coverage_test.go", "verified_inventory.go", "verified_inventory_test.go", "internet_proof.go", "internet_proof_test.go", "legacy_motor_attestation.go", "legacy_motor_attestation_test.go", "legacy_recovery_snapshot.go", "legacy_recovery_snapshot_test.go", "legacy_migration_permit.go", "legacy_migration_permit_test.go", "resident_publisher_recovery_binding.go", "resident_publisher_recovery_binding_test.go", "resident_publisher_durable_grant.go", "resident_publisher_durable_grant_test.go", "legacy_migration_draft.go", "legacy_migration_draft_test.go", "versioned_motor_protected_prepare.go", "versioned_motor_protected_prepare_test.go", "legacy_publisher_review_packet.go", "legacy_publisher_review_packet_test.go", "legacy_observed_candidate_review.go", "legacy_observed_candidate_review_test.go", "resident_journal.go", "resident_journal_test.go", "resident_completion.go", "resident_completion_test.go", "resident_health_probe.go", "resident_health_probe_test.go", "resident_active_health.go", "resident_running_identity.go", "resident_running_identity_test.go", "resident_boot_recovery.go", "resident_boot_recovery_test.go", "fresh_install_policy.go", "fresh_install_policy_test.go", "fresh_activation_admission.go", "fresh_activation_admission_test.go", "fresh_activation_reservation_windows.go", "fresh_activation_reservation_windows_test.go", "fresh_recovery_permit_windows.go", "fresh_recovery_permit_windows_test.go", "fresh_activation_postboot_windows.go", "fresh_activation_postboot_windows_test.go", "fresh_task_inventory_windows.go", "fresh_task_inventory_windows_test.go", "fresh_service_inventory_windows.go", "fresh_service_inventory_windows_test.go", "fresh_dns_adapter_inventory_windows.go", "fresh_dns_adapter_inventory_windows_test.go", "fresh_partial_host_probe_windows.go", "fresh_partial_host_probe_windows_test.go", "fresh_motor_file_inventory_windows.go", "fresh_motor_file_inventory_windows_test.go", "fresh_host_files_integration_windows.go", "fresh_host_files_integration_windows_test.go", "fresh_port53_inventory_windows.go", "fresh_port53_inventory_windows_test.go", "fresh_host_port53_integration_windows.go", "fresh_host_port53_integration_windows_test.go", "fresh_recovery_inventory_windows.go", "fresh_recovery_inventory_windows_test.go", "fresh_complete_host_probe_windows.go", "fresh_complete_host_probe_windows_test.go", "motor_install_route.go", "motor_install_route_test.go", "motor_install_route_windows.go", "motor_install_route_windows_test.go", "motor_install_evidence_summary_windows.go", "motor_install_evidence_summary_windows_test.go", "browser_policy_inventory_windows.go", "browser_policy_inventory_windows_test.go", "fresh_install_preservation.go", "fresh_install_preservation_test.go", "protection_snapshot_windows.go", "protection_snapshot_windows_test.go", "dns_restore_transaction.go", "dns_restore_transaction_test.go", "dns_activation_transaction.go", "dns_activation_transaction_test.go", "dns_activation_signed_grant.go", "dns_activation_signed_grant_test.go", "dns_activation_publisher_guard.go", "dns_activation_publisher_guard_test.go", "dns_activation_nonce_native_windows.go", "dns_activation_nonce_native_windows_test.go", "dns_activation_native_windows.go", "dns_activation_native_windows_test.go", "dns_activation_exclusive_lease.go", "dns_activation_exclusive_lease_test.go", "dns_activation_system_windows.go", "dns_activation_system_windows_test.go", "dns_boot_original_recovery_windows.go", "dns_boot_original_recovery_windows_test.go", "dns_boot_original_binding_store_windows.go", "dns_recovery_journal.go", "dns_recovery_journal_test.go", "dns_recovery_store_windows.go", "dns_recovery_store_windows_test.go", "dns_recovery_store_native_windows.go", "dns_recovery_store_native_windows_test.go", "dns_original_publisher_binding_windows.go", "dns_original_publisher_binding_windows_test.go", "dns_restore_netsh_plan.go", "dns_restore_netsh_plan_test.go", "dns_restore_adapter_inventory_windows.go", "dns_restore_adapter_inventory_windows_test.go", "dns_assignment_provenance_windows.go", "dns_assignment_provenance_windows_test.go", "dns_restore_static_executor_windows.go", "dns_restore_static_executor_windows_test.go", "dns_restore_static_batch_windows_test.go", "dns_restore_native_runner_windows.go", "dns_restore_native_runner_windows_test.go", "dns_restore_native_runner_automatic_windows_test.go", "dns_restore_authorized_windows.go", "dns_restore_authorized_windows_test.go", "dns_restore_lab_mutex_windows.go", "dns_restore_lab_mutex_windows_test.go", "dns_restore_signed_migration_mutex_windows_test.go", "resident_transition_lock_windows.go", "resident_transition_lock_windows_test.go", "resident_protected_boot_driver_windows.go", "resident_protected_boot_driver_windows_test.go", "resident_publisher_protected_boot_windows.go", "resident_publisher_protected_boot_windows_test.go", "resident_durable_publisher_boot_windows.go", "resident_durable_publisher_boot_windows_test.go", "resident_protected_signed_switch_windows.go", "resident_protected_signed_switch_windows_test.go", "resident_protected_signed_transaction_windows_test.go", "dns_restore_sealed_attestor_windows.go", "dns_restore_sealed_attestor_windows_test.go", "dns_restore_ntfs_acl_windows.go", "dns_restore_ntfs_acl_windows_test.go", "dns_restore_disposable_adapter_windows.go", "dns_restore_disposable_adapter_windows_test.go", "dns_restore_disposable_real_windows_test.go", "dns_restore_watchdog_crash_windows_test.go", "dns_restore_crash_lab_attestation_windows_test.go", "dns_restore_system_real_windows_test.go", "legacy_pe_imports.go", "legacy_pe_imports_test.go", "legacy_task_recovery_reader.go", "legacy_task_recovery_reader_windows.go", "legacy_task_recovery_reader_test.go"} {
        data, err := os.ReadFile(filepath.Join(srcDir, name)); if err != nil { panic(err) }
        formatted, err := format.Source(data); if err != nil { panic(err) }
        if err := os.WriteFile(filepath.Join(target, "motorupdate", name), formatted, 0600); err != nil { panic(err) }
    }
    watchdogTarget := filepath.Join(target, "cmd", "volve-managed-watchdog")
    if err := os.MkdirAll(watchdogTarget, 0700); err != nil { panic(err) }
    for _, name := range []string{"main_windows.go", "main_windows_test.go", "recovery_acl_windows.go", "recovery_acl_windows_test.go", "programdata_lab_windows_test.go", "resident_recovery_audit_windows.go", "resident_recovery_audit_windows_test.go", "resident_journal_audit_windows.go", "resident_journal_audit_windows_test.go", "resident_recovery_chain_windows.go", "resident_recovery_chain_windows_test.go", "resident_post_switch_recovery_audit_windows.go", "resident_post_switch_recovery_audit_windows_test.go", "resident_post_switch_file_restore_ci_windows.go", "resident_post_switch_file_restore_ci_windows_test.go", "resident_post_switch_file_task_ci_windows.go", "resident_post_switch_file_task_ci_windows_test.go", "resident_post_switch_real_dns_ci_windows_test.go", "resident_real_completion_ci_windows_test.go", "resident_pilot_restore_windows.go", "resident_pilot_restore_windows_test.go", "resident_boot_lock_windows.go", "resident_boot_lock_windows_test.go", "resident_boot_audit_windows.go", "resident_boot_audit_windows_test.go", "resident_boot_driver_ci_windows.go", "resident_boot_driver_ci_windows_test.go", "resident_boot_protected_gate_windows.go", "resident_signed_boot_admission_windows.go", "resident_signed_boot_admission_windows_test.go", "resident_recovery_quiescence_windows.go", "resident_recovery_quiescence_windows_test.go", "resident_signed_missing_original_restore_windows.go", "resident_signed_missing_original_restore_windows_test.go", "resident_signed_task_restore_windows.go", "resident_signed_task_restore_windows_test.go", "resident_signed_original_start_windows.go", "resident_signed_original_start_windows_test.go", "resident_pinned_boot_terminal_windows.go", "resident_pinned_boot_terminal_windows_test.go", "resident_pinned_boot_cli_windows.go", "resident_pinned_boot_cli_windows_test.go", "resident_signed_task_restore_system_binding_windows.go", "resident_signed_task_restore_system_binding_windows_test.go", "resident_signed_original_and_task_transaction_windows.go", "resident_signed_original_and_task_transaction_windows_test.go", "resident_signed_combined_publisher_binding_windows.go", "resident_signed_combined_publisher_binding_windows_test.go", "resident_signed_system_stage_ci_windows_test.go", "resident_publisher_grant_disk_windows_test.go", "resident_signed_boot_policy_adapter_windows.go", "resident_signed_boot_policy_adapter_windows_test.go", "resident_signed_exact_candidate_rollback_windows.go", "resident_signed_exact_candidate_rollback_windows_test.go", "resident_pinned_boot_driver_windows.go", "resident_pinned_boot_driver_windows_test.go", "resident_pinned_boot_health_windows.go", "resident_pinned_boot_health_windows_test.go", "resident_pinned_boot_components_windows.go"} {
        data, err := os.ReadFile(filepath.Join(srcDir, "watchdogcmd", name)); if err != nil { panic(err) }
        formatted, err := format.Source(data); if err != nil { panic(err) }
        if err := os.WriteFile(filepath.Join(watchdogTarget, name), formatted, 0600); err != nil { panic(err) }
    }
    // Fail closed if a new watchdog source or test is not added to the
    // explicit reconstruction manifest above. Without this census, focused
    // CI can show green while silently compiling an old subset of sources.
    // The CI post-switch motor shim is deliberately injected separately by
    // its dedicated disposable full-DNS workflow, never by the baseline.
    watchdogEntries, err := os.ReadDir(filepath.Join(srcDir, "watchdogcmd"))
    if err != nil { panic(err) }
    for _, entry := range watchdogEntries {
        if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") ||
            entry.Name() == "ci_post_switch_real_motor_shim_windows.go" { continue }
        if _, err := os.Stat(filepath.Join(watchdogTarget, entry.Name())); err != nil {
            panic(fmt.Errorf("watchdog source omitted from rebuilt Go module: %s: %w", entry.Name(), err))
        }
    }
    // Preserve production behavior byte-for-byte except for extracting the
    // same catalog parser into a root-injected helper, so Windows CI can load
    // a 400k+ feed under t.TempDir rather than touching real ProgramData.
    const fullCatalogMarker = "// Use the downloaded Full list, not a status counter."
    const fullCatalogReplacement = `return fullEngineAt(root)
}
func fullEngineAt(root string) (*blocker.Engine, error) {
    // Use the downloaded Full list, not a status counter.`
    if err := patch(filepath.Join(target, "dnsprod_windows.go"), fullCatalogMarker, fullCatalogReplacement); err != nil { panic(err) }
    if err := patchResidentDNSEntry(filepath.Join(target,"dnsprod_windows.go")); err != nil { panic(err) }
    if err := patchDNSPersistentTCP(filepath.Join(target,"dnsproxy","dns.go")); err != nil { panic(err) }
    if err := patchDNSUpstreamTruncation(filepath.Join(target,"dnsproxy","dns.go")); err != nil { panic(err) }
    const oldMain = "if len(os.Args) == 2 && os.Args[1] == \"--check-app-updates\" {"
    const newMain = `if len(os.Args) == 2 && os.Args[1] == "--prepare-legacy-rollback" {
        if err := printLegacyRecoveryPreparation(); err != nil {
            fmt.Println("VOLVÉ: NO SE CREÓ EL RESPALDO DEL MOTOR; NO SE MODIFICÓ EL DNS:", err)
            os.Exit(1)
        }
        return
    }
    if len(os.Args) == 2 && os.Args[1] == "--verify-legacy-rollback" {
        if err := verifyInstalledLegacyRecovery(); err != nil {
            fmt.Println("VOLVÉ: RESPALDO NO VERIFICADO; NO MODIFICÓ EL DNS:", err)
            os.Exit(1)
        }
        return
    }
    if len(os.Args) == 2 && os.Args[1] == "--motor-dns-isolated-loopback" {
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
    if len(os.Args) == 2 && os.Args[1] == "--motor-route-readonly" {
        if err := printInstalledMotorRouteReadOnly(); err != nil {
            fmt.Println("MOTOR DNS: DIAGNÓSTICO DE RUTA INCOMPLETO. No se modificó nada:", err)
            os.Exit(1)
        }
        return
    }
    if len(os.Args) == 3 && os.Args[1] == "--motor-prepare-protected" {
        if err := runProtectedMotorStageCLI(os.Args[2]); err != nil {
            fmt.Println("MOTOR DNS: PREPARACIÓN RECHAZADA. MOTOR ACTIVO Y DNS SIN MODIFICAR:", err)
            os.Exit(1)
        }
        return
    }
    if len(os.Args) == 3 && os.Args[1] == "--motor-migration-draft" {
        if err := runInstalledUnsignedMigrationDraftCLI(os.Args[2]); err != nil {
            fmt.Println("MOTOR DNS: BORRADOR EDITORIAL NO DISPONIBLE. No se modificó nada:", err)
            os.Exit(1)
        }
        return
    }
    if len(os.Args) == 3 && os.Args[1] == "--motor-publisher-review" {
        if err := runInstalledPublisherReviewCLI(os.Args[2]); err != nil {
            fmt.Println("MOTOR DNS: NO SE PUDO PREPARAR EXPEDIENTE EDITORIAL. Nada fue modificado:", err)
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
