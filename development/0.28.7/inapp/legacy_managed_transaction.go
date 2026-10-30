package motorupdate

import (
    "context"
    "crypto/ed25519"
    "errors"
    "fmt"
    "path/filepath"
)

// SignedLegacySwitchDriver is a deliberately stricter contract for the ONE-TIME
// transition from a publisher-authorized, unversioned legacy DNS motor.
// A production implementation does not yet exist. In particular, the future
// Windows implementation must pin immutable candidate bytes for Switch and
// arm an out-of-process SYSTEM recovery watchdog before touching the motor.
type SignedLegacySwitchDriver interface {
    ManagedSwitchDriver
    IndependentRecoveryReady(context.Context, VerifiedLegacyMigrationProof) error
    // Recheck the INSTALLED copy, not just the staged download. This call
    // must validate signed manifest, SHA-256 and size under the versioned
    // destination immediately before the last authorization/watchdog gate.
    VerifyPreparedTarget(context.Context, Manifest) error
}

// ApplySignedLegacyWithRollback is transaction LOGIC only; it does not select
// a driver, schedule a SYSTEM task, replace any executable or modify DNS.
//
// Before any mutation it requires an independently signed exact legacy->new
// migration grant, intact protected rollback, verified live DNS/SYSTEM state
// and a ready independent recovery agent. Snapshot must be durable on success.
// After the staged candidate is prepared, all signed identities and watchdog
// readiness are checked AGAIN immediately before Switch. An unsuccessful
// post-snapshot operation always attempts independent-context rollback and
// probes both local DNS and network connectivity before claiming recovery.
//
// Production remains BLOCKED until an OS driver can prove candidate immutability
// across the final check/switch boundary and pass real reboot recovery tests.
func ApplySignedLegacyWithRollback(
    ctx context.Context,
    liveExe, backupDir, candidate, panelVersion string,
    permitJSON, permitSignature []byte, publisherKey ed25519.PublicKey,
    protectBackup func(string) error, livePreflight func() error,
    driver SignedLegacySwitchDriver,
) error {
    if driver == nil || protectBackup == nil || livePreflight == nil {
        return errors.New("migración sin controlador, ACL o preflight confiable")
    }
    if err := ctx.Err(); err != nil { return err }
    if err := protectBackup(filepath.Dir(backupDir)); err != nil {
        return fmt.Errorf("directorio padre del rescate no seguro: %w", err)
    }
    proof, err := VerifySignedUnversionedLegacyMigration(
        ctx, liveExe, backupDir, candidate, panelVersion,
        permitJSON, permitSignature, publisherKey, protectBackup, livePreflight,
    )
    if err != nil { return fmt.Errorf("migración heredada no autorizada: %w",err) }
    manifest, err := VerifyStaged(candidate,publisherKey)
    if err != nil { return fmt.Errorf("motor de destino no verificable: %w",err) }
    if manifest.Version != proof.CandidateVersion || manifest.SHA256 != proof.CandidateSHA256 {
        return errors.New("versión o huella de motor cambió tras el permiso firmado")
    }
    if err := driver.Preflight(ctx, manifest); err != nil {
        return fmt.Errorf("preflight de conmutación rechazado: %w",err)
    }
    if err := driver.IndependentRecoveryReady(ctx,proof); err != nil {
        return fmt.Errorf("watchdog independiente no listo; motor intacto: %w",err)
    }
    if err := ctx.Err(); err != nil { return err }
    if err := driver.Snapshot(ctx); err != nil {
        return fmt.Errorf("instantánea de reversión no durable; cambio no iniciado: %w",err)
    }
    // Everything after Snapshot is a transaction. The original user context
    // may be cancelled; restoreManagedAndVerify uses a fresh 90s rescue context.
    if err := ctx.Err(); err != nil { return restoreManagedAndVerify(driver,err) }
    if err := driver.InstallVersionedCandidate(ctx,candidate); err != nil {
        return restoreManagedAndVerify(driver,fmt.Errorf("motor versionado no preparado: %w",err))
    }
    if err := ctx.Err(); err != nil { return restoreManagedAndVerify(driver,err) }
    if err := driver.VerifyPreparedTarget(ctx,manifest); err != nil {
        return restoreManagedAndVerify(driver,fmt.Errorf("copia instalada no auténtica o incompleta: %w",err))
    }
    if err := protectBackup(filepath.Dir(backupDir)); err != nil {
        return restoreManagedAndVerify(driver,fmt.Errorf("directorio de recuperación cambió: %w",err))
    }
    rechecked, err := VerifySignedUnversionedLegacyMigration(
        ctx,liveExe,backupDir,candidate,panelVersion,
        permitJSON,permitSignature,publisherKey,protectBackup,livePreflight,
    )
    if err != nil { return restoreManagedAndVerify(driver,fmt.Errorf("identidad o autorización cambió antes de conmutar: %w",err)) }
    if rechecked != proof {
        return restoreManagedAndVerify(driver,errors.New("prueba firmada de migración cambió durante la preparación"))
    }
    if err := driver.IndependentRecoveryReady(ctx,rechecked); err != nil {
        return restoreManagedAndVerify(driver,fmt.Errorf("watchdog independiente dejó de estar listo: %w",err))
    }
    if err := ctx.Err(); err != nil { return restoreManagedAndVerify(driver,err) }
    if err := driver.Switch(ctx); err != nil {
        return restoreManagedAndVerify(driver,fmt.Errorf("conmutación del motor falló: %w",err))
    }
    if err := driver.Probe(ctx); err != nil {
        return restoreManagedAndVerify(driver,fmt.Errorf("nuevo DNS local no respondió: %w",err))
    }
    if err := driver.ProbeConnectivity(ctx); err != nil {
        return restoreManagedAndVerify(driver,fmt.Errorf("Internet tras conmutación falló: %w",err))
    }
    if err := ctx.Err(); err != nil { return restoreManagedAndVerify(driver,err) }
    if err := driver.Commit(ctx,manifest); err != nil {
        return restoreManagedAndVerify(driver,fmt.Errorf("registro administrado no confirmado: %w",err))
    }
    return nil
}
