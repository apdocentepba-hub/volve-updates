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
    // This MUST be an OS-wide, cross-process exclusive lock using the SAME
    // identity as the standalone SYSTEM boot recovery. It must remain held
    // from the first live publisher check through Switch, probes, Commit and
    // any independent rollback. A process-local Go mutex is INSUFFICIENT.
    // The interface is a requirement, not a production implementation.
    AcquireExclusiveMigration(context.Context) (release func(),err error)
    IndependentRecoveryReady(context.Context, VerifiedLegacyMigrationProof) error
    // Recheck the INSTALLED copy, not just the staged download. This call
    // must validate signed manifest, SHA-256 and size under the versioned
    // destination immediately before the last authorization/watchdog gate.
    VerifyPreparedTarget(context.Context, Manifest) error
}

// checkSealedOriginalAtTransactionBoundary proves that the existing rollback
// directory still contains the EXACT old motor and Task Scheduler XML covered
// by the publisher's permit. A successful driver's Snapshot callback is not
// sufficient evidence that the on-disk rollback survived that callback.
func checkSealedOriginalAtTransactionBoundary(
 backupDir string,protect func(string)error,proof VerifiedLegacyMigrationProof,
)error{
 snapshot,err:=VerifyUnversionedLegacyRecovery(backupDir,protect)
 if err!=nil{return fmt.Errorf("protected rollback snapshot unreadable: %w",err)}
 if snapshot.ExeSHA256!=proof.LegacySHA256||
  snapshot.XMLSHA256!=proof.LegacyTaskXMLSHA256{
  return errors.New("protected rollback original differs from signed migration")
 }
 return nil
}

// restoreSignedLegacyAndVerify never reports a successful recovery if the
// original snapshot became untrusted. The independent restore still runs
// with its own context even if the initiating update context is cancelled.
// Recovery success is an OS-driver + health-check claim, not a JSON receipt.
func restoreSignedLegacyAndVerify(
 driver SignedLegacySwitchDriver,cause error,backupDir string,
 protect func(string)error,proof VerifiedLegacyMigrationProof,
)error{
 // NEVER ask an OS recovery driver to execute or restore from an
 // untrusted rollback snapshot. This includes post-switch failures. Keep the
 // in-progress recovery intent unresolved so a trusted external/watchdog
 // operator can investigate; do not claim the original was recovered.
 if err:=checkSealedOriginalAtTransactionBoundary(backupDir,protect,proof);err!=nil{
  return errors.Join(cause,
   fmt.Errorf("CRÍTICO: recuperación automática detenida: original protegido no verificable: %w",err))
 }
 rollbackErr:=restoreManagedAndVerify(driver,cause)
 if err:=checkSealedOriginalAtTransactionBoundary(backupDir,protect,proof);err!=nil{
  return errors.Join(rollbackErr,
   fmt.Errorf("CRÍTICO: respaldo heredado cambió durante el rescate; estado no certificado: %w",err))
 }
 return rollbackErr
}

// ApplySignedLegacyWithRollback is transaction LOGIC only; it does not select
// a driver, schedule a SYSTEM task, replace any executable or modify DNS.
//
// Before any mutation it requires an independently signed exact legacy->new
// migration grant, intact protected rollback, verified live DNS/SYSTEM state
// and a ready independent recovery agent. Snapshot must be durable on success.
// After the staged candidate is prepared, all signed identities and watchdog
// readiness are checked AGAIN immediately before Switch. An unsuccessful
// post-snapshot operation attempts an independent-context rollback ONLY if the
// protected original remains trusted; health probes are still required.
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
    // Lock BEFORE the first task, backup or publisher observation. All
    // transaction exits—including cancellation and post-switch rollback—
    // release it. The real Windows driver must implement a named kernel
    // mutex shared with the boot-rescue service, not an in-process lock.
    release,err:=driver.AcquireExclusiveMigration(ctx)
    if err!=nil{return fmt.Errorf("bloqueo exclusivo de motor no disponible: %w",err)}
    if release==nil{return errors.New("controlador no entregó liberación del bloqueo exclusivo")}
    defer release()
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
    // The last preceding signed proof checked the old snapshot BEFORE
    // Snapshot(). Revalidate the exact protected bytes directly after the
    // callback and BEFORE even installing a new versioned candidate.
    if err := checkSealedOriginalAtTransactionBoundary(backupDir,protectBackup,proof);err != nil {
        // Snapshot is a backup-only driver call. A corrupt copy must never
        // be fed into Restore, nor allow candidate preparation to start.
        return fmt.Errorf("CRÍTICO: respaldo alterado tras Snapshot; actualización detenida antes de instalar motor: %w",err)
    }
    // Everything after Snapshot is a transaction. The original user context
    // may be cancelled; restoreManagedAndVerify uses a fresh 90s rescue context.
    if err := ctx.Err(); err != nil { return restoreSignedLegacyAndVerify(driver,err,backupDir,protectBackup,proof) }
    if err := driver.InstallVersionedCandidate(ctx,candidate); err != nil {
        return restoreSignedLegacyAndVerify(driver,fmt.Errorf("motor versionado no preparado: %w",err),backupDir,protectBackup,proof)
    }
    if err := ctx.Err(); err != nil { return restoreSignedLegacyAndVerify(driver,err,backupDir,protectBackup,proof) }
    if err := driver.VerifyPreparedTarget(ctx,manifest); err != nil {
        return restoreSignedLegacyAndVerify(driver,fmt.Errorf("copia instalada no auténtica o incompleta: %w",err),backupDir,protectBackup,proof)
    }
    if err := protectBackup(filepath.Dir(backupDir)); err != nil {
        return restoreSignedLegacyAndVerify(driver,fmt.Errorf("directorio de recuperación cambió: %w",err),backupDir,protectBackup,proof)
    }
    rechecked, err := VerifySignedUnversionedLegacyMigration(
        ctx,liveExe,backupDir,candidate,panelVersion,
        permitJSON,permitSignature,publisherKey,protectBackup,livePreflight,
    )
    if err != nil { return restoreSignedLegacyAndVerify(driver,fmt.Errorf("identidad o autorización cambió antes de conmutar: %w",err),backupDir,protectBackup,proof) }
    if rechecked != proof {
        return restoreSignedLegacyAndVerify(driver,errors.New("prueba firmada de migración cambió durante la preparación"),backupDir,protectBackup,proof)
    }
    if err := driver.IndependentRecoveryReady(ctx,rechecked); err != nil {
        return restoreSignedLegacyAndVerify(driver,fmt.Errorf("watchdog independiente dejó de estar listo: %w",err),backupDir,protectBackup,proof)
    }
    if err := ctx.Err(); err != nil { return restoreSignedLegacyAndVerify(driver,err,backupDir,protectBackup,proof) }
    if err := driver.Switch(ctx); err != nil {
        return restoreSignedLegacyAndVerify(driver,fmt.Errorf("conmutación del motor falló: %w",err),backupDir,protectBackup,proof)
    }
    if err := driver.Probe(ctx); err != nil {
        return restoreSignedLegacyAndVerify(driver,fmt.Errorf("nuevo DNS local no respondió: %w",err),backupDir,protectBackup,proof)
    }
    if err := driver.ProbeConnectivity(ctx); err != nil {
        return restoreSignedLegacyAndVerify(driver,fmt.Errorf("Internet tras conmutación falló: %w",err),backupDir,protectBackup,proof)
    }
    // CRITICAL POST-SWITCH FENCE: a working DNS response does not prove the
    // original remains recoverable. A compromised backup, altered installed
    // target or stopped SYSTEM watchdog must NEVER be committed as healthy.
    // Recheck after the LIVE DNS and external connectivity probes, not only
    // before Switch. Do not attempt a rollback from a corrupted original.
    if err := ctx.Err(); err != nil { return restoreSignedLegacyAndVerify(driver,err,backupDir,protectBackup,proof) }
    if err := checkSealedOriginalAtTransactionBoundary(backupDir,protectBackup,proof);err != nil {
        return restoreSignedLegacyAndVerify(driver,
            fmt.Errorf("respaldo original cambió después de probar DNS: %w",err),backupDir,protectBackup,proof)
    }
    afterDNS,err:=VerifyStaged(candidate,publisherKey)
    if err != nil || afterDNS!=manifest {
        return restoreSignedLegacyAndVerify(driver,
            fmt.Errorf("candidato firmado cambió después de probar DNS: %v",err),backupDir,protectBackup,proof)
    }
    if err := driver.VerifyPreparedTarget(ctx,manifest);err != nil {
        return restoreSignedLegacyAndVerify(driver,
            fmt.Errorf("copia instalada del motor cambió después de probar DNS: %w",err),backupDir,protectBackup,proof)
    }
    if err := driver.IndependentRecoveryReady(ctx,proof);err != nil {
        return restoreSignedLegacyAndVerify(driver,
            fmt.Errorf("watchdog independiente no disponible al confirmar: %w",err),backupDir,protectBackup,proof)
    }
    if _,err:=parseSignedMigrationPermit(permitJSON,permitSignature,publisherKey);err != nil {
        return restoreSignedLegacyAndVerify(driver,
            fmt.Errorf("permiso editorial inválido al confirmar: %w",err),backupDir,protectBackup,proof)
    }
    if err := ctx.Err(); err != nil { return restoreSignedLegacyAndVerify(driver,err,backupDir,protectBackup,proof) }
    if err := driver.Commit(ctx,manifest); err != nil {
        return restoreSignedLegacyAndVerify(driver,fmt.Errorf("registro administrado no confirmado: %w",err),backupDir,protectBackup,proof)
    }
    return nil
}
