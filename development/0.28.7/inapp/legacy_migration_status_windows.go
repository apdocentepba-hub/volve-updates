//go:build windows

package main

import (
    "context"
    "crypto/ed25519"
    "errors"
    "fmt"
    "os"
    "path/filepath"

    "volve-browser-protection/motorupdate"
)

// A migration permit is an independently publisher-signed pair beside the
// staged (already signed) engine. Neither file authorizes execution by itself.
// The publisher has NOT distributed a production permit in this pilot.
const signedMigrationJSON = ".migration.json"
const signedMigrationSignature = ".migration.sig"

// preparedSignedLegacyMigrationStatus is the READ-ONLY bridge from the native
// "Actualizar VOLVÉ" response to the exact signed legacy-migration verifier.
// The third argument deliberately injects an ACL checker for disposable tests;
// the actual caller ALWAYS supplies checkLegacyRecoveryACL. No task, binary,
// DNS adapter, watchdog or journal is modified here.
func preparedSignedLegacyMigrationStatus(
    ctx context.Context, installDir, candidate, panelVersion string,
    key ed25519.PublicKey, elevated bool,
    preflight func() (string, error), protectBackup func(string) error,
) (string, bool) {
    raw, rawErr := readBoundedProvenance(candidate+signedMigrationJSON, 4096)
    sig, sigErr := readBoundedProvenance(candidate+signedMigrationSignature, 256)
    if errors.Is(rawErr, os.ErrNotExist) && errors.Is(sigErr, os.ErrNotExist) {
        return "", false // Legacy attestation remains a separate supported path.
    }
    if rawErr != nil || sigErr != nil {
        return "permiso firmado de migración incompleto o inseguro; no se instalará el motor", true
    }
    if !elevated {
        return "permiso de migración presente; falta verificación privilegiada del respaldo, tarea SYSTEM y DNS; no se instaló nada", true
    }
    if preflight == nil || protectBackup == nil {
        return "verificación privilegiada o ACL del rescate no disponible; no se instalará el motor", true
    }
    backupDir := filepath.Join(installDir, localRecoveryFolder, localRecoverySnapshot)
    // The recovery parent is as security-sensitive as the snapshot itself.
    // A writable parent could replace the snapshot between verification and
    // a later update even if the snapshot's own DACL were intact.
    if err := protectBackup(filepath.Dir(backupDir)); err != nil {
        return "directorio padre del respaldo inseguro ("+err.Error()+"); no se instalará el motor", true
    }
    proof, err := motorupdate.VerifySignedUnversionedLegacyMigration(
        ctx,
        filepath.Join(installDir, dnsServiceFile), backupDir, candidate,
        panelVersion, raw, sig, key, protectBackup,
        func() error {
            _, checkErr := preflight()
            return checkErr
        },
    )
    if err != nil {
        return fmt.Sprintf("permiso de migración rechazado (%v); no se instalará el motor", err), true
    }
    return fmt.Sprintf(
        "permiso editorial firmado y respaldo original verificados: SHA-256 anterior %s, destino %s (%s); tarea SYSTEM, rescate y DNS comprobados. "+
            "NO se cambió el motor: aplicación productiva bloqueada hasta validar watchdog y recuperación tras reinicio real.",
        proof.LegacySHA256, proof.CandidateVersion, proof.CandidateSHA256,
    ), true
}
