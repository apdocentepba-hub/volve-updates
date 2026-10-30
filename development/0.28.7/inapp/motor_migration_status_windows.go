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

// motorMigrationStatus reports exactly why a newly downloaded, publisher-signed
// motor CANNOT yet be applied to a legacy installation. It never modifies
// tasks, DNS, files, the installation, or release metadata. A status of
// "prerequisites verified" is NOT permission to replace the live DNS engine.
func motorMigrationStatus(
    ctx context.Context, installDir, candidate, panelVersion string,
    key ed25519.PublicKey, elevated bool, preflight func()(string,error),
) string {
    if err:=ctx.Err();err!=nil {return "verificación cancelada; motor actual intacto"}
    if !filepath.IsAbs(installDir) || !filepath.IsAbs(candidate) {
        return "ruta de instalación o descarga no verificable; motor actual intacto"
    }
    if len(key)!=ed25519.PublicKeySize {
        return "clave pública de actualización inválida; motor actual intacto"
    }
    // Reverify the staged candidate even when a caller previously checked it.
    release,err:=motorupdate.VerifyStaged(candidate,key)
    if err!=nil {
        return "paquete descargado no auténtico o incompleto ("+err.Error()+"); no se instalará"
    }
    exe:=filepath.Join(installDir,dnsServiceFile)
    if info,err:=os.Lstat(exe);err!=nil || !info.Mode().IsRegular() {
        return "no se pudo verificar el ejecutable DNS instalado; no se instalará"
    }
    // Prefer an explicitly published signed migration permission when present.
    // A partial/invalid permit fails closed; it cannot silently fall back
    // to a less constrained legacy identity path.
    if result, found := preparedSignedLegacyMigrationStatus(
        ctx, installDir, candidate, panelVersion, key, elevated, preflight,
        checkLegacyRecoveryACL,
    ); found { return result }
    statement,err:=readBoundedProvenance(filepath.Join(installDir,legacyUpgradeStatement),4096)
    if errors.Is(err,os.ErrNotExist) {
        return "falta la constancia firmada del motor heredado; se requiere migración certificada por el editor, sin reinstalar"
    }
    if err!=nil {return "constancia del motor heredado inaccesible o insegura; no se instalará"}
    sig,err:=readBoundedProvenance(filepath.Join(installDir,legacyUpgradeSignature),256)
    if errors.Is(err,os.ErrNotExist) {
        return "falta la firma del motor heredado; no se instalará"
    }
    if err!=nil {return "firma del motor heredado inaccesible o insegura; no se instalará"}
    oldVersion,err:=motorupdate.VerifyLegacyMotorAttestation(
        exe,dnsServiceTask,"--dns-service",statement,sig,key)
    if err!=nil {return "identidad firmada del motor anterior no coincide con lo instalado; no se instalará"}
    eligible,err:=motorupdate.IsEligible(oldVersion,panelVersion,release)
    if err!=nil {return "versiones del Centro y del motor incompatibles; no se instalará"}
    if !eligible {
        return fmt.Sprintf("sin actualización de motor aplicable: instalado %s, publicado %s; no se harán cambios",oldVersion,release.Version)
    }
    if !elevated {
        return fmt.Sprintf(
            "motor %s autenticado y candidato %s apto; falta comprobación privilegiada de DNS y rescate; no se instaló nada",
            oldVersion,release.Version)
    }
    if preflight==nil {return "comprobación de DNS y rescate no disponible; no se instalará"}
    _,err=analyzeResidentUpgradeEvidence(ctx,installDir,candidate,panelVersion,key,preflight)
    if err!=nil {return "comprobación real del motor DNS o rescate rechazada ("+err.Error()+"); no se instalará"}
    return fmt.Sprintf(
        "identidad de motor %s, firma del candidato %s y preflight comprobados; aplicación productiva aún bloqueada hasta probar reversión tras reinicio",
        oldVersion,release.Version)
}

// This function belongs to the *installed update button* response, not a
// separate manual diagnostic. Never prompt for UAC simply for a status check.
func explainPreparedMotorMigration(candidate string,key ed25519.PublicKey) string {
    root,err:=installRoot()
    if err!=nil {return "instalación de VOLVÉ no identificada; motor actual intacto"}
    var preflight func()(string,error)
    elevated:=isAdmin()
    if elevated {preflight=preflightMotorUpgradeReadOnly}
    return motorMigrationStatus(
        context.Background(),root,candidate,version,key,elevated,preflight)
}
