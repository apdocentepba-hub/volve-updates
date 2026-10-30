//go:build windows

package main

import (
    "context"
    "crypto/ed25519"
    "encoding/base64"
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "strings"
    "time"

    "volve-browser-protection/motorupdate"
    "volve-browser-protection/releaseupdate"
)

// checkAllUpdates makes the installed "Actualizar VOLVÉ" action check both
// independently signed channels. The existing Centre install marker must stay
// the LAST line so the current native UI can continue to use UAC safely.
func checkAllUpdates() (string, error) {
    // Both channels have independent timeouts. Checking them concurrently
    // keeps the existing native UI 120-second bound intact even if a remote
    // release server is slow.
    motorDone := make(chan string, 1)
    go func() { motorDone <- checkAndStageMotorUpdate() }()
    panel, err := checkAndStageUpdate()
    if err != nil {
        return "", err
    }
    return mergeUpdateReports(panel, <-motorDone), nil
}

func mergeUpdateReports(panel, motor string) string {
    const marker = "\nVOLVE_STAGE_READY="
    pos := strings.LastIndex(panel, marker)
    if pos < 0 {
        return strings.TrimSpace(panel) + "\n\n" + strings.TrimSpace(motor)
    }
    candidate := strings.TrimSpace(panel[pos+len(marker):])
    return strings.TrimSpace(panel[:pos]) + "\n\n" +
        strings.TrimSpace(motor) + marker + candidate
}

// checkAndStageMotorUpdate stages only a signed DNS-engine release in the
// current user's cache. It NEVER runs it, changes DNS, changes SYSTEM tasks,
// or claims the installed legacy motor version. An independent privileged
// driver with verified rollback is required to apply a staged engine.
func checkAndStageMotorUpdate() string {
    key, err := base64.StdEncoding.DecodeString(updaterPublicKey)
    if err != nil || len(key) != ed25519.PublicKeySize {
        return "MOTOR DNS: clave pública del canal inválida; no se descargó nada."
    }
    ctx, cancel := context.WithTimeout(context.Background(), 55*time.Second)
    defer cancel()
    client := motorupdate.DefaultClient()
    m, raw, sig, err := motorupdate.FetchSigned(ctx, client, motorupdate.ChannelURL, ed25519.PublicKey(key))
    if errors.Is(err, motorupdate.ErrNotPublished) {
        return "MOTOR DNS: todavía no hay una actualización firmada publicada. El motor actual permanece activo."
    }
    if err != nil {
        return "MOTOR DNS: comprobación rechazada (" + err.Error() + "). No se modificó la protección."
    }
    // Check frontend compatibility without guessing the unrecorded legacy
    // engine version. Do not apply, or even claim, an engine upgrade.
    cmp, err := releaseupdate.CompareVersions(version, m.MinPanelVersion)
    if err != nil || cmp < 0 {
        return "MOTOR DNS: la versión anunciada requiere primero actualizar el Centro a " +
            m.MinPanelVersion + ". No se descargó el motor."
    }
    cache, err := os.UserCacheDir()
    if err != nil || !filepath.IsAbs(cache) {
        return "MOTOR DNS: no se pudo identificar una carpeta de descargas segura."
    }
    root := filepath.Join(cache, "VOLVE", "staged-engine")
    if info, statErr := os.Lstat(root); statErr == nil {
        if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
            return "MOTOR DNS: la carpeta de preparación no es un directorio normal. Descarga rechazada."
        }
    } else if !errors.Is(statErr, os.ErrNotExist) {
        return "MOTOR DNS: la carpeta de preparación no es verificable."
    }
    name := "VOLVE_DNS_Motor_" + strings.ReplaceAll(m.Version, ".", "_") + ".exe"
    candidate := filepath.Join(root, "motor-"+m.Version, name)
    if _, err := os.Lstat(filepath.Dir(candidate)); err == nil {
        verified, verifyErr := motorupdate.VerifyStaged(candidate, ed25519.PublicKey(key))
        if verifyErr != nil || verified != m {
            return "MOTOR DNS: existía un paquete preparado, pero no coincide con la versión firmada. No se utilizará."
        }
    } else if errors.Is(err, os.ErrNotExist) {
        candidate, err = motorupdate.Stage(ctx, client, m, raw, sig, ed25519.PublicKey(key), root)
        if err != nil {
            return "MOTOR DNS: no se pudo preparar el paquete firmado (" + err.Error() + "). El motor activo no cambió."
        }
    } else {
        return "MOTOR DNS: no se pudo verificar el destino de preparación."
    }
    return fmt.Sprintf(
        "MOTOR DNS: versión %s descargada y verificada (firma Ed25519, tamaño y SHA-256).\n"+
            "Ubicación de preparación: %s\n"+
            "No se instaló: la identidad/versionado del motor heredado y la reversión independiente deben validarse antes de cambiar el servicio DNS.",
        m.Version, candidate,
    )
}
