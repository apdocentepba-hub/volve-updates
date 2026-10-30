package motorupdate

import (
    "context"
    "crypto/ed25519"
    "errors"
    "fmt"
)

// ManagedSwitchDriver is the contract required before VOLVE can replace a
// resident DNS motor from the installed UI. Probe verifies local DNS responses,
// ProbeConnectivity independently verifies external DNS/network reachability,
// and Commit persists the verified version/journal only after both have passed.
// This package does not implement an OS-specific driver or change the network.
type ManagedSwitchDriver interface {
    SwitchDriver
    ProbeConnectivity(context.Context) error
    Commit(context.Context, Manifest) error
}

// ApplyManagedWithRollback verifies a signed, versioned candidate and performs
// a failback-protected transaction. There is deliberately no production caller
// until a separate SYSTEM watchdog and a Windows driver have been validated.
func ApplyManagedWithRollback(ctx context.Context, candidate string, key ed25519.PublicKey, installedMotorVersion, panelVersion string, driver ManagedSwitchDriver) error {
    if driver == nil || candidate == "" {
        return errors.New("motor o controlador administrado ausente")
    }
    if err := ctx.Err(); err != nil {
        return err
    }
    manifest, err := VerifyStaged(candidate, key)
    if err != nil {
        return fmt.Errorf("candidato de motor no verificado: %w", err)
    }
    eligible, err := IsEligible(installedMotorVersion, panelVersion, manifest)
    if err != nil {
        return err
    }
    if !eligible {
        return errors.New("rechazado: motor de destino no supera la versión instalada")
    }
    if err := driver.Preflight(ctx, manifest); err != nil {
        return fmt.Errorf("revisión de identidad y conectividad no aprobada: %w", err)
    }
    if err := ctx.Err(); err != nil {
        return err
    }
    if err := driver.Snapshot(ctx); err != nil {
        // No mutable operation is allowed before a *complete* durable snapshot.
        return fmt.Errorf("respaldo duradero no confirmado; no se conmutó el motor: %w", err)
    }
    // After the durable snapshot, any unsuccessful transition must restore the
    // original engine using an independent bounded context, even if ctx expired.
    if err := ctx.Err(); err != nil {
        return restoreAndVerify(driver, err)
    }
    if err := driver.InstallVersionedCandidate(ctx, candidate); err != nil {
        return restoreAndVerify(driver, fmt.Errorf("no se preparó el motor versionado: %w", err))
    }
    if err := ctx.Err(); err != nil {
        return restoreAndVerify(driver, err)
    }
    if err := driver.Switch(ctx); err != nil {
        return restoreAndVerify(driver, fmt.Errorf("falló el cambio de motor: %w", err))
    }
    if err := driver.Probe(ctx); err != nil {
        return restoreAndVerify(driver, fmt.Errorf("el motor nuevo no responde localmente: %w", err))
    }
    if err := driver.ProbeConnectivity(ctx); err != nil {
        return restoreAndVerify(driver, fmt.Errorf("no se verificó conectividad tras el cambio: %w", err))
    }
    if err := ctx.Err(); err != nil {
        return restoreAndVerify(driver, err)
    }
    if err := driver.Commit(ctx, manifest); err != nil {
        return restoreAndVerify(driver, fmt.Errorf("no se pudo confirmar versión y registro del motor: %w", err))
    }
    return nil
}
