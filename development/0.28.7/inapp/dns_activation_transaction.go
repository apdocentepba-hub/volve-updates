package motorupdate

// Transaction coordinator for an eventual signed, privileged VOLVE installer.
// No production command calls this code yet. It does not provide a Windows
// writer, a signing key, SYSTEM identity or a watchdog; those MUST be
// independently implemented and attested before enabling any installation.
//
// The only accepted target is the exact dual-stack localhost DNS recorded in
// a canonical, independently pinned ORIGINAL-DNS journal. An injected guard
// must attest the durable protected backup, owner approval, real SYSTEM lock,
// live ready motor and independently armed boot-time recovery at each step.
import (
    "context"
    "errors"
    "fmt"
    "time"
)

// The real disposable Windows Server 2022 DNS recovery trial
// 45459849542/job/138679464895 took 347.56 seconds after reboot and
// the native restoration phase took 437.588 seconds before independent
// readback. A 45s deadline cancels rescue far too early. Reserve a bounded
// 15-minute budget for the separate SYSTEM agent, mutex reacquisition and
// final DNS readback. This is not a guarantee for every host/adapter count:
// exceeding it must leave the protected transaction pending, never mark
// it successful or disarm the independently installed watchdog.
const dnsActivationEmergencyRecoveryTimeout = 15 * time.Minute

type DNSActivationSafetyGuard interface {
    // May not trust a UI boolean or a hash supplied by the same journal.
    // MUST attest the protected backup + signed authorization + SYSTEM mutex
    // and armed, independent recovery before and throughout every write.
    VerifyArmed(context.Context, string) error
    // MUST probe actual permitted DNS resolution and gambling-domain blocking
    // on both IPv4 and IPv6 through the newly activated motor.
    VerifyLiveProtection(context.Context, string) error
    // Must hand off to the independent SYSTEM recovery agent. The coordinator
    // deliberately does not "restore" DNS itself under a cancelled context.
    RecoverIndependently(context.Context, string) error
    // Must durably commit the receipt while keeping recovery available until
    // a separate post-boot proof; not merely set an in-memory success flag.
    CommitActive(context.Context, string) error
}

// activateVOLVEDNSWithRecovery is intentionally unexported. A concrete
// privileged installer adapter cannot use it until it supplies the separately
// authenticated guard. This function does NOT install a Windows task, change
// the registry or claim that real reboot recovery has been proven.
func activateVOLVEDNSWithRecovery(
    ctx context.Context, originalJournal []byte, independentlyPinnedSHA256 string,
    backend DNSAdapterBackend, guard DNSActivationSafetyGuard,
) (err error) {
    if ctx == nil || backend == nil || guard == nil {
        return errors.New("DNS activation requires context, protected backend and recovery guard")
    }
    if err := ctx.Err(); err != nil { return err }
    records, err := VerifyDNSOriginalJournal(ctx, originalJournal, independentlyPinnedSHA256)
    if err != nil { return fmt.Errorf("original DNS backup not independently authenticated: %w", err) }
    if err := guard.VerifyArmed(ctx, independentlyPinnedSHA256); err != nil {
        return fmt.Errorf("independent recovery not armed before DNS activation: %w", err)
    }

    // No writes until ALL adapter GUID / IPv4 / IPv6 original states match.
    if err := verifyDNSActivationTransition(ctx, records, backend, 0); err != nil {
        return fmt.Errorf("DNS activation all-family preflight refused: %w", err)
    }

    writeAttempted := false
    defer func() {
        if err == nil || !writeAttempted { return }
        // A canceled/expired installer context MUST NOT suppress independent
        // rescue. The watchdog must use its own guarded authorization/timeout.
        recoveryCtx, cancel := context.WithTimeout(context.Background(), dnsActivationEmergencyRecoveryTimeout)
        defer cancel()
        if rescueErr := guard.RecoverIndependently(recoveryCtx, independentlyPinnedSHA256); rescueErr != nil {
            err = errors.Join(err, fmt.Errorf("CRITICAL: independent DNS recovery unverified; protected journal must remain pending: %w", rescueErr))
            return
        }
        // An acknowledgment from a watchdog is not proof that Windows DNS
        // was actually restored. Independently inspect every family again.
        if readbackErr := verifyDNSActivationTransition(recoveryCtx, records, backend, 0); readbackErr != nil {
            err = errors.Join(err, fmt.Errorf("CRITICAL: independent recovery acknowledged completion but original DNS readback failed: %w", readbackErr))
        }
    }()

    for i, record := range records {
        if err = ctx.Err(); err != nil { return err }
        if err = guard.VerifyArmed(ctx, independentlyPinnedSHA256); err != nil {
            return fmt.Errorf("recovery attestation lost before DNS write %d: %w", i+1, err)
        }
        // Recheck ALL families on every step, not only the one being written.
        if err = verifyDNSActivationTransition(ctx, records, backend, i); err != nil {
            return fmt.Errorf("DNS was externally modified before write %d: %w", i+1, err)
        }
        writeAttempted = true // driver may mutate DNS then return an error
        if err = backend.Apply(ctx, record.Expected); err != nil {
            return fmt.Errorf("DNS activation write %d failed: %w", i+1, err)
        }
        if err = verifyDNSActivationTransition(ctx, records, backend, i+1); err != nil {
            return fmt.Errorf("DNS activation write %d could not be independently verified: %w", i+1, err)
        }
    }
    if err = guard.VerifyArmed(ctx, independentlyPinnedSHA256); err != nil {
        return fmt.Errorf("recovery attestation lost after DNS switch: %w", err)
    }
    if err = guard.VerifyLiveProtection(ctx, independentlyPinnedSHA256); err != nil {
        return fmt.Errorf("DNS/Internet blocking health probe rejected activation: %w", err)
    }
    // Health probes can take time. A successful probe is not proof the
    // independent watchdog is still armed at the final commit boundary.
    // Reattest recovery after health checks, and only then recensus DNS.
    if err = guard.VerifyArmed(ctx, independentlyPinnedSHA256); err != nil {
        return fmt.Errorf("recovery attestation lost before activation commit: %w", err)
    }
    if err = verifyDNSActivationTransition(ctx, records, backend, len(records)); err != nil {
        return fmt.Errorf("DNS changed during health checks or final recovery attestation: %w", err)
    }
    if err = ctx.Err(); err != nil { return err }
    if err = guard.CommitActive(ctx, independentlyPinnedSHA256); err != nil {
        return fmt.Errorf("durable protected activation commit failed: %w", err)
    }
    return nil
}

func verifyDNSActivationTransition(
    ctx context.Context, records []DNSRestoreRecord, backend DNSAdapterBackend, activated int,
) error {
    if activated < 0 || activated > len(records) { return errors.New("invalid DNS activation stage") }
    for i, record := range records {
        if err := ctx.Err(); err != nil { return err }
        actual, err := backend.Read(ctx, record.Original.InterfaceGUID, record.Original.Family)
        if err != nil { return fmt.Errorf("read adapter/family %d: %w", i, err) }
        if err := validDNSState(actual); err != nil { return fmt.Errorf("untrusted live DNS adapter/family %d: %w", i, err) }
        expected := record.Original
        if i < activated { expected = record.Expected }
        if !sameDNSState(actual, expected) {
            return fmt.Errorf("adapter/family %d differs from the authenticated DNS transaction stage", i)
        }
    }
    return nil
}
