//go:build windows

package motorupdate

// Experimental static-DNS restoration executor. It is NOT wired to any
// production command or scheduled task. A trusted SYSTEM caller must first
// verify the protected recovery journal, original DNS assignment provenance,
// exclusive transaction lock and stopped failed motor. No default writer exists.
import (
    "context"
    "errors"
    "fmt"
    "net"
)

// WindowsDNSRestoreWriter receives ONLY an exact precomputed netsh argv.
// The callback must use exec.CommandContext with separate arguments, never
// powershell string expansion, shell interpolation or an arbitrary command.
type WindowsDNSRestoreWriter func(context.Context, WindowsDNSCommand) error

func sameDNSAddresses(a, b []string) bool {
    if len(a) != len(b) { return false }
    for i := range a {
        x, y := net.ParseIP(a[i]), net.ParseIP(b[i])
        if x == nil || y == nil || !x.Equal(y) { return false }
    }
    return true
}

// observeWindowsDNSRestoreStage binds GUID to live InterfaceIndex twice.
// Stages: 0=exact VOLVE loopback, k=exact first k historical static servers.
// Any unexpected DNS state or adapter replacement aborts before a write.
func observeWindowsDNSRestoreStage(
    ctx context.Context, r DNSRestoreRecord, inspect WindowsReadOnlyPowerShell,
) (uint32, int, error) {
    index, err := FindWindowsAdapterIndex(ctx, r.Original.InterfaceGUID, inspect)
    if err != nil { return 0, 0, err }
    raw, err := inspect(ctx, windowsEffectiveDNSQuery)
    if err != nil { return 0, 0, err }
    observed, err := parseEffectiveDNS(raw, index, r.Original.Family)
    if err != nil { return 0, 0, err }
    checked, err := FindWindowsAdapterIndex(ctx, r.Original.InterfaceGUID, inspect)
    if err != nil || checked != index {
        return 0, 0, errors.New("Windows adapter identity changed during DNS restore")
    }
    // Prefer the longest historical prefix when its first server also
    // happens to be localhost: then the remaining add commands can resume.
    for n := len(r.Original.Servers); n > 0; n-- {
        if sameDNSAddresses(observed, r.Original.Servers[:n]) { return index, n, nil }
    }
    if sameDNSAddresses(observed, r.Expected.Servers) { return index, 0, nil }
    return 0, 0, errors.New("unexpected DNS state; external change or unsafe partial restore")
}

// ExecuteWindowsStaticDNSRestore resumes from a verified prefix after an
// interrupted multi-server restore, without overwriting unrelated DNS values.
// This pilot deliberately refuses automatic/DHCP mode: effective addresses
// alone cannot prove a restored DHCP/RA assignment source.
func ExecuteWindowsStaticDNSRestore(
    ctx context.Context, r DNSRestoreRecord,
    inspect WindowsReadOnlyPowerShell, write WindowsDNSRestoreWriter,
) error {
    if inspect == nil || write == nil { return errors.New("trusted DNS inspector and writer required") }
    if err := ctx.Err(); err != nil { return err }
    if err := validDNSState(r.Original); err != nil { return err }
    if err := validDNSState(r.Expected); err != nil { return err }
    if r.Original.Mode != DNSStatic {
        return errors.New("automatic DNS provenance not yet attested; refusing to execute")
    }
    if r.Original.InterfaceGUID != r.Expected.InterfaceGUID ||
        r.Original.Family != r.Expected.Family ||
        r.Expected.Mode != DNSStatic || len(r.Expected.Servers) != 1 {
        return errors.New("inconsistent protected DNS recovery record")
    }
    loopback := "127.0.0.1"
    if r.Original.Family == DNSIPv6 { loopback = "::1" }
    if !sameDNSAddresses(r.Expected.Servers, []string{loopback}) {
        return errors.New("non-VOLVE localhost DNS expected state")
    }
    index, stage, err := observeWindowsDNSRestoreStage(ctx, r, inspect)
    if err != nil { return err }
    cmds, err := PlanWindowsDNSRestore(r.Original, index)
    if err != nil { return err }
    for i := stage; i < len(cmds); i++ {
        if err := ctx.Err(); err != nil { return err }
        currentIndex, actualStage, err := observeWindowsDNSRestoreStage(ctx, r, inspect)
        if err != nil { return err }
        if currentIndex != index || actualStage != i {
            return errors.New("DNS changed concurrently; refusing next restore command")
        }
        if err := write(ctx, cmds[i]); err != nil {
            return fmt.Errorf("DNS restore step %d failed; journal remains pending: %w", i+1, err)
        }
        currentIndex, actualStage, err = observeWindowsDNSRestoreStage(ctx, r, inspect)
        if err != nil { return fmt.Errorf("cannot verify DNS restore step %d: %w", i+1, err) }
        if currentIndex != index || actualStage != i+1 {
            return fmt.Errorf("DNS restore step %d not proven; journal remains pending", i+1)
        }
    }
    return nil
}
