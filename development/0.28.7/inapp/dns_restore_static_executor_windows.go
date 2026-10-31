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
    "sort"
    "strings"
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

// Validate the recovery intent before looking at live Windows state.
// If the original first server was the same VOLVE localhost address,
// an observed single localhost address cannot distinguish before/after
// states. Without an assignment-mode inspector that ambiguity is unsafe.
func validateWindowsStaticRecoveryRecord(r DNSRestoreRecord) error {
    if err := validDNSState(r.Original); err != nil { return err }
    if err := validDNSState(r.Expected); err != nil { return err }
    if r.Original.Mode != DNSStatic {
        return errors.New("automatic DNS provenance not yet attested; refusing to execute")
    }
    if !strings.EqualFold(r.Original.InterfaceGUID,r.Expected.InterfaceGUID) ||
        r.Original.Family != r.Expected.Family ||
        r.Expected.Mode != DNSStatic || len(r.Expected.Servers) != 1 {
        return errors.New("inconsistent protected DNS recovery record")
    }
    loopback := "127.0.0.1"
    if r.Original.Family == DNSIPv6 { loopback = "::1" }
    if !sameDNSAddresses(r.Expected.Servers, []string{loopback}) {
        return errors.New("non-VOLVE localhost DNS expected state")
    }
    if sameDNSAddresses(r.Original.Servers[:1], r.Expected.Servers) {
        return errors.New("original first DNS server equals VOLVE localhost; restore provenance ambiguous")
    }
    return nil
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
    if err := validateWindowsStaticRecoveryRecord(r); err != nil { return err }
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


// ExecuteWindowsStaticDNSRestoreBatch is the multi-adapter transaction gate.
// It validates *every* protected journal record, rejects duplicate interface
// families, and independently inspects *all* live adapters BEFORE any write.
// This prevents an unsafe later IPv6/adapter record from causing a partial
// earlier IPv4 restoration. A caller must still hold a cross-process lock,
// have attested SYSTEM and the sealed journal, and leave the journal pending
// until subsequent DNS/Internet health probes pass.
func ExecuteWindowsStaticDNSRestoreBatch(
    ctx context.Context, records []DNSRestoreRecord,
    inspect WindowsReadOnlyPowerShell, write WindowsDNSRestoreWriter,
) error {
    if len(records) == 0 || inspect == nil || write == nil {
        return errors.New("missing protected DNS recovery records or trusted backend")
    }
    if err := ctx.Err(); err != nil { return err }
    ordered := append([]DNSRestoreRecord(nil), records...)
    sort.Slice(ordered,func(i,j int)bool{
        a,b := ordered[i].Original, ordered[j].Original
        return strings.ToLower(a.InterfaceGUID)+string(a.Family) <
            strings.ToLower(b.InterfaceGUID)+string(b.Family)
    })
    seen := map[string]bool{}
    for _,r := range ordered {
        if err:=validateWindowsStaticRecoveryRecord(r);err!=nil{return err}
        key:=strings.ToLower(r.Original.InterfaceGUID)+string(r.Original.Family)
        if seen[key] {return errors.New("duplicate interface/family in protected DNS recovery journal")}
        seen[key]=true
        if _,_,err:=observeWindowsDNSRestoreStage(ctx,r,inspect);err!=nil {
            return fmt.Errorf("all-adapter preflight refused %s %s: %w",r.Original.InterfaceGUID,r.Original.Family,err)
        }
    }
    for _,r := range ordered {
        if err:=ExecuteWindowsStaticDNSRestore(ctx,r,inspect,write);err!=nil {
            return fmt.Errorf("recovery incomplete for %s %s: %w",r.Original.InterfaceGUID,r.Original.Family,err)
        }
    }
    return nil
}
