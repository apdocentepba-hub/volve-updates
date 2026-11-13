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
    index,err:=FindWindowsAdapterIndex(ctx,r.Original.InterfaceGUID,inspect)
    if err!=nil{return 0,0,err}
    evidence,err:=InspectWindowsDNSAssignmentProvenanceReadOnly(ctx,inspect)
    if err!=nil{return 0,0,fmt.Errorf("cannot attest current DNS assignment source: %w",err)}
    var current *DNSServerState
    for i:=range evidence.States{
        state:=&evidence.States[i]
        if strings.EqualFold(state.InterfaceGUID,r.Original.InterfaceGUID)&&state.Family==r.Original.Family{
            if current!=nil{return 0,0,errors.New("duplicate live adapter/family DNS provenance")}
            current=state
        }
    }
    if current==nil{return 0,0,errors.New("original adapter/family missing from DNS provenance census")}
    checked,err:=FindWindowsAdapterIndex(ctx,r.Original.InterfaceGUID,inspect)
    if err!=nil||checked!=index{
        return 0,0,errors.New("Windows adapter identity changed during DNS restore")
    }
    cmds,err:=PlanWindowsDNSRestore(r.Original,index)
    if err!=nil{return 0,0,err}
    if r.Original.Mode==DNSAutomatic{
        if sameDNSState(*current,r.Original){return index,len(cmds),nil}
        if sameDNSState(*current,r.Expected){return index,0,nil}
        return 0,0,errors.New("automatic DNS source is neither original nor exact VOLVE localhost; external change refused")
    }
    if current.Mode!=DNSStatic{return 0,0,errors.New("static DNS source changed to automatic or unknown mode")}
    // Prefer the longest exact historical prefix to resume an interrupted
    // multi-server restore without replacing any unrelated DNS value.
    for n:=len(r.Original.Servers);n>0;n--{
        prefix:=DNSServerState{InterfaceGUID:r.Original.InterfaceGUID,Family:r.Original.Family,Mode:DNSStatic,Servers:r.Original.Servers[:n]}
        if sameDNSState(*current,prefix){return index,n,nil}
    }
    if sameDNSState(*current,r.Expected){return index,0,nil}
    return 0,0,errors.New("unexpected DNS assignment source; external change or unsafe partial restore")
}

// validateWindowsDNSRecoveryRecord validates both static and automatic
// original DNS provenance. Expected is always VOLVE's exact localhost source.
func validateWindowsDNSRecoveryRecord(r DNSRestoreRecord) error {
    if err:=validDNSState(r.Original);err!=nil{return err}
    if err:=validDNSState(r.Expected);err!=nil{return err}
    if !strings.EqualFold(r.Original.InterfaceGUID,r.Expected.InterfaceGUID)||
        r.Original.Family!=r.Expected.Family||r.Expected.Mode!=DNSStatic||len(r.Expected.Servers)!=1{
        return errors.New("inconsistent protected DNS recovery record")
    }
    loopback:="127.0.0.1"
    if r.Original.Family==DNSIPv6{loopback="::1"}
    if !sameDNSAddresses(r.Expected.Servers,[]string{loopback}){
        return errors.New("non-VOLVE localhost DNS expected state")
    }
    if r.Original.Mode==DNSStatic&&sameDNSAddresses(r.Original.Servers[:1],r.Expected.Servers){
        return errors.New("original first DNS server equals VOLVE localhost; restore provenance ambiguous")
    }
    return nil
}

// validateWindowsStaticRecoveryRecord preserves the older static-only entry
// point. New transaction callers should use validateWindowsDNSRecoveryRecord.
func validateWindowsStaticRecoveryRecord(r DNSRestoreRecord) error {
    if err:=validateWindowsDNSRecoveryRecord(r);err!=nil{return err}
    if r.Original.Mode!=DNSStatic{
        return errors.New("automatic DNS recovery requires the provenance-aware executor")
    }
    return nil
}

// ExecuteWindowsDNSRestore resumes a verified static prefix or restores an
// original automatic (DHCP/RA) assignment using source-mode provenance.
// Every write is rechecked against the live GUID and source before/after.
func ExecuteWindowsDNSRestore(
    ctx context.Context, r DNSRestoreRecord,
    inspect WindowsReadOnlyPowerShell, write WindowsDNSRestoreWriter,
) error {
    if inspect == nil || write == nil { return errors.New("trusted DNS inspector and writer required") }
    if err := ctx.Err(); err != nil { return err }
    if err := validateWindowsDNSRecoveryRecord(r); err != nil { return err }
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



// ExecuteWindowsStaticDNSRestore is the compatibility entry point for callers
// that explicitly require a static original DNS assignment.
func ExecuteWindowsStaticDNSRestore(
    ctx context.Context,r DNSRestoreRecord,inspect WindowsReadOnlyPowerShell,write WindowsDNSRestoreWriter,
)error{
    if err:=validateWindowsDNSRecoveryRecord(r);err!=nil{return err}
    return ExecuteWindowsDNSRestore(ctx,r,inspect,write)
}

// ExecuteWindowsDNSRestoreBatch is the multi-adapter transaction gate for static and automatic original assignments.
// It validates *every* protected journal record, rejects duplicate interface
// families, and independently inspects *all* live adapters BEFORE any write.
// This prevents an unsafe later IPv6/adapter record from causing a partial
// earlier IPv4 restoration. A caller must still hold a cross-process lock,
// have attested SYSTEM and the sealed journal, and leave the journal pending
// until subsequent DNS/Internet health probes pass.
func ExecuteWindowsDNSRestoreBatch(
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
        if err:=ExecuteWindowsDNSRestore(ctx,r,inspect,write);err!=nil {
            return fmt.Errorf("recovery incomplete for %s %s: %w",r.Original.InterfaceGUID,r.Original.Family,err)
        }
    }
    return nil
}

 
// ExecuteWindowsStaticDNSRestoreBatch preserves the static-only API contract.
func ExecuteWindowsStaticDNSRestoreBatch(
    ctx context.Context,records []DNSRestoreRecord,inspect WindowsReadOnlyPowerShell,write WindowsDNSRestoreWriter,
)error{
    for _,record:=range records{
        if err:=validateWindowsStaticRecoveryRecord(record);err!=nil{return err}
    }
    return ExecuteWindowsDNSRestoreBatch(ctx,records,inspect,write)
}
