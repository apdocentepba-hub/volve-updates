package motorupdate

// DNS adapter restoration contract for the future privileged SYSTEM watchdog.
// This module never calls Windows DNS APIs directly; the trusted Windows
// inventory, journal verifier, and DNS adapter backend must be implemented
// separately. In particular, a cached domain count cannot authorize DNS changes.
import (
    "context"
    "errors"
    "fmt"
    "net"
    "sort"
    "strings"
)

type DNSAddressFamily string
const (
    DNSIPv4 DNSAddressFamily = "IPv4"
    DNSIPv6 DNSAddressFamily = "IPv6"
)
type DNSConfigurationMode string
const (
    DNSAutomatic DNSConfigurationMode = "automatic"
    DNSStatic DNSConfigurationMode = "static"
)

// DNSServerState is an exact independently observed configuration. The
// real Windows inspector must establish automatic/static provenance; missing
// information must never be silently treated as DHCP.
type DNSServerState struct {
    InterfaceGUID string
    Family DNSAddressFamily
    Mode DNSConfigurationMode
    Servers []string
}

type DNSRestoreRecord struct {
    Original DNSServerState
    // Expected is the known localhost configuration written by VOLVE.
    Expected DNSServerState
}

// DNSAdapterBackend is owned by a separate, privileged Windows implementation.
// Read and Apply must not select adapters by a human-friendly alias.
// Apply(automatic) must invoke the Windows reset operation and Apply(static)
// must restore the exact ordered manual servers, never inferred DNS values.
type DNSAdapterBackend interface {
    Read(context.Context, string, DNSAddressFamily) (DNSServerState, error)
    Apply(context.Context, DNSServerState) error
}

func validDNSState(s DNSServerState) error {
    guid:=strings.ToLower(strings.TrimSpace(s.InterfaceGUID))
    if len(guid)!=38 || guid[0]!='{' || guid[37]!='}' {
        return errors.New("adapter GUID must be a complete braced Windows GUID")
    }
    for i,ch:=range guid {
        if i==0||i==37 {continue}
        if i==9||i==14||i==19||i==24 {
            if ch!='-' {return errors.New("malformed interface GUID")}
        }else if !strings.ContainsRune("0123456789abcdef",ch) {
            return errors.New("malformed interface GUID")
        }
    }
    if s.Family!=DNSIPv4 && s.Family!=DNSIPv6 {return errors.New("invalid DNS address family")}
    if s.Mode!=DNSAutomatic && s.Mode!=DNSStatic {return errors.New("unknown DNS assignment mode")}
    if s.Mode==DNSAutomatic && len(s.Servers)>0 {return errors.New("automatic state must not carry manual servers")}
    if s.Mode==DNSStatic && len(s.Servers)==0 {return errors.New("static state must list configured servers")}
    for _,v:=range s.Servers {
        if strings.TrimSpace(v)!=v || v=="" {return errors.New("invalid DNS server string")}
        ip:=net.ParseIP(v)
        if ip==nil {return errors.New("not an IP address")}
        if s.Family==DNSIPv4 && ip.To4()==nil {return errors.New("IPv6 DNS in IPv4 family")}
        if s.Family==DNSIPv6 && ip.To4()!=nil {return errors.New("IPv4 DNS in IPv6 family")}
    }
    return nil
}
func sameDNSState(a,b DNSServerState) bool {
    if !strings.EqualFold(a.InterfaceGUID,b.InterfaceGUID) ||
        a.Family!=b.Family || a.Mode!=b.Mode || len(a.Servers)!=len(b.Servers) {return false}
    for i:=range a.Servers {
        x,y:=net.ParseIP(a.Servers[i]),net.ParseIP(b.Servers[i])
        if x==nil || y==nil || !x.Equal(y) {return false}
    }
    return true
}

// RestoreVOLVEDNSAfterFailure first validates ALL adapters/families before
// changing ANY. The caller must have separately proven: protected immutable
// recovery journal, genuine SYSTEM identity, stopped failed motor, exclusive
// transaction lock, and appropriate original link/adapter identity.
// This checks for concurrent external changes immediately before each Apply,
// and it never overwrites anything except VOLVE's exact localhost setting.
// It does NOT modify hosts or browser policy.
func RestoreVOLVEDNSAfterFailure(ctx context.Context,records []DNSRestoreRecord, backend DNSAdapterBackend) error {
    if backend==nil || len(records)==0 {return errors.New("missing recovery backend or journal")}
    if err:=ctx.Err();err!=nil{return err}
    seen:=map[string]bool{}
    ordered:=append([]DNSRestoreRecord(nil),records...)
    sort.Slice(ordered,func(i,j int)bool {
        a,b:=ordered[i],ordered[j]
        return strings.ToLower(a.Original.InterfaceGUID)+string(a.Original.Family) <
               strings.ToLower(b.Original.InterfaceGUID)+string(b.Original.Family)
    })
    for _,r:=range ordered {
        if err:=validDNSState(r.Original);err!=nil{return fmt.Errorf("invalid original DNS state: %w",err)}
        if err:=validDNSState(r.Expected);err!=nil{return fmt.Errorf("invalid expected DNS state: %w",err)}
        if !strings.EqualFold(r.Original.InterfaceGUID,r.Expected.InterfaceGUID) ||
           r.Original.Family!=r.Expected.Family ||
           r.Expected.Mode!=DNSStatic || len(r.Expected.Servers)!=1 {
            return errors.New("recovery journal has inconsistent adapter or expected local DNS")
        }
        expected:="127.0.0.1"
        if r.Expected.Family==DNSIPv6 {expected="::1"}
        if !net.ParseIP(r.Expected.Servers[0]).Equal(net.ParseIP(expected)) {
            return errors.New("unexpected/nonlocal DNS target, refusing restore")
        }
        key:=strings.ToLower(r.Original.InterfaceGUID)+string(r.Original.Family)
        if seen[key]{return errors.New("duplicate adapter/family journal record")}
        seen[key]=true
        current,err:=backend.Read(ctx,r.Original.InterfaceGUID,r.Original.Family)
        if err!=nil{return fmt.Errorf("cannot independently read current adapter state: %w",err)}
        if err:=validDNSState(current);err!=nil{return fmt.Errorf("invalid observed DNS state: %w",err)}
        if !sameDNSState(current,r.Expected) && !sameDNSState(current,r.Original) {
            return errors.New("external DNS change detected; refuse to overwrite it")
        }
    }
    for _,r:=range ordered {
        if err:=ctx.Err();err!=nil{return err}
        current,err:=backend.Read(ctx,r.Original.InterfaceGUID,r.Original.Family)
        if err!=nil{return err}
        if sameDNSState(current,r.Original){continue} // idempotent after partial recovery
        if !sameDNSState(current,r.Expected){return errors.New("DNS changed during rescue; refusing overwrite")}
        if err:=backend.Apply(ctx,r.Original);err!=nil{return fmt.Errorf("DNS restore failed; recovery remains pending: %w",err)}
        after,err:=backend.Read(ctx,r.Original.InterfaceGUID,r.Original.Family)
        if err!=nil{return fmt.Errorf("cannot verify restored DNS state: %w",err)}
        if !sameDNSState(after,r.Original){return errors.New("DNS restoration did not match original; recovery remains pending")}
    }
    return nil
}
