//go:build windows

package motorupdate

import (
    "context"
    "encoding/json"
    "errors"
    "reflect"
    "strings"
    "testing"
)

type batchDNSHarness struct {
    live map[DNSAddressFamily][]string
    actions []WindowsDNSCommand
    failAt int
    onInspect func(*batchDNSHarness)
}

func (h *batchDNSHarness) inspect(ctx context.Context, query string) ([]byte,error) {
    if err:=ctx.Err();err!=nil{return nil,err}
    if h.onInspect!=nil { cb:=h.onInspect; h.onInspect=nil; cb(h) }
    switch query {
    case windowsAdapterInventoryQuery:
        return []byte(testWindowsAdapterJSON),nil
    case windowsEffectiveDNSQuery:
        entries:=[]windowsEffectiveDNSRecord{
            {InterfaceIndex:14,Family:"IPv4",Servers:append([]string(nil),h.live[DNSIPv4]...)},
            {InterfaceIndex:14,Family:"IPv6",Servers:append([]string(nil),h.live[DNSIPv6]...)},
        }
        return json.Marshal(entries)
    default:
        return nil,errors.New("unexpected read-only Windows command")
    }
}
func (h *batchDNSHarness) write(ctx context.Context,cmd WindowsDNSCommand)error{
    if err:=ctx.Err();err!=nil{return err}
    if cmd.Program!="netsh.exe" || len(cmd.Args)<7 || cmd.Args[0]!="interface" || cmd.Args[4]!="name=14" {
        return errors.New("unsafe or unbound command")
    }
    family:=DNSIPv4
    if cmd.Args[1]=="ipv6" {family=DNSIPv6} else if cmd.Args[1]!="ipv4" {
        return errors.New("unknown family")
    }
    if cmd.Args[2]!="set" && cmd.Args[2]!="add" {return errors.New("unsupported action")}
    h.actions=append(h.actions,cmd)
    if h.failAt>0 && h.failAt==len(h.actions) {return errors.New("simulated interrupted netsh call")}
    var addr string
    for _,arg:=range cmd.Args {
        if strings.HasPrefix(arg,"address=") {addr=strings.TrimPrefix(arg,"address=")}
    }
    if addr=="" {return errors.New("missing DNS address")}
    if cmd.Args[2]=="set" {h.live[family]=[]string{addr}} else {h.live[family]=append(h.live[family],addr)}
    return nil
}

func batchFixture()(DNSRestoreRecord,DNSRestoreRecord,*batchDNSHarness){
    v4:=restoreFixture(DNSIPv4,DNSStatic,"9.9.9.9","1.1.1.1")
    v6:=restoreFixture(DNSIPv6,DNSStatic,"2606:4700:4700::1111")
    h:=&batchDNSHarness{live:map[DNSAddressFamily][]string{
        DNSIPv4:{"127.0.0.1"},
        DNSIPv6:{"::1"},
    }}
    return v4,v6,h
}
func TestWindowsBatchRestoreBothFamiliesAndIdempotent(t *testing.T){
    v4,v6,h:=batchFixture()
    // Caller ordering does not define recovery order.
    records:=[]DNSRestoreRecord{v6,v4}
    if err:=ExecuteWindowsStaticDNSRestoreBatch(context.Background(),records,h.inspect,h.write);err!=nil{t.Fatal(err)}
    if !reflect.DeepEqual(h.live[DNSIPv4],v4.Original.Servers) || !reflect.DeepEqual(h.live[DNSIPv6],v6.Original.Servers){
        t.Fatal("DNS IPv4/IPv6 records were not restored exactly")
    }
    if len(h.actions)!=3{t.Fatalf("unexpected total write count %d",len(h.actions))}
    if err:=ExecuteWindowsStaticDNSRestoreBatch(context.Background(),records,h.inspect,h.write);err!=nil{t.Fatal(err)}
    if len(h.actions)!=3{t.Fatal("idempotent retry modified already restored DNS")}
}
func TestWindowsBatchRestoreRejectsSecondFamilyBeforeAnyWrite(t *testing.T){
    v4,v6,h:=batchFixture()
    h.live[DNSIPv6]=[]string{"2001:4860:4860::8888"}
    if err:=ExecuteWindowsStaticDNSRestoreBatch(context.Background(),[]DNSRestoreRecord{v4,v6},h.inspect,h.write);err==nil{
        t.Fatal("external IPv6 override was accepted")
    }
    if len(h.actions)!=0 || !reflect.DeepEqual(h.live[DNSIPv4],[]string{"127.0.0.1"}){
        t.Fatal("IPv4 was partially modified before detecting unsafe IPv6")
    }
}
func TestWindowsBatchRestoreResumesAfterInterruptedFamily(t *testing.T){
    v4,v6,h:=batchFixture()
    h.failAt=2
    records:=[]DNSRestoreRecord{v4,v6}
    if err:=ExecuteWindowsStaticDNSRestoreBatch(context.Background(),records,h.inspect,h.write);err==nil{
        t.Fatal("simulated partial recovery did not remain pending")
    }
    if !reflect.DeepEqual(h.live[DNSIPv4],[]string{"9.9.9.9"}) ||
        !reflect.DeepEqual(h.live[DNSIPv6],[]string{"::1"}){t.Fatal("unexpected state after interruption")}
    h.failAt=0
    if err:=ExecuteWindowsStaticDNSRestoreBatch(context.Background(),records,h.inspect,h.write);err!=nil{t.Fatal(err)}
    if !reflect.DeepEqual(h.live[DNSIPv4],v4.Original.Servers) ||
        !reflect.DeepEqual(h.live[DNSIPv6],v6.Original.Servers){t.Fatal("failed to resume partial restore")}
}
func TestWindowsBatchRestoreRejectsDuplicateAndUnknownAutomaticWithoutWrites(t *testing.T){
    v4,v6,h:=batchFixture()
    if err:=ExecuteWindowsStaticDNSRestoreBatch(context.Background(),[]DNSRestoreRecord{v4,v4,v6},h.inspect,h.write);err==nil{
        t.Fatal("duplicate family journal record accepted")
    }
    if len(h.actions)!=0{t.Fatal("duplicate record permitted modification")}
    v6.Original.Mode=DNSAutomatic
    v6.Original.Servers=nil
    if err:=ExecuteWindowsStaticDNSRestoreBatch(context.Background(),[]DNSRestoreRecord{v4,v6},h.inspect,h.write);err==nil{
        t.Fatal("automatic provenance was not verified")
    }
    if len(h.actions)!=0{t.Fatal("unverified DHCP intent permitted modification")}
}
func TestWindowsBatchRejectsAmbiguousOriginalLoopbackWithoutWrites(t *testing.T){
    v4,v6,h:=batchFixture()
    v4.Original.Servers=[]string{"127.0.0.1","1.1.1.1"}
    if err:=ExecuteWindowsStaticDNSRestoreBatch(context.Background(),[]DNSRestoreRecord{v6,v4},h.inspect,h.write);err==nil{
        t.Fatal("ambiguous localhost source accepted")
    }
    if len(h.actions)!=0{t.Fatal("ambiguous original DNS permitted write")}
}
