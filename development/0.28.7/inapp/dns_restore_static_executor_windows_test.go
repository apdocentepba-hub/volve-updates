//go:build windows

package motorupdate

import (
    "context"
    "encoding/json"
    "errors"
    "reflect"
    "testing"
)

type staticRestoreHarness struct {
    addresses []string
    commands []WindowsDNSCommand
    index uint32
    failAt int
    noWrite bool
}
func (h *staticRestoreHarness) inspect(ctx context.Context, q string) ([]byte,error) {
    if err := ctx.Err(); err != nil { return nil,err }
    switch q {
    case windowsAdapterInventoryQuery:
        return []byte(testWindowsAdapterJSON),nil
    case windowsEffectiveDNSQuery:
        o := []windowsEffectiveDNSRecord{{InterfaceIndex:h.index,Family:"IPv4",Servers:h.addresses}}
        return json.Marshal(o)
    }
    return nil,errors.New("unexpected PowerShell command")
}
func (h *staticRestoreHarness) write(ctx context.Context, cmd WindowsDNSCommand) error {
    if err := ctx.Err(); err != nil { return err }
    h.commands=append(h.commands,cmd)
    if h.failAt>0 && len(h.commands)==h.failAt { return errors.New("power loss simulation") }
    if !h.noWrite {
        if cmd.Program!="netsh.exe" || len(cmd.Args)<6 {return errors.New("unsafe command")}
        if cmd.Args[0]!="interface" || cmd.Args[1]!="ipv4" || cmd.Args[4]!="name=14" {
            return errors.New("wrong adapter command")
        }
        var next string
        for _,a := range cmd.Args { if len(a)>8 && a[:8]=="address=" { next=a[8:] } }
        if next=="" { return errors.New("missing address") }
        if cmd.Args[2]=="set" {h.addresses=[]string{next}} else if cmd.Args[2]=="add" {
            h.addresses=append(h.addresses,next)
        } else {return errors.New("unexpected netsh action")}
    }
    return nil
}
func TestWindowsStaticDNSExecutorRestoresTwoServersWithLiveChecks(t *testing.T) {
    r:=restoreFixture(DNSIPv4,DNSStatic,"9.9.9.9","1.1.1.1")
    h:=&staticRestoreHarness{addresses:[]string{"127.0.0.1"},index:14}
    if err:=ExecuteWindowsStaticDNSRestore(context.Background(),r,h.inspect,h.write);err!=nil{t.Fatal(err)}
    if !reflect.DeepEqual(h.addresses,r.Original.Servers){t.Fatal("wrong final ordered DNS servers")}
    if len(h.commands)!=2 {t.Fatalf("expected both family-scoped commands; got %d",len(h.commands))}
    if err:=ExecuteWindowsStaticDNSRestore(context.Background(),r,h.inspect,h.write);err!=nil{
        t.Fatal("idempotent repeat failed:",err)
    }
    if len(h.commands)!=2 {t.Fatal("already restored DNS was written again")}
}
func TestWindowsStaticDNSExecutorResumesAfterInterruptedWrite(t *testing.T) {
    r:=restoreFixture(DNSIPv4,DNSStatic,"9.9.9.9","1.1.1.1")
    h:=&staticRestoreHarness{addresses:[]string{"127.0.0.1"},index:14,failAt:2}
    if err:=ExecuteWindowsStaticDNSRestore(context.Background(),r,h.inspect,h.write);err==nil {
        t.Fatal("interrupted second command accepted")
    }
    if !reflect.DeepEqual(h.addresses,[]string{"9.9.9.9"}) {t.Fatal("expected verified partial state")}
    h.failAt=0
    if err:=ExecuteWindowsStaticDNSRestore(context.Background(),r,h.inspect,h.write);err!=nil{t.Fatal(err)}
    if !reflect.DeepEqual(h.addresses,r.Original.Servers) {t.Fatal("failed to resume from safe verified prefix")}
    if len(h.commands)!=3 {t.Fatal("retry incorrectly rewrote first server")}
}
func TestWindowsStaticDNSExecutorRejectsUnsafeStatesWithoutWrites(t *testing.T) {
    r:=restoreFixture(DNSIPv4,DNSStatic,"9.9.9.9","1.1.1.1")
    for _,servers:=range [][]string{{"8.8.8.8"},{"9.9.9.9","8.8.8.8"},{"127.0.0.1","8.8.8.8"}} {
        h:=&staticRestoreHarness{addresses:servers,index:14}
        if err:=ExecuteWindowsStaticDNSRestore(context.Background(),r,h.inspect,h.write);err==nil{
            t.Fatalf("external DNS override was approved: %+v",servers)
        }
        if len(h.commands)!=0{t.Fatal("wrote before rejecting external DNS override")}
    }
    automatic:=restoreFixture(DNSIPv4,DNSAutomatic)
    h:=&staticRestoreHarness{addresses:[]string{"127.0.0.1"},index:14}
    if err:=ExecuteWindowsStaticDNSRestore(context.Background(),automatic,h.inspect,h.write);err==nil{
        t.Fatal("unattested DHCP/automatic restoration must remain blocked")
    }
    if len(h.commands)>0{t.Fatal("automatic restoration wrote DNS")}
}
func TestWindowsStaticDNSExecutorRejectsUnprovenWrite(t *testing.T) {
    r:=restoreFixture(DNSIPv4,DNSStatic,"9.9.9.9","1.1.1.1")
    h:=&staticRestoreHarness{addresses:[]string{"127.0.0.1"},index:14,noWrite:true}
    if err:=ExecuteWindowsStaticDNSRestore(context.Background(),r,h.inspect,h.write);err==nil{
        t.Fatal("lying netsh writer accepted without effective DNS confirmation")
    }
    if len(h.commands)!=1 {t.Fatal("continued after unconfirmed first command")}
}
