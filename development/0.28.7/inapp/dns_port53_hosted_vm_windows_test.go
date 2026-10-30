//go:build windows

package main

// This test is ONLY for an ephemeral, GitHub-hosted Windows VM. It binds the
// production DNS port 53 on 127.0.0.1 and ::1, using the same service runner
// as --dns-service and a 400k+ temporary Full catalog. It NEVER modifies the
// machine's DNS adapters, ProgramData, Task Scheduler, hosts, firewall or
// public network listeners. A developer's ordinary machine MUST fail closed.
import (
    "context"
    "errors"
    "fmt"
    "net"
    "os"
    "testing"
    "time"

    "volve-browser-protection/dnsproxy"
)

const hostedVM53Authorization = "VOLVE-CI-GITHUB-HOSTED-VM-PORT53-ONLY"

func requireHostedVMPort53(t *testing.T) {
    t.Helper()
    for k,want:=range map[string]string{
        "GITHUB_ACTIONS":"true",
        "RUNNER_ENVIRONMENT":"github-hosted",
        "VOLVE_CI_PORT53_VM_APPROVED":hostedVM53Authorization,
    } {
        if os.Getenv(k)!=want {
            t.Fatalf("REFUSED port 53: %s must be %q; not a confirmed disposable GitHub-hosted VM",k,want)
        }
    }
}

// Require ALL IPv4 and IPv6 UDP/TCP local port-53 endpoints free before the
// lab, rather than disrupting a pre-existing DNS service.
func provePort53Available(t *testing.T) {
    t.Helper()
    var probes []interface{Close()error}
    defer func(){for _,p:=range probes{_ =p.Close()}}()
    for _,tc:=range []struct{network,addr string;udp bool}{
        {"udp4","127.0.0.1:53",true},
        {"udp6","[::1]:53",true},
        {"tcp4","127.0.0.1:53",false},
        {"tcp6","[::1]:53",false},
    } {
        var c interface{Close()error}
        var err error
        if tc.udp {c,err=net.ListenPacket(tc.network,tc.addr)
        }else{c,err=net.Listen(tc.network,tc.addr)}
        if err!=nil{
            t.Fatalf("REFUSED port-53 lab: existing listener or unavailable endpoint %s %s: %v",tc.network,tc.addr,err)
        }
        probes=append(probes,c)
    }
}

func TestResidentDNSPort53GitHubHostedVM(t *testing.T) {
    requireHostedVMPort53(t)
    provePort53Available(t)
    root:=t.TempDir()
    putLabFullCatalog(t,root,400002)
    upstream,err:=net.ListenPacket("udp4","127.0.0.1:0")
    if err!=nil{t.Fatal(err)}
    defer upstream.Close()
    go func(){
        b:=make([]byte,2048)
        for {
            n,peer,e:=upstream.ReadFrom(b)
            if e!=nil{return}
            if n<12{continue}
            ans:=append([]byte(nil),b[:n]...)
            ans[2],ans[3]=0x81,0x80
            _,_=upstream.WriteTo(ans,peer)
        }
    }()

    ctx,cancel:=context.WithCancel(context.Background())
    done:=make(chan error,1)
    ready:=make(chan struct{},1)
    // Always cancel and verify shutdown, even if any assertion fails.
    t.Cleanup(func(){
        cancel()
        select {
        case e:=<-done:
            if !errors.Is(e,context.Canceled) {
                t.Errorf("resident service did not stop cleanly: %v",e)
            }
        case <-time.After(5*time.Second):
            t.Error("resident DNS port 53 remained bound after test cancellation")
        }
    })
    go func(){done<-runDNSServiceAt(ctx,root,53,[]string{upstream.LocalAddr().String()},ready)}()
    select {
    case <-ready:
    case err:=<-done:t.Fatalf("real port-53 dual-stack service did not start: %v",err)
    case <-time.After(10*time.Second):t.Fatal("real port-53 dual-stack service timed out")
    }
    for _,host:=range []string{"127.0.0.1","::1"} {
        addr:=net.JoinHostPort(host,"53")
        for _,q:=range []struct{domain string;rcode byte}{
            {"stake.com",3},
            {"vm-ci-dns-400001.bet.ar",3},
            {"example.org",0},
        } {
            queryCtx,stop:=context.WithTimeout(ctx,3*time.Second)
            rcode,queryErr:=dnsproxy.QueryRCode(queryCtx,addr,q.domain)
            stop()
            if queryErr!=nil || rcode!=q.rcode {
                t.Fatalf("DNS %s domain=%s got rcode=%d, expected=%d, err=%v",addr,q.domain,rcode,q.rcode,queryErr)
            }
        }
    }
    t.Log(fmt.Sprintf("PASS: real resident DNS loopback 53, IPv4 + IPv6, Full 400002, 4 NXDOMAIN, 2 forwarded; temporary GitHub-hosted VM ONLY"))
}
