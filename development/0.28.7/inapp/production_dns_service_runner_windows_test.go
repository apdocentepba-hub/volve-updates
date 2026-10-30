//go:build windows

package main

// All test DNS sockets bind only loopback on a random non-53 port. The
// production --dns-service entrypoint is NOT executed in Windows CI.
import (
    "context"
    "errors"
    "fmt"
    "net"
    "strings"
    "testing"
    "time"

    "volve-browser-protection/dnsproxy"
)

func TestResidentDualStackDNSFullCatalogFromRealRunner(t *testing.T) {
    root:=t.TempDir()
    putLabFullCatalog(t,root,400002)

    upstream,err:=net.ListenPacket("udp4","127.0.0.1:0")
    if err!=nil{t.Fatal(err)}
    defer upstream.Close()
    go func(){
        b:=make([]byte,2048)
        for{
            n,client,e:=upstream.ReadFrom(b)
            if e!=nil{return}
            if n<12{continue}
            answer:=append([]byte(nil),b[:n]...)
            answer[2],answer[3]=0x81,0x80
            _,_=upstream.WriteTo(answer,client)
        }
    }()

    free,err:=net.ListenPacket("udp4","127.0.0.1:0")
    if err!=nil{t.Fatal(err)}
    port:=free.LocalAddr().(*net.UDPAddr).Port
    if err:=free.Close();err!=nil{t.Fatal(err)}
    if port==53{t.Fatal("refusing production DNS port")}
    ctx,cancel:=context.WithCancel(context.Background())
    defer cancel()
    ready:=make(chan struct{},1)
    done:=make(chan error,1)
    go func(){done<-runDNSServiceAt(ctx,root,port,[]string{upstream.LocalAddr().String()},ready)}()

    select{
    case <-ready:
    case e:=<-done:t.Fatalf("resident dual-stack server exited before readiness: %v",e)
    case <-time.After(8*time.Second):t.Fatal("dual-stack server not ready")
    }
    for _,host:=range []string{"127.0.0.1","::1"}{
        address:=net.JoinHostPort(host,fmt.Sprint(port))
        for _,tc:=range []struct{domain string;rcode byte}{
            {"vm-ci-dns-400001.bet.ar",3},
            {"sub.stake.com",3},
            {"example.org",0},
        }{
            queryCtx,stop:=context.WithTimeout(ctx,3*time.Second)
            actual,err:=dnsproxy.QueryRCode(queryCtx,address,tc.domain)
            stop()
            if err!=nil || actual!=tc.rcode {
                t.Fatalf("resident motor via %s: %s rcode=%d expected=%d err=%v",
                    address,tc.domain,actual,tc.rcode,err)
            }
        }
    }
    cancel()
    select{
    case err:=<-done:
        if !errors.Is(err,context.Canceled) {
            t.Fatalf("dual-stack resident motor exit after cancellation: %v",err)
        }
    case <-time.After(4*time.Second):t.Fatal("resident motor did not shut down after cancellation")
    }
    t.Log("PASS: resident service runner on IPv4+IPv6; 400002 Full rules, 4 blocked DNS packets, 2 allowed; localhost ephemeral port only")
}

func TestResidentDNSRunnerFailClosedWithoutFullCatalog(t *testing.T){
    ctx,cancel:=context.WithTimeout(context.Background(),3*time.Second)
    defer cancel()
    _,err:=testMissingRealService(ctx,t.TempDir())
    if err==nil || !strings.Contains(err.Error(),"catalog"){
        t.Fatalf("missing Full catalog did not fail closed: %v",err)
    }
}

func testMissingRealService(ctx context.Context,root string)(bool,error) {
    ready:=make(chan struct{},1)
    err:=runDNSServiceAt(ctx,root,54019,nil,ready)
    return len(ready)!=0,err
}

func TestResidentDNSRunnerRejectsAlreadyBoundIPv4Port(t *testing.T){
    root:=t.TempDir()
    putLabFullCatalog(t,root,400002)
    socket,err:=net.ListenPacket("udp4","127.0.0.1:0")
    if err!=nil{t.Fatal(err)}
    defer socket.Close()
    port:=socket.LocalAddr().(*net.UDPAddr).Port
    if port==53{t.Fatal("unexpected reserved 53 port")}
    ctx,cancel:=context.WithTimeout(context.Background(),5*time.Second)
    defer cancel()
    err=runDNSServiceAt(ctx,root,port,nil,nil)
    if err==nil || !strings.Contains(err.Error(),"IPv4"){
        t.Fatalf("occupied local DNS port incorrectly accepted: %v",err)
    }
}
