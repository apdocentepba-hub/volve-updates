//go:build windows

package main

// All test DNS sockets bind only loopback on a random non-53 port. The
// production --dns-service entrypoint is NOT executed in Windows CI.
import (
    "context"
    "encoding/binary"
    "errors"
    "io"
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
    // Reuse the same TCP socket for different questions. This independent
    // regression exercises the real DNS runner without changing Windows DNS
    // assignments, opening port 53 or needing a privileged process.
    for _,host:=range []string{"127.0.0.1","::1"}{
        t.Run("tcp-reuse-"+host,func(t *testing.T){
            address:=net.JoinHostPort(host,fmt.Sprint(port))
            conn,err:=(&net.Dialer{Timeout:3*time.Second}).DialContext(ctx,"tcp",address)
            if err!=nil{t.Fatal(err)}
            defer conn.Close()
            if err=conn.SetDeadline(time.Now().Add(5*time.Second));err!=nil{t.Fatal(err)}
            for i,tc:=range []struct{domain string;rcode byte}{
                {"vm-ci-dns-400001.bet.ar",3},
                {"example.org",0},
                {"sub.stake.com",3},
            }{
                id:=uint16(0x7240+i)
                message:=[]byte{byte(id>>8),byte(id),1,0,0,1,0,0,0,0,0,0}
                for _,label:=range strings.Split(tc.domain,"."){
                    message=append(message,byte(len(label)))
                    message=append(message,label...)
                }
                message=append(message,0,0,1,0,1)
                packet:=make([]byte,2+len(message))
                binary.BigEndian.PutUint16(packet[:2],uint16(len(message)))
                copy(packet[2:],message)
                for len(packet)>0{
                    n,e:=conn.Write(packet)
                    if e!=nil{t.Fatalf("sequence %d write: %v",i+1,e)}
                    if n==0{t.Fatal(io.ErrShortWrite)}
                    packet=packet[n:]
                }
                var length [2]byte
                if _,err=io.ReadFull(conn,length[:]);err!=nil{t.Fatalf("sequence %d frame: %v",i+1,err)}
                size:=int(binary.BigEndian.Uint16(length[:]))
                if size<12||size>4096{t.Fatalf("invalid DNS response length %d",size)}
                response:=make([]byte,size)
                if _,err=io.ReadFull(conn,response);err!=nil{t.Fatalf("sequence %d body: %v",i+1,err)}
                if binary.BigEndian.Uint16(response[:2])!=id||response[2]&0x80==0||response[3]&15!=tc.rcode||binary.BigEndian.Uint16(response[4:6])!=1{
                    t.Fatalf("sequence %d wrong transaction or response code: %x",i+1,response[:12])
                }
                t.Logf("PASS VOLVE_EPHEMERAL_TCP_REUSE address=%s sequence=%d rcode=%d",host,i+1,tc.rcode)
            }
        })
    }
    // A retained, idle TCP client must not delay service shutdown for
    // the old 12-second read deadline or the new connection lifetime.
    idle,err:=net.DialTimeout("tcp",net.JoinHostPort("127.0.0.1",fmt.Sprint(port)),2*time.Second)
    if err!=nil{t.Fatal(err)}
    defer idle.Close()
    if err:=idle.SetReadDeadline(time.Now().Add(4*time.Second));err!=nil{t.Fatal(err)}
    cancel()
    select{
    case err:=<-done:
        if !errors.Is(err,context.Canceled) {
            t.Fatalf("dual-stack resident motor exit after cancellation: %v",err)
        }
    case <-time.After(4*time.Second):t.Fatal("resident motor did not shut down after cancellation")
    }
    var closed [1]byte
    if _,err:=idle.Read(closed[:]);err==nil{t.Fatal("idle TCP connection survived shutdown")}else if timeout,ok:=err.(net.Error);ok&&timeout.Timeout(){t.Fatal("idle TCP connection remained open after shutdown")}
    t.Log("PASS: resident service runner on IPv4+IPv6; 400002 Full rules, 4 blocked DNS packets, 2 allowed; localhost ephemeral port only")
    t.Log("PASS VOLVE_TCP_IDLE_SHUTDOWN")
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

// The IPv6 TCP bind is forced to fail after IPv4 starts. Returning an error
// must mean both owned IPv4 listeners and the partial IPv6 UDP listener are
// closed, without touching the independently owned conflicting TCP socket.
func TestResidentDNSRunnerDrainsPartialIPv6Start(t *testing.T){
    root:=t.TempDir()
    putLabFullCatalog(t,root,400002)
    conflict,err:=net.Listen("tcp6","[::1]:0")
    if err!=nil{t.Fatal(err)}
    defer conflict.Close()
    port:=conflict.Addr().(*net.TCPAddr).Port
    if port==53{t.Fatal("refusing production DNS port")}
    ready:=make(chan struct{},1)
    ctx,cancel:=context.WithTimeout(context.Background(),8*time.Second)
    defer cancel()
    err=runDNSServiceAt(ctx,root,port,nil,ready)
    if err==nil||!strings.Contains(err.Error(),"IPv6")||len(ready)!=0{
        t.Fatalf("expected IPv6 partial-start failure without readiness: %v",err)
    }
    for _,host:=range []string{"127.0.0.1","::1"}{
        addr:=net.JoinHostPort(host,fmt.Sprint(port))
        udp,e:=net.ListenPacket("udp",addr)
        if e!=nil{t.Fatalf("owned UDP still bound at return on %s: %v",host,e)}
        udp.Close()
    }
    tcp,e:=net.Listen("tcp4",net.JoinHostPort("127.0.0.1",fmt.Sprint(port)))
    if e!=nil{t.Fatalf("owned IPv4 TCP still bound at return: %v",e)}
    tcp.Close()
    client,e:=net.DialTimeout("tcp6",conflict.Addr().String(),time.Second)
    if e!=nil{t.Fatalf("independent IPv6 listener was disturbed: %v",e)}
    client.Close()
    t.Log("PASS VOLVE_PARTIAL_START_DRAIN")
}
