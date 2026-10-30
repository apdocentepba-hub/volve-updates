//go:build windows

package main

// This test loads the same >=400,000-rule Full catalog required by the
// production runDNSService() path, but ONLY under t.TempDir. It then uses the
// production dnsproxy.Server for a real UDP query on a random loopback port.
// No Task Scheduler, system DNS settings, hosts file, ProgramData or port 53.
import (
    "bufio"
    "context"
    "errors"
    "fmt"
    "net"
    "os"
    "path/filepath"
    "strings"
    "testing"
    "time"

    "volve-browser-protection/dnsproxy"
)

func putLabFullCatalog(t *testing.T,root string,n int) {
    t.Helper()
    feeds:=filepath.Join(root,"catalog","feeds")
    if err:=os.MkdirAll(feeds,0700);err!=nil{t.Fatal(err)}
    f,err:=os.Create(filepath.Join(feeds,"hagezi_gambling_full.txt"))
    if err!=nil{t.Fatal(err)}
    w:=bufio.NewWriterSize(f,1<<20)
    for i:=0;i<n;i++{
        if _,err=fmt.Fprintf(w,"vm-ci-dns-%06d.bet.ar\n",i);err!=nil{
            f.Close();t.Fatal(err)
        }
    }
    if err=w.Flush();err!=nil{f.Close();t.Fatal(err)}
    if err=f.Sync();err!=nil{f.Close();t.Fatal(err)}
    if err=f.Close();err!=nil{t.Fatal(err)}
}

func TestActualFullCatalogRejectsMissingFileAndShortCatalog(t *testing.T) {
    root:=t.TempDir()
    if _,err:=fullEngineAt(root);!errors.Is(err,os.ErrNotExist) {
        t.Fatalf("fullEngine accepted missing Full catalog: %v",err)
    }
    putLabFullCatalog(t,root,300)
    if _,err:=fullEngineAt(root);err==nil || !strings.Contains(err.Error(),"insuficiente") {
        t.Fatalf("short Full catalog unexpectedly accepted: %v",err)
    }
}

func TestActualFullCatalogLoadsAndBlocksOnLiveWindowsUDP(t *testing.T) {
    root:=t.TempDir()
    // Intentional >400k unique records. This exercises blocker.Parse's
    // production lower bound, not a tiny fake list.
    putLabFullCatalog(t,root,400002)
    eng,err:=fullEngineAt(root)
    if err!=nil{t.Fatalf("real Full catalog loader rejected valid fixture: %v",err)}
    free,err:=net.ListenPacket("udp","127.0.0.1:0")
    if err!=nil{t.Fatal(err)}
    port:=free.LocalAddr().(*net.UDPAddr).Port
    free.Close()
    ctx,cancel:=context.WithCancel(context.Background())
    defer cancel()
    srv:=dnsproxy.New(eng,nil)
    done:=make(chan error,1)
    go func(){done<-srv.Run(ctx,"127.0.0.1",port)}()
    select {
    case <-srv.Ready():
    case err:=<-done:t.Fatalf("real catalog server did not start: %v",err)
    case <-time.After(3*time.Second):t.Fatal("real catalog server readiness timed out")
    }
    server:=fmt.Sprintf("127.0.0.1:%d",port)
    for _,domain:=range []string{"stake.com","sub.stake.com","vm-ci-dns-400001.bet.ar"} {
        cctx,stop:=context.WithTimeout(context.Background(),3*time.Second)
        rc,queryErr:=dnsproxy.QueryRCode(cctx,server,domain)
        stop()
        if queryErr!=nil || rc!=3 {
            t.Fatalf("real full engine failed blocking %s (rcode=%d err=%v)",domain,rc,queryErr)
        }
    }
    cancel()
    select {
    case err:=<-done:
        if err!=nil{t.Fatalf("server failed to shut down: %v",err)}
    case <-time.After(3*time.Second):t.Fatal("real DNS socket remained open")
    }
    t.Log("PASS: 400002 Full rules loaded by production parser, 3 blocked UDP queries, temporary localhost port only")
}
