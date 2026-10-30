//go:build windows

package main

import (
    "context"
    "crypto/sha256"
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "strings"
    "time"

    "volve-browser-protection/dnsproxy"
)

// runDNSServiceAt is the same dual-stack serving loop used by the resident
// --dns-service entrypoint. The production caller supplies its normal root,
// fixed port 53 and upstreams. Only tests supply a throwaway Full catalog,
// random loopback port, fake upstream and a cancellable context.
//
// This function NEVER changes a Windows DNS adapter, task, hosts file or
// firewall rule. It only listens on 127.0.0.1 and ::1.
func runDNSServiceAt(ctx context.Context, root string, port int, upstreams []string, ready chan<- struct{}) error {
    if err:=ctx.Err();err!=nil{return err}
    if !filepath.IsAbs(root) || port<1 || port>65535 {return errors.New("invalid DNS motor root or port")}
    engine,err:=fullEngineAt(root)
    if err!=nil{return fmt.Errorf("DNS Full catalog unavailable: %w",err)}
    running,cancel:=context.WithCancel(ctx)
    defer cancel()

    sv4:=dnsproxy.New(engine,upstreams)
    sv6:=dnsproxy.New(engine,upstreams)
    failures:=make(chan error,2)
    go func(){failures<-sv4.Run(running,"127.0.0.1",port)}()
    select{
    case <-sv4.Ready():
    case err:=<-failures:return fmt.Errorf("IPv4 DNS server did not start: %w",err)
    case <-ctx.Done():return ctx.Err()
    case <-time.After(10*time.Second):return errors.New("UDP IPv4 no inició")
    }
    go func(){failures<-sv6.Run(running,"::1",port)}()
    select{
    case <-sv6.Ready():
    case err:=<-failures:return fmt.Errorf("IPv6 DNS server did not start: %w",err)
    case <-ctx.Done():return ctx.Err()
    case <-time.After(10*time.Second):return errors.New("UDP IPv6 no inició")
    }
    if ready!=nil {
        select{
        case ready<-struct{}{}:
        case <-ctx.Done():return ctx.Err()
        }
    }
    tick:=time.NewTicker(5*time.Minute)
    defer tick.Stop()
    last:=serviceFeedSignatureAt(root)
    for {
        select {
        case <-ctx.Done():return ctx.Err()
        case err:=<-failures:return err
        case <-tick.C:
            stamp:=serviceFeedSignatureAt(root)
            if stamp==last{continue}
            updated,err:=fullEngineAt(root)
            if err!=nil{continue}
            sv4.SwapRules(updated)
            sv6.SwapRules(updated)
            last=stamp
        }
    }
}

func serviceFeedSignatureAt(root string) [32]byte {
    names:=[]string{"hagezi_gambling_full","hagezi_gambling_medium","stevenblack_gambling","arkynx_gambling"}
    var parts []string
    for _,name:=range names {
        p:=filepath.Join(root,"catalog","feeds",name+".txt")
        if f,e:=os.Stat(p);e==nil {
            parts=append(parts,name,fmt.Sprint(f.ModTime().UnixNano()),fmt.Sprint(f.Size()))
        }
    }
    return sha256.Sum256([]byte(strings.Join(parts,"|")))
}
