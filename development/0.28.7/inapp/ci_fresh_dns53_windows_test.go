//go:build windows

package main

import (
 "context"
 "net"
 "os"
 "testing"
 "time"

 "volve-browser-protection/dnsproxy"
)

// External black-box probe: the real separate SYSTEM process must already be
// running from Windows Task Scheduler. Never starts DNS or changes adapters.
func TestCIFreshResidentSYSTEMPort53(t *testing.T){
 if os.Getenv("VOLVE_CI_FRESH_DNS53_PROBE")!="GITHUB-HOSTED-VM-ONLY"{
  t.Skip("external SYSTEM 53 test only")
 }
 for _,host:=range []string{"127.0.0.1","::1"}{
  addr:=net.JoinHostPort(host,"53")
  deadline:=time.Now().Add(15*time.Second)
  var ready bool
  for time.Now().Before(deadline){
   ctx,stop:=context.WithTimeout(context.Background(),700*time.Millisecond)
   rc,err:=dnsproxy.QueryRCode(ctx,addr,"stake.com")
   stop()
   if err==nil && rc==3{ready=true;break}
   time.Sleep(250*time.Millisecond)
  }
  if !ready{t.Fatalf("separate SYSTEM motor not listening on %s",addr)}
  for _,v:=range []struct{host string;rcode byte}{
   {"stake.com",3},
   {"betwarrior.bet.ar",3},
   {"www.betwarrior.bet.ar",3},
   {"example.org",0},
  }{
   ctx,stop:=context.WithTimeout(context.Background(),3*time.Second)
   rc,err:=dnsproxy.QueryRCode(ctx,addr,v.host)
   stop()
   if err!=nil || rc!=v.rcode{
    t.Fatalf("SYSTEM DNS %s %s: got %d expected %d err=%v",addr,v.host,rc,v.rcode,err)
   }
  }
 }
 t.Log("PASS: independent SYSTEM process responds on real UDP DNS/53 in IPv4/IPv6, blocks gambling hosts, permits normal domain")
}
