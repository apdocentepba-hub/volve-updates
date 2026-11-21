//go:build windows

package main

import (
	"strings"
	"io"
	"fmt"
	"encoding/binary"
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
 // Verify the SAME privileged resident service on real DNS-over-TCP/53.
 // DNS clients can fall back to TCP; a UDP-only PASS is incomplete.
 for _,host:=range []string{"127.0.0.1","::1"}{
  addr:=net.JoinHostPort(host,"53")
  for _,check:=range []struct{domain string;rcode byte}{
   {"stake.com",3},
   {"betwarrior.bet.ar",3},
   {"www.betwarrior.bet.ar",3},
   {"example.org",0},
  }{
   ctx,cancel:=context.WithTimeout(context.Background(),3*time.Second)
   actual,err:=queryCITCPRCode(ctx,addr,check.domain)
   cancel()
   if err!=nil || actual!=check.rcode{
    t.Fatalf("SYSTEM TCP DNS %s %s: got %d expected %d err=%v",addr,check.domain,actual,check.rcode,err)
   }
  }
 }
 t.Log("PASS: independent SYSTEM process responds on real UDP and TCP DNS/53 for IPv4/IPv6; gambling hosts blocked and normal domain allowed")
}

 // queryCITCPRCode is a self-contained, standard-library DNS-over-TCP client.
 // It runs only from the test process: no adapter, DNS policy or service writes.
 // DNS framing: two-byte message size prefix followed by a full DNS message.
func queryCITCPRCode(ctx context.Context, addr, domain string) (byte,error) {
 parts:=strings.Split(strings.TrimSuffix(domain,"."),".")
 question:=make([]byte,0,128)
 for _,label:=range parts{
  if len(label)==0 || len(label)>63{return 0,fmt.Errorf("invalid DNS label")}
  question=append(question,byte(len(label)))
  question=append(question,[]byte(label)...)
 }
 question=append(question,0,0,1,0,1) // root, QTYPE A, QCLASS IN
 message:=[]byte{0x4f,0x21,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00}
 message=append(message,question...)
 if len(message)>65535{return 0,fmt.Errorf("DNS query too large")}
 packet:=make([]byte,2+len(message))
 binary.BigEndian.PutUint16(packet[0:2],uint16(len(message)))
 copy(packet[2:],message)
 var dialer net.Dialer
 conn,err:=dialer.DialContext(ctx,"tcp",addr)
 if err!=nil{return 0,err}
 defer conn.Close()
 if deadline,ok:=ctx.Deadline();ok{
  if err:=conn.SetDeadline(deadline);err!=nil{return 0,err}
 }
 for len(packet)>0{
  n,err:=conn.Write(packet)
  if err!=nil{return 0,err}
  if n==0{return 0,io.ErrShortWrite}
  packet=packet[n:]
 }
 var length [2]byte
 if _,err:=io.ReadFull(conn,length[:]);err!=nil{return 0,err}
 size:=int(binary.BigEndian.Uint16(length[:]))
 if size<12 || size>4096{return 0,fmt.Errorf("DNS TCP response size invalid: %d",size)}
 response:=make([]byte,size)
 if _,err:=io.ReadFull(conn,response);err!=nil{return 0,err}
 if response[0]!=0x4f || response[1]!=0x21 || response[2]&0x80==0{
  return 0,fmt.Errorf("DNS TCP response ID or QR flag invalid")
 }
 if binary.BigEndian.Uint16(response[4:6])!=1{
  return 0,fmt.Errorf("DNS TCP question count invalid")
 }
 return response[3]&0x0f,nil
}
