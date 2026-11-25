//go:build windows

package main

import (
 "crypto/rand"
 "syscall"
	"bytes"
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
 // An RCODE=NOERROR with ANCOUNT=0 is NOT a successful DNS resolution.
 // Prove a usable A answer, over both transport protocols and address
 // families, from the real separate SYSTEM process. The address is the
 // TEST-NET-3 fixture (203.0.113.7), not a public Internet lookup.
 for _,network:=range []string{"udp","tcp"}{
  for _,host:=range []string{"127.0.0.1","::1"}{
   ctx,stop:=context.WithTimeout(context.Background(),3*time.Second)
   err:=assertCIFreshAllowedARecord(ctx,network,net.JoinHostPort(host,"53"))
   stop()
   if err!=nil{t.Fatalf("allowlisted A record absent over %s %s: %v",network,host,err)}
  }
 }
 t.Log("PASS: independent SYSTEM DNS/53 UDP/TCP IPv4/IPv6 blocks gambling names and actually forwards an allowed A record (203.0.113.7 fixture)")
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


// assertCIFreshAllowedARecord is a black-box test of the ACTUAL DNS wire
// response from the resident SYSTEM motor. It rejects NOERROR/zero answers.
func assertCIFreshAllowedARecord(ctx context.Context,network,addr string)error{
 if network!="tcp" && network!="udp"{return fmt.Errorf("unexpected DNS transport")}
 question:=[]byte{7,'e','x','a','m','p','l','e',3,'o','r','g',0,0,1,0,1}
 query:=[]byte{0x6f,0x18,1,0,0,1,0,0,0,0,0,0}
 query=append(query,question...)
 dialer:=net.Dialer{}
 conn,err:=dialer.DialContext(ctx,network,addr)
 if err!=nil{return err}
 defer conn.Close()
 if deadline,ok:=ctx.Deadline();ok{
  if err:=conn.SetDeadline(deadline);err!=nil{return err}
 }
 var response []byte
 if network=="tcp"{
  framed:=make([]byte,2+len(query))
  binary.BigEndian.PutUint16(framed[:2],uint16(len(query)))
  copy(framed[2:],query)
  for len(framed)>0{
   n,e:=conn.Write(framed)
   if e!=nil{return e}
   if n==0{return io.ErrShortWrite}
   framed=framed[n:]
  }
  var length [2]byte
  if _,err:=io.ReadFull(conn,length[:]);err!=nil{return err}
  size:=int(binary.BigEndian.Uint16(length[:]))
  if size<len(query)+16 || size>4096{return fmt.Errorf("invalid allowed DNS TCP answer size")}
  response=make([]byte,size)
  if _,err:=io.ReadFull(conn,response);err!=nil{return err}
 }else{
  if _,err:=conn.Write(query);err!=nil{return err}
  b:=make([]byte,4096)
  n,e:=conn.Read(b)
  if e!=nil{return e}
  response=b[:n]
 }
 if len(response)<len(query)+16{return fmt.Errorf("NOERROR without a usable allowed-domain answer")}
 if !bytes.Equal(response[:2],query[:2]) || response[2]&0x80==0 ||
    response[3]&0x0f!=0 || binary.BigEndian.Uint16(response[4:6])!=1 ||
    binary.BigEndian.Uint16(response[6:8])!=1{
  return fmt.Errorf("allowed DNS response ID/rcode/question/answer count invalid")
 }
 if !bytes.Equal(response[12:len(query)],query[12:]){
  return fmt.Errorf("DNS question changed during forwarding")
 }
 // The isolated test upstream returns a real compressed A record for
 // example.org. Reject an empty/no-data referral or an unrelated address.
 expectedAnswer:=[]byte{0xC0,0x0C,0,1,0,1,0,0,0,60,0,4,203,0,113,7}
 if !bytes.Equal(response[len(query):],expectedAnswer){
  return fmt.Errorf("allowed DNS answer differs from expected test fixture")
 }
 return nil
}

// Independent Windows DNS API diagnostic: no explicit DNS server, no
// changes to DNS settings, no hosts/cache lookup. The unique fixture
// name is resolved only by the isolated actual motor's test upstream.
// This observation never overrides a failed configured cmdlet gate.
func TestCIConfiguredNativeTCPDNS(t *testing.T) {
 if os.Getenv("VOLVE_CI_FRESH_DNS53_PROBE")!="GITHUB-HOSTED-VM-ONLY" ||
    os.Getenv("VOLVE_CI_NESTED_GUEST_DNS")!="PRIVATE_GUEST_ONLY" {
  t.Skip("private nested guest only")
 }
 var nonce [16]byte
 if _,err:=rand.Read(nonce[:]);err!=nil {t.Fatal(err)}
 name:=fmt.Sprintf("%x.volve-motor-ci.test.",nonce)
 // windns.h: USE_TCP_ONLY, BYPASS_CACHE, NO_HOSTS_FILE, NO_NETBT.
 const options=0x2|0x8|0x40|0x80
 var records *syscall.DNSRecord
 err:=syscall.DnsQuery(name,syscall.DNS_TYPE_A,options,nil,&records,nil)
 if records!=nil {defer syscall.DnsRecordListFree(records,1)}
 if err!=nil {t.Fatalf("native DnsQuery_W configured TCP status: %v",err)}
 count:=0
 for rec,n:=records,0;rec!=nil;rec,n=rec.Next,n+1 {
  if n>=64 {t.Fatal("unexpectedly long DNS record chain")}
  if rec.Type!=syscall.DNS_TYPE_A || rec.Dw&3!=syscall.DnsSectionAnswer {continue}
  if rec.Length!=4 || !bytes.Equal(rec.Data[:4],[]byte{203,0,113,7}) {t.Fatal("native TCP returned unexpected A record")}
  count++
 }
 if count!=1 {t.Fatalf("native TCP returned %d matching A records, expected one",count)}
 t.Log("PASS VOLVE_NATIVE_DNSQUERY_CONFIGURED_TCP")
}

// Compare an exact allowed challenge over a fresh TCP connection and then
// a second challenge on the SAME socket. This is an independent diagnostic
// of connection reuse, not a substitute for the configured Windows client.
// No data is sent anywhere except the attested isolated loopback motor.
func TestCIResidentTCPConnectionReuse(t *testing.T) {
 if os.Getenv("VOLVE_CI_FRESH_DNS53_PROBE")!="GITHUB-HOSTED-VM-ONLY" ||
    os.Getenv("VOLVE_CI_NESTED_GUEST_DNS")!="PRIVATE_GUEST_ONLY" {
  t.Skip("private nested guest only")
 }
 for _,host:=range []string{"127.0.0.1","::1"} {
  t.Run(host,func(t *testing.T){
   ctx,cancel:=context.WithTimeout(context.Background(),8*time.Second)
   defer cancel()
   var dialer net.Dialer
   c,err:=dialer.DialContext(ctx,"tcp",net.JoinHostPort(host,"53"))
   if err!=nil{t.Fatal(err)}
   defer c.Close()
   if deadline,ok:=ctx.Deadline();ok{if err=c.SetDeadline(deadline);err!=nil{t.Fatal(err)}}
   for attempt:=1;attempt<=2;attempt++{
    var nonce [16]byte
    if _,err=rand.Read(nonce[:]);err!=nil{t.Fatal(err)}
    question:=[]byte{32}
    question=append(question,[]byte(fmt.Sprintf("%x",nonce))...)
    for _,label:=range []string{"volve-motor-ci","test"}{
     question=append(question,byte(len(label)))
     question=append(question,[]byte(label)...)
    }
    question=append(question,0,0,1,0,1)
    message:=append([]byte{0x6f,byte(attempt),1,0,0,1,0,0,0,0,0,0},question...)
    packet:=make([]byte,2+len(message))
    binary.BigEndian.PutUint16(packet[:2],uint16(len(message)))
    copy(packet[2:],message)
    for len(packet)>0{
     n,e:=c.Write(packet)
     if e!=nil{t.Fatalf("connection query %d write: %v",attempt,e)}
     if n==0{t.Fatal(io.ErrShortWrite)}
     packet=packet[n:]
    }
    var length [2]byte
    if _,err=io.ReadFull(c,length[:]);err!=nil{t.Fatalf("connection query %d frame: %v",attempt,err)}
    size:=int(binary.BigEndian.Uint16(length[:]))
    if size!=len(message)+16{t.Fatalf("query %d unexpected DNS frame length %d",attempt,size)}
    response:=make([]byte,size)
    if _,err=io.ReadFull(c,response);err!=nil{t.Fatalf("connection query %d body: %v",attempt,err)}
    if !bytes.Equal(response[:2],message[:2]) || response[2]&0x80==0 ||
       response[3]&0x0f!=0 || binary.BigEndian.Uint16(response[4:6])!=1 ||
       binary.BigEndian.Uint16(response[6:8])!=1 ||
       !bytes.Equal(response[12:len(message)],question) ||
       !bytes.Equal(response[len(message):],[]byte{0xc0,0x0c,0,1,0,1,0,0,0,60,0,4,203,0,113,7}) {
     t.Fatalf("query %d response mismatch",attempt)
    }
    t.Logf("PASS VOLVE_TCP_REUSE_QUERY address=%s sequence=%d",host,attempt)
   }
  })
 }
}
