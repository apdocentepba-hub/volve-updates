//go:build windows

package main

import (
 "crypto/rand"
 "errors"
 "math/bits"
 "runtime"
 "unsafe"
 "strconv"
 "sync"
 "sync/atomic"
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
 return assertCIFreshAllowedARecordWithDialer(ctx,network,addr,net.Dialer{})
}

func assertCIFreshAllowedARecordWithDialer(ctx context.Context,network,addr string,dialer net.Dialer)error{
 if network!="tcp" && network!="udp"{return fmt.Errorf("unexpected DNS transport")}
 question:=[]byte{7,'e','x','a','m','p','l','e',3,'o','r','g',0,0,1,0,1}
 query:=[]byte{0x6f,0x18,1,0,0,1,0,0,0,0,0,0}
 query=append(query,question...)
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
 nested:=os.Getenv("VOLVE_CI_NESTED_GUEST_DNS")=="PRIVATE_GUEST_ONLY"
 hosted:=os.Getenv("GITHUB_ACTIONS")=="true" &&
  os.Getenv("RUNNER_ENVIRONMENT")=="github-hosted" &&
  os.Getenv("VOLVE_CI_TCP_REUSE_PROBE")=="OWNED_SYSTEM_LOOPBACK_ONLY"
 if os.Getenv("VOLVE_CI_FRESH_DNS53_PROBE")!="GITHUB-HOSTED-VM-ONLY" || (!nested && !hosted) {
  t.Skip("private nested guest or explicitly authorized hosted SYSTEM loopback trial only")
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

// Isolate Winsock outgoing-interface selection from the motor's DNS parser.
// Both families exercise identical wire queries with three socket policies:
// OS default, exact loopback interface, exact private adapter. No persistent
// route, adapter, firewall or DNS configuration is changed. The native
// configured-resolver gate remains mandatory regardless of this diagnostic.
func TestCIResidentTCPInterfaceSelection(t *testing.T){
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"||
  os.Getenv("VOLVE_CI_NESTED_GUEST_DNS")!="PRIVATE_GUEST_ONLY"||
  os.Getenv("VOLVE_CI_FRESH_DNS53_PROBE")!="GITHUB-HOSTED-VM-ONLY"{
  t.Skip("isolated hosted private guest only")
 }
 index:=func(name string)int{
  n,err:=strconv.Atoi(os.Getenv(name))
  if err!=nil||n<=0||n>0xffffff{t.Fatalf("invalid attested interface index %s",name)}
  return n
 }
 private:=index("VOLVE_CI_PRIVATE_NIC_INDEX")
 v4loop:=index("VOLVE_CI_LOOPBACK_V4_INDEX")
 v6loop:=index("VOLVE_CI_LOOPBACK_V6_INDEX")
 if private==v4loop||private==v6loop{t.Fatal("private and loopback indexes must differ")}
 for _,family:=range []struct{host string;loop,level int;ipv4 bool}{
  {"127.0.0.1",v4loop,syscall.IPPROTO_IP,true},
  {"::1",v6loop,syscall.IPPROTO_IPV6,false},
 }{
  for _,policy:=range []struct{name string;idx int}{{"default",0},{"loopback",family.loop},{"private",private}}{
   ctx,cancel:=context.WithTimeout(context.Background(),4*time.Second)
   d:=net.Dialer{}
   optionApplied:=false
   if policy.idx!=0{
    d.Control=func(network,address string,raw syscall.RawConn)error{
     if (family.ipv4&&network!="tcp4")||(!family.ipv4&&network!="tcp6"){return errors.New("wrong socket family")}
     var sockErr error
     value:=uint32(policy.idx)
     // Windows SDK: IP_UNICAST_IF=31 uses network byte order;
     // IPV6_UNICAST_IF=31 uses host byte order.
     if family.ipv4{value=bits.ReverseBytes32(value)}
     if err:=raw.Control(func(fd uintptr){
      sockErr=syscall.SetsockoptInt(syscall.Handle(fd),family.level,31,int(value))
      optionApplied=sockErr==nil
     });err!=nil{return err}
     return sockErr
    }
   }
   err:=assertCIFreshAllowedARecordWithDialer(ctx,"tcp",net.JoinHostPort(family.host,"53"),d)
   cancel()
   code:=uint64(0)
   var errno syscall.Errno
   if errors.As(err,&errno){code=uint64(errno)}
   t.Logf("VOLVE_TCP_INTERFACE_OBSERVATION host=%s policy=%s index=%d option_applied=%t answer_verified=%t winsock=%d error=%v",family.host,policy.name,policy.idx,optionApplied,err==nil,code,err)
   if policy.idx==0&&err!=nil{t.Errorf("unbound control failed: %v",err)}
   if policy.idx!=0&&!optionApplied{t.Errorf("interface option not applied for %s %s",family.host,policy.name)}
  }
 }
 // Compare the native DNS API's interface selection, using the same
 // actual running motor and configured resolver, without an explicit server.
 // Every call has a fresh reserved challenge. The outer Go test process
 // enforces a bounded timeout; no DNS configuration is changed.
 if unsafe.Sizeof(uintptr(0))!=8{t.Fatal("DnsQueryEx diagnostic requires Win64")}
 proc:=syscall.NewLazyDLL("dnsapi.dll").NewProc("DnsQueryEx")
 if err:=proc.Find();err!=nil{t.Fatal(err)}
 type queryRequest struct{
  Version uint32
  Name *uint16
  Type uint16
  Options uint64
  Servers uintptr
  InterfaceIndex uint32
  Callback uintptr
  Context uintptr
 }
 type queryResult struct{
  Version uint32
  Status int32
  Options uint64
  Records *syscall.DNSRecord
  Reserved uintptr
 }
 var layout queryRequest
 var resultLayout queryResult
 // windns.h DNS_QUERY_REQUEST / DNS_QUERY_RESULT, Win64 ABI.
 if unsafe.Sizeof(layout)!=64||unsafe.Offsetof(layout.Options)!=24||unsafe.Offsetof(layout.InterfaceIndex)!=40||unsafe.Offsetof(layout.Callback)!=48||
  unsafe.Sizeof(resultLayout)!=32||unsafe.Offsetof(resultLayout.Records)!=16{t.Fatal("unexpected Win64 native DNS ABI")}
 policies:=[]struct{name string;idx int}{{"default",0},{"loopback-v4",v4loop},{"private",private}}
 if v6loop!=v4loop{policies=append(policies,struct{name string;idx int}{"loopback-v6",v6loop})}
 for _,policy:=range policies{
  var nonce [16]byte
  if _,err:=rand.Read(nonce[:]);err!=nil{t.Fatal(err)}
  name,err:=syscall.UTF16PtrFromString(fmt.Sprintf("%x.volve-motor-ci.test.",nonce))
  if err!=nil{t.Fatal(err)}
  request:=queryRequest{Version:1,Name:name,Type:syscall.DNS_TYPE_A,Options:0x2|0x8|0x40|0x80,InterfaceIndex:uint32(policy.idx)}
  result:=queryResult{Version:1}
  status,_,_:=proc.Call(uintptr(unsafe.Pointer(&request)),uintptr(unsafe.Pointer(&result)),0)
  runtime.KeepAlive(name)
  runtime.KeepAlive(&request)
  count:=0
  valid:=status==0&&result.Status==0
  if valid{
   for rec,n:=result.Records,0;rec!=nil;rec,n=rec.Next,n+1{
    if n>=64{valid=false;break}
    if rec.Type==syscall.DNS_TYPE_A&&rec.Dw&3==syscall.DnsSectionAnswer{
     if rec.Length!=4||!bytes.Equal(rec.Data[:4],[]byte{203,0,113,7}){valid=false;break}
     count++
    }
   }
  }
  if result.Records!=nil{syscall.DnsRecordListFree(result.Records,1)}
  runtime.KeepAlive(&result)
  verified:=valid&&count==1
  t.Logf("VOLVE_DNSQUERYEX_INTERFACE_OBSERVATION policy=%s index=%d status=%d result_status=%d answer_verified=%t",policy.name,policy.idx,uint32(status),result.Status,verified)
  if status==0&&result.Status==0&&!verified{t.Error("DnsQueryEx success did not return exact fixture A record")}
 }
}

// Independent reference server for the configured DNS failure experiment.
// It implements only the exact reserved A/IN challenge and fixed control
// example.org; no forwarding, catalog, adapter changes or production code.
func ciReferenceDNSReply(q []byte,challenge string)([]byte,bool,error){
 if len(q)<17||len(q)>4096||q[2]&0xfe!=0||q[3]&0x80!=0||
  binary.BigEndian.Uint16(q[4:6])!=1||binary.BigEndian.Uint16(q[6:8])!=0||
  binary.BigEndian.Uint16(q[8:10])!=0{return nil,false,errors.New("invalid reference query")}
 off:=12
 var labels []string
 for {
  if off>=len(q){return nil,false,io.ErrUnexpectedEOF}
  n:=int(q[off]);off++
  if n==0{break}
  if n>63||off+n>len(q)||len(labels)>=3{return nil,false,errors.New("invalid reference labels")}
  labels=append(labels,strings.ToLower(string(q[off:off+n])));off+=n
 }
 if off+4>len(q)||binary.BigEndian.Uint16(q[off:off+2])!=1||
  binary.BigEndian.Uint16(q[off+2:off+4])!=1{return nil,false,errors.New("reference requires A/IN")}
 off+=4
 extra:=binary.BigEndian.Uint16(q[10:12])
 if extra==0{
  if off!=len(q){return nil,false,errors.New("trailing reference query data")}
 }else{
  if extra!=1||off+11>len(q)||q[off]!=0||binary.BigEndian.Uint16(q[off+1:off+3])!=41||
   off+11+int(binary.BigEndian.Uint16(q[off+9:off+11]))!=len(q){return nil,false,errors.New("invalid reference EDNS")}
 }
 name:=strings.Join(labels,".")
 match:=name==challenge
 if !match&&name!="example.org"{return nil,false,errors.New("not an owned reference challenge")}
 answer:=append([]byte(nil),q[:off]...)
 answer[2]=0x81;answer[3]=0x80
 for i:=6;i<12;i++{answer[i]=0}
 answer[7]=1
 answer=append(answer,0xc0,0x0c,0,1,0,1,0,0,0,60,0,4,203,0,113,7)
 return answer,match,nil
}

func TestCIConfiguredNativeTCPReferenceControl(t *testing.T){
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"||
  os.Getenv("VOLVE_CI_NESTED_GUEST_DNS")!="PRIVATE_GUEST_ONLY"||
  os.Getenv("VOLVE_CI_REFERENCE_DNS53")!="MOTOR_STOPPED_PRIVATE_LOOPBACK_ONLY"{
  t.Skip("independent private guest reference control only")
 }
 var nonce [16]byte
 if _,err:=rand.Read(nonce[:]);err!=nil{t.Fatal(err)}
 challenge:=fmt.Sprintf("%x.volve-motor-ci.test",nonce)
 var listeners []net.Listener
 var packets []net.PacketConn
 var workers sync.WaitGroup
 var acceptedTCP,queryTCP,replyTCP,queryUDP,replyUDP atomic.Int32
 // All listening sockets are exact loopback addresses and only live within
 // this test process. The invoking script verifies no previous port53 owner.
 defer func(){
  for _,l:=range listeners{l.Close()}
  for _,p:=range packets{p.Close()}
  workers.Wait()
 }()
 for _,host:=range []string{"127.0.0.1","::1"}{
  endpoint:=net.JoinHostPort(host,"53")
  l,e:=net.Listen("tcp",endpoint)
  if e!=nil{t.Fatal(e)}
  listeners=append(listeners,l)
  p,e:=net.ListenPacket("udp",endpoint)
  if e!=nil{t.Fatal(e)}
  packets=append(packets,p)
  workers.Add(2)
  go func(l net.Listener){
   defer workers.Done()
   for {
    c,e:=l.Accept();if e!=nil{return}
    acceptedTCP.Add(1)
    func(){
     defer c.Close()
     _=c.SetDeadline(time.Now().Add(3*time.Second))
     for i:=0;i<4;i++{
      var length [2]byte
      if _,e:=io.ReadFull(c,length[:]);e!=nil{return}
      size:=int(binary.BigEndian.Uint16(length[:]))
      if size<17||size>4096{return}
      q:=make([]byte,size)
      if _,e:=io.ReadFull(c,q);e!=nil{return}
      r,match,e:=ciReferenceDNSReply(q,challenge);if e!=nil{return}
      if match{queryTCP.Add(1)}
      frame:=make([]byte,2+len(r))
      binary.BigEndian.PutUint16(frame[:2],uint16(len(r)));copy(frame[2:],r)
      for len(frame)>0{
       n,e:=c.Write(frame);if e!=nil||n<=0{return};frame=frame[n:]
      }
      if match{replyTCP.Add(1)}
     }
    }()
   }
  }(l)
  go func(p net.PacketConn){
   defer workers.Done()
   buf:=make([]byte,4096)
   for {
    n,peer,e:=p.ReadFrom(buf);if e!=nil{return}
    r,match,e:=ciReferenceDNSReply(buf[:n],challenge);if e!=nil{continue}
    if match{queryUDP.Add(1)}
    if n,e=p.WriteTo(r,peer);e==nil&&n==len(r)&&match{replyUDP.Add(1)}
   }
  }(p)
 }
 // Establish that the reference really serves valid DNS on all four sockets
 // before testing the Windows resolver with no explicit DNS server.
 for _,host:=range []string{"127.0.0.1","::1"}{
  for _,network:=range []string{"udp","tcp"}{
   ctx,cancel:=context.WithTimeout(context.Background(),4*time.Second)
   err:=assertCIFreshAllowedARecord(ctx,network,net.JoinHostPort(host,"53"))
   cancel()
   if err!=nil{t.Fatalf("reference control %s %s failed: %v",host,network,err)}
  }
 }
 before:=acceptedTCP.Load()
 const options=0x2|0x8|0x40|0x80
 var records *syscall.DNSRecord
 err:=syscall.DnsQuery(challenge+".",syscall.DNS_TYPE_A,options,nil,&records,nil)
 if records!=nil{defer syscall.DnsRecordListFree(records,1)}
 count:=0
 if err==nil{
  for rec,n:=records,0;rec!=nil;rec,n=rec.Next,n+1{
   if n>=64{t.Fatal("reference native record chain excessive")}
   if rec.Type==syscall.DNS_TYPE_A&&rec.Dw&3==syscall.DnsSectionAnswer{
    if rec.Length!=4||!bytes.Equal(rec.Data[:4],[]byte{203,0,113,7}){t.Fatal("reference native response unexpected")}
    count++
   }
  }
  if count!=1{t.Fatal("reference native result not an actual answer")}
 }
 // Give the reference write goroutine time to finish recording the reply.
 time.Sleep(100*time.Millisecond)
 t.Logf("VOLVE_REFERENCE_TCP_OBSERVATION raw_four_transports=true native_verified=%t native_error=%v tcp_connections=%d tcp_queries=%d tcp_replies=%d udp_queries=%d udp_replies=%d",err==nil,err,acceptedTCP.Load()-before,queryTCP.Load(),replyTCP.Load(),queryUDP.Load(),replyUDP.Load())
 // A failed configured query is valid diagnostic evidence, not a release PASS.
 if err==nil&&(queryTCP.Load()<1||replyTCP.Load()<1){t.Fatal("native reference success lacks matching TCP wire evidence")}
}

func TestCIReferenceDNSReplyRejectsUnexpectedNames(t *testing.T){
 q:=append([]byte{0x6f,0x18,1,0,0,1,0,0,0,0,0,0},[]byte{7,'e','x','a','m','p','l','e',3,'o','r','g',0,0,1,0,1}...)
 reply,match,err:=ciReferenceDNSReply(q,"reserved.volve-motor-ci.test")
 if err!=nil||match||len(reply)!=len(q)+16{t.Fatalf("reference control invalid: %v",err)}
 bad:=append([]byte(nil),q...);bad[13]='z'
 if _,_,err:=ciReferenceDNSReply(bad,"reserved.volve-motor-ci.test");err==nil{t.Fatal("unexpected name accepted")}
 bad=append(append([]byte(nil),q...),1)
 if _,_,err:=ciReferenceDNSReply(bad,"reserved.volve-motor-ci.test");err==nil{t.Fatal("trailing bytes accepted")}
}
