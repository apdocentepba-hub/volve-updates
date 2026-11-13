package motorupdate

// Bounded, active read-only health probes. They do not change DNS, adapters,
// Task Scheduler, user firewall rules, browser settings or installed files.
import (
 "bytes"
 "context"
 "crypto/rand"
 "encoding/binary"
 "errors"
 "fmt"
 "io"
 "net"
 "strconv"
 "strings"
 "time"
)

const residentProbeTimeout = 3*time.Second

// ProbeResidentDNSLoopbacks proves that BOTH local DNS listeners answer a
// fresh, correctly-correlated ordinary allowlisted query. Caller must still
// verify task identity, anti-gambling blocking and upstream connectivity.
// Addresses are loopback-only, but custom ephemeral ports allow safe CI.
func ProbeResidentDNSLoopbacks(ctx context.Context,ipv4Addr,ipv6Addr string) error {
 for _,step:=range []struct{network,addr,host string; qtype uint16}{
  {"udp4",ipv4Addr,"127.0.0.1",1},
  {"udp6",ipv6Addr,"::1",28},
 } {
  host,port,err:=net.SplitHostPort(step.addr)
  if err!=nil || host!=step.host {return fmt.Errorf("DNS endpoint must be %s loopback",step.host)}
  portNum,err:=strconv.Atoi(port)
  if err!=nil || portNum<1 || portNum>65535{return errors.New("invalid loopback DNS port")}
  if err:=probeResidentDNS(ctx,step.network,step.addr,step.qtype);err!=nil {
   return fmt.Errorf("DNS %s listener unhealthy: %w",step.network,err)
  }
 }
 return nil
}

func probeResidentDNS(ctx context.Context,network,address string,qtype uint16)error {
 if err:=ctx.Err();err!=nil{return err}
 ctx,cancel:=context.WithTimeout(ctx,residentProbeTimeout);defer cancel()
 var id [2]byte
 if _,err:=io.ReadFull(rand.Reader,id[:]);err!=nil{return err}
 // DNS header: random request ID, recursion desired, one question.
 question:=[]byte{7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,0,0,1}
 binary.BigEndian.PutUint16(question[len(question)-4:],qtype)
 request:=make([]byte,12,len(question)+12)
 copy(request[0:2],id[:]);request[2]=1;request[5]=1
 request=append(request,question...)
 d:=net.Dialer{Timeout:residentProbeTimeout}
 conn,err:=d.DialContext(ctx,network,address)
 if err!=nil{return err};defer conn.Close()
 deadline,ok:=ctx.Deadline();if ok {if err:=conn.SetDeadline(deadline);err!=nil{return err}}
 if _,err=conn.Write(request);err!=nil{return err}
 response:=make([]byte,1232)
 count,err:=conn.Read(response)
 if err!=nil{return err}
 response=response[:count]
 if count<len(request)+12 || !bytes.Equal(response[:2],id[:]) ||
  response[2]&0x80==0 || response[2]&0x78!=0 || response[2]&0x02!=0 ||
  response[3]&0x0f!=0 || binary.BigEndian.Uint16(response[4:6])!=1 ||
  binary.BigEndian.Uint16(response[6:8])==0 || !bytes.Equal(response[12:len(request)],request[12:]) {
  return errors.New("DNS reply truncated, mismatched, failed or without any answer")
 }
 if !hasResidentDNSAddress(response,len(request),qtype) {
  return errors.New("DNS reply has no valid matching A/AAAA resource record")
 }
 return nil
}

// Parse owner names without trusting DNS compression offsets: all pointers
// must move backwards inside the packet. Return the RR-field start offset.
func readResidentDNSName(packet []byte, pos int) (string,int,bool) {
 if pos<12 || pos>=len(packet){return "",0,false}
 var labels []string
 resume:=-1
 totalLength:=0
 for steps:=0;steps<128;steps++ {
  if pos<12||pos>=len(packet){return "",0,false}
  size:=packet[pos]
  if size&0xc0==0xc0 {
   if pos+1>=len(packet){return "",0,false}
   pointer:=int(size&0x3f)<<8|int(packet[pos+1])
   if pointer<12||pointer>=pos{return "",0,false}
   if resume<0{resume=pos+2}
   pos=pointer
   continue
  }
  if size&0xc0!=0{return "",0,false}
  pos++
  if size==0 {
   if len(labels)==0{return "",0,false}
   if resume<0{resume=pos}
   return strings.Join(labels,"."),resume,true
  }
  if size>63||pos+int(size)>len(packet){return "",0,false}
  label:=packet[pos:pos+int(size)]
  // A dot within one label is not a real DNS label separator.
  if bytes.IndexByte(label,'.')>=0{return "",0,false}
  totalLength+=int(size)+1
  if totalLength>253{return "",0,false}
  labels=append(labels,strings.ToLower(string(label)))
  pos+=int(size)
 }
 return "",0,false
}

// Verify that an answer belongs to the requested name directly or through
// a bounded, internally consistent CNAME alias chain. Unrelated A/AAAA RRs
// cannot make an invalid recovery appear healthy. This is a read-only probe.
func hasResidentDNSAddress(reply []byte, off int, qtype uint16) bool {
 questionName,questionEnd,ok:=readResidentDNSName(reply,12)
 if !ok||questionEnd+4!=off||off>len(reply)||questionName==""{return false}
 if binary.BigEndian.Uint16(reply[questionEnd:questionEnd+2])!=qtype ||
  binary.BigEndian.Uint16(reply[questionEnd+2:off])!=1{return false}
 answers:=int(binary.BigEndian.Uint16(reply[6:8]))
 if answers<1||answers>64{return false}
 // Parse ALL answers before accepting any; malformed trailing entries
 // must not turn a partial reply into certified DNS health.
 addresses:=make(map[string]bool)
 aliases:=make(map[string]string)
 for n:=0;n<answers;n++ {
  owner,next,ok:=readResidentDNSName(reply,off)
  if !ok{return false}
  off=next
  if off+10>len(reply){return false}
  recordType:=binary.BigEndian.Uint16(reply[off:off+2])
  recordClass:=binary.BigEndian.Uint16(reply[off+2:off+4])
  dataLen:=int(binary.BigEndian.Uint16(reply[off+8:off+10]))
  off+=10
  if off+dataLen>len(reply){return false}
  if recordClass==1 {
   switch recordType {
   case 5: // CNAME: RDATA is a DNS-encoded name, possibly compressed
    if dataLen<2{return false}
    target,after,valid:=readResidentDNSName(reply,off)
    if !valid||after!=off+dataLen || target==""{return false}
    if prior,exists:=aliases[owner];exists && prior!=target{return false}
    aliases[owner]=target
   case 1,28:
    if recordType==qtype &&
      ((qtype==1&&dataLen==4)||(qtype==28&&dataLen==16)){
     addresses[owner]=true
    }
   }
  }
  off+=dataLen
 }
 // Up to eight linked aliases; detect circular CNAME references and reject.
 name:=questionName
 seen:=make(map[string]bool)
 for hop:=0;hop<=8;hop++ {
  if seen[name]{return false}
  seen[name]=true
  if addresses[name]{return true}
  next,exists:=aliases[name]
  if !exists || hop==8{return false}
  name=next
 }
 return false
}

// ProbeResidentInternetAt checks direct external TCP reachability, independent
// of the local DNS resolver. Only numeric IP endpoints are allowed; production
// should provide multiple independent trusted networks. No HTTP is requested.
func ProbeResidentInternetAt(ctx context.Context, endpoints []string) error {
 if err:=ctx.Err();err!=nil{return err}
 if len(endpoints)==0 || len(endpoints)>6{return errors.New("missing or excessive connectivity endpoints")}
 for _,address:=range endpoints {
  host,port,err:=net.SplitHostPort(address)
  if err!=nil || net.ParseIP(host)==nil {return errors.New("connectivity endpoint must be an IP literal")}
  number,err:=strconv.Atoi(port)
  if err!=nil || number<1 || number>65535 {return errors.New("invalid connectivity probe port")}
 }
 for _,address:=range endpoints {
  if err:=ctx.Err();err!=nil{return err}
  step,cancel:=context.WithTimeout(ctx,residentProbeTimeout)
  d:=net.Dialer{Timeout:residentProbeTimeout}
  conn,err:=d.DialContext(step,"tcp",address)
  if err==nil{conn.Close();cancel();return nil}
  cancel()
 }
 return errors.New("all configured network connectivity endpoints failed")
}

func ProbeResidentExternalInternet(ctx context.Context)error {
 return ProbeResidentInternetAt(ctx,[]string{"1.1.1.1:443","9.9.9.9:443"})
}
