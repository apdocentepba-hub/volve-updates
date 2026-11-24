// Disposable CI peer only; not a VOLVE component or a recursive resolver.
// Build with go build main.go. The harness must attach this peer ONLY to
// the owned private Hyper-V switch, with no host NIC or default route.
package main

import (
 "encoding/binary"
 "encoding/hex"
 "fmt"
 "io"
 "net"
 "os"
 "strings"
 "time"
)

const clientIP = "192.0.2.10"
const peerIP = "192.0.2.53"
const secondaryIP = "192.0.2.54"

// Respond exclusively to fresh 128-bit challenges under a reserved suffix.
// No external forwarding, no compression in requests, no arbitrary names.
func challengeReply(q []byte) ([]byte,string,error) {
 bad:=func()([]byte,string,error){return nil,"",fmt.Errorf("unrecognized private DNS challenge")}
 if len(q)<18||len(q)>4096||q[2]&0xfe!=0||q[3]&0x8f!=0||
 binary.BigEndian.Uint16(q[4:6])!=1||binary.BigEndian.Uint16(q[6:8])!=0||
 binary.BigEndian.Uint16(q[8:10])!=0{return bad()}
 i:=12
 labels:=[]string{}
 for {
  if i>=len(q){return bad()}
  n:=int(q[i]);i++
  if n==0{break}
  if n>63||i+n>len(q)||len(labels)>=3{return bad()}
  labels=append(labels,strings.ToLower(string(q[i:i+n])));i+=n
 }
 if len(labels)!=3||labels[1]!="volve-ci"||labels[2]!="test"||len(labels[0])!=32{return bad()}
 if _,err:=hex.DecodeString(labels[0]);err!=nil{return bad()}
 if i+4>len(q)||binary.BigEndian.Uint16(q[i:i+2])!=1||binary.BigEndian.Uint16(q[i+2:i+4])!=1{return bad()}
 end:=i+4
 // A Windows resolver may append one EDNS OPT record. Do not echo it.
 extra:=binary.BigEndian.Uint16(q[10:12])
 if extra==0 {if end!=len(q){return bad()}} else {
  if extra!=1||end+11>len(q)||q[end]!=0||binary.BigEndian.Uint16(q[end+1:end+3])!=41{return bad()}
  n:=int(binary.BigEndian.Uint16(q[end+9:end+11]))
  if end+11+n!=len(q){return bad()}
 }
 r:=append([]byte(nil),q[:end]...)
 r[2]=0x84|(q[2]&1) // authoritative answer, preserve RD
 r[3]=0
 binary.BigEndian.PutUint16(r[6:8],1)
 binary.BigEndian.PutUint16(r[10:12],0)
 // QNAME pointer, A/IN, zero TTL, 4-byte address.
 r=append(r,0xc0,0x0c,0,1,0,1,0,0,0,0,0,4,192,0,2,53)
 return r,labels[0],nil
}

func allowedClient(a net.Addr) bool {
 host,_,err:=net.SplitHostPort(a.String())
 return err==nil&&host==clientIP
}

func serveUDP(c net.PacketConn) {
 buf:=make([]byte,4096)
 for {
  n,a,err:=c.ReadFrom(buf);if err!=nil{return}
  if !allowedClient(a){continue}
  reply,nonce,err:=challengeReply(buf[:n]);if err!=nil{continue}
  fmt.Printf("VOLVE_PRIVATE_PEER_RECEIVED transport=udp nonce=%s\n",nonce)
  if _,err=c.WriteTo(reply,a);err==nil{fmt.Printf("VOLVE_PRIVATE_PEER_REPLY transport=udp nonce=%s\n",nonce)}
 }
}
func serveTCP(l net.Listener) {
 for {
  c,err:=l.Accept();if err!=nil{return}
  // Serial, bounded connection handling is sufficient for one lab client.
  func(){
   defer c.Close()
   if !allowedClient(c.RemoteAddr()){return}
   _=c.SetDeadline(time.Now().Add(3*time.Second))
   var size [2]byte
   if _,err:=io.ReadFull(c,size[:]);err!=nil{return}
   n:=int(binary.BigEndian.Uint16(size[:]));if n<18||n>4096{return}
   q:=make([]byte,n);if _,err:=io.ReadFull(c,q);err!=nil{return}
   reply,nonce,err:=challengeReply(q);if err!=nil{return}
   fmt.Printf("VOLVE_PRIVATE_PEER_RECEIVED transport=tcp nonce=%s\n",nonce)
   binary.BigEndian.PutUint16(size[:],uint16(len(reply)))
   packet:=append(size[:],reply...)
   if n,err:=c.Write(packet);err==nil&&n==len(packet){fmt.Printf("VOLVE_PRIVATE_PEER_REPLY transport=tcp nonce=%s\n",nonce)}
  }()
 }
}

func main(){
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"||os.Getenv("VOLVE_CI_PRIVATE_DNS_PEER")!="PRIVATE_GUEST_ONLY"{
  panic("refuse outside explicit private hosted CI peer")
 }
 // Binding to these two exact TEST-NET addresses never opens a wildcard.
 // The host harness independently verifies switch, NIC and route isolation.
 for _,ip:=range []string{peerIP,secondaryIP}{
  endpoint:=net.JoinHostPort(ip,"53")
  udp,err:=net.ListenPacket("udp4",endpoint);if err!=nil{panic(err)}
  tcp,err:=net.Listen("tcp4",endpoint);if err!=nil{udp.Close();panic(err)}
  go serveUDP(udp)
  go serveTCP(tcp)
 }
 fmt.Println("VOLVE_PRIVATE_PEER_READY two_ipv4_addresses udp_tcp53 NO_FORWARDING")
 // Hard upper bound; a test VM is destroyed by the host regardless of result.
 <-time.After(2*time.Hour)
}
