package motorupdate

import (
 "context"
 "encoding/binary"
 "fmt"
 "net"
 "strings"
 "testing"
 "time"
)
func dnsStub(t *testing.T,network,listenAddr string,spoof bool)string {
 t.Helper()
 sock,err:=net.ListenPacket(network,listenAddr)
 if err!=nil{t.Skipf("test runner has no %s loopback: %v",network,err)}
 t.Cleanup(func(){sock.Close()})
 go func(){
  req:=make([]byte,512)
  sock.SetReadDeadline(time.Now().Add(3*time.Second))
  n,addr,err:=sock.ReadFrom(req);if err!=nil || n<20{return}
  request:=req[:n]
  response:=append([]byte(nil),request...)
  response[2]=0x81;response[3]=0x80;response[6]=0;response[7]=1
  if spoof{response[0]^=0xff}
  qtype:=binary.BigEndian.Uint16(request[n-4:n-2])
  answer:=[]byte{0xc0,0x0c,0,0,0,1,0,0,0,30,0,0}
  binary.BigEndian.PutUint16(answer[2:4],qtype)
  if qtype==1 {answer[11]=4;answer=append(answer,1,2,3,4)} else {answer[11]=16;answer=append(answer,make([]byte,16)...)}
  sock.WriteTo(append(response,answer...),addr)
 }()
 return sock.LocalAddr().String()
}
func TestResidentHealthRealLoopbackDNSBothFamilies(t *testing.T){
 ipv4:=dnsStub(t,"udp4","127.0.0.1:0",false)
 ipv6:=dnsStub(t,"udp6","[::1]:0",false)
 if err:=ProbeResidentDNSLoopbacks(context.Background(),ipv4,ipv6);err!=nil{t.Fatal(err)}
}
func TestResidentHealthRejectsFakeOrMissingIPv4Reply(t *testing.T){
 ipv4:=dnsStub(t,"udp4","127.0.0.1:0",true)
 ipv6:=dnsStub(t,"udp6","[::1]:0",false)
 if err:=ProbeResidentDNSLoopbacks(context.Background(),ipv4,ipv6);err==nil{t.Fatal("mismatched DNS transaction ID trusted")}
 for _,tc:=range []string{"8.8.8.8:53","127.0.0.1:0","wrong"}{
  if err:=ProbeResidentDNSLoopbacks(context.Background(),tc,ipv6);err==nil{t.Fatal("untrusted address accepted: "+tc)}
 }
}
func TestResidentHealthRealTCPAndDeniedTargets(t *testing.T){
 listener,err:=net.Listen("tcp","127.0.0.1:0");if err!=nil{t.Fatal(err)}
 defer listener.Close()
 if err:=ProbeResidentInternetAt(context.Background(),[]string{listener.Addr().String()});err!=nil{t.Fatal(err)}
 for _,tc:=range [][]string{nil,{"example.com:443"},{"1.1.1.1:0"},{"garbage"}}{
  if err:=ProbeResidentInternetAt(context.Background(),tc);err==nil{t.Fatalf("invalid targets accepted: %v",tc)}
 }
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 if err:=ProbeResidentInternetAt(ctx,[]string{listener.Addr().String()});err==nil || !strings.Contains(err.Error(),"canceled"){
  t.Fatalf("cancelled probe accepted: %v",err)
 }
}

func TestResidentHealthRejectsFakeAnswerCountWithoutAddress(t *testing.T) {
 question:=[]byte{7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1}
 reply:=append(make([]byte,12),question...)
 reply[6]=0;reply[7]=1
 header:=[]byte{0xc0,0x0c,0,1,0,1,0,0,0,30,0,4}
 if hasResidentDNSAddress(append(append([]byte{},reply...),header...),len(reply),1) {
  t.Fatal("header with ANCOUNT=1 but no actual A address was accepted")
 }
 complete:=append(append(append([]byte{},reply...),header...),1,2,3,4)
 if !hasResidentDNSAddress(complete,len(reply),1) {
  t.Fatal("complete and well-formed A answer rejected")
 }
 complete[len(reply)+11]=16
 if hasResidentDNSAddress(complete,len(reply),1) {
  t.Fatal("false RDLEN claiming extra bytes was trusted")
 }
}

func TestResidentCompletionIntegratesRealDNSAndTCP(t *testing.T){
 ipv4:=dnsStub(t,"udp4","127.0.0.1:0",false)
 ipv6:=dnsStub(t,"udp6","[::1]:0",false)
 listener,err:=net.Listen("tcp","127.0.0.1:0");if err!=nil{t.Fatal(err)}
 defer listener.Close()
 dir:=t.TempDir()
 intent,err:=ArmResidentRecoveryIntent(context.Background(),dir,residentFixture(),
  residentLabACL,residentLabACL)
 if err!=nil{t.Fatal(err)}
 identities:=0
 checks:=ResidentActiveHealthChecks{
  IPv4DNS:ipv4,IPv6DNS:ipv6,TCPAddresses:[]string{listener.Addr().String()},
  VerifyIdentity:func(_ context.Context,actual ResidentRecoveryIntent,outcome string)error{
   identities++
   if actual!=intent||outcome!="restored"{return fmt.Errorf("wrong running motor identity")}
   return nil
  },
 }
 if err:=ConfirmResidentRecoveryOutcome(context.Background(),dir,"restored",
  residentLabACL,residentLabACL,checks);err!=nil{t.Fatal(err)}
 if identities!=2{t.Fatalf("running identity was not rechecked: %d",identities)}
 state,err:=InspectResidentRecoveryJournal(context.Background(),dir,residentLabACL)
 if err!=nil||state.Status!="restored"{t.Fatalf("real DNS/TCP checks did not close recovery: %+v %v",state,err)}
}

func TestResidentCompletionRejectsFalseDNSWithRealTCP(t *testing.T){
 ipv4:=dnsStub(t,"udp4","127.0.0.1:0",true)
 ipv6:=dnsStub(t,"udp6","[::1]:0",false)
 listener,err:=net.Listen("tcp","127.0.0.1:0");if err!=nil{t.Fatal(err)}
 defer listener.Close()
 dir:=t.TempDir()
 if _,err:=ArmResidentRecoveryIntent(context.Background(),dir,residentFixture(),
  residentLabACL,residentLabACL);err!=nil{t.Fatal(err)}
 checks:=ResidentActiveHealthChecks{
  IPv4DNS:ipv4,IPv6DNS:ipv6,TCPAddresses:[]string{listener.Addr().String()},
  VerifyIdentity:func(context.Context,ResidentRecoveryIntent,string)error{return nil}, // CI TEST ONLY
 }
 if err:=ConfirmResidentRecoveryOutcome(context.Background(),dir,"committed",
  residentLabACL,residentLabACL,checks);err==nil{t.Fatal("forged DNS reply completed upgrade")}
 state,err:=InspectResidentRecoveryJournal(context.Background(),dir,residentLabACL)
 if err!=nil||state.Status!="recovery-required"{t.Fatalf("failed DNS probe consumed recovery record: %+v %v",state,err)}
}
func TestResidentActiveHealthNeverAssumesSystemIdentity(t *testing.T){
 checks:=NewResidentNetworkHealth(nil)
 if checks.IPv4DNS!="127.0.0.1:53"||checks.IPv6DNS!="[::1]:53"{
  t.Fatal("production probes have unrecognized DNS port")
 }
 if err:=checks.VerifyRunningIdentity(context.Background(),residentFixture(),"restored");err==nil{
  t.Fatal("missing privileged Windows verifier was silently allowed")
 }
}

func dnsOwnerStub(t *testing.T, network, listenAddr string, answerOwner []byte) string {
 t.Helper()
 sock,err:=net.ListenPacket(network,listenAddr)
 if err!=nil{t.Skipf("test runner has no %s loopback: %v",network,err)}
 t.Cleanup(func(){sock.Close()})
 go func(){
  req:=make([]byte,512)
  sock.SetReadDeadline(time.Now().Add(3*time.Second))
  n,peer,err:=sock.ReadFrom(req);if err!=nil||n<20{return}
  request:=req[:n]
  response:=append([]byte(nil),request...)
  response[2]=0x81;response[3]=0x80;response[6]=0;response[7]=1
  qtype:=binary.BigEndian.Uint16(request[n-4:n-2])
  tail:=[]byte{0,0,0,1,0,0,0,30,0,0}
  binary.BigEndian.PutUint16(tail[0:2],qtype)
  var rdata []byte
  if qtype==1{rdata=[]byte{1,2,3,4}}else{
   rdata=make([]byte,16)
   rdata[0]=0x20;rdata[1]=0x01;rdata[15]=1
  }
  binary.BigEndian.PutUint16(tail[8:10],uint16(len(rdata)))
  answer:=append(append(append([]byte(nil),answerOwner...),tail...),rdata...)
  sock.WriteTo(append(response,answer...),peer)
 }()
 return sock.LocalAddr().String()
}

func TestResidentHealthRejectsAnswerBelongingToAnotherDomain(t *testing.T) {
 // The DNS question is example.com, but a syntactically valid A/AAAA
 // answer advertises a different owner. A transaction ID + RDATA alone
 // is not proof that the requested domain resolved correctly.
 other:=[]byte{4,'e','v','i','l',4,'t','e','s','t',0}
 v4:=dnsOwnerStub(t,"udp4","127.0.0.1:0",other)
 v6:=dnsStub(t,"udp6","[::1]:0",false)
 if err:=ProbeResidentDNSLoopbacks(context.Background(),v4,v6);err==nil{
  t.Fatal("unrelated but well-formed DNS answer was treated as healthy")
 }
}

func TestResidentRecoveryNeverClosesOnDifferentAnswerOwner(t *testing.T) {
 other:=[]byte{4,'e','v','i','l',4,'t','e','s','t',0}
 v4:=dnsOwnerStub(t,"udp4","127.0.0.1:0",other)
 v6:=dnsStub(t,"udp6","[::1]:0",false)
 tcp,err:=net.Listen("tcp","127.0.0.1:0");if err!=nil{t.Fatal(err)}
 defer tcp.Close()
 dir:=t.TempDir()
 if _,err:=ArmResidentRecoveryIntent(context.Background(),dir,residentFixture(),
  residentLabACL,residentLabACL);err!=nil{t.Fatal(err)}
 checks:=ResidentActiveHealthChecks{
  IPv4DNS:v4,IPv6DNS:v6,TCPAddresses:[]string{tcp.Addr().String()},
  VerifyIdentity:func(context.Context,ResidentRecoveryIntent,string)error{return nil}, // synthetic identity (CI only)
 }
 if err:=ConfirmResidentRecoveryOutcome(context.Background(),dir,"restored",
  residentLabACL,residentLabACL,checks);err==nil{
  t.Fatal("an unrelated DNS answer closed a pending recovery")
 }
 state,err:=InspectResidentRecoveryJournal(context.Background(),dir,residentLabACL)
 if err!=nil||state.Status!="recovery-required"{
  t.Fatalf("DNS owner mismatch consumed pending rollback: %+v %v",state,err)
 }
}

func TestResidentHealthMatchesExactOwnerWithSafeDNSCompression(t *testing.T) {
 question:=[]byte{7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1}
 own:=[]byte{7,'e','x','a','m','p','l','e',3,'c','o','m',0}
 cases:=[]struct{name string;owner []byte;accept bool}{
  {"compressed-question-owner",[]byte{0xc0,0x0c},true},
  {"uncompressed-question-owner",own,true},
  {"unrelated-owner",[]byte{4,'e','v','i','l',4,'t','e','s','t',0},false},
  {"pointer-into-label-byte",[]byte{0xc0,0x0d},false},
  {"pointer-into-header",[]byte{0xc0,0x01},false},
  {"one-label-with-dot",[]byte{11,'e','x','a','m','p','l','e','.','c','o','m',0},false},
 }
 for _,tc:=range cases{
  t.Run(tc.name,func(t *testing.T){
   packet:=append(make([]byte,12),question...)
   packet[6]=0;packet[7]=1
   off:=len(packet)
   packet=append(packet,tc.owner...)
   packet=append(packet,[]byte{0,1,0,1,0,0,0,30,0,4,1,2,3,4}...)
   if got:=hasResidentDNSAddress(packet,off,1);got!=tc.accept{
    t.Fatalf("DNS answer owner classification mismatch: accepted=%t wanted=%t",got,tc.accept)
   }
  })
 }
}


func TestResidentHealthValidCNAMEChainAndUnrelatedAnswer(t *testing.T) {
 question:=[]byte{7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1}
 // A compressed name "alias.example.com" refers only backwards to the
 // question at byte 12. This is a normal DNS alias answer, not a fake owner.
 alias:=[]byte{5,'a','l','i','a','s',0xc0,0x0c}
 root:=[]byte{0xc0,0x0c}
 other:=[]byte{4,'e','v','i','l',4,'t','e','s','t',0}
 makeRR:=func(owner []byte,kind uint16,data []byte) []byte {
  rr:=append([]byte(nil),owner...)
  fixed:=[]byte{0,0,0,1,0,0,0,30,0,0}
  binary.BigEndian.PutUint16(fixed[0:2],kind)
  binary.BigEndian.PutUint16(fixed[8:10],uint16(len(data)))
  rr=append(rr,fixed...)
  return append(rr,data...)
 }
 makeDNS:=func(answers ...[]byte) ([]byte,int) {
  msg:=append(make([]byte,12),question...)
  binary.BigEndian.PutUint16(msg[6:8],uint16(len(answers)))
  pos:=len(msg)
  for _,rr:=range answers{msg=append(msg,rr...)}
  return msg,pos
 }
 cases:=[]struct{name string;records [][]byte;want bool}{
  {"normal-cname-to-a",[][]byte{makeRR(root,5,alias),makeRR(alias,1,[]byte{1,2,3,4})},true},
  {"wrong-cname-owner",[][]byte{makeRR(other,5,alias),makeRR(alias,1,[]byte{1,2,3,4})},false},
  {"alias-without-cname",[][]byte{makeRR(alias,1,[]byte{1,2,3,4})},false},
  {"cname-no-a",[][]byte{makeRR(root,5,alias)},false},
  {"cname-ends-in-unrelated-address",[][]byte{makeRR(root,5,alias),makeRR(other,1,[]byte{1,2,3,4})},false},
  {"cname-cycle-with-unrelated-address",[][]byte{makeRR(root,5,alias),makeRR(alias,5,root),makeRR(other,1,[]byte{1,2,3,4})},false},
  {"malformed-cname-target",[][]byte{makeRR(root,5,[]byte{0xc0,0xff}),makeRR(alias,1,[]byte{1,2,3,4})},false},
  {"cname-target-has-trailing-byte",[][]byte{makeRR(root,5,append(append([]byte{},alias...),0)),makeRR(alias,1,[]byte{1,2,3,4})},false},
 }
 for _,tc:=range cases{
  t.Run(tc.name,func(t *testing.T){
   msg,off:=makeDNS(tc.records...)
   got:=hasResidentDNSAddress(msg,off,1)
   if got!=tc.want{t.Fatalf("DNS alias verification got=%t want=%t",got,tc.want)}
  })
 }
}
