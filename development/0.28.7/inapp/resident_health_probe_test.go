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
