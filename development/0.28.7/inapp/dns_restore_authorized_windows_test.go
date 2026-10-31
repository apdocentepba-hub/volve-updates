//go:build windows

package motorupdate

import (
  "context"
  "errors"
  "reflect"
  "testing"
)

type testWindowsDNSRecoveryAttestor struct {
  Calls int
  FailAt int
  Journal []DNSRestoreRecord
}
func (a *testWindowsDNSRecoveryAttestor) Verify(ctx context.Context, records []DNSRestoreRecord) error {
  if err:=ctx.Err();err!=nil{return err}
  a.Calls++
  if a.FailAt==a.Calls{return errors.New("attestation deliberately withdrawn")}
  if !reflect.DeepEqual(records,a.Journal) {return errors.New("recovery intent changed")}
  // An independent production implementation must also inspect SYSTEM,
  // sealed NTFS ACLs, a signed journal, process lock and stopped motor.
  return nil
}
func TestWindowsDNSRecoveryAttestationAroundEveryWrite(t *testing.T) {
  v4,v6,h:=batchFixture()
  records:=[]DNSRestoreRecord{v4,v6}
  gate:=&testWindowsDNSRecoveryAttestor{Journal:cloneWindowsDNSRecoveryRecords(records)}
  invoke:=func(ctx context.Context,args []string)error {
    return h.write(ctx,WindowsDNSCommand{Program:"netsh.exe",Args:args})
  }
  if err:=runAttestedWindowsStaticDNSRecovery(context.Background(),records,h.inspect,gate,invoke);err!=nil{
    t.Fatal(err)
  }
  if gate.Calls!=9 {
    t.Fatalf("attestor was not checked before and after each of three writes: calls=%d",gate.Calls)
  }
  if !reflect.DeepEqual(h.live[DNSIPv4],v4.Original.Servers)||
     !reflect.DeepEqual(h.live[DNSIPv6],v6.Original.Servers) {t.Fatal("DNS not restored precisely")}
}
func TestWindowsDNSRecoveryLosesAuthorizationAndSafelyResumes(t *testing.T) {
  v4,v6,h:=batchFixture()
  records:=[]DNSRestoreRecord{v4,v6}
  gate:=&testWindowsDNSRecoveryAttestor{Journal:cloneWindowsDNSRecoveryRecords(records),FailAt:5}
  invoke:=func(ctx context.Context,args []string)error {
    return h.write(ctx,WindowsDNSCommand{Program:"netsh.exe",Args:args})
  }
  if err:=runAttestedWindowsStaticDNSRecovery(context.Background(),records,h.inspect,gate,invoke);err==nil{
    t.Fatal("expired recovery authorization accepted")
  }
  if len(h.actions)!=1 || !reflect.DeepEqual(h.live[DNSIPv4],[]string{"9.9.9.9"}) ||
      !reflect.DeepEqual(h.live[DNSIPv6],[]string{"::1"}) {
    t.Fatalf("authorization lapse allowed further DNS writes: writes=%d, v4=%v, v6=%v",
      len(h.actions),h.live[DNSIPv4],h.live[DNSIPv6])
  }
  gate.Calls=0
  gate.FailAt=0
  if err:=runAttestedWindowsStaticDNSRecovery(context.Background(),records,h.inspect,gate,invoke);err!=nil{
    t.Fatalf("could not resume authenticated partial recovery: %v",err)
  }
  if len(h.actions)!=3 || !reflect.DeepEqual(h.live[DNSIPv4],v4.Original.Servers) ||
      !reflect.DeepEqual(h.live[DNSIPv6],v6.Original.Servers){
    t.Fatal("repeated recovery did not exactly restore remaining DNS servers")
  }
}
func TestWindowsDNSRecoveryRejectsMissingOrCorruptedAttestationBeforeMutation(t *testing.T){
  v4,_,h:=batchFixture()
  records:=[]DNSRestoreRecord{v4}
  writes:=0
  invoke:=func(context.Context,[]string)error{writes++;return nil}
  if err:=runAttestedWindowsStaticDNSRecovery(context.Background(),records,h.inspect,nil,invoke);err==nil {
    t.Fatal("missing SYSTEM/journal attestor accepted")
  }
  gate:=&testWindowsDNSRecoveryAttestor{Journal:cloneWindowsDNSRecoveryRecords(records),FailAt:1}
  if err:=runAttestedWindowsStaticDNSRecovery(context.Background(),records,h.inspect,gate,invoke);err==nil{
    t.Fatal("unverified recovery accepted")
  }
  gate.FailAt=0;gate.Calls=0
  records[0].Original.Servers[0]="8.8.8.8"
  if err:=runAttestedWindowsStaticDNSRecovery(context.Background(),records,h.inspect,gate,invoke);err==nil{
    t.Fatal("journal mismatch accepted")
  }
  if writes!=0 || len(h.actions)!=0 {t.Fatal("unauthorized DNS mutation occurred")}
}
func TestNativeNetshDirectInvokeIsReadOnly(t *testing.T) {
  mutation:=[]string{"interface","ipv4","set","dnsservers","name=14","source=static","address=9.9.9.9","validate=no"}
  if err:=DefaultWindowsDNSNativeInvoke(context.Background(),mutation);err==nil {
    t.Fatal("exported native invoker may never execute mutations")
  }
  for _,cmd:=range [][]string{
    {"interface","ipv4","delete","dnsservers","name=14","all"},
    {"interface","ipv4","set","dnsservers","name=0","source=static","address=1.1.1.1","validate=no"},
    {"interface","ipv6","set","dnsservers","name=14","source=static","address=1.1.1.1","validate=no"},
    {"interface","ipv4","set","dnsservers","name=14","source=dhcp","address=1.1.1.1","validate=no"},
    {"interface","ipv4","set","dnsservers","name=14","source=static","address=localhost","validate=no"},
    {"interface","ipv4","add","dnsservers","name=14","address=1.1.1.1","index=1","validate=no"},
    {"interface","ipv4","show","dnsservers"},
  } {
    if err:=validatePinnedWindowsDNSArgv(cmd);err==nil{t.Fatalf("unsafe Windows netsh command accepted: %v",cmd)}
  }
  if err:=validatePinnedWindowsDNSArgv(mutation);err!=nil{t.Fatal("valid pinned static mutation rejected:",err)}
  if err:=validatePinnedWindowsDNSArgv([]string{"interface","ipv6","show","interfaces"});err!=nil{
    t.Fatal("read-only inventory query rejected")
  }
}
