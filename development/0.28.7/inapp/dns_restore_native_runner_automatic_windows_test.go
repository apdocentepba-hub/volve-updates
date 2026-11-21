//go:build windows

package motorupdate

// All DNS mutations in this test are in-memory. The hosted Windows runner
// never receives any netsh set/add/dhcp command.
import (
 "context"
 "errors"
 "reflect"
 "strings"
 "testing"
)

type automaticDNSRecoveryFixture struct{
 host *windowsActivationMemoryHost
 records []DNSRestoreRecord
 invoked [][]string
 failAfter int
}
func makeAutomaticDNSRecoveryFixture() *automaticDNSRecoveryFixture{
 v4:=restoreFixture(DNSIPv4,DNSStatic,"9.9.9.9","1.1.1.1")
 v6:=restoreFixture(DNSIPv6,DNSAutomatic)
 host:=windowsActivationHostFixture()
 host.states[DNSIPv4]=copyWindowsActivationDNSState(v4.Expected)
 host.states[DNSIPv6]=copyWindowsActivationDNSState(v6.Expected)
 return &automaticDNSRecoveryFixture{host:host,records:[]DNSRestoreRecord{v4,v6}}
}
func(f *automaticDNSRecoveryFixture)invoke(ctx context.Context,args []string)error{
 if err:=ctx.Err();err!=nil{return err}
 if err:=validatePinnedWindowsDNSArgv(args);err!=nil{return err}
 if args[0]!="interface"||args[3]!="dnsservers"||args[4]!="name=14"{
  return errors.New("DNS test adapter identity untrusted")
 }
 copyArgs:=append([]string(nil),args...)
 f.invoked=append(f.invoked,copyArgs)
 if len(args)==6&&args[2]=="set"&&args[5]=="source=dhcp"{
  if args[1]!="ipv6"{return errors.New("only original IPv6 family is automatic")}
  f.host.states[DNSIPv6]=copyWindowsActivationDNSState(f.records[1].Original)
 }else if len(args)==8{
  if args[1]!="ipv4"{return errors.New("wrong family-scoped static recovery")}
  current:=copyWindowsActivationDNSState(f.host.states[DNSIPv4])
  address:=strings.TrimPrefix(args[6],"address=")
  if args[2]=="set"{current.Servers=[]string{address}}else if args[2]=="add"{
   address=strings.TrimPrefix(args[5],"address=")
   current.Servers=append(current.Servers,address)
  }else{return errors.New("unexpected netsh restore operation")}
  current.Mode=DNSStatic
  f.host.states[DNSIPv4]=current
 }else{return errors.New("unsafe native recovery grammar reached writer")}
 if f.failAfter>0&&len(f.invoked)==f.failAfter{
  return errors.New("synthetic netsh returned error after changing automatic DNS")
 }
 return nil
}

func TestNativeDNSRecoveryAllowlistAcceptsOnlyExactDHCPFamilyArguments(t *testing.T){
 for _,family:=range []string{"ipv4","ipv6"}{
  valid:=[]string{"interface",family,"set","dnsservers","name=14","source=dhcp"}
  if err:=validatePinnedWindowsDNSArgv(valid);err!=nil{
   t.Fatalf("strict original automatic %s DNS restoration incorrectly refused: %v",family,err)
  }
  if err:=DefaultWindowsDNSNativeInvoke(context.Background(),valid);err==nil{
   t.Fatal("public read-only native invoker accidentally authorized DNS restoration")
  }
 }
 for _,bad:=range [][]string{
  {"interface","ipv6","set","dnsservers","name=0","source=dhcp"},
  {"interface","ipv6","set","dnsservers","name=014","source=dhcp"},
  {"interface","ipv6","set","dnsservers","name=4294967296","source=dhcp"},
  {"interface","ipv6","set","dnsservers","name=14","source=static"},
  {"interface","ipv6","add","dnsservers","name=14","source=dhcp"},
  {"interface","ipv6","set","dnsservers","name=14","source=dhcp","address=::1"},
  {"interface","ipv4","set","dnsservers","name=14;whoami","source=dhcp"},
  {"interface","ipv5","set","dnsservers","name=14","source=dhcp"},
 }{
  if err:=validatePinnedWindowsDNSArgv(bad);err==nil{
   t.Fatalf("untrusted DHCP command accepted: %v",bad)
  }
 }
}

func TestNativeDNSRecoveryRestoresStaticIPv4AndAutomaticIPv6ThroughPinnedWriter(t *testing.T){
 f:=makeAutomaticDNSRecoveryFixture()
 ctx:=context.Background()
 writer,err:=NewWindowsPinnedDNSRecoveryWriter(ctx,f.records,f.host.inspect,f.invoke)
 if err!=nil{t.Fatal(err)}
 if err:=ExecuteWindowsDNSRestoreBatch(ctx,f.records,f.host.inspect,writer);err!=nil{
  t.Fatalf("protected native DNS recovery couldn't restore automatic IPv6: %v",err)
 }
 if len(f.invoked)!=3||!reflect.DeepEqual(f.invoked[2],
  []string{"interface","ipv6","set","dnsservers","name=14","source=dhcp"}){
  t.Fatalf("wrong IPv6 restore command count or source: %+v",f.invoked)
 }
 for _,original:=range f.records{
  state:=f.host.states[original.Original.Family]
  if !sameDNSState(state,original.Original){
   t.Fatalf("original %s DNS mode not restored: %+v",original.Original.Family,state)
  }
 }
 // A repeated recovery MUST remain idempotent, including DHCP/RA.
 if err:=ExecuteWindowsDNSRestoreBatch(ctx,f.records,f.host.inspect,writer);err!=nil{t.Fatal(err)}
 if len(f.invoked)!=3{t.Fatal("idempotent automatic DNS recovery wrote again")}
 // The older exported static-only API must remain strict.
 if _,err:=NewWindowsPinnedStaticDNSWriter(ctx,f.records,f.host.inspect,f.invoke);err==nil{
  t.Fatal("static-only recovery entrypoint accepted automatic original IPv6")
 }
}
func TestNativeDNSRecoveryResumesAfterAutomaticDriverFailedPostMutation(t *testing.T){
 f:=makeAutomaticDNSRecoveryFixture()
 f.failAfter=3
 ctx:=context.Background()
 writer,err:=NewWindowsPinnedDNSRecoveryWriter(ctx,f.records,f.host.inspect,f.invoke)
 if err!=nil{t.Fatal(err)}
 if err:=ExecuteWindowsDNSRestoreBatch(ctx,f.records,f.host.inspect,writer);err==nil{
  t.Fatal("post-write driver failure incorrectly marked full DNS restoration successful")
 }
 if !sameDNSState(f.host.states[DNSIPv6],f.records[1].Original){
  t.Fatal("fixture did not simulate DHCP applied before driver returned an error")
 }
 f.failAfter=0
 if err:=ExecuteWindowsDNSRestoreBatch(ctx,f.records,f.host.inspect,writer);err!=nil{
  t.Fatalf("retry failed to verify previously restored original automatic DNS: %v",err)
 }
 if len(f.invoked)!=3{
  t.Fatal("recovery retry issued an unnecessary extra Windows DNS mutation")
 }
}
