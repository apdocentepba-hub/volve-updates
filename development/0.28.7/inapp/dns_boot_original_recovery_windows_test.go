//go:build windows

package motorupdate

import (
 "context"
 "errors"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

type signedDNSBootRecoveryFixture struct{
 root string
 parent string
 pub []byte
 binding []byte
 signature []byte
 records []DNSRestoreRecord
 host *windowsActivationMemoryHost
 writes int
 failAt int
}
func makeSignedDNSBootRecoveryFixture(t *testing.T)*signedDNSBootRecoveryFixture{
 t.Helper()
 signed,parent,binding,signature,pin,_:=prepareNativeSignedDNSRecoveryLab(t)
 records,err:=ReadDNSOriginalBackupNativeWindows(context.Background(),parent,pin)
 if err!=nil{t.Fatal(err)}
 h:=windowsActivationHostFixture()
 for _,record:=range records{
  h.states[record.Original.Family]=copyWindowsActivationDNSState(record.Expected)
 }
 return &signedDNSBootRecoveryFixture{
  root:signed.root,parent:parent,pub:append([]byte(nil),signed.pub...),
  binding:binding,signature:signature,records:records,host:h,
 }
}
func(f *signedDNSBootRecoveryFixture)invoke(ctx context.Context,args []string)error{
 if err:=ctx.Err();err!=nil{return err}
 if err:=validatePinnedWindowsDNSArgv(args);err!=nil{return err}
 if len(args)!=6&&len(args)!=8{return errors.New("unexpected native DNS operation")}
 if args[0]!="interface"||args[3]!="dnsservers"||args[4]!="name=14"{
  return errors.New("untrusted DNS adapter command")
 }
 family:=DNSIPv4
 if args[1]=="ipv6"{family=DNSIPv6}
 next:=copyWindowsActivationDNSState(f.host.states[family])
 if len(args)==6{
  if args[2]!="set"||args[5]!="source=dhcp"{return errors.New("invalid automatic restore")}
  next.Mode=DNSAutomatic
  next.Servers=nil
 }else{
  if args[2]=="set"{
   next.Mode=DNSStatic
   next.Servers=[]string{strings.TrimPrefix(args[6],"address=")}
  }else if args[2]=="add"{
   next.Servers=append(next.Servers,strings.TrimPrefix(args[5],"address="))
  }else{return errors.New("untrusted native action")}
 }
 f.writes++
 f.host.states[family]=next
 if f.failAt==f.writes{return errors.New("synthetic DNS driver failed after modifying state")}
 return nil
}
func(f *signedDNSBootRecoveryFixture)run(
 ctx context.Context,binding,signature []byte,inspect WindowsReadOnlyPowerShell,
)error{
 if inspect==nil{inspect=f.host.inspect}
 return restoreSignedOriginalDNSUnderProtectedLeaseWindows(
  ctx,f.root,f.pub,binding,signature,
  inspect,f.invoke,AcquireProtectedResidentTransitionLease,
 )
}
func(f *signedDNSBootRecoveryFixture)expectOriginal(t *testing.T){
 t.Helper()
 for _,record:=range f.records{
  actual:=f.host.states[record.Original.Family]
  if !sameDNSState(actual,record.Original){
   t.Fatalf("original %s DNS not restored: %+v",record.Original.Family,actual)
  }
 }
}
func(f *signedDNSBootRecoveryFixture)expectStillPending(t *testing.T){
 t.Helper()
 journal:=filepath.Join(f.parent,"motor-recovery-transaction")
 state,err:=InspectResidentRecoveryJournal(context.Background(),journal,
  func(p string)error{return nativeDNSOriginalBackupACL(context.Background(),p)})
 if err!=nil||state.Status!="recovery-required"{
  t.Fatalf("DNS-only stage claimed completed motor/watchdog recovery: state=%s err=%v",state.Status,err)
 }
}

func TestSignedWindowsDNSBootRecoveryReopensPublisherNTFSAndRestoresStaticDHCP(t *testing.T){
 f:=makeSignedDNSBootRecoveryFixture(t)
 if err:=f.run(context.Background(),f.binding,f.signature,nil);err!=nil{t.Fatal(err)}
 if f.writes!=3{t.Fatalf("expected two static+one DHCP restore commands, got %d",f.writes)}
 f.expectOriginal(t)
 f.expectStillPending(t)
 // A second process can reopen the same protected snapshot. No extra
 // native command is justified once both DNS families are original.
 if err:=f.run(context.Background(),f.binding,f.signature,nil);err!=nil{t.Fatal(err)}
 if f.writes!=3{t.Fatal("original DNS restoration not idempotent")}
 t.Log("PASS: Win32 mutex + real NTFS ACL + signed Ed25519 publisher chain + in-memory IPv4 static / IPv6 DHCP restoration; NO REAL DNS WRITES")
}

func TestSignedWindowsDNSBootRecoveryRejectsForgedSignerOrUnjournaledVPN(t *testing.T){
 t.Run("forged-receipt",func(t *testing.T){
  f:=makeSignedDNSBootRecoveryFixture(t)
  forged:=append([]byte(nil),f.signature...)
  forged[0]^=1
  if err:=f.run(context.Background(),f.binding,forged,nil);err==nil||f.writes!=0{
   t.Fatalf("forged publisher signed recovery reached DNS writer: %v",err)
  }
  f.expectStillPending(t)
 })
 t.Run("extra-VPN-family",func(t *testing.T){
  f:=makeSignedDNSBootRecoveryFixture(t)
  extra:=true
  inspect:=windowsActivationInspectorWithExtraAdapter(f.host,&extra)
  if err:=f.run(context.Background(),f.binding,f.signature,inspect);err==nil||
   f.writes!=0{
   t.Fatalf("unprotected VPN adapter reached DNS writer: %v",err)
  }
  f.expectStillPending(t)
 })
}

func TestSignedWindowsDNSBootRecoveryResumesSafeInterruptedStaticPrefix(t *testing.T){
 f:=makeSignedDNSBootRecoveryFixture(t)
 f.failAt=2
 if err:=f.run(context.Background(),f.binding,f.signature,nil);err==nil{
  t.Fatal("simulated driver error after changing second static address accepted")
 }
 if f.writes!=2{t.Fatal("partial restore wrote unexpected number of commands")}
 f.expectStillPending(t)
 f.failAt=0
 if err:=f.run(context.Background(),f.binding,f.signature,nil);err!=nil{
  t.Fatalf("recoverable original DNS prefix cannot be resumed: %v",err)
 }
 if f.writes!=3{t.Fatalf("retry unnecessarily rewrote proven static family: %d",f.writes)}
 f.expectOriginal(t)
 f.expectStillPending(t)
}

func TestSignedWindowsDNSBootProductionEntryRefusesNonSYSTEM(t *testing.T){
 if os.Getenv("GITHUB_ACTIONS")!="true"{t.Skip("disposable Windows GitHub runner only")}
 if err:=VerifyWindowsCurrentSystemSIDReadOnly();err==nil{
  t.Skip("actual SYSTEM token; this test intentionally never activates DNS")
 }
 f:=makeSignedDNSBootRecoveryFixture(t)
 err:=restoreSignedOriginalDNSAsSYSTEM(
  context.Background(),f.root,f.pub,f.binding,f.signature)
 if err==nil||!strings.Contains(err.Error(),"LocalSystem")||f.writes!=0{
  t.Fatalf("non-SYSTEM process entered production DNS recovery: %v",err)
 }
}
