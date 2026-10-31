//go:build windows

package motorupdate

import (
  "context"
  "errors"
  "os"
  "reflect"
  "testing"
  "time"
)

func TestWindowsPinnedNativeDNSWriterEndToEndWithInMemoryNetsh(t *testing.T) {
  v4,v6,h:=batchFixture()
  records:=[]DNSRestoreRecord{v4,v6}
  invoked:=0
  invoke:=func(ctx context.Context,args []string)error{
    invoked++
    return h.write(ctx,WindowsDNSCommand{Program:"netsh.exe",Args:args})
  }
  writer,err:=NewWindowsPinnedStaticDNSWriter(context.Background(),records,h.inspect,invoke)
  if err!=nil{t.Fatal(err)}
  if err:=ExecuteWindowsStaticDNSRestoreBatch(context.Background(),records,h.inspect,writer);err!=nil{
    t.Fatal("pinned writer and recovery transaction could not restore both families:",err)
  }
  if !reflect.DeepEqual(h.live[DNSIPv4],v4.Original.Servers)||
    !reflect.DeepEqual(h.live[DNSIPv6],v6.Original.Servers)||invoked!=3 {
    t.Fatalf("incorrect pinned native actions: calls=%d v4=%v v6=%v",invoked,h.live[DNSIPv4],h.live[DNSIPv6])
  }
  if err:=writer(context.Background(),WindowsDNSCommand{Program:"cmd.exe",Args:[]string{"/c","whoami"}});err==nil{
    t.Fatal("untrusted shell command accepted")
  }
  if invoked!=3{t.Fatal("invalid netsh request reached native invoker")}
}

func TestWindowsPinnedNativeDNSWriterRejectsForgedCommandAndChangedGUIDIndex(t *testing.T){
  v4,_,h:=batchFixture()
  called:=0
  writer,err:=NewWindowsPinnedStaticDNSWriter(context.Background(),[]DNSRestoreRecord{v4},h.inspect,
    func(context.Context,[]string)error{called++;return nil})
  if err!=nil{t.Fatal(err)}
  commands,err:=PlanWindowsDNSRestore(v4.Original,14)
  if err!=nil{t.Fatal(err)}
  for _,forged:=range []WindowsDNSCommand{
    {Program:"netsh.exe",Args:[]string{"interface","ipv4","set","dnsservers","name=28","source=static","address=8.8.8.8","validate=no"}},
    {Program:"powershell.exe",Args:commands[0].Args},
  }{
    if err:=writer(context.Background(),forged);err==nil{t.Fatal("untrusted command approved")}
  }
  if called!=0{t.Fatal("untrusted native command was executed")}
  // The previously observed interface GUID is no longer bound to index 14.
  changed:=false
  inspect:=func(ctx context.Context,q string)([]byte,error){
    if q==windowsAdapterInventoryQuery&&changed {
      return []byte(`[{"InterfaceGuid":"12345678-1234-1234-1234-123456789abc","InterfaceIndex":88}]`),nil
    }
    return h.inspect(ctx,q)
  }
  writer2,err:=NewWindowsPinnedStaticDNSWriter(context.Background(),[]DNSRestoreRecord{v4},inspect,
    func(context.Context,[]string)error{called++;return nil})
  if err!=nil{t.Fatal(err)}
  changed=true
  if err:=writer2(context.Background(),commands[0]);err==nil{t.Fatal("changed adapter index authorized old action")}
  if called!=0{t.Fatal("changed adapter reached privileged invoker")}
}

func TestWindowsPinnedNativeDNSWriterRejectsUnauthenticatedSetup(t *testing.T){
 v4,_,h:=batchFixture()
 if _,err:=NewWindowsPinnedStaticDNSWriter(context.Background(),[]DNSRestoreRecord{v4,v4},h.inspect,func(context.Context,[]string)error{return nil});err==nil{
   t.Fatal("duplicate record approved")
 }
 if _,err:=NewWindowsPinnedStaticDNSWriter(context.Background(),[]DNSRestoreRecord{v4},h.inspect,nil);err==nil{
   t.Fatal("nil native runner approved")
 }
 cancelled,cancel:=context.WithCancel(context.Background());cancel()
 if _,err:=NewWindowsPinnedStaticDNSWriter(cancelled,[]DNSRestoreRecord{v4},h.inspect,func(context.Context,[]string)error{return nil});!errors.Is(err,context.Canceled){
   t.Fatal("cancelled native runner setup approved")
 }
}

func TestWindowsNativeNetshReadOnlyInDisposableCI(t *testing.T){
  if os.Getenv("VOLVE_CI_READONLY_ADAPTER_INSPECTION")!="1"{
    t.Skip("real Windows netsh inspection allowed only in CI")
  }
  ctx,cancel:=context.WithTimeout(context.Background(),20*time.Second)
  defer cancel()
  if err:=DefaultWindowsDNSNativeInvoke(ctx,[]string{"interface","ipv4","show","interfaces"});err!=nil{
    t.Fatal("real Windows netsh read-only invocation failed:",err)
  }
  // The workflow independently snapshots effective DNS before and after.
}
