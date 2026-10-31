//go:build windows

package motorupdate

// This test can change DNS ONLY on a newly created, internally routed and
// independently identified Hyper-V VM switch adapter. Normal CI and local
// go test runs SKIP. A separate workflow owns the switch and deletes it in
// a finally block. NEVER run against Ethernet/Wi-Fi/production adapters.
import (
 "context"
 "errors"
 "os"
 "reflect"
 "testing"
 "time"
)

func TestWindowsRealDNSRestoreOnDisposableVMAdapter(t *testing.T){
 if os.Getenv("VOLVE_CI_DNS_REAL_DISPOSABLE")!="INTERNAL_HYPERV_VM_ONLY"{
  t.Skip("real DNS mutations explicitly disabled outside disposable CI VM workflow")
 }
 if os.Getenv("GITHUB_ACTIONS")!="true"{
  t.Fatal("refusing real DNS writes outside ephemeral GitHub Actions VM")
 }
 alias:=os.Getenv("VOLVE_CI_DNS_LAB_ALIAS")
 guid:=os.Getenv("VOLVE_CI_DNS_LAB_GUID")
 ctx,cancel:=context.WithTimeout(context.Background(),90*time.Second)
 defer cancel()
 adapter,err:=VerifyWindowsDisposableDNSAdapterReadOnly(ctx,alias,guid,DefaultWindowsDisposableDNSInspect)
 if err!=nil{t.Fatalf("real adapter was not proven isolated: %v",err)}
 index,err:=FindWindowsAdapterIndex(ctx,adapter.InterfaceGUID,DefaultWindowsReadOnlyPowerShell)
 if err!=nil||index!=adapter.InterfaceIndex{
  t.Fatalf("real vNIC GUID/index did not match independent Windows inventory: %v",err)
 }
 v4:=DNSRestoreRecord{
  Original:DNSServerState{InterfaceGUID:adapter.InterfaceGUID,Family:DNSIPv4,
   Mode:DNSStatic,Servers:[]string{"9.9.9.9","1.1.1.1"}},
  Expected:DNSServerState{InterfaceGUID:adapter.InterfaceGUID,Family:DNSIPv4,
   Mode:DNSStatic,Servers:[]string{"127.0.0.1"}},
 }
 v6:=DNSRestoreRecord{
  Original:DNSServerState{InterfaceGUID:adapter.InterfaceGUID,Family:DNSIPv6,
   Mode:DNSStatic,Servers:[]string{"2606:4700:4700::1111"}},
  Expected:DNSServerState{InterfaceGUID:adapter.InterfaceGUID,Family:DNSIPv6,
   Mode:DNSStatic,Servers:[]string{"::1"}},
 }
 records:=[]DNSRestoreRecord{v4,v6}
 // OS mutex encloses all real writes; the CI workflow additionally owns
 // cleanup of the entire sacrificial internal virtual switch.
 lockName:=testWindowsDNSLeaseName()
 release,err:=acquireWindowsDNSLabRecoveryLease(ctx,lockName)
 if err!=nil{t.Fatal(err)}
 defer release()
 apply:=func(state DNSServerState)error{
  cmds,e:=PlanWindowsDNSRestore(state,index)
  if e!=nil{return e}
  for _,cmd:=range cmds {
   if e=runPinnedWindowsNativeDNS(ctx,cmd.Args);e!=nil{return e}
  }
  return nil
 }
 read:=func(family DNSAddressFamily)([]string,error){
  idx,e:=FindWindowsAdapterIndex(ctx,adapter.InterfaceGUID,DefaultWindowsReadOnlyPowerShell)
  if e!=nil||idx!=index{return nil,errors.New("disposable adapter index changed during live DNS test")}
  raw,e:=DefaultWindowsReadOnlyPowerShell(ctx,windowsEffectiveDNSQuery)
  if e!=nil{return nil,e}
  return parseEffectiveDNS(raw,index,family)
 }
 // Seed an exact original static configuration ONLY on the sacrificial
 // adapter, then replace it with VOLVE localhost to reproduce recovery.
 for _,r:=range records {
  if err:=apply(r.Original);err!=nil{t.Fatalf("cannot seed isolated original DNS: %v",err)}
  observed,e:=read(r.Original.Family)
  if e!=nil||!sameDNSAddresses(observed,r.Original.Servers){
   t.Fatalf("original static DNS not proven: family=%s observed=%v err=%v",r.Original.Family,observed,e)
  }
 }
 for _,r:=range records {
  if err:=apply(r.Expected);err!=nil{t.Fatalf("cannot seed isolated VOLVE localhost DNS: %v",err)}
  observed,e:=read(r.Expected.Family)
  if e!=nil||!sameDNSAddresses(observed,r.Expected.Servers){
   t.Fatalf("localhost DNS not independently proven: family=%s observed=%v err=%v",r.Expected.Family,observed,e)
  }
 }
 writer,err:=NewWindowsPinnedStaticDNSWriter(ctx,records,DefaultWindowsReadOnlyPowerShell,
  func(ctx context.Context,args []string)error{
   // Return to the OS only after this independently bound writer has
   // rechecked the exact GUID. No shell commands or arbitrary netsh args.
   return runPinnedWindowsNativeDNS(ctx,args)
  })
 if err!=nil{t.Fatal(err)}
 if err:=ExecuteWindowsStaticDNSRestoreBatch(ctx,records,DefaultWindowsReadOnlyPowerShell,writer);err!=nil{
  t.Fatalf("real Windows dual-stack DNS recovery failed: %v",err)
 }
 for _,r:=range records {
  current,e:=read(r.Original.Family)
  if e!=nil||!reflect.DeepEqual(current,r.Original.Servers) {
   t.Fatalf("real Windows DNS recovery mismatch family=%s got=%v err=%v",r.Original.Family,current,e)
  }
 }
 t.Logf("PASS: real Windows DNS v4/v6 static server order recovered on unique nonrouting Hyper-V CI adapter %s; runner switch cleanup remains mandatory",alias)
}
