//go:build windows

package motorupdate

import (
 "context"
 "encoding/json"
 "errors"
 "strings"
 "testing"
)

type windowsActivationMemoryHost struct {
 states map[DNSAddressFamily]DNSServerState
 index uint32
 invocations int
 failAfter int
}

func windowsActivationHostFixture() *windowsActivationMemoryHost {
 return &windowsActivationMemoryHost{
  index:14,
  states:map[DNSAddressFamily]DNSServerState{
   DNSIPv4:{InterfaceGUID:activationTestGUID,Family:DNSIPv4,Mode:DNSStatic,Servers:[]string{"9.9.9.9","1.1.1.1"}},
   DNSIPv6:{InterfaceGUID:activationTestGUID,Family:DNSIPv6,Mode:DNSAutomatic},
  },
 }
}
func (h *windowsActivationMemoryHost)inspect(ctx context.Context,query string)([]byte,error){
 if err:=ctx.Err();err!=nil{return nil,err}
 switch query{
 case windowsAdapterInventoryQuery:
  return json.Marshal([]windowsAdapterRecord{{InterfaceGuid:activationTestGUID,InterfaceIndex:h.index}})
 case windowsDNSAssignmentSourceQuery:
  rows:=make([]windowsDNSAssignmentRecord,0,2)
  for _,fam:=range []DNSAddressFamily{DNSIPv4,DNSIPv6}{
   state:=h.states[fam]
   row:=windowsDNSAssignmentRecord{
    InterfaceGUID:activationTestGUID,InterfaceIndex:h.index,
    Family:string(fam),RegistryKeyPresent:true,
    Servers:[]string{},EffectiveServers:[]string{},
   }
   if state.Mode==DNSStatic{
    row.Mode="static"
    row.NameServerPresent=true
    row.NameServerKind="String"
    row.NameServerNonEmpty=true
    row.Servers=append([]string(nil),state.Servers...)
    row.EffectiveServers=append([]string(nil),state.Servers...)
   }else{
    row.Mode="automatic"
    row.NameServerKind="Missing"
    if fam==DNSIPv6{row.EffectiveServers=[]string{"2001:4860:4860::8888"}}
   }
   rows=append(rows,row)
  }
  return json.Marshal(rows)
 default:return nil,errors.New("unallowlisted Windows read-only inspector request")
 }
}
func (h *windowsActivationMemoryHost) invoke(ctx context.Context,args []string)error{
 if err:=ctx.Err();err!=nil{return err}
 if err:=validatePinnedWindowsDNSArgv(args);err!=nil{return err}
 if len(args)!=8||args[4]!="name=14"||args[2]!="set"||
    args[5]!="source=static"||args[7]!="validate=no"{
  return errors.New("native activation constructed unsafe DNS command")
 }
 family:=DNSIPv4
 expected:="127.0.0.1"
 if args[1]=="ipv6"{family=DNSIPv6;expected="::1"}
 if args[6]!="address="+expected{return errors.New("native activation would alter unrelated DNS")}
 h.invocations++
 h.states[family]=DNSServerState{InterfaceGUID:activationTestGUID,Family:family,Mode:DNSStatic,Servers:[]string{expected}}
 if h.failAfter==h.invocations{return errors.New("fake netsh mutated DNS then failed")}
 return nil
}

type windowsActivationIndependentGuard struct {
 h *windowsActivationMemoryHost
 armErr,recoverErr error
 onArm func(int)
 recoverCount,healthCount,commitCount,armCount int
}
func(g *windowsActivationIndependentGuard)VerifyArmed(ctx context.Context,pin string)error{
 if err:=ctx.Err();err!=nil{return err}
 g.armCount++
 if g.onArm!=nil{g.onArm(g.armCount)}
 if len(pin)!=64{return errors.New("original journal SHA pin missing")}
 return g.armErr
}
func(g *windowsActivationIndependentGuard)VerifyLiveProtection(ctx context.Context,_ string)error{
 if err:=ctx.Err();err!=nil{return err}
 g.healthCount++
 return nil
}
func(g *windowsActivationIndependentGuard)RecoverIndependently(ctx context.Context,_ string)error{
 if err:=ctx.Err();err!=nil{return err}
 g.recoverCount++
 if g.recoverErr!=nil{return g.recoverErr}
 originals:=windowsActivationHostFixture()
 for k,v:=range originals.states{g.h.states[k]=copyWindowsActivationDNSState(v)}
 return nil
}
func(g *windowsActivationIndependentGuard)CommitActive(ctx context.Context,_ string)error{
 if err:=ctx.Err();err!=nil{return err}
 g.commitCount++
 return nil
}
func windowsNativeActivationInput(t *testing.T)([]byte,string){
 t.Helper()
 originals:=[]DNSServerState{
  {InterfaceGUID:activationTestGUID,Family:DNSIPv4,Mode:DNSStatic,Servers:[]string{"9.9.9.9","1.1.1.1"}},
  {InterfaceGUID:activationTestGUID,Family:DNSIPv6,Mode:DNSAutomatic},
 }
 raw,pin,err:=BuildDNSOriginalJournal(context.Background(),originals)
 if err!=nil{t.Fatal(err)}
 return raw,pin
}

func TestWindowsPinnedDNSActivationTransactionWithInMemoryNetsh(t *testing.T){
 raw,pin:=windowsNativeActivationInput(t)
 host:=windowsActivationHostFixture()
 guard:=&windowsActivationIndependentGuard{h:host}
 backend,err:=newWindowsPinnedDNSActivationBackend(context.Background(),raw,pin,host.inspect,host.invoke,guard)
 if err!=nil{t.Fatal(err)}
 if err=activateVOLVEDNSWithRecovery(context.Background(),raw,pin,backend,guard);err!=nil{t.Fatal(err)}
 if host.invocations!=2||guard.commitCount!=1||guard.healthCount!=1||guard.recoverCount!=0{
  t.Fatalf("native transaction not completed: writes=%d commit=%d health=%d recovery=%d",
   host.invocations,guard.commitCount,guard.healthCount,guard.recoverCount)
 }
 for _,fam:=range []DNSAddressFamily{DNSIPv4,DNSIPv6}{
  observed,err:=backend.Read(context.Background(),activationTestGUID,fam)
  if err!=nil{t.Fatal(err)}
  target:="127.0.0.1"
  if fam==DNSIPv6{target="::1"}
  if !sameDNSState(observed,DNSServerState{InterfaceGUID:activationTestGUID,Family:fam,Mode:DNSStatic,Servers:[]string{target}}){
   t.Fatalf("family %s not in exact local state",fam)
  }
 }
 // A direct call to the private backend cannot change DNS to an arbitrary IP.
 err=backend.Apply(context.Background(),DNSServerState{
  InterfaceGUID:activationTestGUID,Family:DNSIPv4,Mode:DNSStatic,Servers:[]string{"8.8.8.8"},
 })
 if err==nil||host.invocations!=2{t.Fatal("untrusted DNS destination approved")}
}

func TestWindowsPinnedDNSActivationRejectsUnsafeInitialState(t *testing.T){
 raw,pin:=windowsNativeActivationInput(t)
 for _,tc:=range []string{"publisher-unarmed","tampered-pin","external-ipv6","missing-inspector","missing-invoker"}{
  t.Run(tc,func(t *testing.T){
   host:=windowsActivationHostFixture()
   guard:=&windowsActivationIndependentGuard{h:host}
   inspector:=WindowsReadOnlyPowerShell(host.inspect)
   invoke:=WindowsDNSNativeInvoke(host.invoke)
   currentPin:=pin
   switch tc{
   case "publisher-unarmed":guard.armErr=errors.New("signed watchdog pending state absent")
   case "tampered-pin":currentPin=strings.Repeat("0",64)
   case "external-ipv6":host.states[DNSIPv6]=DNSServerState{
    InterfaceGUID:activationTestGUID,Family:DNSIPv6,Mode:DNSStatic,Servers:[]string{"2001:4860:4860::8888"},
   }
   case "missing-inspector":inspector=nil
   case "missing-invoker":invoke=nil
   }
   backend,err:=newWindowsPinnedDNSActivationBackend(context.Background(),raw,currentPin,inspector,invoke,guard)
   if err==nil||backend!=nil||host.invocations!=0{t.Fatalf("untrusted native backend created: %v",err)}
  })
 }
}

func TestWindowsPinnedDNSActivationRejectsGUIDIndexChange(t *testing.T){
 raw,pin:=windowsNativeActivationInput(t)
 host:=windowsActivationHostFixture()
 guard:=&windowsActivationIndependentGuard{h:host}
 backend,err:=newWindowsPinnedDNSActivationBackend(context.Background(),raw,pin,host.inspect,host.invoke,guard)
 if err!=nil{t.Fatal(err)}
 host.index=88 // Windows assigned a different InterfaceIndex after preflight.
 err=activateVOLVEDNSWithRecovery(context.Background(),raw,pin,backend,guard)
 if err==nil||host.invocations!=0||guard.recoverCount!=0||guard.commitCount!=0{
  t.Fatalf("changed GUID/InterfaceIndex was allowed to mutate DNS: %v",err)
 }
}

func TestWindowsPinnedDNSActivationDriverFailureRequestsSYSTEMHandoff(t *testing.T){
 raw,pin:=windowsNativeActivationInput(t)
 host:=windowsActivationHostFixture()
 host.failAfter=2
 guard:=&windowsActivationIndependentGuard{h:host}
 backend,err:=newWindowsPinnedDNSActivationBackend(context.Background(),raw,pin,host.inspect,host.invoke,guard)
 if err!=nil{t.Fatal(err)}
 err=activateVOLVEDNSWithRecovery(context.Background(),raw,pin,backend,guard)
 if err==nil||guard.recoverCount!=1||guard.commitCount!=0||host.invocations!=2{
  t.Fatalf("partial native mutation incorrectly committed: %v",err)
 }
 for _,fam:=range []DNSAddressFamily{DNSIPv4,DNSIPv6}{
  current,err:=backend.Read(context.Background(),activationTestGUID,fam)
  if err!=nil{t.Fatal(err)}
  original:=windowsActivationHostFixture().states[fam]
  if !sameDNSState(current,original){t.Fatal("independent recovery did not restore exact original DNS")}
 }
}

func TestWindowsPinnedDNSActivationRejectsLostWatchdogDuringSecondFamily(t *testing.T){
 raw,pin:=windowsNativeActivationInput(t)
 host:=windowsActivationHostFixture()
 guard:=&windowsActivationIndependentGuard{h:host}
 calls:=0
 invoke:=func(ctx context.Context,args []string)error{
  calls++
  if err:=host.invoke(ctx,args);err!=nil{return err}
  if calls==1{guard.armErr=errors.New("independent boot watchdog stopped")}
  return nil
 }
 backend,err:=newWindowsPinnedDNSActivationBackend(context.Background(),raw,pin,host.inspect,invoke,guard)
 if err!=nil{t.Fatal(err)}
 err=activateVOLVEDNSWithRecovery(context.Background(),raw,pin,backend,guard)
 if err==nil||guard.recoverCount!=1||guard.commitCount!=0||host.invocations!=1{
  t.Fatalf("vanished watchdog did not interrupt native activation: %v",err)
 }
}

func TestWindowsPinnedDNSActivationRejectsConcurrentPostAttestationDNSChange(t *testing.T){
 raw,pin:=windowsNativeActivationInput(t)
 host:=windowsActivationHostFixture()
 guard:=&windowsActivationIndependentGuard{h:host,
  recoverErr:errors.New("independent watchdog refuses to overwrite third-party DNS"),
 }
 // Constructor calls VerifyArmed twice; coordinator calls a third time,
 // loop a fourth time, and native Apply performs a fifth check. Simulate an
 // external override in that narrow last-moment authorization window.
 guard.onArm=func(call int){
  if call==5{
   host.states[DNSIPv4]=DNSServerState{InterfaceGUID:activationTestGUID,
    Family:DNSIPv4,Mode:DNSStatic,Servers:[]string{"8.8.8.8"}}
  }
 }
 backend,err:=newWindowsPinnedDNSActivationBackend(context.Background(),raw,pin,host.inspect,host.invoke,guard)
 if err!=nil{t.Fatal(err)}
 err=activateVOLVEDNSWithRecovery(context.Background(),raw,pin,backend,guard)
 if err==nil||!strings.Contains(err.Error(),"CRITICAL")||
  host.invocations!=0||guard.recoverCount!=1||guard.commitCount!=0{
  t.Fatalf("TOCTOU change reached netsh or was falsely restored: %v",err)
 }
 actual:=host.states[DNSIPv4]
 if !sameDNSState(actual,DNSServerState{InterfaceGUID:activationTestGUID,
  Family:DNSIPv4,Mode:DNSStatic,Servers:[]string{"8.8.8.8"}}){
  t.Fatal("external DNS should remain untouched after unsafe intervention")
 }
}


const activationUnexpectedAdapterGUID="{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}"

// A second adapter is not in the signed original DNS journal. The test
// simulates a VPN or virtual interface appearing while VOLVE is activated;
// it NEVER modifies real Windows network configuration.
func windowsActivationInspectorWithExtraAdapter(
 host *windowsActivationMemoryHost, extra *bool,
) WindowsReadOnlyPowerShell {
 return func(ctx context.Context,query string)([]byte,error){
  raw,err:=host.inspect(ctx,query)
  if err!=nil||!*extra{return raw,err}
  switch query {
  case windowsAdapterInventoryQuery:
   var adapters []windowsAdapterRecord
   if err:=json.Unmarshal(raw,&adapters);err!=nil{return nil,err}
   adapters=append(adapters,windowsAdapterRecord{
    InterfaceGuid:activationUnexpectedAdapterGUID,InterfaceIndex:88,
   })
   return json.Marshal(adapters)
  case windowsDNSAssignmentSourceQuery:
   var records []windowsDNSAssignmentRecord
   if err:=json.Unmarshal(raw,&records);err!=nil{return nil,err}
   for _,family:=range []DNSAddressFamily{DNSIPv4,DNSIPv6}{
    effective:=[]string{"8.8.8.8"}
    if family==DNSIPv6{effective=[]string{"2001:4860:4860::8888"}}
    records=append(records,windowsDNSAssignmentRecord{
     InterfaceGUID:activationUnexpectedAdapterGUID,
     InterfaceIndex:88,Family:string(family),
     RegistryKeyPresent:true,NameServerKind:"Missing",
     Mode:"automatic",Servers:[]string{},EffectiveServers:effective,
    })
   }
   return json.Marshal(records)
  default:
   return raw,nil
  }
 }
}

func TestWindowsPinnedDNSActivationRejectsIncompleteAdapterCoverageBeforeWrite(t *testing.T){
 raw,pin:=windowsNativeActivationInput(t)
 host:=windowsActivationHostFixture()
 present:=true
 guard:=&windowsActivationIndependentGuard{h:host}
 inspector:=windowsActivationInspectorWithExtraAdapter(host,&present)
 backend,err:=newWindowsPinnedDNSActivationBackend(
  context.Background(),raw,pin,inspector,host.invoke,guard,
 )
 if err==nil||backend!=nil||host.invocations!=0||guard.commitCount!=0{
  t.Fatalf("original DNS journal omitted an observed VPN adapter but was accepted: %v",err)
 }
 if !strings.Contains(err.Error(),"census"){
  t.Fatalf("unexpected incomplete DNS census rejection: %v",err)
 }
}

func TestWindowsPinnedDNSActivationNewAdapterDuringSwitchNeverCommits(t *testing.T){
 raw,pin:=windowsNativeActivationInput(t)
 host:=windowsActivationHostFixture()
 present:=false
 guard:=&windowsActivationIndependentGuard{h:host}
 inspector:=windowsActivationInspectorWithExtraAdapter(host,&present)
 invoke:=func(ctx context.Context,args []string)error{
  err:=host.invoke(ctx,args)
  if err==nil&&host.invocations==1{present=true}
  return err
 }
 backend,err:=newWindowsPinnedDNSActivationBackend(
  context.Background(),raw,pin,inspector,invoke,guard,
 )
 if err!=nil{t.Fatal(err)}
 err=activateVOLVEDNSWithRecovery(context.Background(),raw,pin,backend,guard)
 if err==nil||!strings.Contains(err.Error(),"CRITICAL")||
  guard.recoverCount!=1||guard.commitCount!=0||host.invocations!=1{
  t.Fatalf("late VPN adapter addition was silently accepted or falsely recovered: %v",err)
 }
 // The rollback restores the original journaled adapter, but cannot claim
 // whole-host safety while an independently observed adapter is still new.
 originals:=windowsActivationHostFixture()
 for _,fam:=range []DNSAddressFamily{DNSIPv4,DNSIPv6}{
  if !sameDNSState(host.states[fam],originals.states[fam]){
   t.Fatalf("interrupted activation did not restore original %s DNS",fam)
  }
 }
}
