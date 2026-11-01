//go:build windows

package motorupdate

import (
 "context"
 "testing"
)

func TestWindowsFiveOfSixReadOnlyNeverGrantsFreshInstall(t *testing.T) {
 for _,tc:=range []struct {
  name string
  endpoints []windowsFreshPort53Row
  busy bool
 }{
  {"no-port53-owner",[]windowsFreshPort53Row{},false},
  {"tcp53-owned",[]windowsFreshPort53Row{{Transport:"TCP",Address:"0.0.0.0",Port:53,PID:4}},true},
  {"udp53-owned",[]windowsFreshPort53Row{{Transport:"UDP",Address:"::1",Port:53,PID:28}},true},
 } {
  t.Run(tc.name,func(t *testing.T) {
   root:=t.TempDir()
   inspect:=partialHostInspectors(t,true,[]windowsVOLVETaskRecord{},[]windowsVOLVEServiceRecord{})
   got,err:=InspectWindowsFreshFiveOfSixReadOnly(context.Background(),root,"","",inspect,
    func(_ context.Context,query string)([]byte,error){
     if query!=WindowsFreshPort53Query{t.Fatal("not the fixed read-only port53 query")}
     return freshPort53Fixture(t,tc.endpoints),nil
    })
   if err!=nil{t.Fatal(err)}
   e:=got.Host.Host.Evidence
   if !e.InspectedAsAdministrator || !e.InspectedMotorFiles || !e.InspectedTaskScheduler ||
    !e.InspectedServices || !e.InspectedDNSAdapters || !e.InspectedPort53Listeners ||
    e.InspectedRecoveryState {
    t.Fatalf("missing true evidence or forged recovery flag: %+v",e)
   }
   observedOccupied:=e.TCP53IPv4OwnerCount+e.TCP53IPv6OwnerCount+
    e.UDP53IPv4OwnerCount+e.UDP53IPv6OwnerCount>0
   if observedOccupied!=tc.busy{t.Fatalf("port53 occupancy lost: %+v",e)}
   if err:=CheckFreshMotorInstallReadiness(context.Background(),e);err==nil{
    t.Fatal("five-of-six census authorized fresh motor install without recovery inspection")
   }
  })
 }
}

func TestWindowsFiveOfSixPort53FailureCannotCompleteSnapshot(t *testing.T) {
 root:=t.TempDir()
 inspectors:=partialHostInspectors(t,true,[]windowsVOLVETaskRecord{},[]windowsVOLVEServiceRecord{})
 if got,err:=InspectWindowsFreshFiveOfSixReadOnly(context.Background(),root,"","",inspectors,nil);
  err==nil || got.Host.Host.Evidence.InspectedPort53Listeners {
  t.Fatal("missing port53 inspector accepted")
 }
 if got,err:=InspectWindowsFreshFiveOfSixReadOnly(context.Background(),root,"","",inspectors,
  func(context.Context,string)([]byte,error){return nil,nil});
  err==nil || got.Host.Host.Evidence.InspectedPort53Listeners {
  t.Fatal("partial port53 query fabricated successful host evidence")
 }
}
