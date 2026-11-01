//go:build windows

package motorupdate

import (
 "context"
 "encoding/json"
 "errors"
 "strings"
 "testing"
)

func freshPort53Fixture(t *testing.T, rows []windowsFreshPort53Row) []byte {
 t.Helper()
 raw,err:=json.Marshal(rows)
 if err!=nil{t.Fatal(err)}
 return raw
}

func TestWindowsFreshPort53DetectsAllListenersAndBlocksFreshMotor(t *testing.T) {
 for _,tc:=range []struct{
  name string
  rows []windowsFreshPort53Row
  udp4,udp6,tcp4,tcp6 int
 }{
  {"empty",[]windowsFreshPort53Row{},0,0,0,0},
  {"udp4",[]windowsFreshPort53Row{{Transport:"UDP",Address:"127.0.0.1",Port:53,PID:4}},1,0,0,0},
  {"udp6",[]windowsFreshPort53Row{{Transport:"UDP",Address:"::1",Port:53,PID:4}},0,1,0,0},
  {"tcp4",[]windowsFreshPort53Row{{Transport:"TCP",Address:"0.0.0.0",Port:53,PID:40}},0,0,1,0},
  {"tcp6",[]windowsFreshPort53Row{{Transport:"TCP",Address:"::1",Port:53,PID:40}},0,0,0,1},
  {"v6-dual-wildcard",[]windowsFreshPort53Row{{Transport:"TCP",Address:"::",Port:53,PID:0}},0,0,1,1},
  {"ipv4-mapped",[]windowsFreshPort53Row{{Transport:"UDP",Address:"::ffff:127.0.0.1",Port:53,PID:7}},1,1,0,0},
 }{
  t.Run(tc.name,func(t *testing.T){
   got,err:=InspectWindowsFreshPort53ReadOnly(context.Background(),func(_ context.Context,q string)([]byte,error){
    if q!=WindowsFreshPort53Query{t.Fatal("unapproved port53 query")}
    return freshPort53Fixture(t,tc.rows),nil
   })
   if err!=nil{t.Fatal(err)}
   if got.UDP53IPv4OwnerCount!=tc.udp4||got.UDP53IPv6OwnerCount!=tc.udp6||
    got.TCP53IPv4OwnerCount!=tc.tcp4||got.TCP53IPv6OwnerCount!=tc.tcp6{
    t.Fatalf("wrong port53 owner classification: %+v",got)
   }
   e:=freshCompleteObservation()
   e.UDP53IPv4OwnerCount=got.UDP53IPv4OwnerCount
   e.UDP53IPv6OwnerCount=got.UDP53IPv6OwnerCount
   e.TCP53IPv4OwnerCount=got.TCP53IPv4OwnerCount
   e.TCP53IPv6OwnerCount=got.TCP53IPv6OwnerCount
   if (CheckFreshMotorInstallReadiness(context.Background(),e)==nil)!=(tc.name=="empty"){
    t.Fatal("occupied TCP/UDP port53 was incorrectly authorized")
   }
  })
 }
}

func TestWindowsFreshPort53RejectsIncompleteOrAlteredEvidence(t *testing.T) {
 good:=windowsFreshPort53Row{Transport:"TCP",Address:"::1",Port:53,PID:4}
 for _,tc:=range []struct{name string;raw []byte}{
  {"nil",nil},{"null",[]byte("null")},{"object",[]byte("{}")},
  {"partial",[]byte("[")},{"extra",[]byte("[] true")},
  {"oversized",[]byte(strings.Repeat(" ",1<<20+1))},
  {"wrong-port",freshPort53Fixture(t,[]windowsFreshPort53Row{{Transport:"TCP",Address:"::1",Port:54,PID:4}})},
  {"wrong-transport",freshPort53Fixture(t,[]windowsFreshPort53Row{{Transport:"SCTP",Address:"::1",Port:53,PID:4}})},
  {"wrong-address",freshPort53Fixture(t,[]windowsFreshPort53Row{{Transport:"UDP",Address:"random",Port:53,PID:4}})},
  {"duplicate",freshPort53Fixture(t,[]windowsFreshPort53Row{good,good})},
  {"extra-field",[]byte("[{\"Transport\":\"TCP\",\"Address\":\"::1\",\"Port\":53,\"PID\":4,\"Mystery\":true}]")},
 } {
  t.Run(tc.name,func(t *testing.T){
   if _,err:=InspectWindowsFreshPort53ReadOnly(context.Background(),func(context.Context,string)([]byte,error){
    return tc.raw,nil
   });err==nil{t.Fatal("untrusted port53 evidence accepted")}
  })
 }
}

func TestWindowsFreshPort53NoUnapprovedQueriesOrCancellation(t *testing.T) {
 if _,err:=DefaultWindowsFreshPort53Inspect(context.Background(),"Stop-Service VOLVE");err==nil{
  t.Fatal("unapproved command could execute")
 }
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 called:=false
 if _,err:=InspectWindowsFreshPort53ReadOnly(ctx,func(context.Context,string)([]byte,error){
  called=true;return []byte("[]"),nil
 });!errors.Is(err,context.Canceled)||called {
  t.Fatalf("cancelled port53 query executed: %v",err)
 }
}

func TestWindowsFreshPort53NativeReadOnly(t *testing.T) {
 if testing.Short(){t.Skip("native Windows port53 inventory integration")}
 got,err:=InspectWindowsFreshPort53ReadOnly(context.Background(),DefaultWindowsFreshPort53Inspect)
 if err!=nil{t.Fatalf("Windows port53 enumeration failed closed: %v",err)}
 t.Logf("READ ONLY: actual Windows port53 owners UDPv4=%d UDPv6=%d TCPv4=%d TCPv6=%d; NO system changes",
  got.UDP53IPv4OwnerCount,got.UDP53IPv6OwnerCount,got.TCP53IPv4OwnerCount,got.TCP53IPv6OwnerCount)
}
