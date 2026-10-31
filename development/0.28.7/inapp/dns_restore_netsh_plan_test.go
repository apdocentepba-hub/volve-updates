package motorupdate

import (
 "reflect"
 "testing"
)

func TestWindowsDNSRestoreUsesFamilySpecificDHCPCommands(t *testing.T){
 for _,tc:=range []struct{family DNSAddressFamily;want []string}{
  {DNSIPv4,[]string{"interface","ipv4","set","dnsservers","name=12","source=dhcp"}},
  {DNSIPv6,[]string{"interface","ipv6","set","dnsservers","name=12","source=dhcp"}},
 } {
  r:=restoreFixture(tc.family,DNSAutomatic)
  cmds,err:=PlanWindowsDNSRestore(r.Original,12)
  if err!=nil{t.Fatal(err)}
  if len(cmds)!=1||cmds[0].Program!="netsh.exe"||!reflect.DeepEqual(cmds[0].Args,tc.want){
   t.Fatalf("wrong family-specific DHCP restore: %+v",cmds)
  }
 }
}
func TestWindowsDNSRestoreKeepsManualServerOrdering(t *testing.T){
 for _,tc:=range []struct{family DNSAddressFamily;ips []string;familyArg string}{
  {DNSIPv4,[]string{"9.9.9.9","1.1.1.1"},"ipv4"},
  {DNSIPv6,[]string{"2606:4700:4700::1111","2620:fe::fe"},"ipv6"},
 }{
  r:=restoreFixture(tc.family,DNSStatic,tc.ips...)
  cmds,err:=PlanWindowsDNSRestore(r.Original,123)
  if err!=nil{t.Fatal(err)}
  expected:=[][]string{
   {"interface",tc.familyArg,"set","dnsservers","name=123","source=static","address="+tc.ips[0],"validate=no"},
   {"interface",tc.familyArg,"add","dnsservers","name=123","address="+tc.ips[1],"index=2","validate=no"},
  }
  if len(cmds)!=len(expected){t.Fatalf("expected 2 separate commands: %+v",cmds)}
  for i:=range cmds{
   if cmds[i].Program!="netsh.exe"||!reflect.DeepEqual(cmds[i].Args,expected[i]){t.Fatalf("unexpected command %d %+v",i,cmds[i])}
  }
 }
}
func TestWindowsDNSRestoreRefusesInvalidIndexAndInjection(t *testing.T){
 cases:=[]DNSServerState{
  {InterfaceGUID:testAdapterGUID,Family:DNSIPv4,Mode:DNSStatic,Servers:[]string{"1.1.1.1;remove-all"}},
  {InterfaceGUID:testAdapterGUID,Family:DNSIPv6,Mode:DNSStatic,Servers:[]string{"127.0.0.1"}},
  {InterfaceGUID:testAdapterGUID,Family:DNSIPv4,Mode:DNSAutomatic,Servers:[]string{"8.8.8.8"}},
  {InterfaceGUID:"Ethernet",Family:DNSIPv4,Mode:DNSStatic,Servers:[]string{"8.8.8.8"}},
 }
 for _,bad:=range cases {
  if cmds,err:=PlanWindowsDNSRestore(bad,15);err==nil||len(cmds)!=0{t.Fatal("unsafe restore plan accepted")}
 }
 if _,err:=PlanWindowsDNSRestore(restoreFixture(DNSIPv4,DNSAutomatic).Original,0);err==nil{
  t.Fatal("index zero accepted")
 }
}
