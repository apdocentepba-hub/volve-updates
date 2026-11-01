//go:build windows

package main

import (
 "context"
 "strings"
 "testing"
)

func ownerFixture()[]byte{
 return []byte(`{"schema":1,"exact_ipv4_socket":true,"exact_ipv6_socket":true,"same_nonzero_pid":true,"process_observed":true,"system_owner":true,"legacy_executable_path_match":true,"dns_service_args_match":true}`)
}

func TestDNSOwnerExactLegacySystemProcessDoesNotAuthorizeMigration(t *testing.T){
 called:=0
 result:=inspectDNSOwnerReadOnly(context.Background(),func(_ context.Context,q string)([]byte,error){
  called++
  if q!=windowsVOLVEDNSOwnerQuery{t.Fatal("unexpected privileged inspection script")}
  return ownerFixture(),nil
 })
 if called!=1||result.Status!="EXACT_LEGACY_SYSTEM_PROCESS_ON_BOTH_UDP53_SOCKETS_NOT_SIGNED"||
  result.Evidence==nil||!result.Evidence.ProcessObserved||!result.Safe()||
  result.RunningMotorConfirmed||result.SignedMigrationAuthorized||result.CanModifyDNS{
  t.Fatalf("read-only PID matching wrongly asserted migration privilege: %+v",result)
 }
}

func TestDNSOwnerRequiresTwoUDP53OwnersSameProcessAndSYSTEM(t *testing.T){
 good:=string(ownerFixture())
 for _,tc:=range []struct{name,payload string;status string}{
  {"non-system",strings.Replace(good,`"system_owner":true`,`"system_owner":false`,1),"SOCKET_OWNER_OBSERVED_READ_ONLY"},
  {"foreign-exe",strings.Replace(good,`"legacy_executable_path_match":true`,`"legacy_executable_path_match":false`,1),"NOT_VERIFIED"},
  {"not-legacy-command",strings.Replace(good,`"dns_service_args_match":true`,`"dns_service_args_match":false`,1),"SOCKET_OWNER_OBSERVED_READ_ONLY"},
  {"missing-IPv6",strings.Replace(good,`"exact_ipv6_socket":true`,`"exact_ipv6_socket":false`,1),"NOT_VERIFIED"},
  {"different-PIDs",strings.Replace(good,`"same_nonzero_pid":true`,`"same_nonzero_pid":false`,1),"NOT_VERIFIED"},
  {"unknown-field",strings.Replace(good,`"schema":1`,`"schema":1,"raw_command_line":"private"`,1),"NOT_VERIFIED"},
  {"invalid-schema",strings.Replace(good,`"schema":1`,`"schema":2`,1),"NOT_VERIFIED"},
  {"empty","null","NOT_VERIFIED"},
  {"no-content","","NOT_VERIFIED"},
 }{
  t.Run(tc.name,func(t *testing.T){
   got:=inspectDNSOwnerReadOnly(context.Background(),func(context.Context,string)([]byte,error){
    return []byte(tc.payload),nil
   })
   if got.Status!=tc.status||!got.Safe()||got.CanModifyDNS||got.RunningMotorConfirmed{
    t.Fatalf("unsafe DNS motor inference on %s: %+v",tc.name,got)
   }
  })
 }
}

func TestDNSOwnerReadOnlyWindowsRealNative(t *testing.T){
 if testing.Short(){t.Skip("requires native Windows")}
 got:=inspectDNSOwnerReadOnly(context.Background(),defaultDNSOwnerRead)
 if !got.Safe()||got.CanModifyDNS||got.SignedMigrationAuthorized||got.RunningMotorConfirmed{
  t.Fatalf("native Windows runtime claimed to authorize an upgrade: %+v",got)
 }
 t.Logf("native Windows read-only owner inspection: %s; no process args, PID or paths exported",got.Status)
}
