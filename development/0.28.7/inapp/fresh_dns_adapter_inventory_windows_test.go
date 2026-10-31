//go:build windows

package motorupdate

import (
 "context"
 "encoding/json"
 "errors"
 "strings"
 "testing"
)

func freshDNSRows(t *testing.T, rows []windowsFreshDNSAdapterRow) []byte {
 t.Helper()
 raw, err := json.Marshal(rows)
 if err != nil { t.Fatal(err) }
 return raw
}

func TestFreshDNSAdaptersReadOnlyDetectsEveryFamilyAndLoopback(t *testing.T) {
 v4 := windowsFreshDNSAdapterRow{InterfaceIndex: 14, Family: "IPv4", Servers: []string{"8.8.8.8"}}
 v6 := windowsFreshDNSAdapterRow{InterfaceIndex: 14, Family: "IPv6", Servers: []string{"2606:4700:4700::1111"}}
 for _, tc := range []struct {
  name string
  rows []windowsFreshDNSAdapterRow
  want4, want6 bool
 }{
  {"clean-external", []windowsFreshDNSAdapterRow{v4, v6}, false, false},
  {"automatic-empty", []windowsFreshDNSAdapterRow{{InterfaceIndex: 20, Family: "IPv4", Servers: []string{}}, {InterfaceIndex: 20, Family: "IPv6", Servers: []string{}}}, false, false},
  {"ipv4-local", []windowsFreshDNSAdapterRow{v4, {InterfaceIndex: 15, Family: "IPv4", Servers: []string{"127.0.0.1"}}}, true, false},
  {"ipv4-loopback-alias", []windowsFreshDNSAdapterRow{{InterfaceIndex: 15, Family: "IPv4", Servers: []string{"127.0.0.2"}}, v6}, true, false},
  {"ipv6-local", []windowsFreshDNSAdapterRow{v4, {InterfaceIndex: 15, Family: "IPv6", Servers: []string{"::1"}}}, false, true},
  {"ipv4-mapped-ipv6-loopback", []windowsFreshDNSAdapterRow{{InterfaceIndex: 15, Family: "IPv6", Servers: []string{"::ffff:127.0.0.1"}}}, false, true},
  {"both-families-local", []windowsFreshDNSAdapterRow{{InterfaceIndex: 9, Family: "IPv4", Servers: []string{"127.0.0.1"}}, {InterfaceIndex: 9, Family: "IPv6", Servers: []string{"::1"}}}, true, true},
 } {
  t.Run(tc.name, func(t *testing.T) {
   observed, err := InspectWindowsFreshDNSAdaptersReadOnly(context.Background(),
    func(_ context.Context, query string) ([]byte, error) {
     if query != WindowsFreshDNSAdapterQuery { t.Fatal("untrusted DNS inventory query") }
     return freshDNSRows(t, tc.rows), nil
    })
   if err != nil || observed.AdapterFamilyRecords != len(tc.rows) ||
    observed.LocalIPv4DNSConfigured != tc.want4 || observed.LocalIPv6DNSConfigured != tc.want6 {
    t.Fatalf("DNS adapter inventory=%+v, err=%v", observed, err)
   }
   // Other OS inspections are synthetic ONLY within this policy unit test.
   e := freshCompleteObservation()
   e.LocalIPv4DNSConfigured = observed.LocalIPv4DNSConfigured
   e.LocalIPv6DNSConfigured = observed.LocalIPv6DNSConfigured
   if (CheckFreshMotorInstallReadiness(context.Background(), e) == nil) != (!tc.want4 && !tc.want6) {
    t.Fatal("local DNS should block the fresh-install policy")
   }
  })
 }
}

func TestFreshDNSAdaptersFailClosedOnInvalidOrMissingEvidence(t *testing.T) {
 good := windowsFreshDNSAdapterRow{InterfaceIndex: 17, Family: "IPv4", Servers: []string{"1.1.1.1"}}
 for _, tc := range []struct {
  name string
  raw []byte
 }{
  {"empty", nil},
  {"null", []byte("null")},
  {"empty-array", []byte("[]")},
  {"object", []byte("{}")},
  {"trailing", []byte("[] true")},
  {"malformed", []byte("[")},
  {"oversized", []byte(strings.Repeat(" ", 1<<20+1))},
  {"missing-servers", []byte("{\"InterfaceIndex\":17,\"Family\":\"IPv4\"}")},
  {"unknown-family", freshDNSRows(t, []windowsFreshDNSAdapterRow{{InterfaceIndex:17, Family:"Unknown", Servers:[]string{}}})},
  {"zero-index", freshDNSRows(t, []windowsFreshDNSAdapterRow{{InterfaceIndex:0, Family:"IPv4", Servers:[]string{}}})},
  {"duplicate-index-family", freshDNSRows(t, []windowsFreshDNSAdapterRow{good,good})},
  {"bad-ip", freshDNSRows(t, []windowsFreshDNSAdapterRow{{InterfaceIndex:17, Family:"IPv4", Servers:[]string{"not-an-ip"}}})},
  {"whitespace-ip", freshDNSRows(t, []windowsFreshDNSAdapterRow{{InterfaceIndex:17, Family:"IPv4", Servers:[]string{" 1.1.1.1"}}})},
  {"family-mismatch", freshDNSRows(t, []windowsFreshDNSAdapterRow{{InterfaceIndex:17, Family:"IPv6", Servers:[]string{"1.1.1.1"}}})},
  {"extra-field", []byte("[{\"InterfaceIndex\":17,\"Family\":\"IPv4\",\"Servers\":[],\"Untrusted\":true}]")},
 }{
  t.Run(tc.name, func(t *testing.T) {
   _, err := InspectWindowsFreshDNSAdaptersReadOnly(context.Background(),
    func(context.Context, string) ([]byte, error) { return tc.raw, nil })
   if err == nil { t.Fatal("malformed DNS inventory was accepted") }
  })
 }
}

func TestFreshDNSAdaptersOnlyFixedQueryAndCancelled(t *testing.T) {
 if _, err := DefaultWindowsFreshDNSAdapterInspect(context.Background(), "Set-DnsClientServerAddress"); err == nil {
  t.Fatal("an unapproved DNS mutation query was allowed")
 }
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 called:=false
 _,err:=InspectWindowsFreshDNSAdaptersReadOnly(ctx,func(context.Context,string)([]byte,error){
  called=true
  return []byte("[]"),nil
 })
 if !errors.Is(err,context.Canceled) || called {t.Fatalf("cancelled DNS inventory executed: %v",err)}
}

func TestFreshDNSAdaptersActualWindowsReadOnly(t *testing.T) {
 if testing.Short(){t.Skip("native Windows adapter inventory integration")}
 got,err:=InspectWindowsFreshDNSAdaptersReadOnly(context.Background(),DefaultWindowsFreshDNSAdapterInspect)
 if err!=nil {t.Fatalf("real Windows DNS adapter inventory unavailable: %v",err)}
 t.Logf("READ ONLY: %d adapter-family records, IPv4 local=%t, IPv6 local=%t; no Windows network changes",
  got.AdapterFamilyRecords,got.LocalIPv4DNSConfigured,got.LocalIPv6DNSConfigured)
}
