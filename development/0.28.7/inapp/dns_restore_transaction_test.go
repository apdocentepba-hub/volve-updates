package motorupdate

import (
 "context"
 "errors"
 "strings"
 "testing"
)

const testAdapterGUID="{12345678-1234-1234-1234-123456789abc}"
type fakeDNSRestoreBackend struct {
 current map[DNSAddressFamily]DNSServerState
 applied []DNSServerState
 failApply bool
 onRead func(*fakeDNSRestoreBackend)
}
func (f *fakeDNSRestoreBackend) Read(_ context.Context,id string,family DNSAddressFamily)(DNSServerState,error){
 if f.onRead!=nil {fn:=f.onRead;f.onRead=nil;fn(f)}
 s,ok:=f.current[family]
 if !ok || !strings.EqualFold(s.InterfaceGUID,id){return DNSServerState{},errors.New("adapter not found")}
 return s,nil
}
func (f *fakeDNSRestoreBackend) Apply(_ context.Context,s DNSServerState)error{
 if f.failApply{return errors.New("simulated denied access")}
 f.applied=append(f.applied,s)
 f.current[s.Family]=s
 return nil
}
func restoreFixture(family DNSAddressFamily, mode DNSConfigurationMode,servers ...string)DNSRestoreRecord{
 local:="127.0.0.1"
 if family==DNSIPv6{local="::1"}
 return DNSRestoreRecord{
  Original:DNSServerState{InterfaceGUID:testAdapterGUID,Family:family,Mode:mode,Servers:servers},
  Expected:DNSServerState{InterfaceGUID:testAdapterGUID,Family:family,Mode:DNSStatic,Servers:[]string{local}},
 }
}
func newDNSFake(records ...DNSRestoreRecord)*fakeDNSRestoreBackend{
 f:=&fakeDNSRestoreBackend{current:make(map[DNSAddressFamily]DNSServerState)}
 for _,r:=range records{f.current[r.Expected.Family]=r.Expected}
 return f
}
func TestVOLVEDNSRollbackRestoresManualAndAutomaticExactly(t *testing.T){
 ipv4:=restoreFixture(DNSIPv4,DNSStatic,"9.9.9.9","1.1.1.1")
 ipv6:=restoreFixture(DNSIPv6,DNSAutomatic)
 backend:=newDNSFake(ipv4,ipv6)
 if err:=RestoreVOLVEDNSAfterFailure(context.Background(),[]DNSRestoreRecord{ipv6,ipv4},backend);err!=nil{t.Fatal(err)}
 if len(backend.applied)!=2{t.Fatalf("expected both families restored, got %d",len(backend.applied))}
 if !sameDNSState(backend.current[DNSIPv4],ipv4.Original)||!sameDNSState(backend.current[DNSIPv6],ipv6.Original){
  t.Fatal("original ordered DNS server settings were not restored")
 }
 if err:=RestoreVOLVEDNSAfterFailure(context.Background(),[]DNSRestoreRecord{ipv4,ipv6},backend);err!=nil{
  t.Fatal("safe idempotent postcrash recovery refused:",err)
 }
 if len(backend.applied)!=2 {t.Fatal("idempotent retry changed DNS")}
}
func TestVOLVEDNSRollbackNeverOverwritesExternalDNSChanges(t *testing.T){
 ipv4:=restoreFixture(DNSIPv4,DNSStatic,"8.8.8.8")
 ipv6:=restoreFixture(DNSIPv6,DNSAutomatic)
 backend:=newDNSFake(ipv4,ipv6)
 backend.current[DNSIPv6]=DNSServerState{InterfaceGUID:testAdapterGUID,Family:DNSIPv6,Mode:DNSStatic,Servers:[]string{"2001:4860:4860::8888"}}
 if err:=RestoreVOLVEDNSAfterFailure(context.Background(),[]DNSRestoreRecord{ipv4,ipv6},backend);err==nil{t.Fatal("external DNS change overwritten")}
 if len(backend.applied)!=0{t.Fatal("partial modification before global preflight")}
}
func TestVOLVEDNSRollbackRejectsForgedMissingOrConflictingJournal(t *testing.T){
 baseline:=restoreFixture(DNSIPv4,DNSStatic,"1.1.1.1")
 cases:=[]struct{name string;modify func(*DNSRestoreRecord)}{
  {"unknown-assignment-mode",func(r *DNSRestoreRecord){r.Original.Mode="unknown"}},
  {"missing-original-static",func(r *DNSRestoreRecord){r.Original.Servers=nil}},
  {"invalid-adapter-guid",func(r *DNSRestoreRecord){r.Original.InterfaceGUID="Ethernet"}},
  {"different-target-guid",func(r *DNSRestoreRecord){r.Expected.InterfaceGUID="{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}"}},
  {"different-family",func(r *DNSRestoreRecord){r.Expected.Family=DNSIPv6}},
  {"remote-target",func(r *DNSRestoreRecord){r.Expected.Servers=[]string{"1.1.1.1"}}},
  {"nonstatic-target",func(r *DNSRestoreRecord){r.Expected.Mode=DNSAutomatic;r.Expected.Servers=nil}},
  {"duplicate-expected-servers",func(r *DNSRestoreRecord){r.Expected.Servers=[]string{"127.0.0.1","127.0.0.1"}}},
  {"nonIP-original",func(r *DNSRestoreRecord){r.Original.Servers=[]string{"evil.invalid"}}},
 }
 for _,tc:=range cases{t.Run(tc.name,func(t *testing.T){
  record:=baseline;record.Original.Servers=append([]string(nil),baseline.Original.Servers...)
  record.Expected.Servers=append([]string(nil),baseline.Expected.Servers...)
  tc.modify(&record)
  backend:=newDNSFake(record)
  if err:=RestoreVOLVEDNSAfterFailure(context.Background(),[]DNSRestoreRecord{record},backend);err==nil {
   t.Fatal("bad DNS journal accepted")
  }
  if len(backend.applied)>0{t.Fatal("unsafe DNS adapter modification")}
 })}
 b:=newDNSFake(baseline)
 if err:=RestoreVOLVEDNSAfterFailure(context.Background(),[]DNSRestoreRecord{baseline,baseline},b);err==nil{t.Fatal("duplicate record accepted")}
 if len(b.applied)!=0{t.Fatal("duplicate journal partially restored")}
}
func TestVOLVEDNSRollbackAbortsOnBackendFailureOrCancel(t *testing.T){
 r:=restoreFixture(DNSIPv4,DNSAutomatic)
 backend:=newDNSFake(r);backend.failApply=true
 if err:=RestoreVOLVEDNSAfterFailure(context.Background(),[]DNSRestoreRecord{r},backend);err==nil{t.Fatal("failed apply accepted")}
 if len(backend.applied)!=0{t.Fatal("failed apply was counted as success")}
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 if err:=RestoreVOLVEDNSAfterFailure(ctx,[]DNSRestoreRecord{r},newDNSFake(r));!errors.Is(err,context.Canceled){t.Fatal(err)}
}
func TestVOLVEDNSRollbackRejectsConcurrentModificationBeforeApply(t *testing.T){
 r:=restoreFixture(DNSIPv4,DNSStatic,"8.8.8.8")
 b:=newDNSFake(r)
 // The first read (preflight) is correct; the second read (immediately
 // before Apply) sees another agent's change.
 reads:=0
 b.onRead=func(f *fakeDNSRestoreBackend){reads++}
 // Replacing the backend with a strict concurrent-change emulator.
 guarded:=&concurrentChangeBackend{fakeDNSRestoreBackend:b,thirdParty:DNSServerState{
  InterfaceGUID:testAdapterGUID,Family:DNSIPv4,Mode:DNSStatic,Servers:[]string{"9.9.9.9"},
 }}
 if err:=RestoreVOLVEDNSAfterFailure(context.Background(),[]DNSRestoreRecord{r},guarded);err==nil{t.Fatal("concurrent DNS change overwritten")}
 if len(b.applied)!=0{t.Fatal("concurrent modification overwritten")}
}
type concurrentChangeBackend struct{
 *fakeDNSRestoreBackend
 reads int
 thirdParty DNSServerState
}
func (c *concurrentChangeBackend)Read(ctx context.Context,id string,family DNSAddressFamily)(DNSServerState,error){
 c.reads++
 if c.reads==2 {c.current[family]=c.thirdParty}
 return c.fakeDNSRestoreBackend.Read(ctx,id,family)
}
