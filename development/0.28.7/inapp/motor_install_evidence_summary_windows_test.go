//go:build windows

package motorupdate

import (
 "context"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestWindowsMotorRouteSummaryKeepsDNSResidueEvenWhenCatalogUnpinned(t *testing.T) {
 root:=t.TempDir()
 readers:=routeFixtureReaders(t,[]windowsVOLVETaskRecord{freshTaskFixture()},true,true)
 got,err:=InspectWindowsMotorRouteWithSummaryReadOnly(context.Background(),root,"","",readers)
 if err!=nil{t.Fatal(err)}
 s:=got.Summary
 if got.Decision.Route!=MotorRouteUnverified || s.InventoriesObserved!=6 ||
  s.VOLVETasks!=1||!s.CatalogTaskSeen||s.CatalogTaskPublisherPinned ||
  s.OtherTaskCount!=0||!s.LocalDNSIPv6Seen||s.UDP53IPv6Listeners!=1 ||
  s.SignedUpgradeAuthorized||s.CanModifyDNS{
  t.Fatalf("unverified catalog hid existing IPv6/DNS port evidence: %+v",got)
 }
 raw,err:=json.Marshal(got);if err!=nil{t.Fatal(err)}
 for _,private:=range []string{`C:\Program Files`,`127.0.0.1`,`::1`,`2001:`,`--catalog`,`VOLVE_Catalog.exe`} {
  if strings.Contains(string(raw),private){t.Fatalf("sensitive task action or address leaked: %s",private)}
 }
}

func TestWindowsMotorRouteSummaryRefusesOrphanedLegacyExecutable(t *testing.T){
 root:=t.TempDir()
 if err:=os.WriteFile(filepath.Join(root,"VOLVE_DNS_Server_0270.exe"),[]byte("MZ_ci_test"),0600);err!=nil{t.Fatal(err)}
 got,err:=InspectWindowsMotorRouteWithSummaryReadOnly(context.Background(),root,"","",
  routeFixtureReaders(t,[]windowsVOLVETaskRecord{},false,false))
 if err!=nil{t.Fatal(err)}
 if got.Decision.Route!=MotorRouteConflictingResidue||
  !got.Summary.LegacyDNSMotorFileSeen||got.Summary.CatalogTaskSeen||
  got.Summary.VOLVETasks!=0||got.Summary.SignedUpgradeAuthorized||got.Summary.CanModifyDNS {
  t.Fatalf("legacy orphan was mistaken for clean host: %+v",got)
 }
}

func TestWindowsMotorRouteSummaryCountsExactLegacyTaskWithoutUpgradingIt(t *testing.T){
 root:=t.TempDir()
 task:=windowsVOLVETaskRecord{
  Name:"VOLVE-DNS-SERVER-0270",TaskPath:"\\",Principal:"SYSTEM",
  DefinitionSHA256:strings.Repeat("a",64),
 }
 got,err:=InspectWindowsMotorRouteWithSummaryReadOnly(context.Background(),root,"","",
  routeFixtureReaders(t,[]windowsVOLVETaskRecord{task},false,false))
 if err!=nil{t.Fatal(err)}
 if got.Decision.Route!=MotorRouteConflictingResidue||got.Summary.VOLVETasks!=1||
  got.Summary.OtherTaskCount!=1||got.Summary.LegacyDNSMotorFileSeen {
  t.Fatalf("task-only engine was accidentally accepted: %+v",got)
 }
}

func TestWindowsMotorRouteSummaryRejectsUnobservedAdministratorOrPort(t *testing.T){
 root:=t.TempDir()
 readers:=routeFixtureReaders(t,[]windowsVOLVETaskRecord{},false,false)
 readers.Host.Admin=func(context.Context,string)([]byte,error){return []byte(`{"Elevated":false}`),nil}
 got,err:=InspectWindowsMotorRouteWithSummaryReadOnly(context.Background(),root,"","",readers)
 if err==nil||got.Summary.InventoriesObserved!=0{t.Fatal("non-admin produced installed route details")}
 readers=routeFixtureReaders(t,[]windowsVOLVETaskRecord{},false,false)
 readers.Port53=func(context.Context,string)([]byte,error){return nil,nil}
 got,err=InspectWindowsMotorRouteWithSummaryReadOnly(context.Background(),root,"","",readers)
 if err==nil||got.Summary.InventoriesObserved!=0{t.Fatal("missing port53 evidence yielded complete summary")}
}
