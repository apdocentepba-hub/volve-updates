package uninstallguard

import "testing"

func knownHost() Evidence {
    return Evidence{Schema:1,Complete:true,Elevated:true}
}
func TestObservedRealLegacyHostMustPreserveProtection(t *testing.T) {
    e:=knownHost();e.LegacyTasks=3;e.UDP53=3;e.TCP53=1;e.ProgramFilesRoot=true;e.ProgramDataResidues=1;e.BrowserPolicyStores=2
    p,err:=Review(e)
    if err!=nil || p.Mode!="STOP_LEGACY_0286_PROTECTION_PRESENT" {t.Fatalf("%+v %v",p,err)}
    ensureNoWrites(t,p)
}
func TestRecoveryJournalPrecedesUninstall(t *testing.T) {
    e:=knownHost();e.LegacyTasks=3;e.RecoveryJournalPresent=true
    p,err:=Review(e)
    if err!=nil || p.Mode!="STOP_RECOVERY_JOURNAL_PRESENT" {t.Fatalf("%+v %v",p,err)}
    ensureNoWrites(t,p)
}
func TestManagedHostStillRequiresSignedOwnership(t *testing.T) {
    e:=knownHost();e.OtherVolveTasks=2;e.ProgramFilesRoot=true
    p,err:=Review(e)
    if err!=nil || p.Mode!="STOP_0287_SIGNED_OWNERSHIP_AND_ROLLBACK_NOT_PROVEN"{t.Fatalf("%+v %v",p,err)}
    ensureNoWrites(t,p)
}
func TestCleanHostAndForeignDNSNeverAuthorizeRemoval(t *testing.T) {
    e:=knownHost()
    p,err:=Review(e)
    if err!=nil||p.Mode!="STOP_NO_CONFIRMED_VOLVE_INSTALL"{t.Fatalf("%+v %v",p,err)}
    ensureNoWrites(t,p)
    e.TCP53=1
    p,err=Review(e)
    if err!=nil||p.Mode!="STOP_UNOWNED_DNS53_LISTENER"{t.Fatalf("%+v %v",p,err)}
    ensureNoWrites(t,p)
}
func TestIncompleteOrMalformedInventoryRejected(t *testing.T) {
    for _,e:=range []Evidence{{}, {Schema:1,Complete:true}, {Schema:1,Elevated:true}} {
        if _,err:=Review(e);err==nil{t.Fatalf("incomplete inventory accepted %+v",e)}
    }
    e:=knownHost();e.LegacyTasks=-1
    if _,err:=Review(e);err==nil{t.Fatal("accepted negative legacy task count")}
    e=knownHost();e.UDP53=100001
    if _,err:=Review(e);err==nil{t.Fatal("accepted unbounded DNS listener count")}
}
func ensureNoWrites(t *testing.T,p Plan) {
    t.Helper()
    if p.CanUninstall||p.CanStopMotor||p.CanChangeDNS||p.CanDeleteTasks||p.CanRemoveBrowserPolicies||p.CanDeleteFiles||len(p.Requirements)!=7||p.Status!="NO_UNINSTALL_OR_HOST_CHANGES"{
        t.Fatalf("an uninstaller preview granted destructive capabilities: %+v",p)
    }
}
