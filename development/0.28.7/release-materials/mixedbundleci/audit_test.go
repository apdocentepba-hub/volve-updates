package mixedbundleci
import(
 "context"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func expectedAudit()Audit{
 roles:=[]string{"centro-updater","dns-motor","motor-manifest","motor-signature","system-watchdog","browser-policies","full-catalog"}
 m:=make([]Material,0,7)
 for _,role:=range roles{
  entry:=Material{ID:role,Filename:wantedFilenames[role],State:"MISSING_PRODUCTION_RELEASE_INPUT"}
  switch role{
  case "centro-updater","system-watchdog":
   entry.State="BUILT_CI_UNSIGNED_NOT_INSTALLABLE"
   entry.PE="PE32+ x64"
   entry.Bytes=1<<20
   entry.SHA256=strings.Repeat("a",64)
  case "dns-motor":
   entry.State="PINNED_HISTORIC_SIGNED_DNS_CANDIDATE_NOT_INSTALLABLE"
   entry.PE="PE32+ x64"
   entry.Bytes=ExpectedHistoricMotorBytes
   entry.SHA256=ExpectedHistoricMotorSHA256
  }
  m=append(m,entry)
 }
 return Audit{Schema:1,TargetRelease:"0.28.7",Platform:"windows-amd64",
  ArtifactType:"CI_BUILD_MATERIALS_AUDIT_NO_RELEASE",Materials:m,CheckedCompiledRoles:2,
  CheckedHistoricCandidateRoles:1,CheckedBuildMaterialRoles:3,MissingProductionReleaseRoles:7,
 }
}
func TestActualThreeMaterialAuditMustRemainNonReleasable(t *testing.T){
 a:=expectedAudit()
 if err:=ValidateAudit(a);err!=nil{t.Fatal(err)}
 if len(a.Materials)!=7{t.Fatal("seven roles required")}
}
func TestReleasePermissionDriftIsRejected(t *testing.T){
 for _,tc:=range []struct{name string;change func(*Audit)}{
  {"install",func(a *Audit){a.ProductionInstallAuthorized=true}},
  {"publisher",func(a *Audit){a.PublisherAuthenticodeVerifiedForRelease=true}},
  {"publishing",func(a *Audit){a.CanPublishRelease=true}},
  {"change-dns",func(a *Audit){a.CanModifyDNSOrTasks=true}},
  {"signed-grant",func(a *Audit){a.SignedLegacyMigrationPermitVerified=true}},
  {"false-ready-count",func(a *Audit){a.MissingProductionReleaseRoles=0}},
  {"old-eight-roles",func(a *Audit){a.MissingProductionReleaseRoles=8}},
  {"no-historic-motor",func(a *Audit){a.CheckedHistoricCandidateRoles=0}},
  {"extra-role",func(a *Audit){a.Materials=append(a.Materials,Material{ID:"uninstaller",Filename:"VOLVE_Uninstall.exe"})}},
  {"owner-uninstaller-replaces-catalog",func(a *Audit){a.Materials[6].Filename="VOLVE_Uninstall.exe"}},
  {"bad-historic-sha",func(a *Audit){a.Materials[1].SHA256=strings.Repeat("f",64)}},
  {"fake-native-windows",func(a *Audit){a.Materials[0].SHA256="garbage"}},
  {"wrong-pe-arch",func(a *Audit){a.Materials[0].PE="PE32 x86"}},
  {"fake-missing-pe",func(a *Audit){a.Materials[6].PE="PE32+ x64"}},
  {"faked-production-catalog",func(a *Audit){a.Materials[6].State="BUILT_CI_UNSIGNED_NOT_INSTALLABLE"}},
 } {
  t.Run(tc.name,func(t *testing.T){a:=expectedAudit();tc.change(&a);if err:=ValidateAudit(a);err==nil{t.Fatal("unsafe auditor claim accepted")}})
 }
}
func TestBuildRejectsMissingOrUntrustedInputsBeforeCreatingOutput(t *testing.T){
 temp:=t.TempDir()
 root:=filepath.Join(temp,"VOLVE-CI-MIXED-REAL-5")
 inactive:=filepath.Join(temp,"VOLVE-CI-VERSION-0287-MIXED")
 a:=expectedAudit()
 raw,err:=json.Marshal(a);if err!=nil{t.Fatal(err)}
 audit:=filepath.Join(temp,"auditor.json")
 if err:=os.WriteFile(audit,raw,0600);err!=nil{t.Fatal(err)}
 _,err=BuildMixedLab(context.Background(),Sources{
  Root:root,Inactive:inactive,AuditJSON:audit,
  Centro:filepath.Join(temp,"missing-centre.exe"),
 })
 if err==nil{t.Fatal("missing real Centro silently replaced by synthetic fixture")}
 for _,p:=range []string{root,inactive}{
  if _,err:=os.Lstat(p);!os.IsNotExist(err){t.Fatalf("unexpected file created by failed preflight: %s %v",p,err)}
 }
}
