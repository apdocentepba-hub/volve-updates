// Package mixedbundleci audits and stages a mixed REAL/SYNTHETIC Windows
// payload only on disposable CI. It cannot authorize an installation.
package mixedbundleci

import (
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "fmt"
 "strings"
)

const (
 ExpectedHistoricMotorSHA256="e451b6289116636986ddd67b39dc15f02e471ebde7be9508b38d7bcb0155b414"
 ExpectedHistoricMotorBytes=int64(18168832)
)

type Material struct {
 ID string `json:"id"`
 Filename string `json:"filename"`
 State string `json:"state"`
 SHA256 string `json:"sha256"`
 PE string `json:"pe"`
 Bytes int64 `json:"bytes"`
}
type Audit struct{
 Schema int `json:"schema"`
 TargetRelease string `json:"target_release"`
 Platform string `json:"platform"`
 ArtifactType string `json:"artifact_type"`
 Materials []Material `json:"materials"`
 CheckedCompiledRoles int `json:"checked_compiled_roles"`
 CheckedHistoricCandidateRoles int `json:"checked_historic_candidate_roles"`
 CheckedBuildMaterialRoles int `json:"checked_build_material_roles"`
 MissingProductionReleaseRoles int `json:"missing_production_release_roles"`
 PublisherAuthenticodeVerifiedForRelease bool `json:"publisher_authenticode_verified_for_release"`
 Ed25519ReleaseManifestVerified bool `json:"ed25519_release_manifest_verified"`
 SignedLegacyMigrationPermitVerified bool `json:"signed_legacy_migration_permit_verified"`
 ProductionInstallAuthorized bool `json:"production_install_authorized"`
 CanModifyDNSOrTasks bool `json:"can_modify_dns_or_tasks"`
 CanPublishRelease bool `json:"can_publish_release"`
}
var wantedFilenames=map[string]string{
 "centro-updater":"VOLVE_Centro_Updater.exe",
 "dns-motor":"VOLVE_DNS_Motor_0_28_7.exe",
 "motor-manifest":"VOLVE_DNS_Motor_0_28_7.exe.json",
 "motor-signature":"VOLVE_DNS_Motor_0_28_7.exe.sig",
 "system-watchdog":"VOLVE_Managed_Watchdog.exe",
 "browser-policies":"VOLVE_Browser_Policies.json",
 "full-catalog":"VOLVE_Full_Catalog.txt",
}
// ValidateAudit refuses a misleading "ready for release" report, even when
// all physical inputs are present. A previous native Windows test must have
// verified the exact historic motor publisher signature independently.
func ValidateAudit(a Audit) error{
 if a.Schema!=1 || a.TargetRelease!="0.28.7" || a.Platform!="windows-amd64" ||
  a.ArtifactType!="CI_BUILD_MATERIALS_AUDIT_NO_RELEASE" ||
  a.CheckedCompiledRoles!=2||a.CheckedHistoricCandidateRoles!=1||
  a.CheckedBuildMaterialRoles!=3||a.MissingProductionReleaseRoles!=7||
  a.PublisherAuthenticodeVerifiedForRelease||a.Ed25519ReleaseManifestVerified||
  a.SignedLegacyMigrationPermitVerified||a.ProductionInstallAuthorized||
  a.CanModifyDNSOrTasks||a.CanPublishRelease {
  return errors.New("audit state does not prove exactly three historic/CI material roles and NO release permission")
 }
 if len(a.Materials)!=len(wantedFilenames){return errors.New("seven public roles required")}
 seen:=map[string]bool{}
 for _,m:=range a.Materials{
  expected,ok:=wantedFilenames[m.ID]
  if !ok||m.Filename!=expected||seen[m.ID]{
   return fmt.Errorf("foreign, owner-only or duplicate public role: %q",m.ID)
  }
  seen[m.ID]=true
  switch m.ID{
  case "centro-updater","system-watchdog":
   if m.State!="BUILT_CI_UNSIGNED_NOT_INSTALLABLE"||m.Bytes<1<<20||!validHash(m.SHA256)||m.PE!="PE32+ x64"{
    return fmt.Errorf("compiled role %q not independently audited",m.ID)
   }
  case "dns-motor":
   if m.State!="PINNED_HISTORIC_SIGNED_DNS_CANDIDATE_NOT_INSTALLABLE"||
    m.Bytes!=ExpectedHistoricMotorBytes||m.SHA256!=ExpectedHistoricMotorSHA256||m.PE!="PE32+ x64"{
    return errors.New("historic publisher-signed motor not pinned to original bytes")
   }
  default:
   if m.State!="MISSING_PRODUCTION_RELEASE_INPUT"||m.SHA256!=""||m.Bytes!=0||m.PE!=""{
    return fmt.Errorf("production-critical role %q was falsely marked complete",m.ID)
   }
  }
 }
 return nil
}
func validHash(s string)bool{
 if len(s)!=64||strings.ToLower(s)!=s{return false}
 _,err:=hex.DecodeString(s)
 return err==nil
}
func SHA256(data []byte)string{sum:=sha256.Sum256(data);return hex.EncodeToString(sum[:])}
