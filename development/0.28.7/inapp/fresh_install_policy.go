package motorupdate

// A CLEAN installation is NOT a migration from a protected legacy DNS task.
// This policy distinguishes the two paths without disabling the legacy signed
// migration and rollback requirements. It is a preflight only; it never writes
// DNS, tasks, files, registry or a product inventory.
import (
 "context"
 "errors"
 "fmt"
 "regexp"
 "strings"
)

// Independent task identity evidence, not an installer-controlled flag.
type VerifiedFreshCatalogTask struct {
 Name string
 TaskPath string
 ActionCount int
 ActionVerified bool
 PrincipalVerified bool
 DefinitionSHA256 string
}
var freshTaskSHA256 = regexp.MustCompile("^[a-f0-9]{64}$")

func allowedFreshAuxiliaryTask(t *VerifiedFreshCatalogTask) bool {
 return t!=nil && t.Name=="VOLVE-CATALOGO-0230" && t.TaskPath=="\\" &&
  t.ActionCount==1 && t.ActionVerified && t.PrincipalVerified &&
  freshTaskSHA256.MatchString(strings.ToLower(t.DefinitionSHA256))
}

type FreshMotorInstallEvidence struct {
 // Root and identity were independently inspected with Administrator access,
 // not read from the candidate installer, an untrusted journal or a UI flag.
 InspectedAsAdministrator bool
 LegacyExecutablePresent bool
 VersionedMotorPresent bool
 InstalledEngineInventoryPresent bool
 VOLVETaskCount int
 VerifiedCatalogTask *VerifiedFreshCatalogTask
 VOLVEServiceCount int
 LocalIPv4DNSConfigured bool
 LocalIPv6DNSConfigured bool
 UDP53IPv4OwnerCount int
 UDP53IPv6OwnerCount int
 RecoveryJournalPresent bool
 PendingRollbackPresent bool
}

// CheckFreshMotorInstallReadiness is necessary but INSUFFICIENT to install.
// The privileged installer MUST separately verify publisher-signed motor and
// Full catalog, NTFS ACL, watchdog, post-boot recovery, exclusive mutex,
// currently installed panel compatibility and working Internet. Tests using
// synthetic evidence do NOT certify a clean Windows host.
func CheckFreshMotorInstallReadiness(ctx context.Context, e FreshMotorInstallEvidence) error {
 if err:=ctx.Err();err!=nil{return err}
 if !e.InspectedAsAdministrator{
  return errors.New("cannot prove clean motor state without Administrator inspection")
 }
 if e.LegacyExecutablePresent || e.VersionedMotorPresent || e.InstalledEngineInventoryPresent {
  return errors.New("motor already exists: use signed migration/update, never a fresh install")
 }
 if e.VOLVETaskCount<0 || e.VOLVEServiceCount!=0 ||
    e.UDP53IPv4OwnerCount!=0 || e.UDP53IPv6OwnerCount!=0 {
  return errors.New("existing/unknown service or occupied DNS/53 prevents clean installation")
 }
 switch e.VOLVETaskCount {
 case 0:
  if e.VerifiedCatalogTask!=nil {return errors.New("catalog task record contradicts observed count")}
 case 1:
  if !allowedFreshAuxiliaryTask(e.VerifiedCatalogTask) {
   return errors.New("unverified or unrelated VOLVE task prevents clean motor installation")
  }
 default:
  return fmt.Errorf("%d VOLVE tasks: clean installation requires exhaustive task inspection",e.VOLVETaskCount)
 }
 if e.LocalIPv4DNSConfigured || e.LocalIPv6DNSConfigured {
  return errors.New("a Windows adapter still points to local DNS; restore original settings first")
 }
 if e.RecoveryJournalPresent || e.PendingRollbackPresent {
  return errors.New("old recovery transaction or journal must be resolved, never overwritten")
 }
 return nil
}
