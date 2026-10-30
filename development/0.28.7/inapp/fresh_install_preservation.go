package motorupdate

// ProtectionSnapshot is an independently collected before/after baseline.
// It proves preservation of existing protections, NOT that DNS is active.
// The privileged Windows installer must populate it using actual hosts,
// registry policies and Task Scheduler evidence, then compare after install
// and after every rollback attempt.
import (
 "errors"
 "fmt"
 "regexp"
 "strings"
)
type ProtectionSnapshot struct {
 HostsSHA256 string
 HostsBlockedRuleCount int
 ChromePoliciesSHA256 string
 EdgePoliciesSHA256 string
 FirefoxPoliciesSHA256 string
 CatalogTaskDefinitionSHA256 string
}
var protectionDigest=regexp.MustCompile("^[a-f0-9]{64}$")
func validProtectionSnapshot(s ProtectionSnapshot) bool {
 if !protectionDigest.MatchString(strings.ToLower(s.HostsSHA256)) || s.HostsBlockedRuleCount<0 {return false}
 for _,d:=range []string{s.ChromePoliciesSHA256,s.EdgePoliciesSHA256,s.FirefoxPoliciesSHA256,s.CatalogTaskDefinitionSHA256} {
  if d!="" && !protectionDigest.MatchString(strings.ToLower(d)) {return false}
 }
 return true
}
// VerifyPartialProtectionPreserved rejects unplanned changes to existing
// hosts rules, browser policies or the auxiliary catalog task. A deliberate
// change would require a separate authenticated migration plan.
func VerifyPartialProtectionPreserved(before,after ProtectionSnapshot) error {
 if !validProtectionSnapshot(before)||!validProtectionSnapshot(after) {
  return errors.New("incomplete or malformed partial-protection snapshot")
 }
 if !strings.EqualFold(before.HostsSHA256,after.HostsSHA256) ||
  before.HostsBlockedRuleCount!=after.HostsBlockedRuleCount {
  return errors.New("hosts file changed: restore existing site blocks")
 }
 for _,p:=range []struct{name,old,new string}{
  {"Chrome",before.ChromePoliciesSHA256,after.ChromePoliciesSHA256},
  {"Edge",before.EdgePoliciesSHA256,after.EdgePoliciesSHA256},
  {"Firefox",before.FirefoxPoliciesSHA256,after.FirefoxPoliciesSHA256},
  {"catalog task",before.CatalogTaskDefinitionSHA256,after.CatalogTaskDefinitionSHA256},
 } {
  if !strings.EqualFold(p.old,p.new) {return fmt.Errorf("%s existing protection changed",p.name)}
 }
 return nil
}
