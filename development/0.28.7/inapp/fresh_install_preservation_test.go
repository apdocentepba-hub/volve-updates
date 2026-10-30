package motorupdate
import (
 "strings"
 "testing"
)
func partialProtectionFixture() ProtectionSnapshot {
 return ProtectionSnapshot{
  HostsSHA256:strings.Repeat("a",64), HostsBlockedRuleCount:160,
  ChromePoliciesSHA256:strings.Repeat("b",64),
  EdgePoliciesSHA256:strings.Repeat("c",64),
  FirefoxPoliciesSHA256:strings.Repeat("d",64),
  CatalogTaskDefinitionSHA256:strings.Repeat("e",64),
 }
}
func TestFreshMotorPreservesHostsBrowserPoliciesAndCatalog(t *testing.T){
 before:=partialProtectionFixture()
 if err:=VerifyPartialProtectionPreserved(before,before);err!=nil{t.Fatal(err)}
}
func TestFreshMotorDetectsPartialProtectionRegressions(t *testing.T){
 cases:=[]struct{name string;edit func(*ProtectionSnapshot)}{
  {"hosts-altered",func(p *ProtectionSnapshot){p.HostsSHA256=strings.Repeat("f",64)}},
  {"hosts-count-dropped",func(p *ProtectionSnapshot){p.HostsBlockedRuleCount=159}},
  {"chrome-removed",func(p *ProtectionSnapshot){p.ChromePoliciesSHA256=""}},
  {"edge-altered",func(p *ProtectionSnapshot){p.EdgePoliciesSHA256=strings.Repeat("f",64)}},
  {"firefox-altered",func(p *ProtectionSnapshot){p.FirefoxPoliciesSHA256=strings.Repeat("f",64)}},
  {"catalog-task-removed",func(p *ProtectionSnapshot){p.CatalogTaskDefinitionSHA256=""}},
  {"hosts-evidence-absent",func(p *ProtectionSnapshot){p.HostsSHA256=""}},
  {"invalid-policy-digest",func(p *ProtectionSnapshot){p.ChromePoliciesSHA256="invalid"}},
  {"unknown-rule-count",func(p *ProtectionSnapshot){p.HostsBlockedRuleCount=-1}},
 }
 for _,tc:=range cases{t.Run(tc.name,func(t *testing.T){
  before:=partialProtectionFixture();after:=before;tc.edit(&after)
  if err:=VerifyPartialProtectionPreserved(before,after);err==nil{t.Fatal("unverified alteration accepted")}
 })}
}
