package mixedbundleci
import(
 "bufio"
 "bytes"
 "crypto/sha256"
 "encoding/json"
 "errors"
 "fmt"
 "regexp"
 "strings"
)
const BrowserReinforcementEntries=256
type BrowserPolicyPlan struct{
 Schema int `json:"schema"`
 Component string `json:"component"`
 Release string `json:"release"`
 Platform string `json:"platform"`
 SourceCommit string `json:"source_commit"`
 Role string `json:"role"`
 Status string `json:"status"`
 ConflictRule string `json:"conflict_rule"`
 BrowserEnforcementVerified bool `json:"browser_enforcement_verified"`
 RegistryWriteAuthorized bool `json:"registry_write_authorized"`
 ProductionInstallAuthorized bool `json:"production_install_authorized"`
 CanPublishRelease bool `json:"can_publish_release"`
 ListLimit int `json:"list_limit"`
 DistinctBlockedDomains int `json:"distinct_blocked_domains"`
 RegistryValues []BrowserRegistryValue `json:"registry_values"`
}
type BrowserRegistryValue struct{
 Browser string `json:"browser"`
 Hive string `json:"hive"`
 Key string `json:"key"`
 Name string `json:"name"`
 Type string `json:"type"`
 Value string `json:"value,omitempty"`
 DWord *uint32 `json:"dword,omitempty"`
}
var policyDomainRe=regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
// selectDomains extracts a reproducible, diverse 256-entry reinforcement
// directly from the authenticated 626k-rule Full feed. It is NOT a claim
// that these are the 256 most visited/important gambling domains.
func selectDomains(catalog []byte)([]string,error){
 pinned:=[]string{"argentina-app-betwarrior.com","argentina-casino-betwarrior.com"}
 found:=map[string]bool{pinned[0]:false,pinned[1]:false}
 candidates:=make([]string,0,512)
 seen:=make(map[string]struct{},65536)
 scan:=bufio.NewScanner(bytes.NewReader(catalog));scan.Buffer(make([]byte,4096),1024*1024)
 index:=0
 for scan.Scan(){
  domain:=strings.TrimSpace(scan.Text())
  if domain==""||strings.HasPrefix(domain,"#"){continue}
  // Never broaden a wildcard-only upstream rule to its apex domain.
  // A later semantic mapping may support wildcard entries separately.
  if strings.HasPrefix(domain,"*."){continue}
  if !policyDomainRe.MatchString(domain){return nil,errors.New("malformed official browser-policy domain")}
  if _,yes:=found[domain];yes{found[domain]=true}
  if _,yes:=seen[domain];yes{continue}
  seen[domain]=struct{}{}
  // Fixed wide spacing avoids taking only the alphabetical beginning.
  if index%1400==0{candidates=append(candidates,domain)}
  index++
 }
 if err:=scan.Err();err!=nil{return nil,err}
 for host,ok:=range found{if !ok{return nil,fmt.Errorf("priority domain missing in exact source: %s",host)}}
 selected:=append([]string{},pinned...)
 used:=map[string]bool{pinned[0]:true,pinned[1]:true}
 for _,domain:=range candidates{
  if !used[domain]{selected=append(selected,domain);used[domain]=true}
  if len(selected)==BrowserReinforcementEntries{break}
 }
 if len(selected)!=BrowserReinforcementEntries{return nil,errors.New("not enough unique pinned-source browser domains")}
 return selected,nil
}
func policyString(browser,key,name,val string)BrowserRegistryValue{
 return BrowserRegistryValue{Browser:browser,Hive:"HKEY_LOCAL_MACHINE",Key:key,Name:name,Type:"REG_SZ",Value:val}
}
func policyDWORD(browser,key,name string,val uint32)BrowserRegistryValue{
 return BrowserRegistryValue{Browser:browser,Hive:"HKEY_LOCAL_MACHINE",Key:key,Name:name,Type:"REG_DWORD",DWord:&val}
}
// buildBrowserPolicyForDomains only describes desired registry values; it
// never alters any registry key, executable, adapter DNS or Windows task.
// A later privileged installer must implement consent, ownership, backups,
// conflict refusal, activation evidence and atomic recovery separately.
func buildBrowserPolicyForDomains(domains []string)([]byte,error){
 if len(domains)!=BrowserReinforcementEntries{return nil,errors.New("256 source domains required")}
 used:=map[string]bool{}
 for _,domain:=range domains{
  if !policyDomainRe.MatchString(domain)||used[domain]{return nil,errors.New("invalid or duplicate browser policy host")}
  used[domain]=true
 }
 const chrome="SOFTWARE\\Policies\\Google\\Chrome"
 const edge="SOFTWARE\\Policies\\Microsoft\\Edge"
 const firefox="SOFTWARE\\Policies\\Mozilla\\Firefox"
 entries:=make([]BrowserRegistryValue,0,3*len(domains)+4)
 for i,domain:=range domains{
  index:=fmt.Sprintf("%d",i+1)
  entries=append(entries,policyString("chrome",chrome+"\\URLBlocklist",index,domain))
  entries=append(entries,policyString("edge",edge+"\\URLBlocklist",index,domain))
  entries=append(entries,policyString("firefox",firefox+"\\WebsiteFilter\\Block",index,"*://*."+domain+"/*"))
 }
 entries=append(entries,policyString("chrome",chrome,"DnsOverHttpsMode","off"))
 entries=append(entries,policyString("edge",edge,"DnsOverHttpsMode","off"))
 entries=append(entries,policyDWORD("firefox",firefox+"\\DNSOverHTTPS","Enabled",0))
 entries=append(entries,policyDWORD("firefox",firefox+"\\DNSOverHTTPS","Locked",1))
 plan:=BrowserPolicyPlan{Schema:1,Component:"browser-policies",Release:"0.28.7",Platform:"windows-amd64",
  SourceCommit:PinnedFullCatalogCommit,Role:"COMPLEMENTARY_URL_FILTER_AND_DOH_POLICY",
  Status:"DESIRED_STATE_ONLY_NOT_APPLIED",ConflictRule:"REFUSE_OR_SKIP_EXISTING_UNOWNED_VALUES",
  BrowserEnforcementVerified:false,RegistryWriteAuthorized:false,ProductionInstallAuthorized:false,
  CanPublishRelease:false,ListLimit:1000,DistinctBlockedDomains:len(domains),RegistryValues:entries}
 raw,err:=json.MarshalIndent(plan,"","  ");if err!=nil{return nil,err}
 return append(raw,'\n'),nil
}
func CreateBrowserPolicyPlan(catalog,receipt []byte)([]byte,error){
 if err:=VerifyPinnedFullCatalog(catalog,receipt);err!=nil{return nil,err}
 domains,err:=selectDomains(catalog);if err!=nil{return nil,err}
 return buildBrowserPolicyForDomains(domains)
}
func VerifyBrowserPolicyPlan(raw,catalog,receipt []byte)error{
 expected,err:=CreateBrowserPolicyPlan(catalog,receipt);if err!=nil{return err}
 if !bytes.Equal(raw,expected){return errors.New("registry policy differs from fixed pinned-source zero-write plan")}
 return nil
}
func BrowserPlanSHA256(plan []byte)string{
 digest:=sha256.Sum256(plan);return fmt.Sprintf("%x",digest[:])
}
