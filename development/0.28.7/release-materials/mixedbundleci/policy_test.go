package mixedbundleci
import("bytes";"encoding/json";"fmt";"strings";"testing")
func testBrowserHosts()[]string{
 domains:=[]string{"argentina-app-betwarrior.com","argentina-casino-betwarrior.com"}
 for i:=2;i<BrowserReinforcementEntries;i++{domains=append(domains,fmt.Sprintf("ci-test-site-%03d.example",i))}
 return domains
}
func TestBrowserRegistryPlanUsesOfficialChromeEdgeFirefoxTypes(t *testing.T){
 raw,err:=buildBrowserPolicyForDomains(testBrowserHosts());if err!=nil{t.Fatal(err)}
 var p BrowserPolicyPlan
 if err:=json.Unmarshal(raw,&p);err!=nil{t.Fatal(err)}
 if p.BrowserEnforcementVerified||p.RegistryWriteAuthorized||p.ProductionInstallAuthorized||p.CanPublishRelease{
  t.Fatal("browser plan falsely authorized to be installed")
 }
 if p.ConflictRule!="REFUSE_OR_SKIP_EXISTING_UNOWNED_VALUES"||p.DistinctBlockedDomains!=256||
  p.ListLimit!=1000||len(p.RegistryValues)!=3*256+4{t.Fatal("invalid complement/limit/ownership contract")}
 if p.RegistryValues[0].Key!=`SOFTWARE\Policies\Google\Chrome\URLBlocklist`||
  p.RegistryValues[1].Key!=`SOFTWARE\Policies\Microsoft\Edge\URLBlocklist`||
  p.RegistryValues[2].Key!=`SOFTWARE\Policies\Mozilla\Firefox\WebsiteFilter\Block`{
  t.Fatal("unexpected Windows GPO registry key")
 }
 if p.RegistryValues[2].Value!="*://*.argentina-app-betwarrior.com/*"{t.Fatal("Firefox match-pattern is not webextensions-compatible")}
 end:=p.RegistryValues[len(p.RegistryValues)-4:]
 if end[0].Name!="DnsOverHttpsMode"||end[0].Value!="off"||end[0].Type!="REG_SZ"||
  end[1].Name!="DnsOverHttpsMode"||end[1].Value!="off"||end[1].Type!="REG_SZ"||
  end[2].Type!="REG_DWORD"||end[2].DWord==nil||*end[2].DWord!=0||
  end[3].Type!="REG_DWORD"||end[3].DWord==nil||*end[3].DWord!=1{
   t.Fatal("Windows Firefox and Chrome/Edge DoH policy types invalid")
 }
 if bytes.Contains(raw,[]byte("VOLVE_Uninstall"))||bytes.Contains(raw,[]byte("powershell")){t.Fatal("private or executable content included")}
}
func TestBrowserPlanRejectsDuplicateMaliciousPatternsOrMissingDomains(t *testing.T){
 tests:=[]struct{name string;mutate func([]string)}{
  {"duplicate",func(a []string){a[5]=a[4]}},
  {"url-injection",func(a []string){a[5]="http://example.com/evil"}},
  {"wildcard-injection",func(a []string){a[5]="*.bad.example"}},
  {"bad-leading-label",func(a []string){a[5]="-bad.example"}},
  {"registry-key-injection",func(a []string){a[5]="bad.example\\registry"}},
 }
 for _,tc:=range tests{
  t.Run(tc.name,func(t *testing.T){a:=testBrowserHosts();tc.mutate(a);if _,err:=buildBrowserPolicyForDomains(a);err==nil{t.Fatal("unsafe host accepted")}})
 }
 if _,err:=buildBrowserPolicyForDomains(testBrowserHosts()[:10]);err==nil{t.Fatal("incomplete list accepted")}
}
func TestBrowserPlanIsCanonicalAndCannotClaimRegistryWasWritten(t *testing.T){
 first,err:=buildBrowserPolicyForDomains(testBrowserHosts());if err!=nil{t.Fatal(err)}
 next,err:=buildBrowserPolicyForDomains(testBrowserHosts());if err!=nil{t.Fatal(err)}
 if !bytes.Equal(first,next)||len(BrowserPlanSHA256(first))!=64{t.Fatal("nondeterministic browser payload")}
 if strings.Contains(string(first),"REG_DELETE")||strings.Contains(string(first),`"registry_write_authorized": true`){
  t.Fatal("unsafe registry instruction or false installation proof")
 }
}
