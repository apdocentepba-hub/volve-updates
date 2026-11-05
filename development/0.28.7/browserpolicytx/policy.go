// Package browserpolicytx validates and rehearses the EXACT 772-value VOLVE
// browser policy plan. This is CI-only preparation, never a registry installer.
package browserpolicytx

import (
    "bytes"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "regexp"
    "strconv"
    "strings"
)

const (
    BlockedDomains = 256
    PlanEntries = 3*BlockedDomains + 4
    PlanStatus = "DESIRED_STATE_ONLY_NOT_APPLIED"
)
const (
    chrome = `SOFTWARE\Policies\Google\Chrome`
    edge = `SOFTWARE\Policies\Microsoft\Edge`
    firefox = `SOFTWARE\Policies\Mozilla\Firefox`
)
var validDomain=regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

type Value struct {
    Browser string `json:"browser"`
    Hive string `json:"hive"`
    Key string `json:"key"`
    Name string `json:"name"`
    Type string `json:"type"`
    Value string `json:"value,omitempty"`
    DWord *uint32 `json:"dword,omitempty"`
}

type Plan struct {
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
    RegistryValues []Value `json:"registry_values"`
}

// Parse validates structure and semantics; it DOES NOT authenticate the
// original HaGeZi source or a publisher signature. The caller must perform
// those separate checks before considering this plan for any later installer.
func Parse(raw []byte)(Plan,error) {
    var p Plan
    if len(raw)==0 || len(raw)>1<<20 {return p,errors.New("unbounded or empty policy plan")}
    dec:=json.NewDecoder(bytes.NewReader(raw))
    dec.DisallowUnknownFields()
    if err:=dec.Decode(&p);err!=nil{return Plan{},err}
    var extra any
    if err:=dec.Decode(&extra);err!=io.EOF{
        if err==nil{return Plan{},errors.New("multiple JSON objects")}
        return Plan{},fmt.Errorf("trailing policy bytes refused: %w",err)
    }
    if err:=Validate(p);err!=nil{return Plan{},err}
    return p,nil
}

func Validate(p Plan)error {
    if p.Schema!=1||p.Component!="browser-policies"||p.Release!="0.28.7"||
        p.Platform!="windows-amd64"||p.Status!=PlanStatus||
        p.Role!="COMPLEMENTARY_URL_FILTER_AND_DOH_POLICY"||
        p.ConflictRule!="REFUSE_OR_SKIP_EXISTING_UNOWNED_VALUES"||
        p.BrowserEnforcementVerified||p.RegistryWriteAuthorized||
        p.ProductionInstallAuthorized||p.CanPublishRelease||
        p.ListLimit!=1000||p.DistinctBlockedDomains!=BlockedDomains||
        len(p.RegistryValues)!=PlanEntries||len(p.SourceCommit)!=40 {
        return errors.New("unsupported, incomplete, or falsely authorized browser plan")
    }
    for _,c:=range p.SourceCommit {if !strings.ContainsRune("0123456789abcdef",c){return errors.New("invalid pinned source commit")}}
    seen:=make(map[string]bool,BlockedDomains)
    for i:=0;i<BlockedDomains;i++ {
        offset:=3*i
        a,b,c:=p.RegistryValues[offset],p.RegistryValues[offset+1],p.RegistryValues[offset+2]
        index:=strconv.Itoa(i+1)
        if !validDomain.MatchString(a.Value)||a.DWord!=nil||a.Value!=strings.ToLower(a.Value)||seen[a.Value]{
            return fmt.Errorf("invalid, duplicate or unsafe domain at position %d",i+1)
        }
        seen[a.Value]=true
        if !equals(a,Value{Browser:"chrome",Hive:"HKEY_LOCAL_MACHINE",Key:chrome+`\URLBlocklist`,Name:index,Type:"REG_SZ",Value:a.Value})||
            !equals(b,Value{Browser:"edge",Hive:"HKEY_LOCAL_MACHINE",Key:edge+`\URLBlocklist`,Name:index,Type:"REG_SZ",Value:a.Value})||
            !equals(c,Value{Browser:"firefox",Hive:"HKEY_LOCAL_MACHINE",Key:firefox+`\WebsiteFilter\Block`,Name:index,Type:"REG_SZ",Value:"*://*."+a.Value+"/*"}) {
            return fmt.Errorf("browser policy triplet invalid at position %d",i+1)
        }
    }
    d0:=uint32(0);d1:=uint32(1)
    required:=[]Value{
        {Browser:"chrome",Hive:"HKEY_LOCAL_MACHINE",Key:chrome,Name:"DnsOverHttpsMode",Type:"REG_SZ",Value:"off"},
        {Browser:"edge",Hive:"HKEY_LOCAL_MACHINE",Key:edge,Name:"DnsOverHttpsMode",Type:"REG_SZ",Value:"off"},
        {Browser:"firefox",Hive:"HKEY_LOCAL_MACHINE",Key:firefox+`\DNSOverHTTPS`,Name:"Enabled",Type:"REG_DWORD",DWord:&d0},
        {Browser:"firefox",Hive:"HKEY_LOCAL_MACHINE",Key:firefox+`\DNSOverHTTPS`,Name:"Locked",Type:"REG_DWORD",DWord:&d1},
    }
    for i,needed:=range required {
        if !equals(p.RegistryValues[3*BlockedDomains+i],needed) {return fmt.Errorf("invalid DNS-over-HTTPS control %d",i)}
    }
    return nil
}
func equals(a,b Value)bool {
    if a.Browser!=b.Browser||a.Hive!=b.Hive||a.Key!=b.Key||
        a.Name!=b.Name||a.Type!=b.Type||a.Value!=b.Value||
        (a.DWord==nil)!=(b.DWord==nil){return false}
    return a.DWord==nil||*a.DWord==*b.DWord
}
