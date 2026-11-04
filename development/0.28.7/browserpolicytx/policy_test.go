package browserpolicytx

import (
    "context"
    "encoding/json"
    "errors"
    "fmt"
    "strconv"
    "strings"
    "testing"
)

func fixturePlan()Plan {
    p:=Plan{
        Schema:1,Component:"browser-policies",Release:"0.28.7",Platform:"windows-amd64",
        SourceCommit:strings.Repeat("a",40),Role:"COMPLEMENTARY_URL_FILTER_AND_DOH_POLICY",
        Status:PlanStatus,ConflictRule:"REFUSE_OR_SKIP_EXISTING_UNOWNED_VALUES",
        ListLimit:1000,DistinctBlockedDomains:BlockedDomains,
    }
    for i:=0;i<BlockedDomains;i++{
        domain:=fmt.Sprintf("ci-%03d.example",i)
        idx:=strconv.Itoa(i+1)
        p.RegistryValues=append(p.RegistryValues,
            Value{Browser:"chrome",Hive:"HKEY_LOCAL_MACHINE",Key:chrome+`\URLBlocklist`,Name:idx,Type:"REG_SZ",Value:domain},
            Value{Browser:"edge",Hive:"HKEY_LOCAL_MACHINE",Key:edge+`\URLBlocklist`,Name:idx,Type:"REG_SZ",Value:domain},
            Value{Browser:"firefox",Hive:"HKEY_LOCAL_MACHINE",Key:firefox+`\WebsiteFilter\Block`,Name:idx,Type:"REG_SZ",Value:"*://*."+domain+"/*"},
        )
    }
    zero:=uint32(0);one:=uint32(1)
    p.RegistryValues=append(p.RegistryValues,
        Value{Browser:"chrome",Hive:"HKEY_LOCAL_MACHINE",Key:chrome,Name:"DnsOverHttpsMode",Type:"REG_SZ",Value:"off"},
        Value{Browser:"edge",Hive:"HKEY_LOCAL_MACHINE",Key:edge,Name:"DnsOverHttpsMode",Type:"REG_SZ",Value:"off"},
        Value{Browser:"firefox",Hive:"HKEY_LOCAL_MACHINE",Key:firefox+`\DNSOverHTTPS`,Name:"Enabled",Type:"REG_DWORD",DWord:&zero},
        Value{Browser:"firefox",Hive:"HKEY_LOCAL_MACHINE",Key:firefox+`\DNSOverHTTPS`,Name:"Locked",Type:"REG_DWORD",DWord:&one},
    )
    return p
}
func TestExact772PolicyAndJSON(t *testing.T){
    p:=fixturePlan()
    if err:=Validate(p);err!=nil{t.Fatal(err)}
    data,err:=json.Marshal(p);if err!=nil{t.Fatal(err)}
    parsed,err:=Parse(data);if err!=nil{t.Fatal(err)}
    if len(parsed.RegistryValues)!=PlanEntries{t.Fatal("wrong value count")}
    for _,tc:=range []struct{name string;mutate func(*Plan)}{
        {"missing-value",func(p *Plan){p.RegistryValues=p.RegistryValues[:771]}},
        {"wrong-order",func(p *Plan){p.RegistryValues[0],p.RegistryValues[1]=p.RegistryValues[1],p.RegistryValues[0]}},
        {"duplicate-host",func(p *Plan){p.RegistryValues[3].Value=p.RegistryValues[0].Value}},
        {"foreign-hive",func(p *Plan){p.RegistryValues[0].Hive="HKEY_CURRENT_USER"}},
        {"foreign-key",func(p *Plan){p.RegistryValues[0].Key=`SOFTWARE\Other`}},
        {"wrong-DoH",func(p *Plan){p.RegistryValues[769].Value="automatic"}},
        {"skip-DNS",func(p *Plan){p.RegistryValues[768].Name="Foreign"}},
        {"false-authority",func(p *Plan){p.ProductionInstallAuthorized=true}},
        {"bad-registry-type",func(p *Plan){p.RegistryValues[0].Type="REG_DWORD"}},
        {"injected-host",func(p *Plan){p.RegistryValues[0].Value="evil.example\\x"}},
        {"wrong-schema",func(p *Plan){p.Schema=2}},
    }{
        t.Run(tc.name,func(t *testing.T){p:=fixturePlan();tc.mutate(&p);if err:=Validate(p);err==nil{t.Fatal("unsafe policy accepted")}})
    }
    if _,err:=Parse(append(data,[]byte("{}")...));err==nil{t.Fatal("extra object accepted")}
}
type memory struct{data map[string]Value;writes int;failAt int;refuseDelete bool}
func newMemory()*memory{return &memory{data:make(map[string]Value)}}
func token(v Value)string{return v.Key+"|"+v.Name}
func(m *memory) Exists(_ context.Context,v Value)(bool,error){_,yes:=m.data[token(v)];return yes,nil}
func(m *memory) CreateOnly(_ context.Context,v Value)error{
    if _,ok:=m.data[token(v)];ok{return errors.New("existing value")}
    m.writes++
    if m.failAt>0&&m.writes==m.failAt{return errors.New("simulated write failure")}
    m.data[token(v)]=v
    return nil
}
func(m *memory) DeleteOnlyIfEqual(_ context.Context,v Value)error{
    if m.refuseDelete{return errors.New("simulated rollback failure")}
    old,ok:=m.data[token(v)]
    if !ok||!equals(old,v){return errors.New("state changed")}
    delete(m.data,token(v))
    return nil
}
func TestTrialFullPolicyRollsBackAll772Values(t *testing.T){
    store:=newMemory()
    outcome,err:=Rehearse(context.Background(),fixturePlan(),store)
    if err!=nil{t.Fatal(err)}
    if outcome.Created!=PlanEntries||outcome.Reverted!=PlanEntries||outcome.Checked!=PlanEntries||
        outcome.State!="LAB_ROLLBACK_COMPLETE_NO_INSTALL"||outcome.CanInstall||len(store.data)!=0{
        t.Fatalf("lab left policy values or claimed install rights: %+v",outcome)
    }
}
func TestTrialRejectsUnownedExistingWithoutWrites(t *testing.T){
    store:=newMemory()
    p:=fixturePlan()
    store.data[token(p.RegistryValues[15])]=p.RegistryValues[15]
    _,err:=Rehearse(context.Background(),p,store)
    if err==nil||store.writes!=0||len(store.data)!=1{t.Fatal("overwrote pre-existing unowned browser policy")}
}
func TestTrialReversesInterruptedWriteAndFailsClosed(t *testing.T){
    store:=newMemory();store.failAt=250
    outcome,err:=Rehearse(context.Background(),fixturePlan(),store)
    if err==nil||outcome.Reverted!=249||len(store.data)!=0||outcome.CanInstall{
        t.Fatalf("failed write lost rollback contract: %+v, %v",outcome,err)
    }
    store=newMemory();store.failAt=3;store.refuseDelete=true
    outcome,err=Rehearse(context.Background(),fixturePlan(),store)
    if err==nil||outcome.Reverted!=0||outcome.CanInstall||len(store.data)!=2{
        t.Fatalf("partial rollback falsely completed: %+v, %v",outcome,err)
    }
}
func TestTrialNeverCallsStoreOnInvalidPlanOrCancelledContext(t *testing.T){
    store:=newMemory()
    p:=fixturePlan();p.RegistryWriteAuthorized=true
    if _,err:=Rehearse(context.Background(),p,store);err==nil||store.writes!=0{t.Fatal("unsafe plan wrote values")}
    ctx,cancel:=context.WithCancel(context.Background());cancel()
    if _,err:=Rehearse(ctx,fixturePlan(),store);!errors.Is(err,context.Canceled)||store.writes!=0{t.Fatal("canceled trial wrote values")}
}
