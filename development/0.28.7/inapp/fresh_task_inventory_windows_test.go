//go:build windows

package motorupdate

import (
 "context"
 "encoding/json"
 "errors"
 "path/filepath"
 "strings"
 "testing"
)

func freshWindowsTaskJSON(t *testing.T,rows []windowsVOLVETaskRecord)[]byte{
 t.Helper();b,e:=json.Marshal(rows);if e!=nil{t.Fatal(e)};return b
}
func freshTaskFixture()windowsVOLVETaskRecord{
 return windowsVOLVETaskRecord{
  Name:"VOLVE-CATALOGO-0230",TaskPath:"\\",Principal:"SYSTEM",
  Actions:[]windowsVOLVETaskAction{{Execute:`C:\Program Files\VOLVE\VOLVE_Catalog.exe`,Arguments:"--catalog"}},
  DefinitionSHA256:strings.Repeat("a",64),
 }
}
func TestWindowsFreshTaskInventoryExactCatalogAndUnknowns(t *testing.T){
 path:=filepath.Clean(`C:\Program Files\VOLVE\VOLVE_Catalog.exe`)
 good:=freshTaskFixture()
 for _,tc:=range []struct{name string;records []windowsVOLVETaskRecord;exe,args string;wantReady bool;wantUnknown int}{
  {"empty",[]windowsVOLVETaskRecord{},"","",true,0},
  {"expected-catalog",[]windowsVOLVETaskRecord{good},path,"--catalog",true,0},
  {"catalog-args-unknown",[]windowsVOLVETaskRecord{good},path,"--delete",false,0},
  {"catalog-path-unknown",[]windowsVOLVETaskRecord{good},"","",false,0},
  {"catalog-principal-untrusted",func()[]windowsVOLVETaskRecord{bad:=good;bad.Principal="Users";return []windowsVOLVETaskRecord{bad}}(),path,"--catalog",false,0},
  {"unknown-dns-task",[]windowsVOLVETaskRecord{{Name:"VOLVE-DNS-SERVER-0270",TaskPath:"\\",Principal:"SYSTEM",DefinitionSHA256:strings.Repeat("b",64)}},path,"--catalog",false,1},
  {"catalog-and-motor",[]windowsVOLVETaskRecord{good,{Name:"VOLVE-DNS-SERVER-0270",TaskPath:"\\",Principal:"SYSTEM",DefinitionSHA256:strings.Repeat("b",64)}},path,"--catalog",false,1},
 }{
  t.Run(tc.name,func(t *testing.T){
   called:=0
   result,err:=InspectWindowsVOLVETasksReadOnly(context.Background(),tc.exe,tc.args,
    func(_ context.Context,query string)([]byte,error){
     called++;if query!=WindowsVOLVETaskInventoryQuery{t.Fatal("not fixed read-only query")}
     return freshWindowsTaskJSON(t,tc.records),nil
    })
   if err!=nil{t.Fatal(err)}
   if called!=1 || len(result.UnknownTaskNames)!=tc.wantUnknown {t.Fatalf("query/unknown mismatch: %+v",result)}
   // Other five OS inventories are synthetic in THIS test; the task
   // inventory itself came from the injected Windows query response.
   evidence:=freshCompleteObservation()
   evidence.VOLVETaskCount=result.VOLVETaskCount
   evidence.VerifiedCatalogTask=result.VerifiedCatalogTask
   accepted:=CheckFreshMotorInstallReadiness(context.Background(),evidence)==nil
   if accepted!=tc.wantReady{t.Fatalf("unsafe fresh classification: accepted=%t want=%t inventory=%+v",accepted,tc.wantReady,result)}
  })
 }
}
func TestWindowsFreshTaskInventoryRejectsMalformedOrAmbiguous(t *testing.T){
 good:=freshTaskFixture()
 for _,tc:=range []struct{name string;raw []byte}{
  {"empty-bytes",nil},{"null",[]byte("null")},
  {"object-not-array",[]byte("{}")},
  {"trailing",[]byte("[] true")},
  {"bad-JSON",[]byte("[")}, 
  {"extra-field",[]byte(`[{"Name":"VOLVE-CATALOGO-0230","TaskPath":"\\","Principal":"SYSTEM","Actions":[],"DefinitionSHA256":"`+strings.Repeat("a",64)+`","Unexpected":true}]`)},
  {"duplicate",freshWindowsTaskJSON(t,[]windowsVOLVETaskRecord{good,good})},
  {"corrupted-SHA",func()[]byte{bad:=good;bad.DefinitionSHA256="not-sha";return freshWindowsTaskJSON(t,[]windowsVOLVETaskRecord{bad})}()},
  {"irrelevant-task",freshWindowsTaskJSON(t,[]windowsVOLVETaskRecord{{Name:"WindowsUpdate",TaskPath:"\\",DefinitionSHA256:strings.Repeat("b",64)}})},
 }{
  t.Run(tc.name,func(t *testing.T){
   _,err:=InspectWindowsVOLVETasksReadOnly(context.Background(),"","",
    func(context.Context,string)([]byte,error){return tc.raw,nil})
   if err==nil{t.Fatalf("unsafe task inventory accepted: %s",tc.name)}
  })
 }
}
func TestWindowsFreshTaskInventoryFailClosedOnCancelledOrUntrustedQuery(t *testing.T){
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 called:=false
 _,err:=InspectWindowsVOLVETasksReadOnly(ctx,"","",func(context.Context,string)([]byte,error){called=true;return []byte("[]"),nil})
 if !errors.Is(err,context.Canceled)||called{t.Fatalf("cancelled inventory was executed: %v",err)}
 if _,err:=DefaultWindowsFreshTaskInspect(context.Background(),"Start-ScheduledTask");err==nil{
  t.Fatal("unallowlisted PowerShell must not execute")
 }
}
// Actual read-only Windows API query with no fixture and no task mutations.
// Runner is disposable; an unrelated VOLVE task, if any, is reported instead
// of incorrectly classified as clean.
func TestWindowsFreshTaskInventoryRealTaskSchedulerReadOnly(t *testing.T){
 if testing.Short(){t.Skip("native Windows inventory only for integration")}
 ctx:=context.Background()
 result,err:=InspectWindowsVOLVETasksReadOnly(ctx,"","",DefaultWindowsFreshTaskInspect)
 if err!=nil{t.Fatalf("real Windows task inventory failed closed: %v",err)}
 if result.VOLVETaskCount!=len(result.UnknownTaskNames) && result.VerifiedCatalogTask==nil {
  t.Fatalf("task inventory count inconsistent: %+v",result)
 }
 t.Logf("READ ONLY: enumerated %d VOLVE tasks, catalog verified=%t, unknown task count=%d (NO task/DNS writes)",
  result.VOLVETaskCount,result.VerifiedCatalogTask!=nil&&result.VerifiedCatalogTask.ActionVerified,len(result.UnknownTaskNames))
}
