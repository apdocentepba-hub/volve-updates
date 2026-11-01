//go:build windows

// VOLVE 0.28.7 standalone Windows diagnosis. No installer, motor, auto-updater,
// network client or task-control code is linked into this executable.
package main

import (
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "strings"
 "time"

 "volve-browser-protection/motorupdate"
)

// Production CI injects this from the *actual original* stateDirName
// definition in main_windows.go using -ldflags -X main.stateDirName=VALUE.
// No directory is inferred from an executable filename or guessed by CI.
var stateDirName="UNCONFIGURED_DO_NOT_USE"

const reportComponent="volve-dns-readonly-host-diagnosis"

type Diagnosis struct {
 Schema int `json:"schema"`
 Component string `json:"component"`
 Mode string `json:"mode"`
 ObservedUTC string `json:"observed_utc"`
 Result string `json:"result"`
 Explanation string `json:"explanation"`
 Route *motorupdate.MotorInstallRouteReport `json:"route,omitempty"`
 HostEvidence *motorupdate.WindowsMotorRouteSummary `json:"host_evidence,omitempty"`
 BrowserPolicies *motorupdate.WindowsBrowserPolicyEvidence `json:"browser_policies,omitempty"`
 BrowserPoliciesStatus string `json:"browser_policies_status"`
}

func installedRootFromOriginalStatePath(programData string)(string,error){
 if stateDirName==""||stateDirName=="UNCONFIGURED_DO_NOT_USE"||
  strings.ContainsAny(stateDirName,`/\:`+"\x00")||
  stateDirName=="."||stateDirName==".."{
  return "",errors.New("original installed state folder was not authenticated in build")
 }
 if programData==""||!filepath.IsAbs(programData)||filepath.Clean(programData)!=programData{
  return "",errors.New("original Windows ProgramData variable is missing or invalid")
 }
 root:=filepath.Join(programData,stateDirName)
 if !filepath.IsAbs(root){return "",errors.New("installation state path not absolute")}
 // The original Centro defines statePath as
 // ProgramData/stateDirName/estado.json. This marker is checked, not parsed,
 // because it contains browser-protection state and must not be disclosed.
 marker:=filepath.Join(root,"estado.json")
 info,err:=os.Lstat(marker)
 if err!=nil{return "",fmt.Errorf("installed Centro state marker not accessible: %w",err)}
 if !info.Mode().IsRegular()||info.Size()<2||info.Size()>100000{
  return "",errors.New("installed Centro state marker linked or invalid size")
 }
 return root,nil
}

func diagnosis(ctx context.Context,programData string,admin bool,
 readers motorupdate.WindowsMotorRouteInspectors) Diagnosis {
 result:=Diagnosis{
  Schema:1, Component:reportComponent, Mode:"READ_ONLY_NOT_AN_INSTALLER",
  ObservedUTC:time.Now().UTC().Format(time.RFC3339),
  Result:"INCOMPLETE",Explanation:"Verification not performed; no DNS, task or file changes.",
 }
 if err:=ctx.Err();err!=nil{result.Explanation="Inspection cancelled; host unchanged.";return result}
 if !admin{result.Explanation="Administrator token required for the six independent Windows checks; no changes.";return result}
 root,err:=installedRootFromOriginalStatePath(programData)
 if err!=nil{
  result.Explanation="The installed Centro state root is not independently verifiable: "+err.Error()
  return result
 }
 details,err:=motorupdate.InspectWindowsMotorRouteWithSummaryReadOnly(ctx,root,"","",readers)
 if err!=nil{
  result.Explanation="Six-inventory Windows observation incomplete: "+err.Error()
  return result
 }
 if err:=motorupdate.RequireMotorRouteReviewOnly(details.Decision);err!=nil{
  result.Explanation="Unsafe diagnosis unexpectedly carried a write authorization; discarded."
  return result
 }
 result.Result="REVIEW_ONLY"
 result.Explanation="Six Windows inventories completed without changes. Registry policy counts are separate and do not prove browser enforcement. A signed release and independent rollback remain mandatory."
 result.Route=&details.Decision
 result.HostEvidence=&details.Summary
 return result
}

// Read browser policy registry independently of the DNS motor. Browser keys
// are merely configured policy entries: never claim that Chrome, Edge or
// Firefox actually applied them, or that the DNS engine is running.
func diagnosisWithBrowserPolicies(
 ctx context.Context,programData string,admin bool,
 host motorupdate.WindowsMotorRouteInspectors,
 policies motorupdate.WindowsBrowserPolicyInspect,
) Diagnosis {
 result:=diagnosis(ctx,programData,admin,host)
 if !admin {
  result.BrowserPoliciesStatus="NOT_INSPECTED_NO_ADMIN_TOKEN"
  return result
 }
 if err:=ctx.Err();err!=nil{
  result.BrowserPoliciesStatus="NOT_INSPECTED_CANCELLED"
  return result
 }
 evidence,err:=motorupdate.InspectWindowsBrowserPoliciesReadOnly(ctx,policies)
 if err!=nil{
  result.BrowserPoliciesStatus="UNKNOWN_REGISTRY_QUERY_FAILED"
  return result
 }
 result.BrowserPolicies=&evidence
 result.BrowserPoliciesStatus="REGISTRY_COUNTS_ONLY_NOT_BROWSER_ENFORCEMENT"
 return result
}

func outputToDownloads(home string,report Diagnosis)(string,error){
 if home==""||!filepath.IsAbs(home){return "",errors.New("user profile not available")}
 dir:=filepath.Join(home,"Downloads")
 if info,err:=os.Lstat(dir);err!=nil||!info.IsDir()||info.Mode()&os.ModeSymlink!=0{
  return "",errors.New("Downloads folder unavailable or redirected; see console instead")
 }
 raw,err:=json.MarshalIndent(report,"","  ");if err!=nil{return "",err}
 // Creation is exclusive and confined to Downloads, not ProgramData. A
 // failed or cancelled diagnostic gets an INCOMPLETE report, never a false
 // "motor absent" verdict. No files are overwritten, removed or uploaded.
 name:="VOLVE_Diagnostico_Solo_Lectura_"+time.Now().UTC().Format("20060102_150405.000000000")+".json"
 path:=filepath.Join(dir,name)
 f,err:=os.OpenFile(path,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
 if err!=nil{return "",err}
 if _,err=f.Write(append(raw,'\n'));err!=nil{f.Close();return "",err}
 if err=f.Sync();err!=nil{f.Close();return "",err}
 if err=f.Close();err!=nil{return "",err}
 return path,nil
}

func main(){
 ctx,cancel:=context.WithTimeout(context.Background(),95*time.Second)
 defer cancel()
 admin,err:=motorupdate.InspectWindowsElevatedTokenReadOnly(ctx,motorupdate.DefaultWindowsFreshAdminInspect)
 if err!=nil{admin=false}
 report:=diagnosisWithBrowserPolicies(ctx,os.Getenv("ProgramData"),admin,
  motorupdate.DefaultWindowsMotorRouteInspectors(),motorupdate.DefaultWindowsBrowserPolicyInspect)
 if err!=nil{
  report.Result="INCOMPLETE"
  report.Explanation="Windows administrator token could not be authenticated; no modifications made."
 }
 home,homeErr:=os.UserHomeDir()
 if homeErr==nil {
  if p,e:=outputToDownloads(home,report);e==nil{
   fmt.Println("VOLVÉ: informe de solo lectura creado en Descargas:\n"+p)
   fmt.Println("La protección del equipo no fue modificada.")
   return
  }
 }
 raw,_:=json.MarshalIndent(report,"","  ")
 fmt.Fprintln(os.Stdout,string(raw))
 fmt.Fprintln(os.Stderr,"No se pudo guardar el informe en Descargas. No se modificó VOLVÉ.")
}
