//go:build windows

package main

// Read-only fence for a future SYSTEM recovery driver. Never edits files,
// services, tasks or DNS. A verified publisher grant is necessary but NOT
// sufficient to replace a live DNS executable.
import (
 "bytes"
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "path/filepath"
 "strings"
)

type residentQuiescenceObservation struct {
 TaskName string
 TaskPath string
 Principal string
 ActionCount int
 ActionExecute string
 ActionArguments string
 MotorProcessCount int
 UDP53Count int
 TCP53Count int
}
type residentQuiescenceDecision struct {
 TaskIdentityVerified bool
 DNSPortFree bool
 MotorProcessesStopped bool
 ReadyForFurtherChecks bool
}

func validateResidentQuiescence(root, version string, o residentQuiescenceObservation)(residentQuiescenceDecision,error){
 var no residentQuiescenceDecision
 if !filepath.IsAbs(root)||filepath.Clean(root)!=root||version!="0.28.7"{
  return no,errors.New("untrusted installation root or unsigned target version")
 }
 if o.TaskName!="VOLVE-DNS-SERVER-0270" || o.TaskPath!="\\" ||
  (o.Principal!="SYSTEM"&&o.Principal!="S-1-5-18") ||
  o.ActionCount!=1 || o.ActionArguments!="--dns-service" {
  return no,errors.New("live SYSTEM DNS task identity is not exact")
 }
 target:="VOLVE_DNS_Motor_0_28_7.exe"
 paths:=[]string{filepath.Join(root,residentLegacyExe),
  filepath.Join(root,target),filepath.Join(root,"installed-engines",target)}
 path:=strings.Trim(o.ActionExecute,"\"")
 if !filepath.IsAbs(path)||filepath.Clean(path)!=path {return no,errors.New("task executable is not absolute/canonical")}
 allowed:=false
 for _,p:=range paths {if strings.EqualFold(path,p){allowed=true;break}}
 if !allowed {return no,errors.New("task points to unrelated executable")}
 if o.MotorProcessCount<0||o.MotorProcessCount>10000||
  o.UDP53Count<0||o.UDP53Count>10000||
  o.TCP53Count<0||o.TCP53Count>10000{
  return no,errors.New("untrustworthy process or port counts")
 }
 decision:=residentQuiescenceDecision{
  TaskIdentityVerified:true,
  DNSPortFree:o.UDP53Count==0&&o.TCP53Count==0,
  MotorProcessesStopped:o.MotorProcessCount==0,
 }
 if !decision.DNSPortFree||!decision.MotorProcessesStopped{
  return decision,errors.New("motor or DNS port 53 is still active: refuse restoration")
 }
 decision.ReadyForFurtherChecks=true
 return decision,nil
}

func residentQuiescenceWithQuery(ctx context.Context,root,version string,
 query func(context.Context,string)(string,error),
)(residentQuiescenceDecision,error){
 var no residentQuiescenceDecision
 if err:=ctx.Err();err!=nil{return no,err}
 if query==nil||!filepath.IsAbs(root)||filepath.Clean(root)!=root{
  return no,errors.New("missing trusted Windows read-only query")
 }
 // Query ALL port endpoints so a missing port 53 is an empty result,
 // not a suppressed access error. Errors must fail closed.
 script:="$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';"+
  "$user=[Security.Principal.WindowsIdentity]::GetCurrent();"+
  "$admin=[Security.Principal.WindowsPrincipal]::new($user);"+
  "if(-not $admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Elevated Windows access required for reliable process/DNS observation'};"+
  "$r="+q(root)+";"+
  "$t=Get-ScheduledTask -TaskName 'VOLVE-DNS-SERVER-0270' -TaskPath '\\' -ErrorAction Stop;"+
  "if(@($t).Count -ne 1){throw 'Ambiguous DNS task'};"+
  "$prefix=$r.TrimEnd('\\')+'\\';"+
  "$all=@(Get-CimInstance Win32_Process -ErrorAction Stop);"+
  "$motor=@($all|Where-Object{([string]$_.ExecutablePath).StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase) -and ([string]$_.Name -like 'VOLVE_DNS_*')});"+
  "$udp=@(Get-NetUDPEndpoint -ErrorAction Stop|Where-Object{[int]$_.LocalPort -eq 53});"+
  "$tcp=@(Get-NetTCPConnection -State Listen -ErrorAction Stop|Where-Object{[int]$_.LocalPort -eq 53});"+
  "$report=[ordered]@{TaskName=[string]$t.TaskName;TaskPath=[string]$t.TaskPath;"+
  "Principal=[string]$t.Principal.UserId;ActionCount=[int]@($t.Actions).Count;"+
  "ActionExecute=[string]$t.Actions[0].Execute;ActionArguments=[string]$t.Actions[0].Arguments;"+
  "MotorProcessCount=[int]$motor.Count;UDP53Count=[int]$udp.Count;TCP53Count=[int]$tcp.Count};"+
  "$report|ConvertTo-Json -Compress -Depth 3"
 raw,err:=query(ctx,script)
 if err!=nil{return no,fmt.Errorf("Windows task/process/DNS evidence unavailable: %w",err)}
 if len(raw)<30||len(raw)>4096{return no,errors.New("quiescence report size invalid")}
 decoder:=json.NewDecoder(bytes.NewReader([]byte(raw)))
 decoder.DisallowUnknownFields()
 var data residentQuiescenceObservation
 if err:=decoder.Decode(&data);err!=nil{return no,fmt.Errorf("quiescence report invalid: %w",err)}
 var rest any
 if err:=decoder.Decode(&rest);err!=io.EOF{return no,errors.New("trailing data in quiescence report")}
 if err:=ctx.Err();err!=nil{return no,err}
 return validateResidentQuiescence(root,version,data)
}

func auditResidentQuiescenceReadOnly(ctx context.Context,root string)(residentQuiescenceDecision,error){
 // A single observation is NOT authority for mutation. The future
 // restorer must repeat this check inside the existing protected OS mutex.
 return residentQuiescenceWithQuery(ctx,root,"0.28.7",
  func(ctx context.Context,script string)(string,error){return ps(ctx,script)})
}
