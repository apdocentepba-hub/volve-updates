//go:build windows

package main

import (
 "context"
 "encoding/json"
 "errors"
 "path/filepath"
 "strings"
 "testing"
)

func quiescentFixture(root string)residentQuiescenceObservation{
 return residentQuiescenceObservation{TaskName:"VOLVE-DNS-SERVER-0270",
  TaskPath:"\\",Principal:"SYSTEM",ActionCount:1,
  ActionExecute:filepath.Join(root,residentLegacyExe),ActionArguments:"--dns-service"}
}

func TestResidentQuiescenceAcceptsExactStoppedSYSTEMTaskOnly(t *testing.T){
 root:=filepath.Join(t.TempDir(),"VOLVE-LAB")
 for _,name:=range []string{residentLegacyExe,"VOLVE_DNS_Motor_0_28_7.exe",
  filepath.Join("installed-engines","VOLVE_DNS_Motor_0_28_7.exe")}{
  o:=quiescentFixture(root);o.ActionExecute=filepath.Join(root,name)
  decision,err:=validateResidentQuiescence(root,"0.28.7",o)
  if err!=nil||!decision.ReadyForFurtherChecks||!decision.DNSPortFree{
   t.Fatalf("exact quiescent executable %s was rejected: %+v %v",name,decision,err)
  }
 }
}
func TestResidentQuiescenceFailsClosedOnUnknownOrRunningMotor(t *testing.T){
 root:=filepath.Join(t.TempDir(),"VOLVE-LAB")
 cases:=map[string]func(*residentQuiescenceObservation){
  "unexpected-task":func(o *residentQuiescenceObservation){o.TaskName="VOLVE-CI-PILOT"},
  "foreign-task-folder":func(o *residentQuiescenceObservation){o.TaskPath="\\Windows\\"},
  "non-SYSTEM-principal":func(o *residentQuiescenceObservation){o.Principal="S-1-5-21-101"},
  "extra-action":func(o *residentQuiescenceObservation){o.ActionCount=2},
  "wrong-arguments":func(o *residentQuiescenceObservation){o.ActionArguments="--launcher"},
  "foreign-executable":func(o *residentQuiescenceObservation){o.ActionExecute=filepath.Join(root,"other.exe")},
  "active-process":func(o *residentQuiescenceObservation){o.MotorProcessCount=1},
  "udp53-in-use":func(o *residentQuiescenceObservation){o.UDP53Count=1},
  "tcp53-in-use":func(o *residentQuiescenceObservation){o.TCP53Count=1},
  "bad-count":func(o *residentQuiescenceObservation){o.TCP53Count=-1},
 }
 for name,f:=range cases {t.Run(name,func(t *testing.T){
  o:=quiescentFixture(root);f(&o)
  result,err:=validateResidentQuiescence(root,"0.28.7",o)
  if err==nil||result.ReadyForFurtherChecks{t.Fatalf("unsafe state admitted: %+v %v",result,err)}
 })}
}
func TestResidentQuiescenceQueryFailClosedAndContainsRealWindowsProbes(t *testing.T){
 root:=filepath.Join(t.TempDir(),"VOLVE-LAB")
 o:=quiescentFixture(root)
 raw,err:=json.Marshal(o);if err!=nil{t.Fatal(err)}
 for _,tc:=range []struct{body string;err error}{
  {"",errors.New("access denied")},{"",nil},{"{",nil},
  {string(raw)+"{}",nil},
  {string(raw[:len(raw)-1])+`,"Extra":1}`,nil},
 }{
  r,err:=residentQuiescenceWithQuery(context.Background(),root,"0.28.7",
   func(context.Context,string)(string,error){return tc.body,tc.err})
  if err==nil||r.ReadyForFurtherChecks{t.Fatalf("malformed/denied report accepted: %+v %v",r,err)}
 }
 r,err:=residentQuiescenceWithQuery(context.Background(),root,"0.28.7",
  func(ctx context.Context,script string)(string,error){
   for _,name:=range []string{"Get-ScheduledTask","Get-CimInstance","Get-NetUDPEndpoint","Get-NetTCPConnection"}{
    if !strings.Contains(script,name){t.Fatalf("missing probe %s",name)}
   }
   return string(raw),nil
  })
 if err!=nil||!r.ReadyForFurtherChecks{t.Fatalf("valid observation rejected: %+v %v",r,err)}
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 _,err=residentQuiescenceWithQuery(ctx,root,"0.28.7",
  func(context.Context,string)(string,error){t.Fatal("canceled probe invoked");return "",nil})
 if !errors.Is(err,context.Canceled){t.Fatalf("context cancellation ignored: %v",err)}
}
