//go:build windows

package main

// Pure read-only parser/PowerShell-source tests: no SYSTEM tasks are queried,
// modified or started. Test executor returns synthetic data.
import (
 "context"
 "encoding/json"
 "errors"
 "os"
 "path/filepath"
 "strings"
 "testing"

 "volve-browser-protection/motorupdate"
)

func TestWindowsResidentProcessEvidenceUsesReadOnlySystemCommands(t *testing.T){
 exe:=filepath.Join(t.TempDir(),"VOLVE_DNS_Server_0270.exe")
 if err:=os.WriteFile(exe,[]byte("CI motor process fixture"),0600);err!=nil{t.Fatal(err)}
 ev:=motorupdate.ResidentRunningEvidence{
  TaskName:"VOLVE-DNS-SERVER-0270",TaskFolder:`\`,TaskPrincipal:"S-1-5-18",
  TaskState:"Running",TaskActionCount:1,TaskActionExecute:exe,TaskActionArguments:"--dns-service",
  ProcessCount:1,ProcessID:4242,DNSIPv4OwnerPID:4242,DNSIPv6OwnerPID:4242,ProcessPath:exe,ProcessCommandLine:`"`+exe+`" --dns-service`,
  ProcessOwnerSID:"S-1-5-18",DiskSHA256:strings.Repeat("a",64),
 }
 raw,_:=json.Marshal(ev)
 called:=0
 query:=func(_ context.Context,script string)(string,error){
  called++
  for _,need:=range []string{
   "Get-ScheduledTask","Win32_Process","GetOwnerSid","Get-FileHash","Get-NetUDPEndpoint",
   "ConvertTo-Json","VOLVE-DNS-SERVER-0270",
  }{
   if !strings.Contains(script,need){t.Fatalf("read-only observation lacks %s",need)}
  }
  for _,forbidden:=range []string{
   "Register-ScheduledTask","Set-ScheduledTask","Start-ScheduledTask",
   "Stop-ScheduledTask","Unregister-ScheduledTask",
  }{
   if strings.Contains(script,forbidden){t.Fatalf("unsafe command in observer: %s",forbidden)}
  }
  return string(raw),nil
 }
 got,err:=readResidentRunningEvidenceWithQuery(context.Background(),exe,query)
 if err!=nil{t.Fatal(err)}
 if got!=ev||called!=1{t.Fatalf("read-only observation lost identity: %+v calls=%d",got,called)}
 if err:=motorupdate.CheckResidentRunningEvidence(got,exe,ev.DiskSHA256);err!=nil{t.Fatal(err)}
}

func TestWindowsResidentProcessEvidenceFailsClosed(t *testing.T){
 exe:=filepath.Join(t.TempDir(),"VOLVE_DNS_Server_0270.exe")
 if err:=os.WriteFile(exe,[]byte("CI simulated binary"),0600);err!=nil{t.Fatal(err)}
 for _,tc:=range []struct{name,output string;err error}{
  {"malformed-json","{",nil},
  {"extra-field",`{"unknown":1}`,nil},
  {"trailing-json",`{}{}`,nil},
  {"query-failure","",errors.New("CIM process inaccessible")},
 }{
  t.Run(tc.name,func(t *testing.T){
   if _,err:=readResidentRunningEvidenceWithQuery(context.Background(),exe,
    func(context.Context,string)(string,error){return tc.output,tc.err});err==nil{
    t.Fatal("invalid Windows process evidence accepted")
   }
  })
 }
 for _,p:=range []string{filepath.Join(t.TempDir(),"powershell.exe"),
  filepath.Join(t.TempDir(),"VOLVE_DNS_Server_0270.exe.other"),
  "relative.exe",
 }{
  if _,err:=readResidentRunningEvidenceWithQuery(context.Background(),p,
   func(context.Context,string)(string,error){t.Fatal("unauthorized process queried");return "",nil});err==nil{
   t.Fatalf("untrusted executable accepted: %q",p)
  }
 }
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 called:=false
 if _,err:=readResidentRunningEvidenceWithQuery(ctx,exe,
  func(context.Context,string)(string,error){called=true;return "",nil});err==nil||called{
  t.Fatal("cancelled observation executed PowerShell")
 }
}
