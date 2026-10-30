package motorupdate

import (
 "path/filepath"
 "strings"
 "testing"
)

func runningEvidenceFixture(t *testing.T)(ResidentRunningEvidence,string,string) {
 t.Helper()
 exe:=filepath.Join(t.TempDir(),"VOLVE_DNS_Server_0270.exe")
 sha:=strings.Repeat("a",64)
 return ResidentRunningEvidence{
  TaskName:"VOLVE-DNS-SERVER-0270",TaskFolder:`\`,TaskPrincipal:"S-1-5-18",
  TaskState:"Running",TaskActionExecute:exe,TaskActionArguments:"--dns-service",
  ProcessCount:1,ProcessPath:exe,ProcessCommandLine:`"`+exe+`" --dns-service`,
  ProcessOwnerSID:"S-1-5-18",DiskSHA256:sha,
 },exe,sha
}
func TestResidentRunningEvidenceExactIdentity(t *testing.T) {
 observation,exe,sha:=runningEvidenceFixture(t)
 if err:=CheckResidentRunningEvidence(observation,exe,sha);err!=nil {t.Fatal(err)}
 observation.ProcessCommandLine=exe+" --dns-service"
 if err:=CheckResidentRunningEvidence(observation,exe,sha);err!=nil {t.Fatal(err)}
}
func TestResidentRunningEvidenceRejectsUnrelatedOrForgedProcess(t *testing.T) {
 for _,kind:=range []string{
  "task","folder","principal","state","action-exe","action-args",
  "process-count","process-path","process-owner","process-args","disk-sha",
  "invalid-expected-sha","relative-expected-path",
 } {
  t.Run(kind,func(t *testing.T){
   observed,exe,sha:=runningEvidenceFixture(t)
   switch kind {
   case "task":observed.TaskName="VOLVE-CI-ManagedMotor-123456789123"
   case "folder":observed.TaskFolder=`\Foreign\`
   case "principal":observed.TaskPrincipal="S-1-5-21-1000"
   case "state":observed.TaskState="Ready"
   case "action-exe":observed.TaskActionExecute=exe+".old"
   case "action-args":observed.TaskActionArguments="--disable"
   case "process-count":observed.ProcessCount=2
   case "process-path":observed.ProcessPath=exe+".other"
   case "process-owner":observed.ProcessOwnerSID="S-1-5-21-1000"
   case "process-args":observed.ProcessCommandLine=exe+" --dns-service --extra"
   case "disk-sha":observed.DiskSHA256=strings.Repeat("b",64)
   case "invalid-expected-sha":sha=strings.Repeat("X",64)
   case "relative-expected-path":exe="relative.exe"
   }
   if err:=CheckResidentRunningEvidence(observed,exe,sha);err==nil {
    t.Fatalf("unsafe evidence accepted: %s",kind)
   }
  })
 }
}
