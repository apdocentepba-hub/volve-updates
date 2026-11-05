//go:build windows

package main

// Policy tests only: use a signed disposable fixture and injected runner;
// no production Task Scheduler or DNS settings are read or modified.
import (
 "context"
 "crypto/ed25519"
 "errors"
 "os"
 "path/filepath"
 "strings"
 "testing"

 "volve-browser-protection/motorupdate"
)

// A signed boot recovery performs TWO distinct scheduler actions: import of
// the sealed original XML, then START of that exact original. Synthetic
// runners must not confuse a successful import with a process start.
func signedRecoveryTaskFixtureResult(script string)(string,error){
 importTask:=strings.Contains(script,"Register-ScheduledTask")
 startTask:=strings.Contains(script,"Start-ScheduledTask")
 switch {
 case importTask && !startTask:
  return "VOLVE_SIGNED_ORIGINAL_TASK_RESTORED",nil
 case startTask && !importTask:
  return "VOLVE_SIGNED_ORIGINAL_START_REQUESTED",nil
 default:
  return "",errors.New("unknown or combined Scheduler mutation in signed boot recovery")
 }
}

func TestSignedOriginalSYSTEMStartRequiresSignedPendingTaskAndNeverCommits(t *testing.T){
 root,key,p:=signedTaskRecoveryFixture(t)
 calls:=0
 deps:=residentSignedTaskRestoreDeps{
  VerifySystem:p.VerifySystem,VerifyACL:p.VerifyACL,
  ProbeQuiescence:p.ProbeQuiescence,
  RunWindowsTask:func(_ context.Context,script string)(string,error){
   calls++
   required:=[]string{
    "Start-ScheduledTask","VOLVE-DNS-SERVER-0270","S-1-5-18","--dns-service",
    "MSFT_TaskBootTrigger","$t.State -ne 'Ready'","Get-NetUDPEndpoint",
    "Get-NetTCPConnection","Win32_Process","Get-CimInstance",
    "[IO.File]::OpenRead($old)","[Security.Cryptography.SHA256]::Create()",
    "finally{$h.Dispose();$a.Dispose()}","$actual -cne $sha",
    "VOLVE_SIGNED_ORIGINAL_START_REQUESTED",
   }
   for _,require:=range required{
    if !strings.Contains(script,require){t.Errorf("original recovery start omitted %q",require)}
   }
   if strings.Contains(script,"Get-FileHash"){t.Error("original recovery start uses optional Get-FileHash cmdlet")}
   for _,forbidden:=range []string{"Register-ScheduledTask","Set-ScheduledTask","Stop-ScheduledTask",
    "Set-DnsClientServerAddress","Set-NetIPInterface","Remove-Item","Remove-ScheduledTask"}{
    if strings.Contains(script,forbidden){t.Errorf("original recovery start mutated unexpected subsystem: %q",forbidden)}
   }
   return "VOLVE_SIGNED_ORIGINAL_START_REQUESTED",nil
  },
 }
 if err:=startSignedRestoredOriginalTaskLockedWindows(context.Background(),root,key,deps);err!=nil{
  t.Fatalf("signed original start refused verified pending journal: %v",err)
 }
 if calls!=1{t.Fatalf("expected one original-only Scheduler start, got %d",calls)}
 state,err:=auditResidentJournal(context.Background(),filepath.Join(root,residentRecoveryParent,residentJournalDirName))
 if err!=nil||state.Status!="recovery-required"{
  t.Fatalf("starting original task must not claim network recovered: %+v %v",state,err)
 }
 if _,err:=os.Lstat(filepath.Join(root,residentRecoveryParent,residentJournalDirName,motorupdate.ResidentResultFile));!errors.Is(err,os.ErrNotExist){
  t.Fatalf("original task start falsely wrote terminal receipt: %v",err)
 }
}

func TestSignedOriginalSYSTEMStartFailClosedBeforeTaskMutation(t *testing.T){
 // Reuse one cryptographically signed, real-NTFS fixture. Only the LAST
 // scenario mutates original bytes; all earlier cases are read-only.
 // Avoid re-creating the same protected signed grant nine times on Windows.
 fixtureRoot,fixtureKey,fixtureProbes:=signedTaskRecoveryFixture(t)
 for _,scenario:=range []string{
  "cancelled","wrong-editor","not-system","bad-acl","busy-port53",
  "ambiguous-scheduler","scheduler-error","invalid-root","foreign-original",
 }{
  t.Run(scenario,func(t *testing.T){
   root,key,p:=fixtureRoot,fixtureKey,fixtureProbes
   ctx:=context.Background()
   publisher:=ed25519.PublicKey(key)
   calls:=0
   deps:=residentSignedTaskRestoreDeps{
    VerifySystem:p.VerifySystem,VerifyACL:p.VerifyACL,
    ProbeQuiescence:p.ProbeQuiescence,
    RunWindowsTask:func(context.Context,string)(string,error){
     calls++
     switch scenario{
     case "scheduler-error":return "",errors.New("scheduler refused task start")
     case "ambiguous-scheduler":return "PARTIAL",nil
     }
     return "VOLVE_SIGNED_ORIGINAL_START_REQUESTED",nil
    },
   }
   switch scenario {
   case "cancelled":c,done:=context.WithCancel(ctx);done();ctx=c
   case "wrong-editor":publisher=make(ed25519.PublicKey,ed25519.PublicKeySize)
   case "not-system":deps.VerifySystem=func(context.Context)error{return errors.New("not SYSTEM")}
   case "bad-acl":deps.VerifyACL=func(string)error{return errors.New("untrusted NTFS ACL")}
   case "busy-port53":
    deps.ProbeQuiescence=func(context.Context,string)(residentQuiescenceDecision,error){
     return residentQuiescenceDecision{TaskIdentityVerified:true,DNSPortFree:false,MotorProcessesStopped:true},errors.New("port53 busy")
    }
   case "foreign-original":
    if err:=os.WriteFile(filepath.Join(root,residentLegacyExe),[]byte("MZ-FORGERY"),0600);err!=nil{t.Fatal(err)}
   case "invalid-root":root=filepath.Join(root,"..")
   }
   err:=startSignedRestoredOriginalTaskLockedWindows(ctx,root,publisher,deps)
   if err==nil{t.Fatalf("%s: unsafe original task start was accepted",scenario)}
   expectedRuns:=0
   if scenario=="scheduler-error"||scenario=="ambiguous-scheduler"{expectedRuns=1}
   if calls!=expectedRuns{t.Fatalf("%s: unexpected Scheduler writes %d, expected %d",scenario,calls,expectedRuns)}
   if scenario=="ambiguous-scheduler"||scenario=="scheduler-error"{
    state,e:=auditResidentJournal(context.Background(),filepath.Join(root,residentRecoveryParent,residentJournalDirName))
    if e!=nil||state.Status!="recovery-required"{
     t.Fatalf("%s: failed Start wrote false recovery success: %v %+v",scenario,e,state)
    }
   }
  })
 }
}
