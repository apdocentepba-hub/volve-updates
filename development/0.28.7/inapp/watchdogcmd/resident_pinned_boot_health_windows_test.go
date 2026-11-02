//go:build windows

package main

// These tests validate the future private health adapter's fail-closed
// construction and exact OS identity interrogation script. Script runners
// are injected ONLY in disposable unit tests; positive synthetic tokens
// never exercise Windows production Task Scheduler or port53.
import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"

 "volve-browser-protection/motorupdate"
)

func TestPinnedBootHealthRejectsUntrustedContextRootAndAdmin(t *testing.T){
 cancelled,done:=context.WithCancel(context.Background());done()
 if h,err:=newPinnedResidentBootHealthWindows(cancelled,t.TempDir());h!=nil||
  !errors.Is(err,context.Canceled){
  t.Fatalf("cancelled private health gate accepted: %v",err)
 }
 if h,err:=newPinnedResidentBootHealthWindows(context.Background(),"relative");h!=nil||err==nil{
  t.Fatalf("relative health root accepted: %v",err)
 }
 ctx,cancel:=context.WithTimeout(context.Background(),30*time.Second)
 defer cancel()
 if err:=verifyResidentActualSYSTEM(ctx);err==nil{
  t.Skip("runner has SYSTEM token: do not construct an activated original health gate")
 }
 if h,err:=newPinnedResidentBootHealthWindows(ctx,t.TempDir());h!=nil||err==nil{
  t.Fatalf("interactive administrative token constructed SYSTEM-only health: %v",err)
 }
}

func TestPinnedBootHealthRequiresExactMotorBytesBeforeQueryingWindows(t *testing.T){
 root:=t.TempDir()
 original:=filepath.Join(root,residentLegacyExe)
 if err:=os.WriteFile(original,[]byte("MZ-synthetic-local-health-fixture"),0600);err!=nil{t.Fatal(err)}
 queryCalls:=0
 health:=&residentPinnedBootHealthWindows{
  root:root,
  verifySystem:func(context.Context)error{return nil},
  verifyACL:func(string)error{return nil},
  queryWindows:func(context.Context,string)(string,error){queryCalls++;return "",errors.New("no shell operation allowed")},
 }
 intent:=motorupdate.ResidentRecoveryIntent{
  Task:"VOLVE-DNS-SERVER-0270",TargetVersion:"0.28.7",
  LegacySHA256:strings.Repeat("a",64),
 }
 if err:=health.VerifyRunningIdentity(context.Background(),intent,"restored");err==nil{
  t.Fatal("forged legacy hash reached live SYSTEM process verification")
 }
 if queryCalls!=0{t.Fatal("unknown binary invoked privileged Windows shell")}
 intent.LegacySHA256=strings.Repeat("b",64)
 if err:=health.VerifyRunningIdentity(context.Background(),intent,"committed");err==nil{
  t.Fatal("original recovery health accepted candidate commitment")
 }
 if queryCalls!=0{t.Fatal("candidate health unexpectedly queried Windows")}
 health.verifySystem=func(context.Context)error{return errors.New("not SYSTEM")}
 if err:=health.VerifyRunningIdentity(context.Background(),intent,"restored");err==nil{
  t.Fatal("admin-only health actor bypassed SYSTEM admission")
 }
 if queryCalls!=0{t.Fatal("non SYSTEM actor queried process/task identity")}
}

func TestPinnedBootHealthQueriesLiveTaskProcessAndBothDNS53Owners(t *testing.T){
 root:=t.TempDir()
 original:=filepath.Join(root,residentLegacyExe)
 payload:=[]byte("MZ-synthetic-executable-test-do-not-run")
 if err:=os.WriteFile(original,payload,0600);err!=nil{t.Fatal(err)}
 hash:=sha256.Sum256(payload)
 intent:=motorupdate.ResidentRecoveryIntent{
  Task:"VOLVE-DNS-SERVER-0270",TargetVersion:"0.28.7",
  LegacySHA256:hex.EncodeToString(hash[:]),
 }
 calls:=0
 health:=&residentPinnedBootHealthWindows{
  root:root,
  verifySystem:func(context.Context)error{return nil},
  verifyACL:func(string)error{return nil},
  queryWindows:func(_ context.Context,script string)(string,error){
   calls++
   required:=[]string{
    "WindowsIdentity", "S-1-5-18","Get-ScheduledTask",
    "VOLVE-DNS-SERVER-0270","$t.State -ne 'Running'",
    "--dns-service","Get-FileHash","Win32_Process","GetOwnerSid",
    "Get-NetUDPEndpoint","127.0.0.1","::1","OwningProcess",
    "VOLVE_ORIGINAL_SYSTEM_DNS53_IDENTITY_VERIFIED",
   }
   for _,token:=range required{
    if !strings.Contains(script,token){t.Errorf("health OS probe missing %q",token)}
   }
   if !strings.Contains(script,intent.LegacySHA256) {
    t.Error("health OS identity script omitted original hash binding")
   }
   return "VOLVE_ORIGINAL_SYSTEM_DNS53_IDENTITY_VERIFIED",nil
  },
 }
 if err:=health.VerifyRunningIdentity(context.Background(),intent,"restored");err!=nil{
  t.Fatalf("synthetic contract verifier did not interrogate all identity fields: %v",err)
 }
 if calls!=1{t.Fatalf("expected one bounded Windows identity probe, got %d",calls)}
 health.queryWindows=func(context.Context,string)(string,error){calls++;return "PARTIAL",nil}
 if err:=health.VerifyRunningIdentity(context.Background(),intent,"restored");err==nil{
  t.Fatal("ambiguous Windows identity output accepted as verified")
 }
 if calls!=2{t.Fatal("test did not execute ambiguous native observation")}
 health.verifyACL=func(string)error{return errors.New("untrusted restored NTFS DACL")}
 if err:=health.VerifyRunningIdentity(context.Background(),intent,"restored");err==nil{
  t.Fatal("unprotected original motor trusted as restored")
 }
 if calls!=2{t.Fatal("untrusted NTFS ACL reached process-owner probe")}
}


func TestPinnedBootComponentsOnlyConstructUnderActualSYSTEMAndCanonicalRoot(t *testing.T){
 ctx,cancel:=context.WithCancel(context.Background())
 cancel()
 if value,err:=newPinnedResidentBootComponentsWindows(ctx,t.TempDir());err==nil||
  value.Driver!=nil||value.Health!=nil||value.JournalDir!=""{
  t.Fatalf("cancelled component construction did not fail closed: %+v %v",value,err)
 }
 if value,err:=newPinnedResidentBootComponentsWindows(context.Background(),"relative");err==nil||
  value.Driver!=nil||value.Health!=nil||value.JournalDir!=""{
  t.Fatalf("relative component root accepted: %+v %v",value,err)
 }
 if err:=verifyResidentActualSYSTEM(context.Background());err==nil{
  t.Skip("actual SYSTEM positive constructor is covered by disposable SYSTEM task test")
 }
 if value,err:=newPinnedResidentBootComponentsWindows(context.Background(),t.TempDir());err==nil||
  value.Driver!=nil||value.Health!=nil||value.JournalDir!=""{
  t.Fatalf("non-SYSTEM constructed signed recovery/health pair: %+v %v",value,err)
 }
}
