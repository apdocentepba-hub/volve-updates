//go:build windows

package motorupdate

// No SYSTEM task or adapter changes are made by these concurrency tests.
// All mutex names are disposable, unique to the test process, and CI-only.
import (
 "context"
 "errors"
 "fmt"
 "os"
 "os/exec"
 "strings"
 "testing"
 "time"
)

func testWindowsDNSLeaseName() string {
 return fmt.Sprintf("VOLVE-CI-DNSLock-%d",time.Now().UnixNano())
}

func TestWindowsDNSLabMutexAcrossProcesses(t *testing.T){
 if mode:=os.Getenv("VOLVE_CI_DNS_LOCK_CHILD");mode!=""{
  name:=os.Getenv("VOLVE_CI_DNS_LOCK_NAME")
  ctx,cancel:=context.WithTimeout(context.Background(),750*time.Millisecond)
  defer cancel()
  release,err:=acquireWindowsDNSLabRecoveryLease(ctx,name)
  if mode=="blocked"{
   if !errors.Is(err,context.DeadlineExceeded){
    t.Fatalf("another process acquired a held DNS recovery mutex: %v",err)
   }
   fmt.Println("VOLVE_CI_DNS_LOCK_BLOCKED")
   return
  }
  if err!=nil{t.Fatalf("released DNS recovery lock unavailable: %v",err)}
  release()
  fmt.Println("VOLVE_CI_DNS_LOCK_ACQUIRED")
  return
 }
 name:=testWindowsDNSLeaseName()
 release,err:=acquireWindowsDNSLabRecoveryLease(context.Background(),name)
 if err!=nil{t.Fatal(err)}
 child:=func(mode string){
  ctx,cancel:=context.WithTimeout(context.Background(),15*time.Second)
  defer cancel()
  cmd:=exec.CommandContext(ctx,os.Args[0],"-test.run=^TestWindowsDNSLabMutexAcrossProcesses$")
  cmd.Env=append(os.Environ(),"VOLVE_CI_DNS_LOCK_CHILD="+mode,"VOLVE_CI_DNS_LOCK_NAME="+name)
  out,err:=cmd.CombinedOutput()
  if err!=nil{t.Fatalf("child DNS recovery lock check %s: %v, %s",mode,err,string(out))}
  expected:="VOLVE_CI_DNS_LOCK_ACQUIRED"
  if mode=="blocked"{expected="VOLVE_CI_DNS_LOCK_BLOCKED"}
  if !strings.Contains(string(out),expected){
   t.Fatalf("unexpected child DNS lock result %s: %s",mode,string(out))
  }
 }
 child("blocked")
 release()
 release() // repeated release cannot free someone else's handle
 child("acquired")
}

func TestWindowsDNSRecoveryLeaseHoldsUntilHealthGateCompletes(t *testing.T){
 name:=testWindowsDNSLeaseName()
 release,err:=acquireWindowsDNSLabRecoveryLease(context.Background(),name)
 if err!=nil{t.Fatal(err)}
 v4,_,h:=batchFixture()
 records:=[]DNSRestoreRecord{v4}
 gate:=&testWindowsDNSRecoveryAttestor{Journal:cloneWindowsDNSRecoveryRecords(records)}
 ctx,cancel:=context.WithTimeout(context.Background(),300*time.Millisecond)
 defer cancel()
 result:=make(chan error,1)
 go func(){
  result<-runAttestedWindowsStaticDNSRecovery(ctx,records,h.inspect,gate,
   func(ctx context.Context,args []string)error{
    return h.write(ctx,WindowsDNSCommand{Program:"netsh.exe",Args:args})
   },name)
 }()
 select {
 case e:=<-result:
  if !errors.Is(e,context.DeadlineExceeded){
   t.Fatalf("concurrent DNS recovery did not fail closed under lease: %v",e)
  }
 case <-time.After(4*time.Second):
  t.Fatal("OS recovery lease ignored context deadline")
 }
 if gate.Calls!=0||len(h.actions)!=0{
  t.Fatal("concurrent recovery inspected authorization or modified DNS without OS lease")
 }
 release()
 if err:=runAttestedWindowsStaticDNSRecovery(context.Background(),records,h.inspect,gate,
  func(ctx context.Context,args []string)error{
   return h.write(ctx,WindowsDNSCommand{Program:"netsh.exe",Args:args})
  },name);err!=nil{t.Fatalf("DNS recovery could not resume after OS lock release: %v",err)}
 if len(h.actions)!=2||gate.Calls!=7{
  t.Fatalf("wrong independent post-lease recovery result: actions=%d gates=%d",len(h.actions),gate.Calls)
 }
}

func TestWindowsDNSLabMutexRejectsProductionNamesAndCanceledContext(t *testing.T){
 for _,name:=range []string{
  "VOLVE-DNS-SERVER-0270","Global\\VOLVE-DNS-SERVER-0270",
  "VOLVE-CI-DNSLock-abc","VOLVE-CI-DNSLock-5",
  "VOLVE-CI-DNSLock-123456789012\\other",
  "VOLVE-CI-BootLock-1234567890123456789",
 }{
  if unlock,err:=acquireWindowsDNSLabRecoveryLease(context.Background(),name);err==nil{
   if unlock!=nil{unlock()}
   t.Fatalf("production or malformed mutex name approved: %q",name)
  }
 }
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 if _,err:=acquireWindowsDNSLabRecoveryLease(ctx,testWindowsDNSLeaseName());!errors.Is(err,context.Canceled){
  t.Fatalf("cancelled mutex acquisition approved: %v",err)
 }
}
