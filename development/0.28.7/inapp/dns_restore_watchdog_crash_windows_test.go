//go:build windows

package motorupdate

// Real independent-process recovery proof on a disposable internal Hyper-V
// adapter. A child updater deliberately exits with code 83 after setting
// loopback DNS. A watchdog process started BEFORE that crash holds an OS
// process handle, detects the nonzero exit, validates a pinned lab plan,
// independently observes the isolated NIC and restores BOTH DNS families.
// Never a production Windows service, SYSTEM agent or signed release.
import (
 "bytes"
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "os"
 "os/exec"
 "path/filepath"
 "reflect"
 "strconv"
 "syscall"
 "testing"
 "time"
 "unsafe"
)

const windowsLabUpdaterCrashExitCode=83

type windowsDNSCrashRecoveryPlan struct {
 Schema int
 Alias string
 GUID string
 Records []DNSRestoreRecord
}

func windowsDNSCrashRecords(guid string) []DNSRestoreRecord {
 return []DNSRestoreRecord{
  {
   Original:DNSServerState{InterfaceGUID:guid,Family:DNSIPv4,Mode:DNSStatic,
    Servers:[]string{"9.9.9.9","1.1.1.1"}},
   Expected:DNSServerState{InterfaceGUID:guid,Family:DNSIPv4,Mode:DNSStatic,
    Servers:[]string{"127.0.0.1"}},
  },
  {
   Original:DNSServerState{InterfaceGUID:guid,Family:DNSIPv6,Mode:DNSStatic,
    Servers:[]string{"2606:4700:4700::1111"}},
   Expected:DNSServerState{InterfaceGUID:guid,Family:DNSIPv6,Mode:DNSStatic,
    Servers:[]string{"::1"}},
  },
 }
}

func windowsDNSCrashPlanFromDisk() (windowsDNSCrashRecoveryPlan,error) {
 var plan windowsDNSCrashRecoveryPlan
 path:=os.Getenv("VOLVE_CI_DNS_CRASH_PLAN")
 expected:=os.Getenv("VOLVE_CI_DNS_CRASH_SHA256")
 if path==""||!filepath.IsAbs(path)||len(expected)!=64{return plan,errors.New("lab recovery plan path/hash missing")}
 raw,err:=os.ReadFile(path);if err!=nil{return plan,err}
 if len(raw)<100||len(raw)>8192{return plan,errors.New("lab recovery plan oversized or empty")}
 sum:=sha256.Sum256(raw)
 if hex.EncodeToString(sum[:])!=expected{return plan,errors.New("lab recovery plan hash mismatch")}
 if err:=json.Unmarshal(raw,&plan);err!=nil{return plan,err}
 canonical,err:=json.Marshal(plan)
 if err!=nil||!bytes.Equal(canonical,raw){return plan,errors.New("noncanonical recovery plan")}
 if plan.Schema!=1||plan.Alias!=os.Getenv("VOLVE_CI_DNS_LAB_ALIAS")||
    plan.GUID!=os.Getenv("VOLVE_CI_DNS_LAB_GUID")||
    !reflect.DeepEqual(plan.Records,windowsDNSCrashRecords(plan.GUID)) {
  return plan,errors.New("lab recovery plan does not match exact vNIC/restore intent")
 }
 return plan,nil
}

func windowsDNSCrashApplyAndVerify(ctx context.Context,record DNSRestoreRecord,index uint32,original bool) error {
 state:=record.Expected
 if original{state=record.Original}
 cmds,err:=PlanWindowsDNSRestore(state,index)
 if err!=nil{return err}
 for _,cmd:=range cmds{
  if err:=runPinnedWindowsNativeDNS(ctx,cmd.Args);err!=nil{return err}
 }
 raw,err:=DefaultWindowsReadOnlyPowerShell(ctx,windowsEffectiveDNSQuery)
 if err!=nil{return err}
 observed,err:=parseEffectiveDNS(raw,index,state.Family)
 if err!=nil||!sameDNSAddresses(observed,state.Servers){
  return fmt.Errorf("live DNS assignment not proven for %s: observed=%v, %w",state.Family,observed,err)
 }
 return nil
}

func windowsDNSCrashAwaitFile(ctx context.Context,path string)error{
 if path==""||!filepath.IsAbs(path){return errors.New("invalid CI crash handshake path")}
 for {
  if err:=ctx.Err();err!=nil{return err}
  if info,err:=os.Lstat(path);err==nil{
   if info.Mode().IsRegular(){return nil}
   return errors.New("CI crash handshake path is not regular")
  }else if !errors.Is(err,os.ErrNotExist){return err}
  time.Sleep(80*time.Millisecond)
 }
}

func windowsDNSCrashChildUpdater(t *testing.T){
 plan,err:=windowsDNSCrashPlanFromDisk()
 if err!=nil{t.Fatal(err)}
 ctx,cancel:=context.WithTimeout(context.Background(),65*time.Second)
 defer cancel()
 adapter,err:=VerifyWindowsDisposableDNSAdapterReadOnly(ctx,plan.Alias,plan.GUID,DefaultWindowsDisposableDNSInspect)
 if err!=nil{t.Fatalf("updater did not prove fresh isolated adapter: %v",err)}
 index,err:=FindWindowsAdapterIndex(ctx,plan.GUID,DefaultWindowsReadOnlyPowerShell)
 if err!=nil||index!=adapter.InterfaceIndex{t.Fatal("updater lost pinned disposable index")}
 for _,record:=range plan.Records {
  if err:=windowsDNSCrashApplyAndVerify(ctx,record,index,true);err!=nil{t.Fatal(err)}
 }
 for _,record:=range plan.Records {
  if err:=windowsDNSCrashApplyAndVerify(ctx,record,index,false);err!=nil{t.Fatal(err)}
 }
 if _,err:=VerifyWindowsDisposableDNSAdapterWithLocalDNSReadOnly(ctx,plan.Alias,plan.GUID,DefaultWindowsDisposableDNSInspect);err!=nil{
  t.Fatalf("updater produced untrusted network state: %v",err)
 }
 ready:=os.Getenv("VOLVE_CI_DNS_CRASH_ARMED")
 trigger:=os.Getenv("VOLVE_CI_DNS_CRASH_TRIGGER")
 if err:=os.WriteFile(ready,[]byte("both families loopback; update intent pending"),0600);err!=nil{t.Fatal(err)}
 if err:=windowsDNSCrashAwaitFile(ctx,trigger);err!=nil{t.Fatal(err)}
 // Simulated UNGRACEFUL crash: no defer, no rollback, no normal Go test exit.
 os.Exit(windowsLabUpdaterCrashExitCode)
}

var (
 windowsCrashKernel32=syscall.NewLazyDLL("kernel32.dll")
 windowsCrashOpenProcess=windowsCrashKernel32.NewProc("OpenProcess")
 windowsCrashWaitForSingleObject=windowsCrashKernel32.NewProc("WaitForSingleObject")
 windowsCrashGetExitCodeProcess=windowsCrashKernel32.NewProc("GetExitCodeProcess")
 windowsCrashCloseHandle=windowsCrashKernel32.NewProc("CloseHandle")
)

func windowsDNSCrashWaitForUpdater(ctx context.Context,pid int)error{
 if pid<1{return errors.New("invalid updater PID")}
 const synchronize=0x00100000
 const processQueryLimitedInformation=0x1000
 handle,_,callErr:=windowsCrashOpenProcess.Call(synchronize|processQueryLimitedInformation,0,uintptr(pid))
 if handle==0{
  return fmt.Errorf("cannot open exact crashed updater process handle: %w",callErr)
 }
 defer windowsCrashCloseHandle.Call(handle)
 ready:=os.Getenv("VOLVE_CI_DNS_WATCHDOG_READY")
 if err:=os.WriteFile(ready,[]byte(strconv.Itoa(pid)),0600);err!=nil{return err}
 for {
  if err:=ctx.Err();err!=nil{return err}
  state,_,e:=windowsCrashWaitForSingleObject.Call(handle,100)
  if uint32(state)==windowsDNSWaitTimeout{continue}
  if uint32(state)!=windowsDNSWaitObject0{
   return fmt.Errorf("cannot determine updater process termination: %v",e)
  }
  var code uint32
  ok,_,err:=windowsCrashGetExitCodeProcess.Call(handle,uintptr(unsafe.Pointer(&code)))
  if ok==0{return fmt.Errorf("cannot read crashed updater result: %v",err)}
  if code!=windowsLabUpdaterCrashExitCode{
   return fmt.Errorf("updater did not crash as intended; code %d",code)
  }
  return nil
 }
}

func windowsDNSCrashChildWatchdog(t *testing.T){
 plan,err:=windowsDNSCrashPlanFromDisk()
 if err!=nil{t.Fatal(err)}
 ctx,cancel:=context.WithTimeout(context.Background(),100*time.Second)
 defer cancel()
 pid,e:=strconv.Atoi(os.Getenv("VOLVE_CI_DNS_UPDATER_PID"))
 if e!=nil{t.Fatal(e)}
 if err:=windowsDNSCrashWaitForUpdater(ctx,pid);err!=nil{t.Fatal(err)}
 // No controller cooperation after the updater has exited.
 adapter,err:=VerifyWindowsDisposableDNSAdapterWithLocalDNSReadOnly(ctx,plan.Alias,plan.GUID,DefaultWindowsDisposableDNSInspect)
 if err!=nil{t.Fatalf("watchdog refused unsafe post-crash vNIC: %v",err)}
 lockName:=os.Getenv("VOLVE_CI_DNS_CRASH_LOCK")
 release,err:=acquireWindowsDNSLabRecoveryLease(ctx,lockName)
 if err!=nil{t.Fatal(err)}
 defer release()
 // Read snapshot again UNDER lock immediately before taking any action.
 currentPlan,err:=windowsDNSCrashPlanFromDisk()
 if err!=nil||!reflect.DeepEqual(plan,currentPlan){t.Fatal("recovery journal changed during OS lease")}
 pinned,err:=FindWindowsAdapterIndex(ctx,plan.GUID,DefaultWindowsReadOnlyPowerShell)
 if err!=nil||pinned!=adapter.InterfaceIndex{t.Fatal("watchdog vNIC index changed")}
 writer,err:=NewWindowsPinnedStaticDNSWriter(ctx,plan.Records,DefaultWindowsReadOnlyPowerShell,
  func(ctx context.Context,args []string)error{
   return runPinnedWindowsNativeDNS(ctx,args)
  })
 if err!=nil{t.Fatal(err)}
 if err:=ExecuteWindowsStaticDNSRestoreBatch(ctx,plan.Records,DefaultWindowsReadOnlyPowerShell,writer);err!=nil{
  t.Fatalf("independent watchdog could not restore both families: %v",err)
 }
 for _,record:=range plan.Records{
  raw,err:=DefaultWindowsReadOnlyPowerShell(ctx,windowsEffectiveDNSQuery)
  if err!=nil{t.Fatal(err)}
  got,err:=parseEffectiveDNS(raw,pinned,record.Original.Family)
  if err!=nil||!sameDNSAddresses(got,record.Original.Servers){
   t.Fatalf("watchdog independent DNS postcheck failed for %s: %v %v",record.Original.Family,got,err)
  }
 }
 if err:=os.WriteFile(os.Getenv("VOLVE_CI_DNS_WATCHDOG_RECEIPT"),[]byte("recovered after updater exited 83"),0600);err!=nil{t.Fatal(err)}
 t.Log("PASS: independent Windows watchdog observed updater crash and restored real IPv4/IPv6 DNS without updater assistance")
}

func TestWindowsRealDNSWatchdogAfterUpdaterCrash(t *testing.T){
 if mode:=os.Getenv("VOLVE_CI_DNS_RECOVERY_CHILD");mode!=""{
  if mode=="updater"{windowsDNSCrashChildUpdater(t);return}
  if mode=="watchdog"{windowsDNSCrashChildWatchdog(t);return}
  t.Fatal("unknown real DNS CI helper")
 }
 if os.Getenv("VOLVE_CI_DNS_REAL_DISPOSABLE")!="INTERNAL_HYPERV_VM_ONLY"{
  t.Skip("real DNS failure recovery requires dedicated disposable Hyper-V CI workflow")
 }
 if os.Getenv("GITHUB_ACTIONS")!="true"{
  t.Fatal("refusing independent-process DNS mutation outside ephemeral GitHub VM")
 }
 ctx,cancel:=context.WithTimeout(context.Background(),140*time.Second)
 defer cancel()
 alias,guid:=os.Getenv("VOLVE_CI_DNS_LAB_ALIAS"),os.Getenv("VOLVE_CI_DNS_LAB_GUID")
 if _,err:=VerifyWindowsDisposableDNSAdapterReadOnly(ctx,alias,guid,DefaultWindowsDisposableDNSInspect);err!=nil{
  t.Fatalf("crash test rejected unsafe preflight: %v",err)
 }
 plan:=windowsDNSCrashRecoveryPlan{Schema:1,Alias:alias,GUID:guid,Records:windowsDNSCrashRecords(guid)}
 raw,err:=json.Marshal(plan);if err!=nil{t.Fatal(err)}
 root:=t.TempDir()
 path:=filepath.Join(root,"pending-recovery-plan.json")
 if err:=os.WriteFile(path,raw,0600);err!=nil{t.Fatal(err)}
 sum:=sha256.Sum256(raw)
 nonce:=strconv.FormatInt(time.Now().UnixNano(),10)
 common:=append(os.Environ(),
  "VOLVE_CI_DNS_CRASH_PLAN="+path,
  "VOLVE_CI_DNS_CRASH_SHA256="+hex.EncodeToString(sum[:]),
  "VOLVE_CI_DNS_CRASH_ARMED="+filepath.Join(root,"armed"),
  "VOLVE_CI_DNS_CRASH_TRIGGER="+filepath.Join(root,"trigger"),
  "VOLVE_CI_DNS_WATCHDOG_READY="+filepath.Join(root,"watchdog-ready"),
  "VOLVE_CI_DNS_WATCHDOG_RECEIPT="+filepath.Join(root,"restored"),
  "VOLVE_CI_DNS_CRASH_LOCK=VOLVE-CI-DNSLock-"+nonce,
 )
 updater:=exec.CommandContext(ctx,os.Args[0],"-test.run=^TestWindowsRealDNSWatchdogAfterUpdaterCrash$")
 updater.Env=append(append([]string(nil),common...),"VOLVE_CI_DNS_RECOVERY_CHILD=updater")
 var updaterOutput bytes.Buffer
 updater.Stdout=&updaterOutput
 updater.Stderr=&updaterOutput
 if err:=updater.Start();err!=nil{t.Fatal(err)}
 // Parent orchestrator NEVER restores DNS. It only starts the independent
 // watchdog and checks that the crash and recovery actually happened.
 if err:=windowsDNSCrashAwaitFile(ctx,filepath.Join(root,"armed"));err!=nil{
  updater.Process.Kill()
  t.Fatalf("updater could not stage loopback DNS: %v: %s",err,updaterOutput.String())
 }
 watchdog:=exec.CommandContext(ctx,os.Args[0],"-test.run=^TestWindowsRealDNSWatchdogAfterUpdaterCrash$")
 watchdog.Env=append(append([]string(nil),common...),
  "VOLVE_CI_DNS_RECOVERY_CHILD=watchdog",
  "VOLVE_CI_DNS_UPDATER_PID="+strconv.Itoa(updater.Process.Pid))
 var watchdogOutput bytes.Buffer
 watchdog.Stdout=&watchdogOutput
 watchdog.Stderr=&watchdogOutput
 if err:=watchdog.Start();err!=nil{
  updater.Process.Kill();t.Fatal(err)
 }
 if err:=windowsDNSCrashAwaitFile(ctx,filepath.Join(root,"watchdog-ready"));err!=nil{
  updater.Process.Kill();watchdog.Process.Kill()
  t.Fatalf("independent watchdog could not open updater handle: %v; %s",err,watchdogOutput.String())
 }
 if err:=os.WriteFile(filepath.Join(root,"trigger"),[]byte("crash-now"),0600);err!=nil{
  updater.Process.Kill();watchdog.Process.Kill();t.Fatal(err)
 }
 updaterErr:=updater.Wait()
 if updaterErr==nil{
  watchdog.Process.Kill();t.Fatal("updater did not simulate an abrupt crash")
 }
 if err:=watchdog.Wait();err!=nil{
  t.Fatalf("separate watchdog did not recover after crash: %v, updater=%s, watchdog=%s",err,updaterOutput.String(),watchdogOutput.String())
 }
 if err:=windowsDNSCrashAwaitFile(ctx,filepath.Join(root,"restored"));err!=nil{t.Fatal(err)}
 index,err:=FindWindowsAdapterIndex(ctx,guid,DefaultWindowsReadOnlyPowerShell)
 if err!=nil{t.Fatal(err)}
 for _,record:=range plan.Records {
  raw,err:=DefaultWindowsReadOnlyPowerShell(ctx,windowsEffectiveDNSQuery)
  if err!=nil{t.Fatal(err)}
  got,err:=parseEffectiveDNS(raw,index,record.Original.Family)
  if err!=nil||!sameDNSAddresses(got,record.Original.Servers){
   t.Fatalf("third independent DNS check failed after watchdog: %s: %v %v",record.Original.Family,got,err)
  }
 }
 t.Log("PASS: updater crashed with exit 83; independently running watchdog detected terminated process and restored REAL IPv4 and IPv6 DNS using pinned journal")
}
