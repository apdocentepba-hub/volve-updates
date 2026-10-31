//go:build windows

package motorupdate

// This is a CI-only E2E where a separate Windows Task Scheduler process runs
// as the ACTUAL LocalSystem account and restores REAL IPv4/IPv6 DNS on one
// disposable internal Hyper-V vNIC after an independent updater crashes.
// A disposable journal with SYSTEM/Administrators NTFS DACL and an ephemeral
// Ed25519 lab signature are revalidated before/after each DNS write.
// THIS IS NOT a product watchdog, publisher permit, or reboot test.
import (
 "bytes"
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "os"
 "os/exec"
 "path/filepath"
 "regexp"
 "strconv"
 "strings"
 "testing"
 "time"
)

var windowsSYSDNSConfigFlag=flag.String("volve-ci-sys-watchdog-config","",
 "path to CI-only disposable SYSTEM DNS watchdog transaction")

var windowsSYSDNSTaskPattern=regexp.MustCompile(`^VOLVE-CI-DNS-SYSTEM-[0-9]{12,20}$`)

type windowsSYSDNSLabConfig struct {
 Schema int
 Task string
 Alias string
 GUID string
 PID int
 PlanPath string
 PlanSHA256 string
 JournalDir string
 SnapshotPath string
 SnapshotSHA256 string
 Pubkey string
 Signature string
 Lock string
 WatchdogReady string
 Recovered string
}

func windowsSYSDNSQuote(s string)string{return "'"+strings.ReplaceAll(s,"'","''")+"'"}

func windowsSYSDNSShell(ctx context.Context,script string)error {
 root:=os.Getenv("SystemRoot")
 if root==""||!filepath.IsAbs(root){return errors.New("Windows OS directory unavailable")}
 ps:=filepath.Join(root,"System32","WindowsPowerShell","v1.0","powershell.exe")
 out,err:=exec.CommandContext(ctx,ps,"-NoLogo","-NoProfile",
  "-NonInteractive","-ExecutionPolicy","Bypass","-Command",script).CombinedOutput()
 if err!=nil{return fmt.Errorf("CI Windows task/DACL operation failed: %w: %s",err,string(out))}
 return nil
}

// An allowlisted exact pair of paths, not a general-purpose ACL editing API.
// Called ONLY to create/finish a journal in an isolated CI TEMP fixture.
func windowsSYSDNSSealFixture(ctx context.Context,dir,snapshot string)error {
 if filepath.Base(dir)!="motor-recovery-transaction"||
    filepath.Base(filepath.Dir(dir))!="legacy-engine-recovery"||
    snapshot!=filepath.Join(filepath.Dir(dir),WindowsDNSRecoverySnapshotName){
  return errors.New("not a disposable resident recovery journal")
 }
 intent:=filepath.Join(dir,ResidentIntentFile)
 items:=[]string{filepath.Dir(dir),dir,intent,snapshot}
 quoted:=make([]string,0,len(items))
 for _,p:=range items{quoted=append(quoted,windowsSYSDNSQuote(p))}
 script:=`$ErrorActionPreference='Stop';`+
  `$paths=@(`+strings.Join(quoted,",")+`);`+
  `$a=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544');`+
  `$s=[Security.Principal.SecurityIdentifier]::new('S-1-5-18');`+
  `$full=[Security.AccessControl.FileSystemRights]::FullControl;`+
  `$allow=[Security.AccessControl.AccessControlType]::Allow;`+
  `foreach($p in $paths){`+
  `if([IO.Directory]::Exists($p)){`+
  `$acl=New-Object Security.AccessControl.DirectorySecurity;`+
  `$flags=[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit;`+
  `foreach($sid in @($s,$a)){$rule=[Security.AccessControl.FileSystemAccessRule]::new($sid,$full,$flags,[Security.AccessControl.PropagationFlags]::None,$allow);$acl.AddAccessRule($rule)};`+
  `$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner($a);Set-Acl -LiteralPath $p -AclObject $acl -ErrorAction Stop`+
  `}else{`+
  `$acl=New-Object Security.AccessControl.FileSecurity;`+
  `foreach($sid in @($s,$a)){$rule=[Security.AccessControl.FileSystemAccessRule]::new($sid,$full,$allow);$acl.AddAccessRule($rule)};`+
  `$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner($a);Set-Acl -LiteralPath $p -AclObject $acl -ErrorAction Stop`+
  `}`+
  `}`
 return windowsSYSDNSShell(ctx,script)
}

func windowsSYSDNSSealNewReceipt(ctx context.Context,dir string)error{
 if filepath.Base(dir)!="motor-recovery-transaction"||
    filepath.Base(filepath.Dir(dir))!="legacy-engine-recovery"{
  return errors.New("invalid CI terminal receipt location")
 }
 source:=filepath.Join(dir,ResidentIntentFile)
 result:=filepath.Join(dir,ResidentResultFile)
 // An inherited freshly written file is NOT yet protected. Copying the
 // already verified exact intent file descriptor protects the new result.
 script:=`$ErrorActionPreference='Stop';`+
  `$source=`+windowsSYSDNSQuote(source)+`;`+
  `$target=`+windowsSYSDNSQuote(result)+`;`+
  `if(-not [IO.File]::Exists($source) -or -not [IO.File]::Exists($target)){throw 'Missing receipt/intent'};`+
  `$acl=Get-Acl -LiteralPath $source -ErrorAction Stop;`+
  `Set-Acl -LiteralPath $target -AclObject $acl -ErrorAction Stop`
 return windowsSYSDNSShell(ctx,script)
}

func windowsSYSDNSReadConfig(path string)(windowsSYSDNSLabConfig,error){
 var c windowsSYSDNSLabConfig
 if !filepath.IsAbs(path){return c,errors.New("CI SYSTEM watchdog requires absolute transaction path")}
 raw,err:=os.ReadFile(path)
 if err!=nil{return c,err}
 if len(raw)<300||len(raw)>8192{return c,errors.New("CI SYSTEM watchdog config size invalid")}
 if err:=json.Unmarshal(raw,&c);err!=nil{return c,err}
 canonical,err:=json.Marshal(c)
 if err!=nil||!bytes.Equal(raw,canonical){return c,errors.New("noncanonical CI SYSTEM transaction")}
 if c.Schema!=1||!windowsSYSDNSTaskPattern.MatchString(c.Task)||
  c.Alias==""||!windowsDisposableDNSAlias.MatchString(c.Alias)||
  !validWindowsSYSDNSGUID(c.GUID)||
  c.PID<=0||!windowsDNSLabLeaseName.MatchString(c.Lock)||
  !filepath.IsAbs(c.PlanPath)||len(c.PlanSHA256)!=64||
  !filepath.IsAbs(c.JournalDir)||!filepath.IsAbs(c.SnapshotPath)||
  len(c.SnapshotSHA256)!=64||c.Pubkey==""||c.Signature==""||
  !filepath.IsAbs(c.WatchdogReady)||!filepath.IsAbs(c.Recovered){
  return c,errors.New("CI-only SYSTEM transaction contains unsupported identity")
 }
 return c,nil
}

func validWindowsSYSDNSGUID(guid string)bool{
 if len(guid)!=38{return false}
 return validDNSState(DNSServerState{InterfaceGUID:guid,Family:DNSIPv4,
  Mode:DNSStatic,Servers:[]string{"1.1.1.1"}})==nil
}

func windowsSYSDNSWatchdog(t *testing.T){
 if err:=VerifyWindowsCurrentSystemSIDReadOnly();err!=nil{t.Fatal(err)}
 cfg,err:=windowsSYSDNSReadConfig(*windowsSYSDNSConfigFlag)
 if err!=nil{t.Fatal(err)}
 defer func(){
  if t.Failed(){
   _=os.WriteFile(filepath.Join(filepath.Dir(cfg.Recovered),"watchdog-failure"),
    []byte("Real SYSTEM watchdog rejected recovery; inspect scheduler logs"),0600)
  }
 }()
 ctx,cancel:=context.WithTimeout(context.Background(),110*time.Second)
 defer cancel()
 // CI-only config is generated by the controller, not a product permit.
 for k,v:=range map[string]string{
  "VOLVE_CI_DNS_REAL_DISPOSABLE":"INTERNAL_HYPERV_VM_ONLY",
  "VOLVE_CI_DNS_LAB_ALIAS":cfg.Alias,
  "VOLVE_CI_DNS_LAB_GUID":cfg.GUID,
  "VOLVE_CI_DNS_CRASH_PLAN":cfg.PlanPath,
  "VOLVE_CI_DNS_CRASH_SHA256":cfg.PlanSHA256,
  "VOLVE_CI_DNS_RESIDENT_DIR":cfg.JournalDir,
  "VOLVE_CI_DNS_SNAPSHOT_PATH":cfg.SnapshotPath,
  "VOLVE_CI_DNS_SNAPSHOT_SHA256":cfg.SnapshotSHA256,
  "VOLVE_CI_DNS_LAB_PUBKEY":cfg.Pubkey,
  "VOLVE_CI_DNS_LAB_SIGNATURE":cfg.Signature,
 }{if err:=os.Setenv(k,v);err!=nil{t.Fatal(err)}}
 plan,err:=windowsDNSCrashPlanFromDisk()
 if err!=nil{t.Fatal(err)}
 if cfg.Alias!=plan.Alias||cfg.GUID!=plan.GUID{
  t.Fatal("SYSTEM task points to another disposable vNIC")
 }
 observed,err:=newWindowsCrashExitHandle(cfg.PID)
 if err!=nil{t.Fatal(err)}
 defer observed.Close()
 if err:=os.WriteFile(cfg.WatchdogReady,[]byte("SYSTEM has opened original updater process handle"),0600);err!=nil{t.Fatal(err)}
 if err:=observed.Wait(ctx);err!=nil{t.Fatal(err)}
 adapter,err:=VerifyWindowsDisposableDNSAdapterWithLocalDNSReadOnly(
  ctx,cfg.Alias,cfg.GUID,DefaultWindowsDisposableDNSInspect)
 if err!=nil{t.Fatal(err)}
 pinned,err:=FindWindowsAdapterIndex(ctx,cfg.GUID,DefaultWindowsReadOnlyPowerShell)
 if err!=nil||pinned!=adapter.InterfaceIndex{t.Fatal("disposable adapter GUID/index mismatch")}
 acl,err:=NewWindowsDNSProtectedACLVerifier(ctx,cfg.JournalDir,cfg.SnapshotPath,
  DefaultWindowsDNSProtectedACLInspect)
 if err!=nil{t.Fatal(err)}
 attestor,err:=windowsCrashLabAttestor(observed)
 if err!=nil{t.Fatal(err)}
 attestor.Protect=acl
 prior:=attestor.VerifySYSTEMAndFailedMotor
 attestor.VerifySYSTEMAndFailedMotor=func(ctx context.Context,j ResidentRecoveryIntent)error{
  if err:=VerifyWindowsCurrentSystemSIDReadOnly();err!=nil{return err}
  return prior(ctx,j)
 }
 // Mandatory independent SYSTEM + DACL + publisher (ephemeral CI) + crash
 // attestation under the same Windows OS-wide mutex AND before each command.
 if err:=runAttestedWindowsStaticDNSRecovery(ctx,plan.Records,
  DefaultWindowsReadOnlyPowerShell,attestor,runPinnedWindowsNativeDNS,cfg.Lock);err!=nil{
  t.Fatalf("true SYSTEM attested real IPv4/IPv6 recovery failed: %v",err)
 }
 for _,r:=range plan.Records{
  raw,err:=DefaultWindowsReadOnlyPowerShell(ctx,windowsEffectiveDNSQuery)
  if err!=nil{t.Fatal(err)}
  actual,err:=parseEffectiveDNS(raw,pinned,r.Original.Family)
  if err!=nil||!sameDNSAddresses(actual,r.Original.Servers){
   t.Fatalf("SYSTEM restore DNS mismatch %s %v %v",r.Original.Family,actual,err)
  }
 }
 if err:=FinishResidentRecoveryIntent(ctx,cfg.JournalDir,"restored",
  func(p string)error{
   if p!=filepath.Join(cfg.JournalDir,ResidentResultFile){
    return errors.New("CI SYSTEM can only seal its just-created result")
   }
   return windowsSYSDNSSealNewReceipt(ctx,cfg.JournalDir)
  },acl);err!=nil{t.Fatalf("true SYSTEM recovery receipt failed: %v",err)}
 if err:=os.WriteFile(cfg.Recovered,
  []byte("REAL SYSTEM DNS v4/v6 restored + signed CI journal + NTFS ACL + crash exit 83"),
  0600);err!=nil{t.Fatal(err)}
 t.Log("PASS: true LocalSystem process recovered REAL DNS v4/v6 after crashed updater, validating NTFS ACL + signed lab journal before each command")
}

func windowsSYSDNSCreateTask(ctx context.Context,name,exe,config string)error {
 if !windowsSYSDNSTaskPattern.MatchString(name)||!filepath.IsAbs(exe)||
  !filepath.IsAbs(config){return errors.New("unsafe SYSTEM lab task declaration")}
 args:="-test.run=^TestWindowsRealDNSSYSTEMWatchdogAfterUpdaterCrash$ -test.v -volve-ci-sys-watchdog-config="+strconv.Quote(config)
 script:=`$ErrorActionPreference='Stop';`+
  `$name=`+windowsSYSDNSQuote(name)+`;`+
  `if(Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue){throw 'Existing task collision'};`+
  `$principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest;`+
  `$action=New-ScheduledTaskAction -Execute `+windowsSYSDNSQuote(exe)+
    ` -Argument `+windowsSYSDNSQuote(args)+`;`+
  `$trigger=New-ScheduledTaskTrigger -Once -At ((Get-Date).AddDays(7));`+
  `Register-ScheduledTask -TaskName $name -Principal $principal -Action $action -Trigger $trigger -ErrorAction Stop | Out-Null;`+
  `$task=Get-ScheduledTask -TaskName $name -ErrorAction Stop;`+
  `if($task.TaskPath -ne '\' -or $task.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or @($task.Actions).Count -ne 1 -or $task.Actions[0].Execute -ine `+windowsSYSDNSQuote(exe)+`){throw 'CI task identity mismatch'};`+
  `Start-ScheduledTask -TaskName $name -ErrorAction Stop`
 return windowsSYSDNSShell(ctx,script)
}

func windowsSYSDNSRemoveTask(ctx context.Context,name string)error{
 if !windowsSYSDNSTaskPattern.MatchString(name){return errors.New("not a CI SYSTEM task")}
 script:=`$ErrorActionPreference='Stop';$name=`+windowsSYSDNSQuote(name)+`;`+
  `$task=Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue;`+
  `if($null -ne $task){`+
  `if($task.TaskPath -ne '\' -or $task.Principal.UserId -notin @('SYSTEM','S-1-5-18')){throw 'Unsafe task cleanup identity'};`+
  `if($task.State -eq 'Running'){Stop-ScheduledTask -TaskName $name -ErrorAction Stop};`+
  `Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction Stop`+
  `}`
 return windowsSYSDNSShell(ctx,script)
}

func windowsSYSDNSAwaitResult(ctx context.Context,success,fail string)error{
 for{
  if err:=ctx.Err();err!=nil{return err}
  if _,err:=os.Lstat(fail);err==nil{
   raw,_:=os.ReadFile(fail)
   return fmt.Errorf("LocalSystem recovery refused: %s",raw)
  }
  if st,err:=os.Lstat(success);err==nil {
   if !st.Mode().IsRegular(){return errors.New("invalid CI recovery evidence")}
   return nil
  }
  time.Sleep(200*time.Millisecond)
 }
}

func TestWindowsRealDNSSYSTEMWatchdogAfterUpdaterCrash(t *testing.T){
 if *windowsSYSDNSConfigFlag!=""{
  // The SYSTEM scheduler process is the ONLY way this mode reaches netsh.
  windowsSYSDNSWatchdog(t)
  return
 }
 if os.Getenv("VOLVE_CI_DNS_RECOVERY_CHILD")=="updater"{
  windowsDNSCrashChildUpdater(t)
  return
 }
 if os.Getenv("VOLVE_CI_DNS_REAL_DISPOSABLE")!="INTERNAL_HYPERV_VM_ONLY" {
  t.Skip("real SYSTEM DNS test requires uniquely disposable internal Hyper-V CI workflow")
 }
 if os.Getenv("GITHUB_ACTIONS")!="true"{t.Fatal("not on ephemeral GitHub Windows runner")}
 ctx,cancel:=context.WithTimeout(context.Background(),185*time.Second)
 defer cancel()
 alias,guid:=os.Getenv("VOLVE_CI_DNS_LAB_ALIAS"),os.Getenv("VOLVE_CI_DNS_LAB_GUID")
 if _,err:=VerifyWindowsDisposableDNSAdapterReadOnly(ctx,alias,guid,
  DefaultWindowsDisposableDNSInspect);err!=nil{t.Fatal(err)}
 root:=t.TempDir()
 records:=windowsDNSCrashRecords(guid)
 proof:=prepareWindowsCrashLabSeal(t,root,records)
 if err:=windowsSYSDNSSealFixture(ctx,proof["VOLVE_CI_DNS_RESIDENT_DIR"],
  proof["VOLVE_CI_DNS_SNAPSHOT_PATH"]);err!=nil{t.Fatal(err)}
 verifier,err:=NewWindowsDNSProtectedACLVerifier(ctx,
  proof["VOLVE_CI_DNS_RESIDENT_DIR"],proof["VOLVE_CI_DNS_SNAPSHOT_PATH"],
  DefaultWindowsDNSProtectedACLInspect)
 if err!=nil{t.Fatal(err)}
 for _,path:=range []string{
  filepath.Dir(proof["VOLVE_CI_DNS_RESIDENT_DIR"]),
  proof["VOLVE_CI_DNS_RESIDENT_DIR"],
  filepath.Join(proof["VOLVE_CI_DNS_RESIDENT_DIR"],ResidentIntentFile),
  proof["VOLVE_CI_DNS_SNAPSHOT_PATH"],
 }{if err:=verifier(path);err!=nil{t.Fatalf("CI journal not protected before crash: %v",err)}}
 plan:=windowsDNSCrashRecoveryPlan{Schema:1,Alias:alias,GUID:guid,Records:records}
 raw,err:=json.Marshal(plan);if err!=nil{t.Fatal(err)}
 planPath:=filepath.Join(root,"pinned-ci-dns-plan.json")
 if err:=os.WriteFile(planPath,raw,0600);err!=nil{t.Fatal(err)}
 digest:=sha256.Sum256(raw)
 unique:=os.Getenv("GITHUB_RUN_ID")+"00000"
 taskName:="VOLVE-CI-DNS-SYSTEM-"+unique
 lock:="VOLVE-CI-DNSLock-"+unique
 if !windowsSYSDNSTaskPattern.MatchString(taskName)||
    !windowsDNSLabLeaseName.MatchString(lock){t.Fatal("CI task or mutex name not unique")}
 common:=append(os.Environ(),
  "VOLVE_CI_DNS_CRASH_PLAN="+planPath,
  "VOLVE_CI_DNS_CRASH_SHA256="+hex.EncodeToString(digest[:]),
  "VOLVE_CI_DNS_CRASH_ARMED="+filepath.Join(root,"armed"),
  "VOLVE_CI_DNS_CRASH_TRIGGER="+filepath.Join(root,"trigger"),
 )
 updater:=exec.CommandContext(ctx,os.Args[0],"-test.run=^TestWindowsRealDNSSYSTEMWatchdogAfterUpdaterCrash$")
 updater.Env=append(common,"VOLVE_CI_DNS_RECOVERY_CHILD=updater")
 var updaterOutput bytes.Buffer
 updater.Stdout=&updaterOutput
 updater.Stderr=&updaterOutput
 if err:=updater.Start();err!=nil{t.Fatal(err)}
 if err:=windowsDNSCrashAwaitFile(ctx,filepath.Join(root,"armed"));err!=nil{
  updater.Process.Kill()
  t.Fatalf("isolated updater did not prove localhost DNS before crash: %v; %s",err,updaterOutput.String())
 }
 cfg:=windowsSYSDNSLabConfig{
  Schema:1,Task:taskName,Alias:alias,GUID:guid,PID:updater.Process.Pid,
  PlanPath:planPath,PlanSHA256:hex.EncodeToString(digest[:]),
  JournalDir:proof["VOLVE_CI_DNS_RESIDENT_DIR"],
  SnapshotPath:proof["VOLVE_CI_DNS_SNAPSHOT_PATH"],
  SnapshotSHA256:proof["VOLVE_CI_DNS_SNAPSHOT_SHA256"],
  Pubkey:proof["VOLVE_CI_DNS_LAB_PUBKEY"],
  Signature:proof["VOLVE_CI_DNS_LAB_SIGNATURE"],Lock:lock,
  WatchdogReady:filepath.Join(root,"watchdog-ready"),
  Recovered:filepath.Join(root,"restored"),
 }
 configPath:=filepath.Join(root,"system-watchdog-config.json")
 conf,err:=json.Marshal(cfg);if err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(configPath,conf,0600);err!=nil{t.Fatal(err)}
 taskCreated:=false
 defer func(){
  if taskCreated {
   cleanupCtx,cancel:=context.WithTimeout(context.Background(),20*time.Second)
   defer cancel()
   if err:=windowsSYSDNSRemoveTask(cleanupCtx,taskName);err!=nil{
    t.Errorf("could not delete disposable SYSTEM task: %v",err)
   }
  }
 }()
 if err:=windowsSYSDNSCreateTask(ctx,taskName,os.Args[0],configPath);err!=nil{
  updater.Process.Kill()
  cleanupCtx,cancel:=context.WithTimeout(context.Background(),15*time.Second)
  _=windowsSYSDNSRemoveTask(cleanupCtx,taskName)
  cancel()
  t.Fatal(err)
 }
 taskCreated=true
 if err:=windowsDNSCrashAwaitFile(ctx,cfg.WatchdogReady);err!=nil{
  updater.Process.Kill();t.Fatalf("SYSTEM watchdog did not open updater handle: %v",err)
 }
 if err:=os.WriteFile(filepath.Join(root,"trigger"),[]byte("crash-now"),0600);err!=nil{
  updater.Process.Kill();t.Fatal(err)
 }
 updaterErr:=updater.Wait()
 if updaterErr==nil{t.Fatal("updater did not crash on command")}
 if err:=windowsSYSDNSAwaitResult(ctx,cfg.Recovered,filepath.Join(root,"watchdog-failure"));err!=nil{
  t.Fatalf("true SYSTEM DNS recovery missing: %v; updater=%s",err,updaterOutput.String())
 }
 journalState,err:=InspectResidentRecoveryJournal(ctx,cfg.JournalDir,verifier)
 if err!=nil||journalState.Status!="restored"{
  t.Fatalf("true SYSTEM journal not durably finalized: %s %v",journalState.Status,err)
 }
 idx,err:=FindWindowsAdapterIndex(ctx,guid,DefaultWindowsReadOnlyPowerShell)
 if err!=nil{t.Fatal(err)}
 for _,record:=range records{
  raw,err:=DefaultWindowsReadOnlyPowerShell(ctx,windowsEffectiveDNSQuery)
  if err!=nil{t.Fatal(err)}
  got,err:=parseEffectiveDNS(raw,idx,record.Original.Family)
  if err!=nil||!sameDNSAddresses(got,record.Original.Servers){
   t.Fatalf("third-party verification of SYSTEM-restored DNS %s failed: %v %v",record.Original.Family,got,err)
  }
 }
 t.Log("PASS: Windows LocalSystem SYSTEM watchdog restored REAL DNS IPv4/IPv6 after updater crash using sealed NTFS DACL, ephemeral signed journal and pinned process handle")
}
