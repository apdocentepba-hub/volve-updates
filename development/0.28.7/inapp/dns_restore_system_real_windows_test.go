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
 "crypto/ed25519"
 "crypto/rand"
 "reflect"
 "encoding/hex"
 "encoding/base64"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "os"
 "os/exec"
 "path/filepath"
 "regexp"
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
 FreshRoot string
 FreshPins freshActivationEvidence
 FreshPub []byte
 FreshAdmission []byte
 FreshAdmissionSignature []byte
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
  `$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner($a);[IO.Directory]::SetAccessControl($p,$acl)`+
  `}else{`+
  `$acl=New-Object Security.AccessControl.FileSecurity;`+
  `foreach($sid in @($s,$a)){$rule=[Security.AccessControl.FileSystemAccessRule]::new($sid,$full,$allow);$acl.AddAccessRule($rule)};`+
  `$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner($a);[IO.File]::SetAccessControl($p,$acl)`+
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
  `$admins=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544');`+
  `$system=[Security.Principal.SecurityIdentifier]::new('S-1-5-18');`+
  `$full=[Security.AccessControl.FileSystemRights]::FullControl;`+
  `$allow=[Security.AccessControl.AccessControlType]::Allow;`+
  `$acl=New-Object Security.AccessControl.FileSecurity;`+
  `foreach($sid in @($system,$admins)){`+
  `$rule=[Security.AccessControl.FileSystemAccessRule]::new($sid,$full,$allow);`+
  `$acl.AddAccessRule($rule)};`+
  `$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner($admins);`+
  `[IO.File]::SetAccessControl($target,$acl)`
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
 if c.FreshRoot!=""{
  if c.FreshRoot!=filepath.Join(filepath.Dir(c.PlanPath),c.FreshPins.TransactionID)||
   len(c.FreshPub)!=ed25519.PublicKeySize||validateFreshActivationEvidence(c.FreshPins)!=nil||len(c.FreshAdmission)==0||len(c.FreshAdmissionSignature)==0{
   return c,errors.New("invalid disposable fresh rescue identity")
  }
 }else if c.FreshPins!=(freshActivationEvidence{})||len(c.FreshPub)!=0||len(c.FreshAdmission)!=0||len(c.FreshAdmissionSignature)!=0{return c,errors.New("partial fresh lab configuration")}
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
 stage:="system-init"
 defer func(){
  if t.Failed(){
   _=os.WriteFile(filepath.Join(filepath.Dir(cfg.Recovered),"watchdog-failure"),
    []byte("LocalSystem watchdog refused at stage: "+stage),0600)
  }
 }()
 ctx,cancel:=context.WithTimeout(context.Background(),360*time.Second)
 defer cancel()
 if cfg.FreshRoot!=""{
  if err:=nativeDNSOriginalBackupACL(ctx,*windowsSYSDNSConfigFlag);err!=nil{t.Fatal("fresh CI configuration not sealed",err)}
  if err:=nativeDNSOriginalBackupACL(ctx,cfg.FreshRoot);err!=nil{t.Fatal("fresh CI transaction not sealed",err)}
 }
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
 stage="read-pinned-plan"
 plan,err:=windowsDNSCrashPlanFromDisk()
 if err!=nil{t.Fatal(err)}
 if cfg.Alias!=plan.Alias||cfg.GUID!=plan.GUID{
  t.Fatal("SYSTEM task points to another disposable vNIC")
 }
 stage="open-pinned-updater-handle"
 observed,err:=newWindowsCrashExitHandle(cfg.PID)
 if err!=nil{t.Fatal(err)}
 defer observed.Close()
 if err:=os.WriteFile(cfg.WatchdogReady,[]byte("SYSTEM has opened original updater process handle"),0600);err!=nil{t.Fatal(err)}
 stage="await-updater-crash-exit-83"
 if err:=observed.Wait(ctx);err!=nil{t.Fatal(err)}
 stage="inspect-live-hyperv-localhost-state"
 adapter,err:=VerifyWindowsDisposableDNSAdapterWithLocalDNSReadOnly(
  ctx,cfg.Alias,cfg.GUID,DefaultWindowsDisposableDNSInspect)
 if err!=nil{t.Fatal(err)}
 stage="pin-network-interface"
 pinned,err:=FindWindowsAdapterIndex(ctx,cfg.GUID,DefaultWindowsReadOnlyPowerShell)
 if err!=nil||pinned!=adapter.InterfaceIndex{t.Fatal("disposable adapter GUID/index mismatch")}
 stage="create-real-ntfs-acl-verifier"
 acl,err:=NewWindowsDNSProtectedACLVerifier(ctx,cfg.JournalDir,cfg.SnapshotPath,
  DefaultWindowsDNSProtectedACLInspect)
 if err!=nil{t.Fatal(err)}
 stage="create-signed-journal-attestor"
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
 stage="verify-scoped-lab-provenance"
 if err:=attestor.Verify(ctx,plan.Records);err!=nil{t.Fatal(err)}
 // Only the CI test's unique nonrouting adapter may be restored. Use
 // the existing exact-GUID lab query, NOT a change to production census.
 // Outer workflow independently compares all preexisting host DNS/routes.
 scoped,err:=windowsCrashLabPinnedProvenanceInspector(cfg.Alias,cfg.GUID,DefaultWindowsReadOnlyPowerShell)
 if err!=nil{t.Fatal(err)}
 evidence,err:=InspectWindowsDNSAssignmentProvenanceReadOnly(ctx,scoped)
 if err!=nil||evidence.AdapterCount!=1||len(evidence.States)!=2||evidence.interfaceIndexes[strings.ToLower(cfg.GUID)]!=pinned{
  t.Fatal("exact isolated adapter provenance unavailable",err)
 }
 for _,r:=range plan.Records{
  found:=false
  for _,state:=range evidence.States{if sameDNSState(state,r.Expected){found=true}}
  if !found{t.Fatal("isolated initial localhost source not proven")}
 }
 stage="execute-attested-real-dns-batch"
 if cfg.FreshRoot!=""{
  stage="fresh-signed-pending-system-rescue"
  // Same exact scoped disposable vNIC, same real exited process handle
  // and independently attested CI plan. The new fresh rescue code owns
  // the protected native transaction mutex. Production remains unchanged.
  if err:=runFreshSYSTEMRecoveryLab(ctx,cfg,plan.Records,scoped,attestor,pinned);err!=nil{t.Fatal(err)}
 }else if err:=runAttestedWindowsStaticDNSRecovery(ctx,plan.Records,
  scoped,attestor,runPinnedWindowsNativeDNS,cfg.Lock);err!=nil{
  // Record a bounded reason category, not arbitrary native output.
  for _,reason:=range []struct{match,code string}{
   {"exclusive DNS recovery lease unavailable","lease"},
   {"independent DNS recovery authorization expired","authorization"},
   {"DNS assignment source unavailable","native-source"},
   {"static NameServer registry list does not match","source-mismatch"},
   {"unsupported profile-specific source","source-profile"},
   {"all-adapter preflight refused","preflight"},
   {"recovery incomplete","write-or-readback"},
   {"final native DNS recovery census","final-census"},
  }{if strings.Contains(err.Error(),reason.match){stage+=":"+reason.code;break}}
  t.Fatalf("true SYSTEM attested real IPv4/IPv6 recovery failed: %v",err)
 }
 stage="verify-restored-dns"
 for _,r:=range plan.Records{
  raw,err:=DefaultWindowsReadOnlyPowerShell(ctx,windowsEffectiveDNSQuery)
  if err!=nil{t.Fatal(err)}
  actual,err:=parseEffectiveDNS(raw,pinned,r.Original.Family)
  if err!=nil||!sameDNSAddresses(actual,r.Original.Servers){
   t.Fatalf("SYSTEM restore DNS mismatch %s %v %v",r.Original.Family,actual,err)
  }
 }
 stage="finalize-durable-recovery-receipt"
 if err:=FinishResidentRecoveryIntent(ctx,cfg.JournalDir,"restored",
  func(p string)error{
   if p!=filepath.Join(cfg.JournalDir,ResidentResultFile){
    return errors.New("CI SYSTEM can only seal its just-created result")
   }
   return windowsSYSDNSSealNewReceipt(ctx,cfg.JournalDir)
  },acl);err!=nil{
  stage="finalize-durable-recovery-receipt: "+err.Error()
  t.Fatalf("true SYSTEM recovery receipt failed: %v",err)
 }
 stage="write-real-system-success-evidence"
 if err:=os.WriteFile(cfg.Recovered,
  []byte("REAL SYSTEM DNS v4/v6 restored + signed CI journal + NTFS ACL + crash exit 83"),
  0600);err!=nil{t.Fatal(err)}
 t.Log("PASS: true LocalSystem process recovered REAL DNS v4/v6 after crashed updater, validating NTFS ACL + signed lab journal before each command")
}

func windowsSYSDNSCreateTask(ctx context.Context,name,exe,config string)error {
 if !windowsSYSDNSTaskPattern.MatchString(name)||!filepath.IsAbs(exe)||
  !filepath.IsAbs(config){return errors.New("unsafe SYSTEM lab task declaration")}
 args:="-test.run=^TestWindowsRealDNSSYSTEMWatchdogAfterUpdaterCrash$ -test.v -volve-ci-sys-watchdog-config="+"\""+config+"\""
 script:=`$ErrorActionPreference='Stop';`+
  `$name=`+windowsSYSDNSQuote(name)+`;`+
  `if(Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue){throw 'Existing task collision'};`+
  `$principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest;`+
  `$action=New-ScheduledTaskAction -Execute `+windowsSYSDNSQuote(exe)+
    ` -Argument `+windowsSYSDNSQuote(args)+`;`+
  `$trigger=New-ScheduledTaskTrigger -AtStartup;`+
  `Register-ScheduledTask -TaskName $name -Principal $principal -Action $action -Trigger $trigger -ErrorAction Stop | Out-Null;`+
  `$task=Get-ScheduledTask -TaskName $name -ErrorAction Stop;`+
  `if($task.TaskPath -ne '\' -or $task.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or @($task.Actions).Count -ne 1 -or @($task.Triggers).Count -ne 1 -or $task.Triggers[0].CimClass.CimClassName -ne 'MSFT_TaskBootTrigger' -or $task.Actions[0].Execute -ine `+windowsSYSDNSQuote(exe)+`){throw 'CI task identity mismatch'};`+
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
 ctx,cancel:=context.WithTimeout(context.Background(),480*time.Second)
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
  "VOLVE_CI_DNS_WAIT_FOR_SYSTEM_WATCHDOG="+filepath.Join(root,"system-prearmed"),
 )
 updater:=exec.CommandContext(ctx,os.Args[0],"-test.run=^TestWindowsRealDNSSYSTEMWatchdogAfterUpdaterCrash$")
 updater.Env=append(common,"VOLVE_CI_DNS_RECOVERY_CHILD=updater")
 var updaterOutput bytes.Buffer
 updater.Stdout=&updaterOutput
 updater.Stderr=&updaterOutput
 if err:=updater.Start();err!=nil{t.Fatal(err)}
 // The updater is running for process-handle pinning, but blocked
 // BEFORE changing any network state. Prearm the SYSTEM watchdog first.
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
 if os.Getenv("VOLVE_CI_FRESH_REAL_RESCUE")=="1"{
  if os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{t.Fatal("fresh real rescue requires hosted disposable VM")}
  cfg.FreshRoot,cfg.FreshPins,cfg.FreshPub,cfg.FreshAdmission,cfg.FreshAdmissionSignature=prepareFreshSYSTEMRecoveryLab(t,ctx,root,records)
 }
 configPath:=filepath.Join(root,"system-watchdog-config.json")
 conf,err:=json.Marshal(cfg);if err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(configPath,conf,0600);err!=nil{t.Fatal(err)}
 if cfg.FreshRoot!=""{
  if err:=nativeSealApprovedOriginalBackupNode(ctx,configPath);err!=nil{t.Fatal(err)}
 }
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
  updater.Process.Kill();t.Fatalf("SYSTEM watchdog did not open updater handle before DNS writes: %v",err)
 }
 // Reject prearm unless the separately registered boot-triggered SYSTEM
 // watchdog already pinned the updater AND no DNS settings changed.
 if _,err:=VerifyWindowsDisposableDNSAdapterReadOnly(ctx,alias,guid,
  DefaultWindowsDisposableDNSInspect);err!=nil{
  updater.Process.Kill()
  t.Fatalf("isolated vNIC changed before SYSTEM watchdog was armed: %v",err)
 }
 if cfg.FreshRoot!=""{
  // Existing native test already established the SYSTEM task and exact
  // pinned live updater handle. Arm the fresh record while the updater
  // is still blocked. The readiness shim is CI-only, not a product guard.
  release,err:=AcquireProtectedResidentTransitionLease(ctx);if err!=nil{t.Fatal(err)}
  held:=&exclusiveDNSActivationGuard{inner:&freshReservationFixtureGuard{},acquire:AcquireProtectedResidentTransitionLease,release:release}
  _,err=armFreshRecoveryPendingUnderLease(ctx,cfg.FreshRoot,cfg.FreshPub,cfg.FreshPins,held)
  held.close()
  if err!=nil{t.Fatal("fresh pending record not armed before DNS mutation",err)}
 }
 if err:=os.WriteFile(filepath.Join(root,"system-prearmed"),
  []byte("SYSTEM boot-triggered task has pinned updater before DNS changes"),0600);err!=nil{
  updater.Process.Kill();t.Fatal(err)
 }
 if err:=windowsDNSCrashAwaitFile(ctx,filepath.Join(root,"armed"));err!=nil{
  updater.Process.Kill()
  t.Fatalf("updater failed to set isolated loopback DNS after SYSTEM prearm: %v; %s",err,updaterOutput.String())
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
 if cfg.FreshRoot!=""{
  release,err:=AcquireProtectedResidentTransitionLease(ctx);if err!=nil{t.Fatal(err)}
  verifyErr:=func()error{
   envelope,err:=loadFreshRecoveryPermitUnderLease(ctx,cfg.FreshRoot,cfg.FreshPub,cfg.FreshPins)
   if err!=nil{return err}
   pending,err:=expectedFreshRecoveryPending(cfg.FreshPins,envelope);if err!=nil{return err}
   result,err:=expectedFreshDNSRestored(pending);if err!=nil{return err}
   return verifyFreshDNSRestoredUnderLease(ctx,cfg.FreshRoot,pending,result)
  }()
  release()
  if verifyErr!=nil{t.Fatal("separate controller could not reopen fresh SYSTEM DNS completion",verifyErr)}
  // Verify the independently consumed admission, not only the recovery.
  raw,err:=os.ReadFile(filepath.Join(cfg.FreshRoot,freshReservationName))
  if err!=nil{t.Fatal("missing native activation reservation",err)}
  var receipt freshActivationReservation
  if err:=json.Unmarshal(raw,&receipt);err!=nil{t.Fatal(err)}
  sum:=sha256.Sum256(cfg.FreshAdmission)
  if receipt.Evidence!=cfg.FreshPins||receipt.AdmissionSHA256!=hex.EncodeToString(sum[:]){t.Fatal("native activation receipt not bound to exact signed admission")}
  release,err=AcquireProtectedResidentTransitionLease(ctx);if err!=nil{t.Fatal(err)}
  verifyErr=verifyFreshReservationNative(ctx,cfg.FreshRoot,receipt)
  release()
  if verifyErr!=nil{t.Fatal("native activation receipt verification failed",verifyErr)}
  t.Log("PASS VOLVE_FRESH_NATIVE_ADMISSION_RESERVED_BEFORE_REAL_DUAL_STACK_ACTIVATION_AND_SYSTEM_RESCUE")
  t.Log("PASS VOLVE_FRESH_SIGNED_PENDING_REAL_SYSTEM_DNS_RESCUE_NATIVE_RECEIPT")
 }
 t.Log("PASS: SYSTEM watchdog with genuine at-startup trigger prearmed BEFORE first DNS write, restored REAL IPv4/IPv6 after crash with sealed NTFS CI permit and durable receipt")
}


// Native SYSTEM trial of the fresh recovery engine. All unrelated pins in
// this fixture are explicitly synthetic CI identities, not publisher trust.
// The DNS original is the existing disposable vNIC's fixed lab plan.
// No user or production installation root is accepted.
func prepareFreshSYSTEMRecoveryLab(t *testing.T,ctx context.Context,outer string,records []DNSRestoreRecord)(string,freshActivationEvidence,[]byte,[]byte,[]byte){
 t.Helper()
 nonce:=make([]byte,16);if _,err:=rand.Read(nonce);err!=nil{t.Fatal(err)}
 id:=hex.EncodeToString(nonce)
 root:=filepath.Join(outer,id)
 parent:=filepath.Join(root,"legacy-engine-recovery")
 seal:=func(p string)error{return nativeSealApprovedOriginalBackupNode(ctx,p)}
 check:=func(p string)error{return nativeDNSOriginalBackupACL(ctx,p)}
 for _,dir:=range []string{root,parent}{
  if err:=os.Mkdir(dir,0700);err!=nil{t.Fatal(err)}
  if err:=seal(dir);err!=nil{t.Fatal(err)}
 }
 originals:=make([]DNSServerState,0,len(records))
 for _,r:=range records{originals=append(originals,r.Original)}
 raw,pin,err:=BuildDNSOriginalJournal(ctx,originals);if err!=nil{t.Fatal(err)}
 if _,err:=StoreDNSOriginalBackupUnarmed(ctx,parent,raw,pin,seal,check);err!=nil{t.Fatal(err)}
 pins:=freshActivationEvidence{id,strings.Repeat("1",64),strings.Repeat("2",64),strings.Repeat("3",64),pin,strings.Repeat("5",64),strings.Repeat("6",64),strings.Repeat("7",64),strings.Repeat("8",64)}
 historical,err:=json.Marshal(originalRecoveryReviewEvidence{1,"original-recovery-review-unarmed",id,pins.OriginalReviewSHA256});if err!=nil{t.Fatal(err)}
 if err:=residentCreate(filepath.Join(root,originalRecoveryReviewFile),historical,seal,check);err!=nil{t.Fatal(err)}
 pub,private,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 permit,err:=json.Marshal(freshRecoveryPermit{1,freshRecoveryPermitComponent,freshRecoveryOperation,pins});if err!=nil{t.Fatal(err)}
 if err:=persistFreshRecoveryPermitNative(ctx,root,permit,ed25519.Sign(private,permit),pub,pins);err!=nil{t.Fatal(err)}
 now:=time.Now()
 admission,err:=json.Marshal(freshActivationAdmission{2,freshActivationComponent,freshActivationOperation,pins,now.Unix(),now.Add(10*time.Minute).Unix()})
 if err!=nil{t.Fatal(err)}
 signature:=[]byte(base64.StdEncoding.EncodeToString(ed25519.Sign(private,admission)))
 return root,pins,pub,admission,signature
}
func runFreshSYSTEMRecoveryLab(ctx context.Context,cfg windowsSYSDNSLabConfig,records []DNSRestoreRecord,scoped WindowsReadOnlyPowerShell,attestor WindowsSealedDNSRecoveryAttestor,index uint32)error{
 if err:=VerifyWindowsCurrentSystemSIDReadOnly();err!=nil{return err}
 if !windowsDisposableDNSAlias.MatchString(cfg.Alias)||cfg.FreshRoot!=filepath.Join(filepath.Dir(cfg.PlanPath),cfg.FreshPins.TransactionID)||len(records)!=2{return errors.New("fresh lab scope invalid")}
 release,err:=AcquireProtectedResidentTransitionLease(ctx);if err!=nil{return err}
 defer release()
 sealed,err:=ReadDNSOriginalBackupNativeWindows(ctx,filepath.Join(cfg.FreshRoot,"legacy-engine-recovery"),cfg.FreshPins.OriginalDNSJournalSHA256)
 if err!=nil||!reflect.DeepEqual(sealed,records){return errors.New("fresh rescue journal differs from independently attested disposable plan")}
 fence:=func(c context.Context,pins freshActivationEvidence)error{
  if pins!=cfg.FreshPins{return errors.New("foreign fresh lab transaction")}
  if err:=VerifyWindowsCurrentSystemSIDReadOnly();err!=nil{return err}
  if err:=attestor.Verify(c,records);err!=nil{return err}
  observed,err:=FindWindowsAdapterIndex(c,cfg.GUID,DefaultWindowsReadOnlyPowerShell)
  if err!=nil||observed!=index{return errors.New("fresh lab disposable adapter identity changed")}
  return c.Err()
 }
 // Additional independent invocation fence: only exact commands derived
 // from the disposable journal and pinned interface may reach real netsh.
 allowed:=[][]string{}
 for _,r:=range records{
  if !strings.EqualFold(r.Original.InterfaceGUID,cfg.GUID){return errors.New("fresh lab journal includes unrelated adapter")}
  cmds,err:=PlanWindowsDNSRestore(r.Original,index);if err!=nil{return err}
  for _,cmd:=range cmds{allowed=append(allowed,cmd.Args)}
 }
 writes:=0
 invoke:=func(c context.Context,args []string)error{
  permitted:=false
  for _,exact:=range allowed{if reflect.DeepEqual(exact,args){permitted=true}}
  if !permitted{return errors.New("fresh lab writer refused command outside exact disposable plan")}
  if err:=fence(c,cfg.FreshPins);err!=nil{return err}
  if err:=runPinnedWindowsNativeDNS(c,args);err!=nil{return err}
  writes++
  return nil
 }
 if err:=restoreFreshOriginalDNSUnderLease(ctx,cfg.FreshRoot,cfg.FreshPub,cfg.FreshPins,fence,scoped,invoke);err!=nil{return err}
 if writes!=3{return fmt.Errorf("fresh real DNS rescue performed unexpected write count: %d",writes)}
 // Reopen on the same native lease. Terminal DNS receipt must prevent
 // any additional write on the second invocation.
 if err:=restoreFreshOriginalDNSUnderLease(ctx,cfg.FreshRoot,cfg.FreshPub,cfg.FreshPins,fence,scoped,invoke);err!=nil{return err}
 if writes!=3{return errors.New("fresh real DNS completion was not idempotent")}
 return nil
}


// CI-only native activation guard. The parent has created a separate
// SYSTEM task which holds the exact live updater handle. This guard is
// never a production trust root, health/commit adapter, or full installer.
type freshCrashActivationLabGuard struct{
 freshReservationFixtureGuard
 verify func(context.Context,string)error
}
func(g *freshCrashActivationLabGuard)VerifyArmed(ctx context.Context,pin string)error{return g.verify(ctx,pin)}

func activateFreshCrashLabNative(ctx context.Context,plan windowsDNSCrashRecoveryPlan,index uint32)error{
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"||os.Getenv("VOLVE_CI_DNS_REAL_DISPOSABLE")!="INTERNAL_HYPERV_VM_ONLY"||os.Getenv("VOLVE_CI_FRESH_REAL_RESCUE")!="1"{return errors.New("native activation trial requires disposable hosted VM")}
 config:=filepath.Join(filepath.Dir(os.Getenv("VOLVE_CI_DNS_CRASH_PLAN")),"system-watchdog-config.json")
 if err:=nativeDNSOriginalBackupACL(ctx,config);err!=nil{return err}
 cfg,err:=windowsSYSDNSReadConfig(config)
 if err!=nil{return err}
 if cfg.FreshRoot==""||cfg.PID!=os.Getpid()||cfg.Alias!=plan.Alias||cfg.GUID!=plan.GUID||cfg.PlanPath!=os.Getenv("VOLVE_CI_DNS_CRASH_PLAN")||cfg.PlanSHA256!=os.Getenv("VOLVE_CI_DNS_CRASH_SHA256"){return errors.New("native activation trial config not bound to exact updater")}
 scoped,err:=windowsCrashLabProvenanceInspector(cfg.Alias,cfg.GUID,DefaultWindowsReadOnlyPowerShell)
 if err!=nil{return err}
 originals:=[]DNSServerState{}
 for _,r:=range plan.Records{originals=append(originals,r.Original)}
 journal,pin,err:=BuildDNSOriginalJournal(ctx,originals)
 if err!=nil||pin!=cfg.FreshPins.OriginalDNSJournalSHA256{return errors.New("native activation trial journal pin mismatch")}
 records,err:=VerifyDNSOriginalJournal(ctx,journal,pin)
 if err!=nil{return err}
 // These flags refer to the disposable lab's synthetic initial inventory;
 // no full-machine fresh-install authorization is inferred.
 host:=FreshMotorInstallEvidence{InspectedAsAdministrator:true,InspectedMotorFiles:true,InspectedTaskScheduler:true,InspectedServices:true,InspectedDNSAdapters:true,InspectedPort53Listeners:true,InspectedRecoveryState:true}
 release,err:=AcquireProtectedResidentTransitionLease(ctx)
 if err!=nil{return err}
 var spent *freshActivationReservation
 guard:=&freshCrashActivationLabGuard{verify:func(c context.Context,p string)error{
  if p!=pin{return errors.New("foreign lab activation journal")}
  if _,err:=verifyFreshActivationAdmission(c,cfg.FreshAdmission,cfg.FreshAdmissionSignature,cfg.FreshPub,cfg.FreshPins,host,time.Now());err!=nil{return err}
  permit,err:=loadFreshRecoveryPermitUnderLease(c,cfg.FreshRoot,cfg.FreshPub,cfg.FreshPins)
  if err!=nil{return err}
  pending,err:=expectedFreshRecoveryPending(cfg.FreshPins,permit)
  if err!=nil{return err}
  if err:=verifyFreshRecoveryPendingUnderLease(c,cfg.FreshRoot,pending);err!=nil{return err}
  if err:=requireFreshDNSRestoredAbsent(c,cfg.FreshRoot);err!=nil{return err}
  if spent!=nil{if err:=verifyFreshReservationNative(c,cfg.FreshRoot,*spent);err!=nil{return err}}
  if err:=windowsSYSDNShellVerifyRunning(c,cfg,config);err!=nil{return err}
  observed,err:=FindWindowsAdapterIndex(c,cfg.GUID,DefaultWindowsReadOnlyPowerShell)
  if err!=nil||observed!=index{return errors.New("lab activation adapter index changed")}
  return c.Err()
 }}
 held:=&exclusiveDNSActivationGuard{inner:guard,acquire:AcquireProtectedResidentTransitionLease,release:release}
 defer held.close()
 allowed:=[][]string{}
 for _,r:=range records{
  if !strings.EqualFold(r.Original.InterfaceGUID,cfg.GUID){return errors.New("foreign lab activation adapter")}
  cmds,err:=PlanWindowsDNSRestore(r.Expected,index);if err!=nil{return err}
  for _,cmd:=range cmds{allowed=append(allowed,cmd.Args)}
 }
 writes:=0
 backend,err:=newWindowsPinnedDNSActivationBackend(ctx,journal,pin,scoped,func(c context.Context,args []string)error{
  ok:=false;for _,exact:=range allowed{if reflect.DeepEqual(exact,args){ok=true}}
  if !ok||spent==nil{return errors.New("unreserved or out-of-scope native lab activation")}
  if err:=runPinnedWindowsNativeDNS(c,args);err!=nil{return err}
  writes++
  return nil
 },held)
 if err!=nil{return err}
 if err:=verifyDNSActivationTransition(ctx,records,backend,0);err!=nil{return err}
 reservation,err:=reserveFreshActivationUnderHeldLease(ctx,cfg.FreshRoot,cfg.FreshAdmission,cfg.FreshAdmissionSignature,cfg.FreshPub,cfg.FreshPins,host,held)
 if err!=nil{return err}
 spent=&reservation
 for i,r:=range records{
  if err:=held.VerifyArmed(ctx,pin);err!=nil{return err}
  if err:=verifyDNSActivationTransition(ctx,records,backend,i);err!=nil{return err}
  if err:=backend.Apply(ctx,r.Expected);err!=nil{return err}
  if err:=verifyDNSActivationTransition(ctx,records,backend,i+1);err!=nil{return err}
 }
 if writes!=2{return errors.New("native trial did not perform exactly two family writes")}
 // Intentional crash follows in the existing child handshake. No commit,
 // no claim of live health, and no production activation is attempted.
 return held.VerifyArmed(ctx,pin)
}

func windowsSYSDNShellVerifyRunning(ctx context.Context,cfg windowsSYSDNSLabConfig,config string)error{
 if !windowsSYSDNSTaskPattern.MatchString(cfg.Task){return errors.New("invalid lab watchdog task identity")}
 args:="-test.run=^TestWindowsRealDNSSYSTEMWatchdogAfterUpdaterCrash$ -test.v -volve-ci-sys-watchdog-config="+"\""+config+"\""
 q:=windowsSYSDNSQuote
 return windowsSYSDNSShell(ctx,`$ErrorActionPreference='Stop';$t=Get-ScheduledTask -TaskPath '\' -TaskName `+q(cfg.Task)+` -ErrorAction Stop;
 if($t.State -ne 'Running' -or $t.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or @($t.Actions).Count -ne 1 -or @($t.Triggers).Count -ne 1 -or $t.Triggers[0].CimClass.CimClassName -ne 'MSFT_TaskBootTrigger' -or $t.Actions[0].Execute -ine `+q(os.Args[0])+` -or $t.Actions[0].Arguments -cne `+q(args)+`){throw 'Independent lab SYSTEM watchdog no longer running with exact action'}`)
}
