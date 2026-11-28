//go:build windows

package motorupdate

// Provisional activation is NOT a successful installation. Require an
// independently observed Windows reboot before any future final health
// certification. None of these helpers disables recovery or changes DNS.
import(
 "bytes"
 "context"
 "crypto/ed25519"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "syscall"
 "time"
 "unsafe"
)

const freshProvisionalName="fresh-activation-provisional.json"

type freshBootIdentity struct{
 BootUnixMilli int64 `json:"boot_unix_milli"`
 StartEventRecordID uint64 `json:"start_event_record_id"`
 StartEventUnixMilli int64 `json:"start_event_unix_milli"`
}

func validFreshBootIdentity(b freshBootIdentity)bool{
 const earliest int64=946684800000
 const latest int64=4102444800000
 if b.BootUnixMilli<earliest||b.BootUnixMilli>=latest||b.StartEventUnixMilli<earliest||b.StartEventUnixMilli>=latest||b.StartEventRecordID==0{return false}
 delta:=b.StartEventUnixMilli-b.BootUnixMilli
 return delta>=-300000&&delta<=300000
}

// WMI and event-log evidence must agree with the kernel's native uptime,
// rather than trusting a task's start time, elapsed wall time or a UI flag.
// Clock corrections, a missing/cleared event log or fast startup can
// prevent proof; such cases are refused, never treated as a reboot.
func validateFreshBootSample(b freshBootIdentity,wallBefore,wallAfter int64,uptimeBefore,uptimeAfter uint64)error{
 if !validFreshBootIdentity(b)||wallAfter<wallBefore||wallAfter-wallBefore>30000||uptimeAfter<uptimeBefore||uptimeAfter-uptimeBefore>30000||uptimeAfter>uint64(wallAfter)||uptimeBefore>uint64(wallBefore){return errors.New("inconsistent Windows boot observation")}
 const tolerance int64=180000
 earliest:=wallBefore-int64(uptimeBefore)
 latest:=wallAfter-int64(uptimeAfter)
 if b.BootUnixMilli>wallBefore||b.StartEventUnixMilli>wallAfter||b.BootUnixMilli-earliest>tolerance||earliest-b.BootUnixMilli>tolerance||b.BootUnixMilli-latest>tolerance||latest-b.BootUnixMilli>tolerance{return errors.New("Windows start event and WMI boot time do not agree with kernel uptime")}
 return nil
}
func verifyFreshLaterBoot(before,after freshBootIdentity)error{
 if !validFreshBootIdentity(before)||!validFreshBootIdentity(after){return errors.New("invalid pre/post boot evidence")}
 if after.StartEventRecordID<=before.StartEventRecordID||after.BootUnixMilli<=before.BootUnixMilli||after.StartEventUnixMilli<=before.StartEventUnixMilli{return errors.New("a later Windows boot is not independently proven")}
 return nil
}

var freshGetTickCount64=syscall.NewLazyDLL("kernel32.dll").NewProc("GetTickCount64")
func freshKernelUptimeMillis()(uint64,error){
 if err:=freshGetTickCount64.Find();err!=nil{return 0,err}
 lo,hi,_:=freshGetTickCount64.Call()
 if unsafe.Sizeof(uintptr(0))==4{return uint64(uint32(lo))|uint64(uint32(hi))<<32,nil}
 return uint64(lo),nil
}
func observeFreshBootNative(ctx context.Context)(freshBootIdentity,error){
 var denied freshBootIdentity
 if ctx==nil{return denied,errors.New("fresh boot observation requires context")}
 if err:=ctx.Err();err!=nil{return denied,err}
 root:=os.Getenv("SystemRoot")
 if !filepath.IsAbs(root)||strings.HasPrefix(root,string(filepath.Separator)+string(filepath.Separator)){return denied,errors.New("Windows system root unavailable")}
 ps:=filepath.Join(root,"System32","WindowsPowerShell","v1.0","powershell.exe")
 script:=`$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';
 $os=@(Get-CimInstance Win32_OperatingSystem -ErrorAction Stop);
 if($os.Count -ne 1 -or $null -eq $os[0].LastBootUpTime){throw 'Missing unique Windows boot time'};
 $ev=Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='Microsoft-Windows-Kernel-General';Id=12} -MaxEvents 1 -ErrorAction Stop;
 if($null -eq $ev -or $null -eq $ev.TimeCreated -or $ev.RecordId -le 0){throw 'Missing Windows startup event'};
 [pscustomobject]@{boot_unix_milli=([DateTimeOffset]($os[0].LastBootUpTime.ToUniversalTime())).ToUnixTimeMilliseconds();start_event_record_id=[uint64]$ev.RecordId;start_event_unix_milli=([DateTimeOffset]($ev.TimeCreated.ToUniversalTime())).ToUnixTimeMilliseconds()}|ConvertTo-Json -Compress`
 sample,cancel:=context.WithTimeout(ctx,20*time.Second);defer cancel()
 wallBefore:=time.Now().UnixMilli()
 uptimeBefore,err:=freshKernelUptimeMillis();if err!=nil{return denied,err}
 out,err:=exec.CommandContext(sample,ps,"-NoLogo","-NoProfile","-NonInteractive","-Command",script).Output()
 if err!=nil||len(out)==0||len(out)>2048{return denied,errors.New("native Windows boot observation unavailable")}
 uptimeAfter,err:=freshKernelUptimeMillis();if err!=nil{return denied,err}
 wallAfter:=time.Now().UnixMilli()
 var got freshBootIdentity
 dec:=json.NewDecoder(bytes.NewReader(out));dec.DisallowUnknownFields()
 if err:=dec.Decode(&got);err!=nil{return denied,err}
 var extra any
 if err:=dec.Decode(&extra);err!=io.EOF{return denied,errors.New("trailing boot observation")}
 if err:=validateFreshBootSample(got,wallBefore,wallAfter,uptimeBefore,uptimeAfter);err!=nil{return denied,err}
 return got,ctx.Err()
}

type freshActivationProvisional struct{
 Schema int `json:"schema"`
 Component string `json:"component"`
 PendingSHA256 string `json:"pending_sha256"`
 AdmissionSHA256 string `json:"admission_sha256"`
 Boot freshBootIdentity `json:"boot"`
}

func expectedFreshActivationProvisional(pending freshRecoveryPending,admissionSHA string,boot freshBootIdentity)(freshActivationProvisional,error){
 var denied freshActivationProvisional
 if _,err:=expectedFreshDNSRestored(pending);err!=nil{return denied,err}
 if verifyCanonicalLowerSHA256(admissionSHA)!=nil||admissionSHA==strings.Repeat("0",64)||!validFreshBootIdentity(boot){return denied,errors.New("missing independently verified provisional activation evidence")}
 raw,err:=json.Marshal(pending);if err!=nil{return denied,err}
 digest:=sha256.Sum256(raw)
 return freshActivationProvisional{1,"volve-fresh-activation-provisional-only-v1",hex.EncodeToString(digest[:]),admissionSHA,boot},nil
}

// Provisional and post-boot admission must reopen the actual consumed
// reservation. The independent admission digest alone is not evidence
// that a one-use authorization was ever durably reserved.
func verifyFreshProvisionalConsumptionUnderLease(ctx context.Context,root string,pins freshActivationEvidence,admissionSHA string)error{
 if _,err:=originalRecoveryEvidencePath(root,pins.TransactionID);err!=nil{return err}
 data,err:=readFreshFixedRecordUnderLease(ctx,root,freshReservationName)
 if err!=nil{return err}
 var receipt freshActivationReservation
 if err:=residentCanonical(data,&receipt);err!=nil{return err}
 if receipt.Evidence!=pins||receipt.AdmissionSHA256!=admissionSHA{return errors.New("provisional admission differs from consumed authorization")}
 return verifyFreshReservationNative(ctx,root,receipt)
}

func persistFreshActivationProvisionalUnderLease(ctx context.Context,root string,pending freshRecoveryPending,admissionSHA string,before freshBootIdentity,observe func(context.Context)(freshBootIdentity,error))error{
 if ctx==nil||observe==nil{return errors.New("missing independent boot observer")}
 if err:=verifyFreshRecoveryPendingUnderLease(ctx,root,pending);err!=nil{return err}
 if err:=verifyFreshProvisionalConsumptionUnderLease(ctx,root,pending.Evidence,admissionSHA);err!=nil{return err}
 if err:=requireFreshDNSRestoredAbsent(ctx,root);err!=nil{return err}
 current,err:=observe(ctx)
 if err!=nil||current!=before{return errors.New("Windows boot identity changed during activation")}
 receipt,err:=expectedFreshActivationProvisional(pending,admissionSHA,before);if err!=nil{return err}
 encoded,err:=json.Marshal(receipt);if err!=nil{return err}
 check:=func(p string)error{return nativeDNSOriginalBackupACL(ctx,p)}
 if err:=ctx.Err();err!=nil{return err}
 if err:=residentCreate(filepath.Join(root,freshProvisionalName),encoded,func(p string)error{return nativeSealApprovedOriginalBackupNode(ctx,p)},check);err!=nil{return err}
 if err:=verifyFreshFixedRecordUnderLease(ctx,root,freshProvisionalName,receipt);err!=nil{return err}
 if err:=verifyFreshRecoveryPendingUnderLease(ctx,root,pending);err!=nil{return err}
 return verifyFreshProvisionalConsumptionUnderLease(ctx,root,pending.Evidence,admissionSHA)
}

// Reopen the signed rescue permit and exact protected provisional record
// under the native lease after a reboot. This is only a boot-evidence
// admission for later independent health checks, NOT a terminal outcome.
// Activation permission need not still be live after reboot.
func verifyFreshPostBootEvidenceUnderLease(ctx context.Context,root string,key ed25519.PublicKey,pins freshActivationEvidence,admissionSHA string,observe func(context.Context)(freshBootIdentity,error))(freshBootIdentity,error){
 var denied freshBootIdentity
 if ctx==nil||observe==nil{return denied,errors.New("missing independent boot observer")}
 permit,err:=loadFreshRecoveryPermitUnderLease(ctx,root,key,pins);if err!=nil{return denied,err}
 pending,err:=expectedFreshRecoveryPending(pins,permit);if err!=nil{return denied,err}
 if err:=verifyFreshRecoveryPendingUnderLease(ctx,root,pending);err!=nil{return denied,err}
 if err:=verifyFreshProvisionalConsumptionUnderLease(ctx,root,pins,admissionSHA);err!=nil{return denied,err}
 if err:=requireFreshDNSRestoredAbsent(ctx,root);err!=nil{return denied,err}
 data,err:=readFreshFixedRecordUnderLease(ctx,root,freshProvisionalName)
 if err!=nil{return denied,err}
 var saved freshActivationProvisional
 if err:=residentCanonical(data,&saved);err!=nil{return denied,err}
 expected,err:=expectedFreshActivationProvisional(pending,admissionSHA,saved.Boot)
 if err!=nil||saved!=expected{return denied,errors.New("provisional activation does not match trusted transaction")}
 if err:=verifyFreshFixedRecordUnderLease(ctx,root,freshProvisionalName,expected);err!=nil{return denied,err}
 current,err:=observe(ctx);if err!=nil{return denied,err}
 if err:=verifyFreshLaterBoot(saved.Boot,current);err!=nil{return denied,err}
 if err:=verifyFreshRecoveryPendingUnderLease(ctx,root,pending);err!=nil{return denied,err}
 if err:=verifyFreshProvisionalConsumptionUnderLease(ctx,root,pins,admissionSHA);err!=nil{return denied,err}
 if err:=requireFreshDNSRestoredAbsent(ctx,root);err!=nil{return denied,err}
 if err:=verifyFreshFixedRecordUnderLease(ctx,root,freshProvisionalName,expected);err!=nil{return denied,err}
 again,err:=observe(ctx)
 if err!=nil||again!=current{return denied,fmt.Errorf("Windows boot changed during independent observation: %w",errors.Join(err,errors.New("boot evidence refused")))}
 return current,ctx.Err()
}

type freshBootCommitGuard struct{
 *freshAdmissionGuard
 after func(context.Context)error
}
func(g *freshBootCommitGuard)CommitActive(ctx context.Context,pin string)error{
 if g==nil||g.freshAdmissionGuard==nil||g.after==nil{return errors.New("fresh provisional commit dependencies missing")}
 // Independent commit MUST retain the watchdog until post-boot proof.
 if err:=g.freshAdmissionGuard.CommitActive(ctx,pin);err!=nil{return err}
 if err:=g.freshAdmissionGuard.VerifyArmed(ctx,pin);err!=nil{return err}
 return g.after(ctx)
}


// Read-only diagnostics for the isolated VM reboot kit. Neither exported
// helper authorizes installation, recovery writes, or terminal completion.
// The preboot sample must be preserved independently by the operator.
func ObserveFreshWindowsBootReadOnly(ctx context.Context)([]byte,error){
 b,err:=observeFreshBootNative(ctx);if err!=nil{return nil,err}
 return json.Marshal(b)
}
func VerifyLaterFreshWindowsBootReadOnly(ctx context.Context,previous []byte)([]byte,error){
 if ctx==nil||len(previous)<2||len(previous)>2048{return nil,errors.New("bounded previous boot observation required")}
 var before freshBootIdentity
 if err:=residentCanonical(previous,&before);err!=nil{return nil,err}
 after,err:=observeFreshBootNative(ctx);if err!=nil{return nil,err}
 if err:=verifyFreshLaterBoot(before,after);err!=nil{return nil,err}
 return json.Marshal(after)
}


// Verify all live DNS families against the authenticated expected state.
// Reboot may legitimately change InterfaceIndex, so this read-only audit
// compares complete GUID/family coverage and exact static assignments.
// No arbitrary netsh writer or mutable backend is involved.
func verifyFreshActiveDNSCensus(records []DNSRestoreRecord,states []DNSServerState)error{
 if len(records)==0||len(records)!=len(states){return errors.New("postboot DNS family coverage differs from authenticated journal")}
 expected:=make(map[string]DNSServerState,len(records))
 for _,record:=range records{
  if err:=validDNSState(record.Expected);err!=nil{return err}
  if record.Expected.Mode!=DNSStatic||len(record.Expected.Servers)!=1||
   (record.Expected.Family==DNSIPv4&&record.Expected.Servers[0]!="127.0.0.1")||
   (record.Expected.Family==DNSIPv6&&record.Expected.Servers[0]!="::1"){
   return errors.New("postboot expected DNS is not exact local protection")
  }
  k:=windowsActivationFamilyKey(record.Expected.InterfaceGUID,record.Expected.Family)
  if _,exists:=expected[k];exists{return errors.New("duplicate authenticated DNS family")}
  expected[k]=record.Expected
 }
 for _,state:=range states{
  if err:=validDNSState(state);err!=nil{return err}
  k:=windowsActivationFamilyKey(state.InterfaceGUID,state.Family)
  want,exists:=expected[k]
  if !exists||!sameDNSState(state,want){return errors.New("postboot live DNS assignment differs from authenticated localhost state")}
  delete(expected,k)
 }
 if len(expected)!=0{return errors.New("postboot DNS family missing")}
 return nil
}

// Production-oriented read-only audit, not a product installation outcome.
// The privileged controller must independently pin the admission digest,
// policy baseline and actual signed motor identity. A separate signed
// staging proof binds the motor registration and the four catalog slots.
// Exact on-disk catalog verification is not an attestation of loaded rules.
// Actual permitted/blocked UDP, persistent TCP DNS and external TCP
// probes are mandatory. A successful
// audit does not disable rescue or grant authority to write terminal state.
func auditFreshPostBootHealthAsSYSTEM(ctx context.Context,root string,key ed25519.PublicKey,pins freshActivationEvidence,admissionSHA string,watchdog freshWatchdogTaskPin,policy WindowsDNSOverrideCensus,motor freshMotorRuntimePin,stageRaw,stageSig []byte)(freshBootIdentity,error){
 var denied freshBootIdentity
 if ctx==nil{return denied,errors.New("trusted postboot context required")}
 if err:=ctx.Err();err!=nil{return denied,err}
 if err:=VerifyWindowsCurrentSystemSIDReadOnly();err!=nil{return denied,err}
 if watchdog.Name!="VOLVE-FRESH-WATCHDOG"{return denied,errors.New("postboot audit requires exact production watchdog identity")}
 if err:=bindFreshWatchdogAdmission(pins,watchdog);err!=nil{return denied,err}
 key=append(ed25519.PublicKey(nil),key...)
 stage,err:=verifyFreshStagingProof(key,append([]byte(nil),stageRaw...),append([]byte(nil),stageSig...),pins,admissionSHA,motor)
 if err!=nil{return denied,err}
 release,err:=AcquireProtectedResidentTransitionLease(ctx)
 if err!=nil{return denied,err}
 defer release()
 first,err:=verifyFreshPostBootEvidenceUnderLease(ctx,root,key,pins,admissionSHA,observeFreshBootNative)
 if err!=nil{return denied,err}
 records,err:=ReadDNSOriginalBackupNativeWindows(ctx,filepath.Join(root,"legacy-engine-recovery"),pins.OriginalDNSJournalSHA256)
 if err!=nil{return denied,err}
 attest:=func()error{
  if err:=VerifyWindowsCurrentSystemSIDReadOnly();err!=nil{return err}
  if err:=verifyFreshWatchdogRegistrationNative(ctx,watchdog);err!=nil{return err}
  observed,err:=InspectWindowsDNSOverrideCensusReadOnly(ctx,DefaultWindowsReadOnlyPowerShell)
  if err!=nil{return err}
  if observed!=policy{return errors.New("postboot DNS override policy differs from trusted baseline")}
  census,err:=InspectWindowsDNSAssignmentProvenanceReadOnly(ctx,DefaultWindowsReadOnlyPowerShell)
  if err!=nil{return err}
  return verifyFreshActiveDNSCensus(records,census.States)
 }
 if err:=attest();err!=nil{return denied,err}
 running,err:=verifyFreshMotorRuntimeNative(ctx,pins,motor,first);if err!=nil{return denied,err}
 if err:=verifyFreshStagedCatalogNative(ctx,stage);err!=nil{return denied,err}
 if err:=probeFreshResidentNetworkHealth(ctx);err!=nil{return denied,err}
 if err:=verifyFreshStagedCatalogNative(ctx,stage);err!=nil{return denied,err}
 again,err:=verifyFreshMotorRuntimeNative(ctx,pins,motor,first);if err!=nil{return denied,err}
 if running.PID!=again.PID||running.CreatedUnixMilli!=again.CreatedUnixMilli{return denied,errors.New("motor process replaced during postboot health checks")}
 if err:=attest();err!=nil{return denied,err}
 final,err:=verifyFreshPostBootEvidenceUnderLease(ctx,root,key,pins,admissionSHA,observeFreshBootNative)
 if err!=nil||final!=first{return denied,errors.New("postboot protected transaction changed during health audit")}
 if err:=verifyFreshStagedCatalogNative(ctx,stage);err!=nil{return denied,err}
 // Reopen exact authenticated original backup after the health checks.
 if _,err:=ReadDNSOriginalBackupNativeWindows(ctx,filepath.Join(root,"legacy-engine-recovery"),pins.OriginalDNSJournalSHA256);err!=nil{return denied,err}
 if err:=attest();err!=nil{return denied,err}
 return final,ctx.Err()
}


// The motor task's XML and DACL are separately pinned by the trusted staging
// controller. They are not automatically authenticated by the existing nine
// admission pins. The executable digest MUST match the signed admission.
type freshMotorRuntimePin struct{
 Executable,WorkingDirectory,TaskXMLSHA256,TaskDaclSHA256 string
}
type freshMotorRuntimeObservation struct{
 PID uint32
 CreatedUnixMilli int64
 Path,CommandLine,OwnerSID string
 Endpoints []windowsFreshPort53Row
}
func verifyFreshMotorRuntimeObservation(pin freshMotorRuntimePin,got freshMotorRuntimeObservation,boot freshBootIdentity)error{
 if !validFreshBootIdentity(boot)||got.PID==0||got.CreatedUnixMilli<boot.BootUnixMilli||got.CreatedUnixMilli>time.Now().UnixMilli()||got.OwnerSID!="S-1-5-18"||!strings.EqualFold(got.Path,pin.Executable){return errors.New("fresh motor process identity or boot origin invalid")}
 if got.CommandLine!=pin.Executable+" --dns-service"&&got.CommandLine!="\""+pin.Executable+"\" --dns-service"{return errors.New("fresh motor command line mismatch")}
 if len(got.Endpoints)!=4{return errors.New("fresh motor requires exactly four host-wide DNS listeners")}
 want:=map[string]bool{"UDP|127.0.0.1":true,"UDP|::1":true,"TCP|127.0.0.1":true,"TCP|::1":true}
 for _,e:=range got.Endpoints{
  k:=e.Transport+"|"+e.Address
  if e.Port!=53||e.PID!=got.PID||!want[k]{return errors.New("foreign, duplicate or non-loopback DNS listener")}
  delete(want,k)
 }
 return nil
}

func observeFreshMotorRuntimeNative(ctx context.Context,pin freshMotorRuntimePin)(freshMotorRuntimeObservation,error){
 var denied freshMotorRuntimeObservation
 if ctx==nil||!filepath.IsAbs(pin.Executable)||filepath.Clean(pin.Executable)!=pin.Executable||strings.HasPrefix(pin.Executable,"\\\\"){return denied,errors.New("exact local motor executable required")}
 root:=os.Getenv("SystemRoot")
 if !filepath.IsAbs(root){return denied,errors.New("Windows system root unavailable")}
 ps:=filepath.Join(root,"System32","WindowsPowerShell","v1.0","powershell.exe")
 script:=`$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';
 $exe='`+strings.ReplaceAll(pin.Executable,"'","''")+`';
 $procs=@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {[string]$_.ExecutablePath -ieq $exe});
 if($procs.Count -ne 1){throw 'Expected exactly one motor process'};
 $p=$procs[0];$owner=Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid -ErrorAction Stop;
 if($owner.ReturnValue -ne 0){throw 'Cannot verify SYSTEM SID'};
 $rows=@(
 Get-NetTCPConnection -State Listen -ErrorAction Stop|Where-Object {$_.LocalPort -eq 53}|ForEach-Object {[pscustomobject]@{Transport='TCP';Address=[string]$_.LocalAddress;Port=53;PID=[uint32]$_.OwningProcess}}
 Get-NetUDPEndpoint -ErrorAction Stop|Where-Object {$_.LocalPort -eq 53}|ForEach-Object {[pscustomobject]@{Transport='UDP';Address=[string]$_.LocalAddress;Port=53;PID=[uint32]$_.OwningProcess}}
 );
 [pscustomobject]@{PID=[uint32]$p.ProcessId;CreatedUnixMilli=([DateTimeOffset]($p.CreationDate.ToUniversalTime())).ToUnixTimeMilliseconds();Path=[string]$p.ExecutablePath;CommandLine=[string]$p.CommandLine;OwnerSID=[string]$owner.Sid;Endpoints=$rows}|ConvertTo-Json -Compress -Depth 5`
 out,err:=exec.CommandContext(ctx,ps,"-NoLogo","-NoProfile","-NonInteractive","-Command",script).Output()
 if err!=nil||len(out)==0||len(out)>16384{return denied,errors.New("native motor runtime observation failed")}
 dec:=json.NewDecoder(bytes.NewReader(out));dec.DisallowUnknownFields()
 var got freshMotorRuntimeObservation
 if err:=dec.Decode(&got);err!=nil{return denied,err}
 var extra any
 if err:=dec.Decode(&extra);err!=io.EOF{return denied,errors.New("trailing motor observation")}
 return got,ctx.Err()
}

// Independent OS identity check. No task changes or process termination.
// Disk image hash does not prove loaded memory bytes or task ancestry.
// Catalog authority is still a separate authenticated dependency.
func verifyFreshMotorRuntimeNative(ctx context.Context,pins freshActivationEvidence,pin freshMotorRuntimePin,boot freshBootIdentity)(freshMotorRuntimeObservation,error){
 var denied freshMotorRuntimeObservation
 if ctx==nil{return denied,errors.New("motor identity context required")}
 if err:=validateFreshActivationEvidence(pins);err!=nil{return denied,err}
 if !filepath.IsAbs(pin.Executable)||filepath.Clean(pin.Executable)!=pin.Executable||strings.HasPrefix(pin.Executable,"\\\\")||!strings.EqualFold(filepath.Base(pin.Executable),"VOLVE_DNS_Motor_0_28_7.exe"){return denied,errors.New("unrecognized pinned 0.28.7 motor executable")}
 for _,v:=range []string{pin.TaskXMLSHA256,pin.TaskDaclSHA256}{if verifyCanonicalLowerSHA256(v)!=nil||v==strings.Repeat("0",64){return denied,errors.New("motor task trust pins missing")}}
 taskCheck:=func()error{
  t,err:=observeFreshWatchdogTaskNative(ctx,residentRunningTask);if err!=nil{return err}
  if t.Name!=residentRunningTask||t.TaskPath!="\\"||!(strings.EqualFold(t.Principal,"SYSTEM")||t.Principal=="S-1-5-18")||t.LogonType!="ServiceAccount"||t.RunLevel!="Highest"||!t.Enabled||t.State!="Running"||t.Actions!=1||t.ActionType!="MSFT_TaskExecAction"||!strings.EqualFold(t.Execute,pin.Executable)||t.Arguments!="--dns-service"||t.WorkingDirectory!=pin.WorkingDirectory||t.Triggers!=1||t.BootTriggers!=1||t.EnabledBootTriggers!=1||t.DefinitionSHA256!=pin.TaskXMLSHA256||t.SecurityDescriptorSHA256!=pin.TaskDaclSHA256{return errors.New("fresh SYSTEM motor task differs from independent registration pins")}
  return nil
 }
 check:=func(p string)error{return nativeDNSOriginalBackupACL(ctx,p)}
 fileCheck:=func()error{
  if err:=verifyOriginalHostsBackupNode(filepath.Dir(pin.Executable),true,check);err!=nil{return err}
  return verifyOriginalHostsBackupNode(pin.Executable,false,check)
 }
 if err:=taskCheck();err!=nil{return denied,err}
 if err:=fileCheck();err!=nil{return denied,err}
 first,err:=observeFreshMotorRuntimeNative(ctx,pin);if err!=nil{return denied,err}
 if err:=verifyFreshMotorRuntimeObservation(pin,first,boot);err!=nil{return denied,err}
 before,err:=os.Lstat(pin.Executable);if err!=nil||before.Size()<1||before.Size()>128<<20{return denied,errors.New("motor disk image size invalid")}
 file,err:=os.Open(pin.Executable);if err!=nil{return denied,err}
 opened,err:=file.Stat()
 if err!=nil||!os.SameFile(before,opened){file.Close();return denied,errors.New("motor disk image replaced")}
 h:=sha256.New()
 n,readErr:=io.Copy(h,io.LimitReader(file,(128<<20)+1));closeErr:=file.Close()
 if readErr!=nil||closeErr!=nil{return denied,errors.Join(readErr,closeErr)}
 if n!=before.Size()||hex.EncodeToString(h.Sum(nil))!=pins.MotorSHA256{return denied,errors.New("motor disk image differs from signed admission")}
 if err:=fileCheck();err!=nil{return denied,err}
 after,err:=os.Lstat(pin.Executable);if err!=nil||!os.SameFile(before,after)||before.Size()!=after.Size()||!before.ModTime().Equal(after.ModTime()){return denied,errors.New("motor disk identity changed")}
 if err:=taskCheck();err!=nil{return denied,err}
 second,err:=observeFreshMotorRuntimeNative(ctx,pin);if err!=nil{return denied,err}
 if err:=verifyFreshMotorRuntimeObservation(pin,second,boot);err!=nil{return denied,err}
 if first.PID!=second.PID||first.CreatedUnixMilli!=second.CreatedUnixMilli{return denied,errors.New("motor process replaced during identity verification")}
 return second,ctx.Err()
}


// Separate publisher scope, compatible with the existing nine-pin admission.
// The signed proof does not grant install, recovery, or permission to change
// feeds; it merely pins the staged state that the postboot audit must reopen.
var freshStageFeedNames=[4]string{"hagezi_gambling_full.txt","hagezi_gambling_medium.txt","stevenblack_gambling.txt","arkynx_gambling.txt"}
type freshStageFeed struct{
 Name string `json:"name"`
 Bytes int64 `json:"bytes"`
 SHA256 string `json:"sha256"`
}
type freshStagingProof struct{
 Schema int `json:"schema"`
 Scope string `json:"scope"`
 Evidence freshActivationEvidence `json:"evidence"`
 AdmissionSHA256 string `json:"admission_sha256"`
 Motor freshMotorRuntimePin `json:"motor"`
 InstallRoot string `json:"install_root"`
 Feeds [4]freshStageFeed `json:"feeds"`
}
func verifyFreshStagingProof(key ed25519.PublicKey,raw,sig []byte,pins freshActivationEvidence,admissionSHA string,motor freshMotorRuntimePin)(freshStagingProof,error){
 var denied freshStagingProof
 if err:=validateFreshActivationEvidence(pins);err!=nil{return denied,err}
 if verifyCanonicalLowerSHA256(admissionSHA)!=nil||admissionSHA==strings.Repeat("0",64){return denied,errors.New("missing consumed admission digest")}
 if len(raw)<2||len(raw)>16384||len(key)!=ed25519.PublicKeySize||len(sig)!=ed25519.SignatureSize||!ed25519.Verify(key,raw,sig){return denied,errors.New("fresh staging proof signature invalid")}
 var got freshStagingProof
 if err:=json.Unmarshal(raw,&got);err!=nil{return denied,err}
 canonical,err:=json.Marshal(got)
 if err!=nil||!bytes.Equal(raw,canonical){return denied,errors.New("fresh staging proof not canonical")}
 if got.Schema!=1||got.Scope!="volve-fresh-staged-motor-catalog-review-only-v1"||got.Evidence!=pins||got.AdmissionSHA256!=admissionSHA||got.Motor!=motor{return denied,errors.New("fresh staging proof transaction or motor mismatch")}
 if !filepath.IsAbs(got.InstallRoot)||filepath.Clean(got.InstallRoot)!=got.InstallRoot||strings.HasPrefix(got.InstallRoot,"\\\\")||
  !strings.EqualFold(motor.Executable,filepath.Join(got.InstallRoot,"motor-0.28.7","VOLVE_DNS_Motor_0_28_7.exe")){return denied,errors.New("staged catalog root does not match exact versioned motor")}
 for _,v:=range []string{motor.TaskXMLSHA256,motor.TaskDaclSHA256}{if verifyCanonicalLowerSHA256(v)!=nil||v==strings.Repeat("0",64){return denied,errors.New("staged motor task pins invalid")}}
 for i,feed:=range got.Feeds{
  if feed.Name!=freshStageFeedNames[i]{return denied,errors.New("missing or reordered staged catalog slot")}
  if feed.Bytes==0&&feed.SHA256==""&&i!=0{continue}
  if feed.Bytes<1||feed.Bytes>128<<20||verifyCanonicalLowerSHA256(feed.SHA256)!=nil||feed.SHA256==strings.Repeat("0",64){return denied,errors.New("invalid staged catalog digest or size")}
 }
 return got,nil
}

// Caller holds the protected transition lease and has verified the signed
// proof. Each of the four names read by the service feed reloader must be
// present with exact signed bytes or explicitly absent. Nothing is rewritten.
func verifyFreshStagedCatalogNative(ctx context.Context,stage freshStagingProof)error{
 if ctx==nil{return errors.New("catalog verification requires context")}
 catalog:=filepath.Join(stage.InstallRoot,"catalog")
 feeds:=filepath.Join(catalog,"feeds")
 check:=func(p string)error{return nativeDNSOriginalBackupACL(ctx,p)}
 directories:=[]string{stage.InstallRoot,catalog,feeds}
 dirIdentity:=make(map[string]os.FileInfo,len(directories))
 for _,dir:=range directories{
  if err:=verifyOriginalHostsBackupNode(dir,true,check);err!=nil{return err}
  info,err:=os.Lstat(dir);if err!=nil||!info.IsDir(){return errors.New("catalog directory identity unavailable")}
  dirIdentity[dir]=info
 }
 fileIdentity:=make(map[string]os.FileInfo,len(stage.Feeds))
 for _,feed:=range stage.Feeds{
  if err:=ctx.Err();err!=nil{return err}
  path:=filepath.Join(feeds,feed.Name)
  if feed.Bytes==0&&feed.SHA256==""{
   if _,err:=os.Lstat(path);!errors.Is(err,os.ErrNotExist){return errors.New("unsigned optional catalog appeared")}
   continue
  }
  if err:=verifyOriginalHostsBackupNode(path,false,check);err!=nil{return err}
  before,err:=os.Lstat(path)
  if err!=nil||before.Size()!=feed.Bytes{return errors.New("signed catalog size mismatch")}
  file,err:=os.Open(path);if err!=nil{return err}
  opened,err:=file.Stat()
  if err!=nil||!os.SameFile(before,opened){file.Close();return errors.New("catalog replaced before read")}
  h:=sha256.New()
  n,readErr:=io.Copy(h,io.LimitReader(file,feed.Bytes+1));closeErr:=file.Close()
  if readErr!=nil||closeErr!=nil{return errors.Join(readErr,closeErr)}
  if n!=feed.Bytes||hex.EncodeToString(h.Sum(nil))!=feed.SHA256{return errors.New("catalog differs from signed staged content")}
  if err:=verifyOriginalHostsBackupNode(path,false,check);err!=nil{return err}
  after,err:=os.Lstat(path)
  if err!=nil||!os.SameFile(before,after)||before.Size()!=after.Size()||!before.ModTime().Equal(after.ModTime()){return errors.New("catalog identity changed")}
  fileIdentity[path]=after
 }
 // Reobserve all slots, including absent optional files, after reading the
 // entire set. Individual checks alone can miss a later replacement.
 for _,feed:=range stage.Feeds{
  path:=filepath.Join(feeds,feed.Name)
  if old,ok:=fileIdentity[path];ok{
   if err:=verifyOriginalHostsBackupNode(path,false,check);err!=nil{return err}
   current,err:=os.Lstat(path)
   if err!=nil||!os.SameFile(old,current)||old.Size()!=current.Size()||!old.ModTime().Equal(current.ModTime()){return errors.New("catalog identity changed across complete census")}
  }else if _,err:=os.Lstat(path);!errors.Is(err,os.ErrNotExist){return errors.New("unsigned optional catalog appeared during complete census")}
 }
 for _,dir:=range directories{
  if err:=verifyOriginalHostsBackupNode(dir,true,check);err!=nil{return err}
  current,err:=os.Lstat(dir)
  if err!=nil||!os.SameFile(dirIdentity[dir],current){return errors.New("catalog directory replaced during complete census")}
 }
 return ctx.Err()
}
