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

func persistFreshActivationProvisionalUnderLease(ctx context.Context,root string,pending freshRecoveryPending,admissionSHA string,before freshBootIdentity,observe func(context.Context)(freshBootIdentity,error))error{
 if ctx==nil||observe==nil{return errors.New("missing independent boot observer")}
 if err:=verifyFreshRecoveryPendingUnderLease(ctx,root,pending);err!=nil{return err}
 if err:=requireFreshDNSRestoredAbsent(ctx,root);err!=nil{return err}
 current,err:=observe(ctx)
 if err!=nil||current!=before{return errors.New("Windows boot identity changed during activation")}
 receipt,err:=expectedFreshActivationProvisional(pending,admissionSHA,before);if err!=nil{return err}
 encoded,err:=json.Marshal(receipt);if err!=nil{return err}
 check:=func(p string)error{return nativeDNSOriginalBackupACL(ctx,p)}
 if err:=ctx.Err();err!=nil{return err}
 if err:=residentCreate(filepath.Join(root,freshProvisionalName),encoded,func(p string)error{return nativeSealApprovedOriginalBackupNode(ctx,p)},check);err!=nil{return err}
 return verifyFreshFixedRecordUnderLease(ctx,root,freshProvisionalName,receipt)
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
