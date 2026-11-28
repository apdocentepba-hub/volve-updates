//go:build windows

package motorupdate

// Fresh-install one-use reservation, not a migration receipt. This
// private primitive requires an independently authenticated admission,
// actual protected recovery parent and a controller already holding
// the shared native lease. It creates no task and performs no DNS writes.
// An administrator who can delete the entire protected transaction tree
// is outside this primitive's replay threat model.
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
 "regexp"
 "path/filepath"
 "strings"
 "time"
)

const freshReservationName="fresh-activation-reserved.json"
type freshActivationReservation struct{
 Schema int `json:"schema"`
 Component string `json:"component"`
 Evidence freshActivationEvidence `json:"evidence"`
 AdmissionSHA256 string `json:"admission_sha256"`
 ReservedAtUnix int64 `json:"reserved_at_unix"`
}

// Independent reattestation must check actual protected original archives,
// owner approval and boot watchdog before the first durable reservation.
// Host readiness refers to the pre-staging snapshot, not to a host that
// already has its newly installed motor running. The trusted controller
// must independently verify all expected staging changes.
func reserveFreshActivationUnderHeldLease(ctx context.Context,root string,raw,sig []byte,key ed25519.PublicKey,pins freshActivationEvidence,host FreshMotorInstallEvidence,held *exclusiveDNSActivationGuard)(freshActivationReservation,error){
 var denied freshActivationReservation
 if ctx==nil||held==nil{return denied,errors.New("fresh admission requires protected lease")}
 if err:=ctx.Err();err!=nil{return denied,err}
 if !filepath.IsAbs(root)||filepath.Clean(root)!=root||strings.HasPrefix(root,string(filepath.Separator)+string(filepath.Separator))||filepath.Base(root)!=pins.TransactionID{return denied,errors.New("fresh activation requires exact local transaction directory")}
 if _,err:=originalRecoveryEvidencePath(root,pins.TransactionID);err!=nil{return denied,err}
 raw=append([]byte(nil),raw...);sig=append([]byte(nil),sig...);key=append(ed25519.PublicKey(nil),key...)
 verify:=func()(freshActivationAdmission,error){return verifyFreshActivationAdmission(ctx,raw,sig,key,pins,host,time.Now())}
 if _,err:=verify();err!=nil{return denied,err}
 if err:=held.VerifyArmed(ctx,pins.OriginalDNSJournalSHA256);err!=nil{return denied,err}
 check:=func(p string)error{return nativeDNSOriginalBackupACL(ctx,p)}
 if err:=verifyOriginalHostsBackupNode(root,true,check);err!=nil{return denied,err}
 // Match the archive review to the independent admission pin. This
 // historical evidence is necessary but never a sufficient watchdog proof.
 if err:=loadOriginalRecoveryReviewEvidenceUnarmed(ctx,root,pins.TransactionID,pins.OriginalReviewSHA256,check);err!=nil{return denied,err}
 admitted,err:=verify();if err!=nil{return denied,err}
 now:=time.Now()
 if !now.Before(time.Unix(admitted.ExpiresAtUnix,0)){return denied,errors.New("fresh activation admission expired")}
 digest:=sha256.Sum256(raw)
 receipt:=freshActivationReservation{1,"volve-fresh-activation-once-v1",pins,hex.EncodeToString(digest[:]),now.Unix()}
 encoded,err:=json.Marshal(receipt);if err!=nil{return denied,err}
 destination:=filepath.Join(root,freshReservationName)
 if err:=ctx.Err();err!=nil{return denied,err}
 file,err:=os.OpenFile(destination,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
 if err!=nil{return denied,err}
 n,writeErr:=file.Write(encoded)
 if writeErr==nil&&n!=len(encoded){writeErr=io.ErrShortWrite}
 if writeErr==nil{writeErr=file.Sync()}
 closeErr:=file.Close()
 if writeErr!=nil||closeErr!=nil{return denied,errors.Join(writeErr,closeErr)}
 // Never remove or reuse the marker, even if sealing/readback fails.
 if err:=nativeSealApprovedOriginalBackupNode(ctx,destination);err!=nil{return denied,err}
 before,err:=os.Lstat(destination);if err!=nil{return denied,err}
 if err:=verifyOriginalHostsBackupNode(destination,false,check);err!=nil{return denied,err}
 got,err:=os.ReadFile(destination)
 if err!=nil||!bytes.Equal(encoded,got){return denied,errors.New("fresh reservation readback mismatch")}
 after,err:=os.Lstat(destination)
 if err!=nil||!os.SameFile(before,after)||before.Size()!=after.Size()||!before.ModTime().Equal(after.ModTime()){return denied,errors.New("fresh reservation identity changed")}
 if err:=verifyOriginalHostsBackupNode(root,true,check);err!=nil{return denied,err}
 if err:=held.VerifyArmed(ctx,pins.OriginalDNSJournalSHA256);err!=nil{return denied,err}
 if _,err:=verify();err!=nil{return denied,err}
 return receipt,nil
}


// Reopen the exact consumed marker, not a newly supplied or reconstructed
// authorization. Native ACL and identity checks surround bounded readback.
// A missing, partial or altered reservation is never treated as fresh.
func verifyFreshReservationNative(ctx context.Context,root string,expected freshActivationReservation)error{
 if ctx==nil{return errors.New("fresh reservation verification requires context")}
 if err:=ctx.Err();err!=nil{return err}
 if expected.Schema!=1||expected.Component!="volve-fresh-activation-once-v1"||expected.ReservedAtUnix<=0||verifyCanonicalLowerSHA256(expected.AdmissionSHA256)!=nil{return errors.New("missing independent fresh reservation receipt")}
 if err:=validateFreshActivationEvidence(expected.Evidence);err!=nil{return err}
 if _,err:=originalRecoveryEvidencePath(root,expected.Evidence.TransactionID);err!=nil{return err}
 check:=func(p string)error{return nativeDNSOriginalBackupACL(ctx,p)}
 path:=filepath.Join(root,freshReservationName)
 verify:=func()error{
  if err:=verifyOriginalHostsBackupNode(root,true,check);err!=nil{return err}
  return verifyOriginalHostsBackupNode(path,false,check)
 }
 if err:=verify();err!=nil{return err}
 before,err:=os.Lstat(path)
 if err!=nil||!before.Mode().IsRegular()||before.Size()<2||before.Size()>4096{return errors.New("fresh reservation invalid type or length")}
 file,err:=os.Open(path);if err!=nil{return err}
 opened,err:=file.Stat()
 if err!=nil||!os.SameFile(before,opened){file.Close();return errors.New("fresh reservation replaced before read")}
 data,readErr:=io.ReadAll(io.LimitReader(file,4097))
 closeErr:=file.Close()
 if readErr!=nil||closeErr!=nil{return errors.Join(readErr,closeErr)}
 canonical,err:=json.Marshal(expected)
 if err!=nil||int64(len(data))!=before.Size()||!bytes.Equal(data,canonical){return errors.New("fresh reservation differs from independent consumed receipt")}
 if err:=verify();err!=nil{return err}
 after,err:=os.Lstat(path)
 if err!=nil||!os.SameFile(before,after)||before.Size()!=after.Size()||!before.ModTime().Equal(after.ModTime()){return errors.New("fresh reservation changed during verification")}
 return ctx.Err()
}

// This private controller joins the previously isolated fresh admission,
// signed original archives and durable reservation to the existing DNS
// transaction coordinator. No product entrypoint calls it yet. The caller
// must supply an independently authenticated actual SYSTEM watchdog guard,
// trusted host observations and native backend; the CI test supplies memory
// DNS and a simulated guard. The native mutex itself is not simulated.
type freshAdmissionGuard struct{
 inner DNSActivationSafetyGuard
 verify func(context.Context,string)error
 review func(context.Context)error
}
func(g *freshAdmissionGuard)VerifyArmed(ctx context.Context,pin string)error{
 if err:=g.verify(ctx,pin);err!=nil{return err}
 if err:=g.inner.VerifyArmed(ctx,pin);err!=nil{return err}
 return g.verify(ctx,pin)
}
func(g *freshAdmissionGuard)VerifyLiveProtection(ctx context.Context,pin string)error{
 if err:=g.verify(ctx,pin);err!=nil{return err}
 if err:=g.inner.VerifyLiveProtection(ctx,pin);err!=nil{return err}
 return g.verify(ctx,pin)
}
func(g *freshAdmissionGuard)CommitActive(ctx context.Context,pin string)error{
 if err:=g.verify(ctx,pin);err!=nil{return err}
 if err:=g.review(ctx);err!=nil{return err}
 if err:=g.VerifyArmed(ctx,pin);err!=nil{return err}
 return g.inner.CommitActive(ctx,pin)
}
func(g *freshAdmissionGuard)RecoverIndependently(ctx context.Context,pin string)error{
 // Expired admission or damaged review must not suppress emergency rescue.
 return g.inner.RecoverIndependently(ctx,pin)
}

func activateFreshDNSUnderProtectedLease(ctx context.Context,root string,raw,sig []byte,key ed25519.PublicKey,pins freshActivationEvidence,host FreshMotorInstallEvidence,baseline ProtectionSnapshot,browser WindowsBrowserPolicyEvidence,inventory WindowsFreshVOLVETaskInventory,originalJournal []byte,inner DNSActivationSafetyGuard,factory dnsActivationBackendFactory)error{
 if ctx==nil||inner==nil||factory==nil{return errors.New("fresh controller missing context, independent watchdog or backend")}
 raw=append([]byte(nil),raw...);sig=append([]byte(nil),sig...);key=append(ed25519.PublicKey(nil),key...)
 originalJournal=append([]byte(nil),originalJournal...)
 if _,err:=verifyFreshActivationAdmission(ctx,raw,sig,key,pins,host,time.Now());err!=nil{return err}
 if inventory.VOLVETaskCount!=0||inventory.VerifiedCatalogTask!=nil||len(inventory.UnknownTaskNames)!=0{return errors.New("fresh controller requires absence of original VOLVE tasks")}
 reviewPin,err:=originalRecoveryReviewPin(pins.TransactionID,baseline,pins.OriginalDNSJournalSHA256)
 if err!=nil||reviewPin!=pins.OriginalReviewSHA256{return errors.New("fresh admission not bound to original protection census")}
 records,err:=VerifyDNSOriginalJournal(ctx,originalJournal,pins.OriginalDNSJournalSHA256)
 if err!=nil{return err}
 review:=func(c context.Context)error{
  r,err:=inspectPersistedSignedReviewUnderLease(c,root,pins.TransactionID,key,baseline,browser,inventory,pins.OriginalDNSJournalSHA256)
  if err!=nil||r.Status!="SIGNED_BOUND_FOUR_ARCHIVES_VERIFIED_READ_ONLY"||!r.HostsVerified||r.BrowserKeysVerified!=3||!r.DNSBackupVerified||!r.CatalogBackupVerified||r.CompleteRecoverySnapshot||r.InstallAuthorized||r.RestoreAuthorized{return errors.New("fresh controller requires intact signed four-archive review")}
  return c.Err()
 }
 var consumed *freshActivationReservation
 guard:=&freshAdmissionGuard{inner:inner,review:review,verify:func(c context.Context,pin string)error{
  if pin!=pins.OriginalDNSJournalSHA256{return errors.New("fresh activation journal changed")}
  if _,err:=verifyFreshActivationAdmission(c,raw,sig,key,pins,host,time.Now());err!=nil{return err}
  if consumed!=nil{return verifyFreshReservationNative(c,root,*consumed)}
  return c.Err()
 }}
 return activateVOLVEDNSUnderProtectedLease(ctx,originalJournal,pins.OriginalDNSJournalSHA256,guard,AcquireProtectedResidentTransitionLease,func(c context.Context,held DNSActivationSafetyGuard)(DNSAdapterBackend,error){
  exclusive,ok:=held.(*exclusiveDNSActivationGuard)
  if !ok{return nil,errors.New("fresh controller lost shared native lease")}
  if err:=held.VerifyArmed(c,pins.OriginalDNSJournalSHA256);err!=nil{return nil,err}
  if err:=review(c);err!=nil{return nil,err}
  // Refuse replays before calling even the read-only backend factory.
  if _,err:=os.Lstat(filepath.Join(root,freshReservationName));!errors.Is(err,os.ErrNotExist){return nil,errors.New("fresh activation reservation already exists or is inaccessible")}
  backend,err:=factory(c,held)
  if err!=nil||backend==nil{return nil,errors.New("fresh controller backend unavailable")}
  if err:=verifyDNSActivationTransition(c,records,backend,0);err!=nil{return nil,err}
  receipt,err:=reserveFreshActivationUnderHeldLease(c,root,raw,sig,key,pins,host,exclusive)
  if err!=nil{return nil,err}
  consumed=&receipt
  if err:=verifyFreshReservationNative(c,root,receipt);err!=nil{return nil,err}
  return backend,nil
 })
}


// Read-only native watchdog registration attestation. It is NOT a proof of
// watchdog liveness, recovery authorization, or successful restoration.
// The future SYSTEM controller must independently pin these identities in
// its signed, durable recovery evidence. No production task is created here.
type freshWatchdogTaskObservation struct{
 Name string
 TaskPath string
 Principal string
 LogonType string
 RunLevel string
 State string
 Enabled bool
 Actions int
 ActionType string
 Execute string
 Arguments string
 WorkingDirectory string
 Triggers int
 BootTriggers int
 EnabledBootTriggers int
 DefinitionSHA256 string
 SecurityDescriptorSHA256 string
}
type freshWatchdogTaskPin struct{
 Name string
 Executable string
 Arguments string
 WorkingDirectory string
 ExecutableSHA256 string
 DefinitionSHA256 string
 SecurityDescriptorSHA256 string
}
var freshWatchdogLabName=regexp.MustCompile(`^VOLVE-CI-FreshWatchdog-[0-9]{12,20}$`)
func allowedFreshWatchdogName(name string)bool{
 return name=="VOLVE-FRESH-WATCHDOG"||(freshWatchdogLabName.MatchString(name)&&os.Getenv("GITHUB_ACTIONS")=="true"&&os.Getenv("RUNNER_ENVIRONMENT")=="github-hosted")
}

func observeFreshWatchdogTaskNative(ctx context.Context,name string)(freshWatchdogTaskObservation,error){
 var denied freshWatchdogTaskObservation
 if ctx==nil||!allowedFreshWatchdogName(name){return denied,errors.New("untrusted fresh watchdog task name")}
 if err:=ctx.Err();err!=nil{return denied,err}
 root:=os.Getenv("SystemRoot")
 if !filepath.IsAbs(root)||strings.HasPrefix(root,string(filepath.Separator)+string(filepath.Separator)){return denied,errors.New("Windows system root unavailable")}
 ps:=filepath.Join(root,"System32","WindowsPowerShell","v1.0","powershell.exe")
 script:=`$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$n='`+name+`';
 $tasks=@(Get-ScheduledTask -TaskPath '\' -TaskName $n -ErrorAction Stop);
 if($tasks.Count -ne 1){throw 'Watchdog task identity not unique'};
 $t=$tasks[0];
 $actions=@($t.Actions);$triggers=@($t.Triggers);
 $boot=@($triggers|Where-Object {$_.CimClass.CimClassName -eq 'MSFT_TaskBootTrigger'});
 $enabledBoot=@($boot|Where-Object {$_.Enabled -eq $true});
 if($actions.Count -ne 1){throw 'Watchdog must have one action'};
 $xml=Export-ScheduledTask -TaskPath '\' -TaskName $n -ErrorAction Stop;
 $svc=New-Object -ComObject 'Schedule.Service';$svc.Connect();
 $rt=$svc.GetFolder('\').GetTask($n);
 $sd=[string]$rt.GetSecurityDescriptor(7);
 if([string]::IsNullOrWhiteSpace($sd)){throw 'Missing watchdog security descriptor'};
 $h=[Security.Cryptography.SHA256]::Create();
 try {
 $xmlHash=[BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$xml))).Replace('-','').ToLowerInvariant();
 $sdHash=[BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($sd))).Replace('-','').ToLowerInvariant();
 }finally{$h.Dispose()};
 [pscustomobject]@{
 Name=[string]$t.TaskName;TaskPath=[string]$t.TaskPath;Principal=[string]$t.Principal.UserId;
 LogonType=[string]$t.Principal.LogonType;RunLevel=[string]$t.Principal.RunLevel;State=[string]$t.State;
 Enabled=[bool]$t.Settings.Enabled;Actions=[int]$actions.Count;ActionType=[string]$actions[0].CimClass.CimClassName;
 Execute=[string]$actions[0].Execute;Arguments=[string]$actions[0].Arguments;WorkingDirectory=[string]$actions[0].WorkingDirectory;
 Triggers=[int]$triggers.Count;BootTriggers=[int]$boot.Count;EnabledBootTriggers=[int]$enabledBoot.Count;
 DefinitionSHA256=$xmlHash;SecurityDescriptorSHA256=$sdHash
 }|ConvertTo-Json -Compress`
 out,err:=exec.CommandContext(ctx,ps,"-NoLogo","-NoProfile","-NonInteractive","-Command",script).Output()
 if err!=nil||len(out)==0||len(out)>16384{return denied,errors.New("native watchdog registration observation unavailable")}
 dec:=json.NewDecoder(bytes.NewReader(out));dec.DisallowUnknownFields()
 var got freshWatchdogTaskObservation
 if err:=dec.Decode(&got);err!=nil{return denied,err}
 var extra any
 if err:=dec.Decode(&extra);err!=io.EOF{return denied,errors.New("trailing watchdog task observation")}
 return got,ctx.Err()
}

func verifyFreshWatchdogRegistrationNative(ctx context.Context,pin freshWatchdogTaskPin)error{
 if ctx==nil||!allowedFreshWatchdogName(pin.Name)||!filepath.IsAbs(pin.Executable)||filepath.Clean(pin.Executable)!=pin.Executable||strings.HasPrefix(pin.Executable,string(filepath.Separator)+string(filepath.Separator))||!strings.EqualFold(filepath.Base(pin.Executable),"VOLVE-FreshWatchdog.exe")||pin.Arguments==""{return errors.New("fresh watchdog requires exact independently pinned executable and command")}
 for _,v:=range []string{pin.ExecutableSHA256,pin.DefinitionSHA256,pin.SecurityDescriptorSHA256}{
  if verifyCanonicalLowerSHA256(v)!=nil||v==strings.Repeat("0",64){return errors.New("fresh watchdog digest missing")}
 }
 check:=func(p string)error{return nativeDNSOriginalBackupACL(ctx,p)}
 verifyFile:=func()error{
  if err:=verifyOriginalHostsBackupNode(filepath.Dir(pin.Executable),true,check);err!=nil{return err}
  return verifyOriginalHostsBackupNode(pin.Executable,false,check)
 }
 verifyTask:=func(t freshWatchdogTaskObservation)error{
  if t.Name!=pin.Name||t.TaskPath!="\\"||!(strings.EqualFold(t.Principal,"SYSTEM")||t.Principal=="S-1-5-18")||t.LogonType!="ServiceAccount"||t.RunLevel!="Highest"||!t.Enabled||(t.State!="Ready"&&t.State!="Running")||t.Actions!=1||t.ActionType!="MSFT_TaskExecAction"||!strings.EqualFold(t.Execute,pin.Executable)||t.Arguments!=pin.Arguments||t.WorkingDirectory!=pin.WorkingDirectory||t.Triggers!=1||t.BootTriggers!=1||t.EnabledBootTriggers!=1||t.DefinitionSHA256!=pin.DefinitionSHA256||t.SecurityDescriptorSHA256!=pin.SecurityDescriptorSHA256{return errors.New("fresh watchdog registration no longer matches trusted enabled SYSTEM boot identity")}
  return nil
 }
 first,err:=observeFreshWatchdogTaskNative(ctx,pin.Name)
 if err!=nil{return err}
 if err:=verifyTask(first);err!=nil{return err}
 if err:=verifyFile();err!=nil{return err}
 before,err:=os.Lstat(pin.Executable)
 if err!=nil||before.Size()<1||before.Size()>128<<20{return errors.New("fresh watchdog executable size invalid")}
 file,err:=os.Open(pin.Executable);if err!=nil{return err}
 opened,err:=file.Stat()
 if err!=nil||!os.SameFile(before,opened){file.Close();return errors.New("fresh watchdog executable replaced before read")}
 h:=sha256.New()
 n,readErr:=io.Copy(h,io.LimitReader(file,(128<<20)+1))
 closeErr:=file.Close()
 if readErr!=nil||closeErr!=nil{return errors.Join(readErr,closeErr)}
 if n!=before.Size()||hex.EncodeToString(h.Sum(nil))!=pin.ExecutableSHA256{return errors.New("fresh watchdog executable digest mismatch")}
 if err:=verifyFile();err!=nil{return err}
 after,err:=os.Lstat(pin.Executable)
 if err!=nil||!os.SameFile(before,after)||before.Size()!=after.Size()||!before.ModTime().Equal(after.ModTime()){return errors.New("fresh watchdog executable changed during verification")}
 second,err:=observeFreshWatchdogTaskNative(ctx,pin.Name)
 if err!=nil{return err}
 if err:=verifyTask(second);err!=nil{return err}
 return ctx.Err()
}


// Check that the watchdog registration pins are covered by the SAME signed
// fresh admission, not an independently substituted executable or DACL.
func bindFreshWatchdogAdmission(pins freshActivationEvidence,watchdog freshWatchdogTaskPin)error{
 if err:=validateFreshActivationEvidence(pins);err!=nil{return err}
 if watchdog.DefinitionSHA256!=pins.WatchdogTaskXMLSHA256||
  watchdog.ExecutableSHA256!=pins.WatchdogExecutableSHA256||
  watchdog.SecurityDescriptorSHA256!=pins.WatchdogSecurityDescriptorSHA256{
  return errors.New("fresh watchdog identity differs from signed admission")
 }
 return nil
}

// Private native adapter, deliberately no CLI or installation command.
// The independent guard MUST be the real authenticated boot recovery
// controller, including live readiness and durable commit/restore.
// Registration alone cannot satisfy that dependency. The original policy
// census must originate in the independently observed pre-staging state.
func activateFreshDNSAsSYSTEM(ctx context.Context,root string,raw,sig []byte,key ed25519.PublicKey,pins freshActivationEvidence,host FreshMotorInstallEvidence,baseline ProtectionSnapshot,browser WindowsBrowserPolicyEvidence,inventory WindowsFreshVOLVETaskInventory,originalJournal []byte,watchdog freshWatchdogTaskPin,expectedPolicy WindowsDNSOverrideCensus,independent DNSActivationSafetyGuard)error{
 if ctx==nil||independent==nil{return errors.New("fresh native activation requires independent authenticated recovery")}
 if err:=ctx.Err();err!=nil{return err}
 if err:=VerifyWindowsCurrentSystemSIDReadOnly();err!=nil{return errors.New("fresh native activation requires actual LocalSystem")}
 if watchdog.Name!="VOLVE-FRESH-WATCHDOG"{return errors.New("fresh native activation requires exact production watchdog identity")}
 if err:=bindFreshWatchdogAdmission(pins,watchdog);err!=nil{return err}
 // Detach once before closures retain the trusted evidence.
 raw=append([]byte(nil),raw...);sig=append([]byte(nil),sig...)
 key=append(ed25519.PublicKey(nil),key...);originalJournal=append([]byte(nil),originalJournal...)
 if _,err:=verifyFreshActivationAdmission(ctx,raw,sig,key,pins,host,time.Now());err!=nil{return err}
 // Native registration attestation and all-policy baseline comparison
 // are repeated inside the shared activation lease. Recovery is delegated
 // directly and must not be blocked by expiry or watchdog identity drift.
 policy:=&dnsActivationOverrideGuard{inner:independent,observe:func(c context.Context)(WindowsDNSOverrideCensus,error){
  return InspectWindowsDNSOverrideCensusReadOnly(c,DefaultWindowsReadOnlyPowerShell)
 }}
 var firstRescue *freshRecoveryEnvelope
 var pending *freshRecoveryPending
 native:=&freshAdmissionGuard{inner:independent,review:func(c context.Context)error{return c.Err()},verify:func(c context.Context,pin string)error{
  if pin!=pins.OriginalDNSJournalSHA256{return errors.New("fresh native original DNS pin mismatch")}
  if err:=VerifyWindowsCurrentSystemSIDReadOnly();err!=nil{return err}
  if err:=verifyFreshWatchdogRegistrationNative(c,watchdog);err!=nil{return err}
  // Require the distinct, durable rescue authorization BEFORE activation
  // and throughout the protected transition. Rescue itself never depends
  // on the activation permit or reservation remaining readable.
  rescue,err:=loadFreshRecoveryPermitUnderLease(c,root,key,pins)
  if err!=nil{return fmt.Errorf("fresh native activation lacks protected recovery permit: %w",err)}
  if firstRescue==nil{firstRescue=&rescue}else if !bytes.Equal(firstRescue.Payload,rescue.Payload)||!bytes.Equal(firstRescue.Signature,rescue.Signature){return errors.New("fresh recovery permit changed during activation")}
  if pending!=nil{if err:=verifyFreshRecoveryPendingUnderLease(c,root,*pending);err!=nil{return err}}
  if !policy.captured{
   if err:=policy.capture(c);err!=nil{return err}
   if policy.baseline!=expectedPolicy{return errors.New("fresh native DNS policy changed since original census")}
  }
  if policy.baseline!=expectedPolicy{return errors.New("fresh native DNS policy is not bound to original census")}
  return policy.check(c)
 }}
 return activateFreshDNSUnderProtectedLease(ctx,root,raw,sig,key,pins,host,baseline,browser,inventory,originalJournal,native,
  func(c context.Context,held DNSActivationSafetyGuard)(DNSAdapterBackend,error){
   backend,err:=newWindowsPinnedDNSActivationBackend(c,originalJournal,pins.OriginalDNSJournalSHA256,
    DefaultWindowsReadOnlyPowerShell,runPinnedWindowsNativeDNS,held)
   if err!=nil{return nil,err}
   exclusive,ok:=held.(*exclusiveDNSActivationGuard)
   if !ok{return nil,errors.New("fresh native pending arming lost shared lease")}
   // The coordinator has already reopened the signed four archives. Arm
   // rescue before spending the admission and before any actual DNS write.
   record,err:=armFreshRecoveryPendingUnderLease(c,root,key,pins,exclusive)
   if err!=nil{return nil,err}
   pending=&record
   return backend,nil
  })
}
