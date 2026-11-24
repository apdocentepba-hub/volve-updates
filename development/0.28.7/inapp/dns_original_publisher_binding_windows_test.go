//go:build windows

package motorupdate

import (
 "bytes"
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "testing"
 "time"
)

func signedDNSBindingFixture(t *testing.T,f signedRecoveryFixture,pin string)([]byte,[]byte){
 t.Helper()
 state,err:=InspectResidentRecoveryJournal(context.Background(),f.journal,func(string)error{return nil})
 if err!=nil||state.Status!="recovery-required"{t.Fatalf("no armed CI resident transaction: %v",err)}
 permitHash:=sha256.Sum256(f.permit)
 binding:=SignedDNSOriginalBinding{
  Schema:1,Component:signedDNSReceiptComponent,
  IntentNonce:state.Intent.Nonce,LegacyMotorSHA256:state.Intent.LegacySHA256,
  LegacyTaskXMLSHA256:state.Intent.TaskXMLSHA256,
  TargetMotorSHA256:state.Intent.TargetSHA256,
  TargetMotorVersion:state.Intent.TargetVersion,
  SignedMigrationPermitSHA256:hex.EncodeToString(permitHash[:]),
  OriginalDNSJournalSHA256:pin,
 }
 raw,err:=json.Marshal(binding)
 if err!=nil{t.Fatal(err)}
 return raw,[]byte(base64.StdEncoding.EncodeToString(ed25519.Sign(f.priv,raw)))
}

func TestSignedDNSBindingRejectsReplayedNonceMotorTaskPermitAndBackup(t *testing.T){
 f:=makeSignedRecoveryFixture(t,false)
 _,_,pin:=makeStagedDNSFixture(t)
 raw,sig:=signedDNSBindingFixture(t,f,pin)
 state,err:=InspectResidentRecoveryJournal(context.Background(),f.journal,func(string)error{return nil})
 if err!=nil{t.Fatal(err)}
 if _,err:=VerifySignedDNSOriginalBinding(context.Background(),raw,sig,f.pub,state.Intent,f.permit);err!=nil{
  t.Fatalf("valid editor binding rejected: %v",err)
 }
 var original SignedDNSOriginalBinding
 if err:=json.Unmarshal(raw,&original);err!=nil{t.Fatal(err)}
 for _,tc:=range []struct{
  name string
  apply func(*SignedDNSOriginalBinding)
 }{
  {"other-nonce",func(b *SignedDNSOriginalBinding){b.IntentNonce=strings.Repeat("0",32)}},
  {"old-motor",func(b *SignedDNSOriginalBinding){b.LegacyMotorSHA256=strings.Repeat("1",64)}},
  {"task-xml",func(b *SignedDNSOriginalBinding){b.LegacyTaskXMLSHA256=strings.Repeat("2",64)}},
  {"target-motor",func(b *SignedDNSOriginalBinding){b.TargetMotorSHA256=strings.Repeat("3",64)}},
  {"target-version",func(b *SignedDNSOriginalBinding){b.TargetMotorVersion="0.28.8"}},
  {"signed-permit",func(b *SignedDNSOriginalBinding){b.SignedMigrationPermitSHA256=strings.Repeat("4",64)}},
  {"missing-dns-digest",func(b *SignedDNSOriginalBinding){b.OriginalDNSJournalSHA256=""}},
 } {
  t.Run(tc.name,func(t *testing.T){
   changed:=original
   tc.apply(&changed)
   changedRaw,err:=json.Marshal(changed)
   if err!=nil{t.Fatal(err)}
   changedSig:=[]byte(base64.StdEncoding.EncodeToString(ed25519.Sign(f.priv,changedRaw)))
   if _,err:=VerifySignedDNSOriginalBinding(context.Background(),changedRaw,changedSig,f.pub,state.Intent,f.permit);err==nil{
    t.Fatal("publisher-signed mismatched DNS receipt accepted for a different pending recovery")
   }
  })
 }
}

func TestSignedDNSBindingDeniesForgeryAndNonCanonicalPayload(t *testing.T){
 f:=makeSignedRecoveryFixture(t,false)
 _,_,pin:=makeStagedDNSFixture(t)
 raw,sig:=signedDNSBindingFixture(t,f,pin)
 state,err:=InspectResidentRecoveryJournal(context.Background(),f.journal,func(string)error{return nil})
 if err!=nil{t.Fatal(err)}
 otherPub,_,err:=ed25519.GenerateKey(rand.Reader)
 if err!=nil{t.Fatal(err)}
 forged:=append([]byte(nil),raw...)
 pos:=bytes.Index(forged,[]byte(pin))
 if pos<0{t.Fatal("signed original DNS digest absent")}
 forged[pos]='0'
 cases:=[]struct{name string;payload,signature []byte;key ed25519.PublicKey}{
  {"forged-payload",forged,sig,f.pub},
  {"wrong-publisher",raw,sig,otherPub},
  {"no-signature",raw,nil,f.pub},
  {"no-publisher-key",raw,sig,nil},
  {"trailing-json",append(append([]byte(nil),raw...),[]byte("{}")...),sig,f.pub},
 }
 for _,tc:=range cases{t.Run(tc.name,func(t *testing.T){
  if _,err:=VerifySignedDNSOriginalBinding(context.Background(),tc.payload,tc.signature,tc.key,state.Intent,f.permit);err==nil{
   t.Fatal("untrusted signed DNS receipt accepted")
  }
 })}
 pretty:=new(bytes.Buffer)
 if err:=json.Indent(pretty,raw,"","  ");err!=nil{t.Fatal(err)}
 prettySig:=[]byte(base64.StdEncoding.EncodeToString(ed25519.Sign(f.priv,pretty.Bytes())))
 if _,err:=VerifySignedDNSOriginalBinding(context.Background(),pretty.Bytes(),prettySig,f.pub,state.Intent,f.permit);err==nil{
  t.Fatal("noncanonical JSON accepted despite a syntactically valid Ed25519 signature")
 }
}

func TestSignedDNSBindingRejectsCancelledAndUnrelatedPermit(t *testing.T){
 f:=makeSignedRecoveryFixture(t,false)
 _,_,pin:=makeStagedDNSFixture(t)
 raw,sig:=signedDNSBindingFixture(t,f,pin)
 state,err:=InspectResidentRecoveryJournal(context.Background(),f.journal,func(string)error{return nil})
 if err!=nil{t.Fatal(err)}
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 if _,err:=VerifySignedDNSOriginalBinding(ctx,raw,sig,f.pub,state.Intent,f.permit);!errors.Is(err,context.Canceled){
  t.Fatalf("cancelled signed DNS binding admitted: %v",err)
 }
 if _,err:=VerifySignedDNSOriginalBinding(context.Background(),raw,sig,f.pub,state.Intent,[]byte("other permit"));err==nil{
  t.Fatal("DNS receipt accepted with different publisher permit bytes")
 }
}

func prepareNativeSignedDNSRecoveryLab(t *testing.T)(signedRecoveryFixture,string,[]byte,[]byte,string,context.Context){
 t.Helper()
 const guid="{12345678-1234-1234-1234-123456789abc}"
 return prepareNativeSignedDNSRecoveryLabWithOriginals(t,[]DNSServerState{
  {InterfaceGUID:guid,Family:DNSIPv6,Mode:DNSAutomatic},
  {InterfaceGUID:guid,Family:DNSIPv4,Mode:DNSStatic,Servers:[]string{"1.1.1.1","8.8.8.8"}},
 })
}

func prepareNativeSignedDNSRecoveryLabWithOriginals(t *testing.T,originals []DNSServerState)(signedRecoveryFixture,string,[]byte,[]byte,string,context.Context){
 t.Helper()
 ctx:=context.Background()
 f:=makeSignedRecoveryFixture(t,false)
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{
  t.Skip("real ACL/publisher/Win32 lock integration requires disposable Windows CI")
 }
 // Unlike earlier test doubles, EVERY persisted grant, journal and fallback
 // object is sealed using the exact native Windows SYSTEM/Admin SID policy.
 parent:=filepath.Join(f.root,"legacy-engine-recovery")
 for _,path:=range []string{f.root,parent,f.journal,f.backup}{
  if err:=sealDNSBackupLabNode(ctx,path);err!=nil{t.Fatalf("cannot seal recovery parent: %v",err)}
 }
 for _,dir:=range []string{f.journal,f.backup}{
  nodes,err:=os.ReadDir(dir)
  if err!=nil{t.Fatal(err)}
  for _,node:=range nodes{
   path:=filepath.Join(dir,node.Name())
   if node.IsDir(){t.Fatal("unexpected recursive CI recovery original")}
   if err:=sealDNSBackupLabNode(ctx,path);err!=nil{t.Fatalf("cannot seal fixture evidence: %v",err)}
  }
 }
 protect:=func(path string)error{return nativeDNSOriginalBackupACL(ctx,path)}
 seal:=func(path string)error{return sealDNSBackupLabNode(ctx,path)}
 if err:=PersistResidentDurablePublisherGrant(ctx,f.root,f.permit,f.sig,f.pub,
  seal,protect,protect,protect);err!=nil{t.Fatalf("cannot persist signed publisher grant under real ACL: %v",err)}
 raw,pin,err:=BuildDNSOriginalJournal(ctx,originals)
 if err!=nil{t.Fatal(err)}
 if report,err:=StoreDNSOriginalBackupNativeWindows(ctx,parent,raw,pin);err!=nil||
  !report.FileVerified{t.Fatalf("native sealed original DNS backup invalid: %v",err)}
 binding,signature:=signedDNSBindingFixture(t,f,pin)
 return f,parent,binding,signature,pin,ctx
}

func TestNativeSignedDNSOriginalReadOnlyReviewBindsPermitJournalAndDNS(t *testing.T){
 f,_,binding,signature,_,ctx:=prepareNativeSignedDNSRecoveryLab(t)
 review,err:=ReviewSignedDNSOriginalBackupNativeWindows(ctx,f.root,f.pub,binding,signature)
 if err!=nil{t.Fatal(err)}
 if !review.PublisherBindingVerified||!review.MotorAndTaskBindingVerified||
  !review.OriginalDNSReadbackVerified||!review.NativeNTFSACLVerified||
  !review.ProtectedKernelMutexHeld||review.ReviewedFamilies!=2||
  review.PerformedDNSWrites||review.InstallAuthorized||review.RestoreAuthorized{
  t.Fatalf("joined trust review unintentionally allowed real DNS writes: %+v",review)
 }
 // It must be callable again from an independently acquired Win32 thread
 // after releasing the first lease; no lock or descriptor may be cached.
 second,err:=ReviewSignedDNSOriginalBackupNativeWindows(ctx,f.root,f.pub,binding,signature)
 if err!=nil||second!=review{t.Fatalf("durable publisher/DNS evidence failed independent reopen: %v",err)}
 t.Log("PASS VOLVE_NATIVE_DNS_BACKUP_PUBLISHER_GRANT_NONCE_SIGNED_UNDER_WIN32_MUTEX_NO_WRITES")
}

func TestNativeSignedDNSOriginalReadOnlyReviewRejectsTamperBeforeApproval(t *testing.T){
 f,parent,binding,signature,_,ctx:=prepareNativeSignedDNSRecoveryLab(t)
 if _,err:=ReviewSignedDNSOriginalBackupNativeWindows(ctx,f.root,f.pub,binding,signature);err!=nil{t.Fatal(err)}
 file:=filepath.Join(parent,DNSOriginalBackupDirectoryName,DNSOriginalBackupFileName)
 out,err:=exec.CommandContext(ctx,"icacls.exe",file,"/grant","*S-1-1-0:W").CombinedOutput()
 if err!=nil{t.Fatalf("cannot weaken lab DNS backup ACL: %v %s",err,string(out))}
 if review,err:=ReviewSignedDNSOriginalBackupNativeWindows(ctx,f.root,f.pub,binding,signature);err==nil||
  review.PublisherBindingVerified||review.RestoreAuthorized{
  t.Fatal("tampered native backup ACL admitted into publisher-bound DNS review")
 }
}

func TestNativeSignedDNSOriginalReadOnlyReviewRejectsDifferentSignature(t *testing.T){
 f,_,binding,signature,_,ctx:=prepareNativeSignedDNSRecoveryLab(t)
 altered:=append([]byte(nil),signature...)
 altered[0]='X'
 if review,err:=ReviewSignedDNSOriginalBackupNativeWindows(ctx,f.root,f.pub,binding,altered);err==nil||
  review.PublisherBindingVerified||review.RestoreAuthorized{
  t.Fatal("modified signed DNS receipt accepted for a pending protected motor recovery")
 }
 state,err:=InspectResidentRecoveryJournal(ctx,f.journal,func(p string)error{return nativeDNSOriginalBackupACL(ctx,p)})
 if err!=nil||state.Status!="recovery-required"{
  t.Fatal("read-only signed-DNS review changed the pending recovery journal")
 }
}

func TestNativeSignedDNSOriginalReadOnlyReviewRejectsOtherWin32Lease(t *testing.T){
 f,_,binding,signature,_,ctx:=prepareNativeSignedDNSRecoveryLab(t)
 release,err:=AcquireProtectedResidentTransitionLease(ctx)
 if err!=nil{t.Fatal(err)}
 busy,done:=context.WithTimeout(ctx,140*time.Millisecond)
 defer done()
 review,err:=ReviewSignedDNSOriginalBackupNativeWindows(busy,f.root,f.pub,binding,signature)
 release()
 if !errors.Is(err,context.DeadlineExceeded)||review.PublisherBindingVerified{
  t.Fatalf("publisher DNS reviewer bypassed another protected Windows transaction: %v",err)
 }
}



// The production inventory reader deliberately refuses arbitrary queries.
// Keep the extra isolation check in this test-only fixed-command helper.
const nestedGuestDNSIsolationScript = `$ErrorActionPreference='Stop'; $cs=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop; if(($cs.Manufacturer+' '+$cs.Model) -notmatch '(?i)virtual machine|hyper-v'){throw 'Not a guest'}; $n=@(Get-NetAdapter -ErrorAction Stop); if($n.Count -ne 1 -or $n[0].Name -cne 'VOLVE-CI-PRIVATE-DNS' -or $n[0].Status -ne 'Up' -or $n[0].InterfaceDescription -notmatch '^Microsoft Hyper-V Network Adapter( #[0-9]+)?$'){throw 'Expected one dedicated private Hyper-V guest NIC'}; if(@(Get-NetRoute -ErrorAction Stop|Where-Object {$_.DestinationPrefix -in @('0.0.0.0/0','::/0')}).Count -ne 0){throw 'Default route exists'}; if(Get-ScheduledTask -TaskName 'VOLVE-DNS-SERVER-0270' -ErrorAction SilentlyContinue){throw 'Installed motor exists'}; $g='{'+([string]$n[0].InterfaceGuid).Trim('{}').ToLowerInvariant()+'}'; Write-Output $g`

func nestedGuestDNSIsolationReadOnly(ctx context.Context)([]byte,error){
 const guard=nestedGuestDNSIsolationScript
 if _,err:=DefaultWindowsReadOnlyPowerShell(ctx,guard);err==nil{
  return nil,errors.New("production inventory unexpectedly accepts lab-only command")
 }
 if err:=ctx.Err();err!=nil{return nil,err}
 root:=os.Getenv("SystemRoot")
 if !filepath.IsAbs(root)||strings.HasPrefix(root,`\\`){
  return nil,errors.New("trusted Windows SystemRoot unavailable")
 }
 exe:=filepath.Join(root,"System32","WindowsPowerShell","v1.0","powershell.exe")
 info,err:=os.Lstat(exe)
 if err!=nil||!info.Mode().IsRegular()||info.Mode()&os.ModeSymlink!=0{
  return nil,errors.New("pinned lab PowerShell executable unavailable")
 }
 return exec.CommandContext(ctx,exe,"-NoLogo","-NoProfile","-NonInteractive","-Command",guard).Output()
}

// Real native DNS recovery slice for a nested, disconnected CI guest. The
// controller must attach one PRIVATE Hyper-V switch (no host or uplink).
// Never enable this test on a user machine. It is not a product installer,
// real publisher key, motor-stop proof, connectivity proof or reboot test.
func TestNestedGuestSignedOriginalDNSNativeSYSTEM(t *testing.T){
 t.Helper()
 if os.Getenv("VOLVE_CI_NESTED_GUEST_DNS")!="PRIVATE_GUEST_ONLY"{t.Skip("explicit private nested guest required")}
 if os.Getenv("GITHUB_ACTIONS")!="true"||os.Getenv("RUNNER_ENVIRONMENT")!="github-hosted"{t.Fatal("not isolated CI")}
 if err:=VerifyWindowsCurrentSystemSIDReadOnly();err!=nil{t.Fatal(err)}
 // Native NTFS/PowerShell verification is intentionally expensive: the
 // durable-driver CI test alone previously took over four minutes.
 // Use one finite deadline for this isolated guest, not shorter per-stage
 // deadlines that can strand a partially exercised lab fixture.
 ctx,cancel:=context.WithTimeout(context.Background(),12*time.Minute)
 defer cancel()
 start:=time.Now()
 stage:=func(name string){t.Logf("VOLVE_GUEST_DNS_STAGE=%s elapsed_ms=%d",name,time.Since(start).Milliseconds())}
 stage("isolation")

 raw,err:=nestedGuestDNSIsolationReadOnly(ctx)
 if err!=nil{t.Fatalf("guest isolation guard: %v",err)}
 guid:=strings.TrimSpace(string(raw))
 if len(guid)!=38{t.Fatal("invalid pinned guest NIC identity")}
 stage("original-census")
 census,err:=InspectWindowsDNSAssignmentProvenanceReadOnly(ctx,DefaultWindowsReadOnlyPowerShell)
 if err!=nil{t.Fatalf("actual guest DNS provenance refused: %v",err)}
 if census.AdapterCount!=1||len(census.States)!=2||census.StaticFamilyCount!=1||census.AutomaticFamilyCount!=1{t.Fatal("expected exactly one static/one automatic DNS family")}
 for _,state:=range census.States{
  if state.InterfaceGUID!=guid{t.Fatal("foreign guest DNS adapter")}
  if state.Family==DNSIPv4&&(!sameDNSAddresses(state.Servers,[]string{"192.0.2.53","192.0.2.54"})||state.Mode!=DNSStatic){t.Fatal("unexpected original IPv4 lab DNS")}
  if state.Family==DNSIPv6&&state.Mode!=DNSAutomatic{t.Fatal("unexpected original IPv6 lab DNS")}
 }
 stage("seal-original")
 f,parent,binding,signature,pin,_:=prepareNativeSignedDNSRecoveryLabWithOriginals(t,census.States)
 records,err:=ReadDNSOriginalBackupNativeWindows(ctx,parent,pin)
 if err!=nil{t.Fatal(err)}
 stage("persist-binding")
 if err:=PersistSignedOriginalDNSEvidenceNativeWindows(ctx,f.root,f.pub,binding,signature);err!=nil{t.Fatal(err)}
 if err:=verifySignedDNSBootRestoreCensus(ctx,records,DefaultWindowsReadOnlyPowerShell,true);err!=nil{t.Fatal(err)}
 stage("fault-injection")
 // Fault injection is confined to the one positively identified guest NIC.
 // The native restoration entry must use its real signed evidence, NTFS ACL,
 // LocalSystem token, full census and Win32 mutex; never an injected writer.
 for _,record:=range records{
  observed,err:=nestedGuestDNSIsolationReadOnly(ctx)
  if err!=nil||strings.TrimSpace(string(observed))!=guid{t.Fatal("guest isolation changed before fault injection")}
  idx,err:=FindWindowsAdapterIndex(ctx,guid,DefaultWindowsReadOnlyPowerShell)
  if err!=nil{t.Fatal(err)}
  cmds,err:=PlanWindowsDNSRestore(record.Expected,idx)
  if err!=nil{t.Fatal(err)}
  for _,cmd:=range cmds{if err:=runPinnedWindowsNativeDNS(ctx,cmd.Args);err!=nil{t.Fatal(err)}}
 }
 stage("verify-fault")
 broken,err:=InspectWindowsDNSAssignmentProvenanceReadOnly(ctx,DefaultWindowsReadOnlyPowerShell)
 if err!=nil{t.Fatal(err)}
 if broken.AdapterCount!=1||broken.StaticFamilyCount!=2||len(broken.States)!=2{t.Fatal("dual-stack loopback fault not proven")}
 for _,record:=range records{
  found:=false
  for _,state:=range broken.States{if sameDNSState(state,record.Expected){found=true}}
  if !found{t.Fatal("expected actual loopback DNS state missing")}
 }
 stage("native-system-restore")
 if err:=restorePersistedSignedOriginalDNSAsSYSTEM(ctx,f.root,f.pub);err!=nil{t.Fatalf("real native SYSTEM restoration: %v",err)}
 if err:=verifySignedDNSBootRestoreCensus(ctx,records,DefaultWindowsReadOnlyPowerShell,true);err!=nil{t.Fatal(err)}
 after,err:=InspectWindowsDNSAssignmentProvenanceReadOnly(ctx,DefaultWindowsReadOnlyPowerShell)
 if err!=nil||after.SHA256!=census.SHA256{t.Fatal("original DNS provenance digest mismatch")}
 stage("idempotence")
 if err:=restorePersistedSignedOriginalDNSAsSYSTEM(ctx,f.root,f.pub);err!=nil{t.Fatalf("idempotent restoration: %v",err)}
 if err:=verifySignedDNSBootRestoreCensus(ctx,records,DefaultWindowsReadOnlyPowerShell,true);err!=nil{t.Fatal(err)}
 pending,err:=InspectResidentRecoveryJournal(ctx,f.journal,func(p string)error{return nativeDNSOriginalBackupACL(ctx,p)})
 if err!=nil||pending.Status!="recovery-required"{t.Fatal("DNS-only recovery must not finalize motor transaction")}
 stage("verified")
 t.Log("PASS VOLVE_NESTED_GUEST_REAL_SIGNED_SYSTEM_DNS_STATIC_IPV4_AUTOMATIC_IPV6 NO_REAL_MOTOR NO_REBOOT_DNS NO_CONNECTIVITY_PROOF")
}


// A raw Go string can compile while containing malformed PowerShell. Parse
// the exact guard without executing it, independently of the private VM test.
// The parser uses the inbox Windows PowerShell binary, not a generated shell.
func TestNestedGuestDNSIsolationScriptParsesWithoutExecution(t *testing.T){
 ctx,cancel:=context.WithTimeout(context.Background(),30*time.Second)
 defer cancel()
 if strings.Contains(nestedGuestDNSIsolationScript,"func Test")||strings.Contains(nestedGuestDNSIsolationScript,"\n")||len(nestedGuestDNSIsolationScript)>2000{
  t.Fatal("nested guest isolation script contains unexpected embedded source")
 }
 for _,required:=range []string{"Get-NetAdapter","Get-NetRoute","Get-ScheduledTask","VOLVE-CI-PRIVATE-DNS","0.0.0.0/0","::/0","Microsoft Hyper-V Network Adapter( #[0-9]+)?$"}{
  if !strings.Contains(nestedGuestDNSIsolationScript,required){t.Fatalf("isolation guard missing %q",required)}
 }
 root:=os.Getenv("SystemRoot")
 if !filepath.IsAbs(root)||strings.HasPrefix(root,`\\`){t.Fatal("trusted Windows SystemRoot unavailable")}
 exe:=filepath.Join(root,"System32","WindowsPowerShell","v1.0","powershell.exe")
 path:=filepath.Join(t.TempDir(),"isolation-guard.ps1")
 if err:=os.WriteFile(path,[]byte(nestedGuestDNSIsolationScript),0600);err!=nil{t.Fatal(err)}
 const parse=`$ErrorActionPreference='Stop';$tokens=$null;$errors=$null;[void][System.Management.Automation.Language.Parser]::ParseFile($env:VOLVE_CI_PARSE_FILE,[ref]$tokens,[ref]$errors);if(@($errors).Count -ne 0){throw ($errors|Out-String)};Write-Output 'VOLVE_GUARD_PARSE_OK'`
 cmd:=exec.CommandContext(ctx,exe,"-NoLogo","-NoProfile","-NonInteractive","-Command",parse)
 cmd.Env=append(os.Environ(),"VOLVE_CI_PARSE_FILE="+path)
 out,err:=cmd.CombinedOutput()
 if err!=nil||strings.TrimSpace(string(out))!="VOLVE_GUARD_PARSE_OK"{t.Fatalf("Windows PowerShell guard parse failed: %v %s",err,out)}
}
