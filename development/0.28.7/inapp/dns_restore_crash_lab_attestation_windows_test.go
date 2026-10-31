//go:build windows

package motorupdate

// EXPERIMENTAL CI-ONLY bridge from a crashed updater to the real durable
// resident journal and WindowsSealedDNSRecoveryAttestor. The disposable
// GitHub-hosted Hyper-V vNIC is the only permitted mutation target.
// The generated Ed25519 key is EPHEMERAL, not VOLVE's publisher key;
// filesystem verifier here rejects redirection but DOES NOT attest NTFS ACLs.
// A production controller must supply genuine publisher signature, ACL
// protection, SYSTEM token/failed motor evidence and reboot survival.
import (
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "strconv"
 "strings"
 "syscall"
 "testing"
 "time"
 "unsafe"
)

func windowsCrashLabFileProtection(root string)func(string)error {
 return func(path string)error{
  if !filepath.IsAbs(path){return errors.New("journal test path not absolute")}
  rel,err:=filepath.Rel(root,path)
  if err!=nil||rel=="."||rel==".."||strings.HasPrefix(rel,".."+string(filepath.Separator)){
   return errors.New("journal test path escaped disposable fixture")
  }
  info,err:=os.Lstat(path)
  if err!=nil{return err}
  if info.Mode()&os.ModeSymlink!=0||(!info.IsDir()&&!info.Mode().IsRegular()){
   return errors.New("journal fixture node is redirected or unusual")
  }
  return nil
 }
}

func windowsCrashLabPermitPayload(nonce,snapshotSHA string)[]byte {
 return []byte("VOLVE-CI-ONLY-DNS-CRASH-RESTORE:v1:"+nonce+":"+snapshotSHA)
}

func prepareWindowsCrashLabSeal(t *testing.T,root string,records []DNSRestoreRecord)map[string]string {
 t.Helper()
 parent:=filepath.Join(root,"legacy-engine-recovery")
 dir:=filepath.Join(parent,"motor-recovery-transaction")
 if err:=os.MkdirAll(dir,0700);err!=nil{t.Fatal(err)}
 protect:=windowsCrashLabFileProtection(root)
 initial:=ResidentRecoveryIntent{
  Schema:1,Component:"dns-engine-recovery-intent",
  Task:"VOLVE-DNS-SERVER-0270",LegacySHA256:strings.Repeat("a",64),
  TaskXMLSHA256:strings.Repeat("b",64),TargetSHA256:strings.Repeat("c",64),
  TargetVersion:"0.28.7",
 }
 intent,err:=ArmResidentRecoveryIntent(context.Background(),dir,initial,protect,protect)
 if err!=nil{t.Fatalf("could not create durable CI journal: %v",err)}
 snap:=WindowsSealedDNSRecoverySnapshot{
  Schema:1,Component:"volve-dns-restore-snapshot",
  IntentNonce:intent.Nonce,OriginalMotorSHA256:intent.LegacySHA256,
  CandidateMotorSHA256:intent.TargetSHA256,
  Records:cloneWindowsDNSRecoveryRecords(records),
 }
 raw,err:=json.Marshal(snap);if err!=nil{t.Fatal(err)}
 path:=filepath.Join(parent,WindowsDNSRecoverySnapshotName)
 f,err:=os.OpenFile(path,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
 if err!=nil{t.Fatal(err)}
 _,err=f.Write(raw)
 if err==nil{err=f.Sync()}
 closeErr:=f.Close()
 if err!=nil{t.Fatal(err)}
 if closeErr!=nil{t.Fatal(closeErr)}
 if err:=protect(path);err!=nil{t.Fatal(err)}
 digest:=sha256.Sum256(raw)
 pinned:=hex.EncodeToString(digest[:])
 public,private,err:=ed25519.GenerateKey(rand.Reader)
 if err!=nil{t.Fatal(err)}
 signature:=ed25519.Sign(private,windowsCrashLabPermitPayload(intent.Nonce,pinned))
 return map[string]string{
  "VOLVE_CI_DNS_RESIDENT_DIR":dir,
  "VOLVE_CI_DNS_SNAPSHOT_PATH":path,
  "VOLVE_CI_DNS_SNAPSHOT_SHA256":pinned,
  "VOLVE_CI_DNS_LAB_PUBKEY":base64.StdEncoding.EncodeToString(public),
  "VOLVE_CI_DNS_LAB_SIGNATURE":base64.StdEncoding.EncodeToString(signature),
 }
}

// Watcher owns the Windows process handle throughout all independent
// journal attestation and netsh writes. This closes the PID-reuse race that
// would exist if we reopened a name or a PID after the updater crashed.
type windowsCrashExitHandle struct {
 handle uintptr
 pid int
}
func newWindowsCrashExitHandle(pid int)(*windowsCrashExitHandle,error){
 if pid<1{return nil,errors.New("invalid failed updater PID")}
 const synchronize=0x00100000
 const limitedQuery=0x1000
 handle,_,err:=windowsCrashOpenProcess.Call(synchronize|limitedQuery,0,uintptr(pid))
 if handle==0{return nil,fmt.Errorf("cannot open pinned Windows updater process: %w",err)}
 return &windowsCrashExitHandle{handle:handle,pid:pid},nil
}
func (w *windowsCrashExitHandle) Close(){
 if w!=nil&&w.handle!=0{windowsCrashCloseHandle.Call(w.handle);w.handle=0}
}
func (w *windowsCrashExitHandle) VerifyCrashed(ctx context.Context)error{
 if err:=ctx.Err();err!=nil{return err}
 if w==nil||w.handle==0{return errors.New("updater handle closed")}
 state,_,err:=windowsCrashWaitForSingleObject.Call(w.handle,0)
 if uint32(state)!=windowsDNSWaitObject0{
  if uint32(state)==windowsDNSWaitTimeout{return errors.New("updater still running")}
  return fmt.Errorf("cannot prove pinned updater exited: %v",err)
 }
 var code uint32
 ok,_,err:=windowsCrashGetExitCodeProcess.Call(w.handle,uintptr(unsafe.Pointer(&code)))
 if ok==0{return fmt.Errorf("cannot read pinned updater exit: %w",err)}
 if code!=windowsLabUpdaterCrashExitCode{
  return fmt.Errorf("updater exited with wrong code: %d",code)
 }
 return nil
}
func (w *windowsCrashExitHandle) Wait(ctx context.Context)error{
 for{
  err:=w.VerifyCrashed(ctx)
  if err==nil{return nil}
  if ctx.Err()!=nil{return ctx.Err()}
  if err.Error()!="updater still running"{return err}
  time.Sleep(80*time.Millisecond)
 }
}

func windowsCrashLabAttestor(w *windowsCrashExitHandle)(WindowsSealedDNSRecoveryAttestor,error){
 journal:=os.Getenv("VOLVE_CI_DNS_RESIDENT_DIR")
 snapshot:=os.Getenv("VOLVE_CI_DNS_SNAPSHOT_PATH")
 pinned:=os.Getenv("VOLVE_CI_DNS_SNAPSHOT_SHA256")
 key,err:=base64.StdEncoding.Strict().DecodeString(os.Getenv("VOLVE_CI_DNS_LAB_PUBKEY"))
 if err!=nil||len(key)!=ed25519.PublicKeySize{return WindowsSealedDNSRecoveryAttestor{},errors.New("CI attestor has no valid ephemeral public key")}
 sig,err:=base64.StdEncoding.Strict().DecodeString(os.Getenv("VOLVE_CI_DNS_LAB_SIGNATURE"))
 if err!=nil||len(sig)!=ed25519.SignatureSize{return WindowsSealedDNSRecoveryAttestor{},errors.New("CI attestor has no valid ephemeral publisher proof")}
 if filepath.Base(journal)!="motor-recovery-transaction"||filepath.Dir(journal)!=filepath.Dir(snapshot){
  return WindowsSealedDNSRecoveryAttestor{},errors.New("lab journal and snapshot are not siblings")
 }
 root:=filepath.Dir(filepath.Dir(journal))
 protector:=windowsCrashLabFileProtection(root)
 return WindowsSealedDNSRecoveryAttestor{
  JournalDir:journal,SnapshotPath:snapshot,PinnedSnapshotSHA256:pinned,
  Protect:protector,
  VerifyPublisherPermit:func(ctx context.Context,intent ResidentRecoveryIntent)error{
   if err:=ctx.Err();err!=nil{return err}
   if !ed25519.Verify(ed25519.PublicKey(key),windowsCrashLabPermitPayload(intent.Nonce,pinned),sig){
    return errors.New("ephemeral CI signed recovery permit rejected")
   }
   return nil
  },
  VerifySYSTEMAndFailedMotor:func(ctx context.Context,intent ResidentRecoveryIntent)error{
   // CI ONLY: verify that the exact process handle genuinely exited 83.
   // A production implementation must additionally require LocalSystem SID,
   // failed motor/task identity and stopped listeners before every write.
   if intent.Task!="VOLVE-DNS-SERVER-0270"{return errors.New("wrong pending motor task")}
   return w.VerifyCrashed(ctx)
  },
 },nil
}

func TestWindowsCrashLabAttestationRejectsMissingSignatureAndPlan(t *testing.T){
 if os.Getenv("VOLVE_CI_DNS_RECOVERY_CHILD")!=""{t.Skip("helper process")}
 root:=t.TempDir()
 records:=windowsDNSCrashRecords("{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}")
 env:=prepareWindowsCrashLabSeal(t,root,records)
 // Do not enable real adapter mutations in this test.
 for k,v:=range env {t.Setenv(k,v)}
 t.Setenv("VOLVE_CI_DNS_LAB_PUBKEY","not-a-key")
 if _,err:=windowsCrashLabAttestor(nil);err==nil{t.Fatal("invalid publisher key accepted")}
 t.Setenv("VOLVE_CI_DNS_LAB_PUBKEY",env["VOLVE_CI_DNS_LAB_PUBKEY"])
 t.Setenv("VOLVE_CI_DNS_LAB_SIGNATURE","invalid")
 if _,err:=windowsCrashLabAttestor(nil);err==nil{t.Fatal("invalid publisher signature accepted")}
 t.Setenv("VOLVE_CI_DNS_LAB_SIGNATURE",env["VOLVE_CI_DNS_LAB_SIGNATURE"])
 t.Setenv("VOLVE_CI_DNS_SNAPSHOT_PATH",filepath.Join(root,"rogue-snapshot.json"))
 if _,err:=windowsCrashLabAttestor(nil);err==nil{t.Fatal("wrong snapshot location accepted")}
}

func WindowsCrashLabJournalState(ctx context.Context)(ResidentRecoveryJournalState,error){
 dir:=os.Getenv("VOLVE_CI_DNS_RESIDENT_DIR")
 if dir==""||!filepath.IsAbs(dir){return ResidentRecoveryJournalState{},errors.New("CI resident journal unset")}
 root:=filepath.Dir(filepath.Dir(dir))
 return InspectResidentRecoveryJournal(ctx,dir,windowsCrashLabFileProtection(root))
}

func windowsCrashLabFinishRecovered(ctx context.Context)error{
 state,err:=WindowsCrashLabJournalState(ctx)
 if err!=nil{return err}
 if state.Status!="recovery-required"{return errors.New("lab journal no longer pending")}
 dir:=os.Getenv("VOLVE_CI_DNS_RESIDENT_DIR")
 return FinishResidentRecoveryIntent(ctx,dir,"restored",
  windowsCrashLabFileProtection(filepath.Dir(filepath.Dir(dir))),
  windowsCrashLabFileProtection(filepath.Dir(filepath.Dir(dir))))
}

func windowsCrashLabNonce()string {return strconv.FormatInt(time.Now().UnixNano(),10)}

var _ = syscall.Errno(0)

func TestWindowsCrashLabAttestorRejectsJournalAndSignatureTamper(t *testing.T){
 root:=t.TempDir()
 records:=windowsDNSCrashRecords("{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}")
 env:=prepareWindowsCrashLabSeal(t,root,records)
 for key,value:=range env{t.Setenv(key,value)}
 ctx:=context.Background()
 a,err:=windowsCrashLabAttestor(nil)
 if err!=nil{t.Fatal(err)}
 // This isolated unit test uses a fake crashed-process callback ONLY to
 // exercise real signed snapshot + create-only journal data validation.
 a.VerifySYSTEMAndFailedMotor=func(context.Context,ResidentRecoveryIntent)error{return nil}
 if err:=a.Verify(ctx,records);err!=nil{t.Fatalf("untampered signed journal rejected: %v",err)}
 wrong:=cloneWindowsDNSRecoveryRecords(records)
 wrong[0].Original.Servers[0]="8.8.8.8"
 if err:=a.Verify(ctx,wrong);err==nil{t.Fatal("changed source DNS accepted")}
 signed:=a.VerifyPublisherPermit
 a.VerifyPublisherPermit=func(ctx context.Context,intent ResidentRecoveryIntent)error{
  intent.Nonce=strings.Repeat("d",32)
  return signed(ctx,intent)
 }
 if err:=a.Verify(ctx,records);err==nil{t.Fatal("publisher signature accepted with changed journal nonce")}
 a.VerifyPublisherPermit=signed
 raw,err:=os.ReadFile(env["VOLVE_CI_DNS_SNAPSHOT_PATH"])
 if err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(env["VOLVE_CI_DNS_SNAPSHOT_PATH"],[]byte("{}"),0600);err!=nil{t.Fatal(err)}
 if err:=a.Verify(ctx,records);err==nil{t.Fatal("changed snapshot content accepted")}
 if err:=os.WriteFile(env["VOLVE_CI_DNS_SNAPSHOT_PATH"],raw,0600);err!=nil{t.Fatal(err)}
 if err:=windowsCrashLabFinishRecovered(ctx);err!=nil{t.Fatal(err)}
 if err:=a.Verify(ctx,records);err==nil{t.Fatal("already finalized resident journal authorized another DNS write")}
}
