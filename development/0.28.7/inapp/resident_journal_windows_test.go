//go:build windows

package main

// Windows integration uses exclusively t.TempDir(), a dummy EXE identity,
// and a separate read-only watchdog binary. Never touches Windows DNS,
// production Task Scheduler, browser policies or installed VOLVE.
import (
    "context"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "os"
    "os/exec"
    "path/filepath"
    "strings"
    "testing"

    "volve-browser-protection/motorupdate"
)

func residentWindowsIntent() motorupdate.ResidentRecoveryIntent {
    digest:=func(x string)string{
        h:=sha256.Sum256([]byte(x))
        return hex.EncodeToString(h[:])
    }
    return motorupdate.ResidentRecoveryIntent{
        Schema:1,Component:"dns-engine-recovery-intent",
        Task:"VOLVE-DNS-SERVER-0270",
        LegacySHA256:digest("disposable old motor"),
        TaskXMLSHA256:digest("disposable task XML"),
        TargetSHA256:digest("disposable candidate"),
        TargetVersion:"0.28.7",
    }
}


// Test-only protected original executable and original SYSTEM-task snapshot.
// It uses bytes, not a real task or DNS engine.
func prepareDisposableResidentFallback(t *testing.T,root string) motorupdate.ResidentRecoveryIntent {
    t.Helper()
    parent,err:=ensureSecureLegacyRecoveryParent(root)
    if err!=nil{t.Fatal(err)}
    oldExe:=filepath.Join(root,dnsServiceFile)
    if err:=os.WriteFile(oldExe,[]byte("MZ-WINDOWS-CI-ORIGINAL-DNS-MOTOR-BYTES"),0600);err!=nil{t.Fatal(err)}
    xml:=[]byte(fmt.Sprintf("<?xml version=\"1.0\" encoding=\"UTF-16\"?>"+
        "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">"+
        "<Principals><Principal><UserId>S-1-5-18</UserId></Principal></Principals>"+
        "<Actions><Exec><Command>%s</Command><Arguments>--dns-service</Arguments></Exec></Actions></Task>",oldExe))
    record,err:=motorupdate.PrepareUnversionedLegacyRecoveryWithSealing(
        context.Background(),oldExe,xml,filepath.Join(parent,localRecoverySnapshot),
        checkSealedLegacyRecoveryACL,sealNewLegacyRecoveryNode)
    if err!=nil{t.Fatal(err)}
    intent:=residentWindowsIntent()
    intent.LegacySHA256=record.ExeSHA256
    intent.TaskXMLSHA256=record.XMLSHA256
    return intent
}

func TestWindowsResidentJournalPathAllowlist(t *testing.T) {
    root:=filepath.Join(os.Getenv("WINDIR"),"VOLVE-CI")
    parent:=filepath.Join(root,localRecoveryFolder)
    dir:=filepath.Join(parent,localRecoveryJournal)
    for _,p:=range []string{
        dir,filepath.Join(dir,motorupdate.ResidentIntentFile),
        filepath.Join(dir,motorupdate.ResidentResultFile),
    }{
        if !isNewResidentJournalNode(p){
            t.Fatalf("new recovery journal path rejected: %s",p)
        }
    }
    for _,p:=range []string{
        filepath.Join(parent,localRecoverySnapshot),
        filepath.Join(root,"VOLVE_DNS_Server_0270.exe"),
        filepath.Join(dir,"untrusted.ps1"),
        filepath.Join(root,"other",localRecoveryJournal,motorupdate.ResidentIntentFile),
        "relative"+string(os.PathSeparator)+localRecoveryJournal,
    }{
        if isNewResidentJournalNode(p){
            t.Fatalf("unrelated object could be sealed: %s",p)
        }
    }
}

func TestWindowsResidentJournalSetupAcceptedByIndependentWatchdog(t *testing.T) {
    if !isAdmin(){t.Skip("elevated Windows CI required")}
    helper:=os.Getenv("VOLVE_CI_MANAGED_WATCHDOG_EXE")
    if helper==""{t.Fatal("independent compiled watchdog required")}
    if fi,err:=os.Lstat(helper);err!=nil || !fi.Mode().IsRegular(){
        t.Fatalf("compiled Windows watchdog not found: %v",err)
    }
    root:=t.TempDir()
    intent:=prepareDisposableResidentFallback(t,root)
    dir,err:=ensureSecureResidentRecoveryJournalDir(root)
    if err!=nil{t.Fatal(err)}
    // Reopening an existing trusted directory never resets ownership/ACL.
    reopened,err:=ensureSecureResidentRecoveryJournalDir(root)
    if err!=nil || reopened!=dir{t.Fatalf("reopen of protected directory rejected: %v",err)}
    intended,err:=armPreparedResidentJournal(context.Background(),root,intent)
    if err!=nil{t.Fatal(err)}
    if intended.Nonce==""{t.Fatal("fresh intent has no nonce")}
    if err:=checkSealedResidentJournalACL(filepath.Join(dir,motorupdate.ResidentIntentFile));err!=nil{
        t.Fatalf("read-only ACL verifier rejected freshly sealed intent: %v",err)
    }
    cmd:=exec.Command(helper,"--audit-resident-journal",dir)
    out,err:=cmd.CombinedOutput()
    if err!=nil||!strings.Contains(string(out),"Estado: recovery-required"){
        t.Fatalf("independent watchdog did not accept journal from installed-code creator: %v %s",err,string(out))
    }
    // The same Windows writer seals an independently auditable final receipt.
    if err:=motorupdate.FinishResidentRecoveryIntent(context.Background(),dir,"restored",
        sealNewResidentJournalNode,checkSealedResidentJournalACL);err!=nil{t.Fatal(err)}
    cmd=exec.Command(helper,"--audit-resident-journal",dir)
    out,err=cmd.CombinedOutput()
    if err!=nil||!strings.Contains(string(out),"Estado: restored"){
        t.Fatalf("separate watchdog rejected final sealed receipt: %v %s",err,string(out))
    }
    if _,err:=armPreparedResidentJournal(context.Background(),root,residentWindowsIntent());err==nil{
        t.Fatal("sealed journal with final result was rearmed")
    }
}

func TestWindowsResidentJournalRejectsInsecureExistingDirectory(t *testing.T) {
    if !isAdmin(){t.Skip("elevated Windows CI required")}
    root:=t.TempDir()
    parent,err:=ensureSecureLegacyRecoveryParent(root)
    if err!=nil{t.Fatal(err)}
    untrusted:=filepath.Join(parent,localRecoveryJournal)
    if err:=os.Mkdir(untrusted,0700);err!=nil{t.Fatal(err)}
    // Force a deterministic untrusted WRITE ACE, regardless of the current
    // elevated runner's default Windows owner or inheritance policy.
    aclOutput,aclErr:=exec.Command("icacls.exe",untrusted,"/grant","*S-1-1-0:W").CombinedOutput()
    if aclErr!=nil{t.Fatalf("cannot create unsafe disposable ACL fixture: %v %s",aclErr,aclOutput)}
    // Existing unsafe NTFS directories must be rejected, not repaired.
    if _,err:=ensureSecureResidentRecoveryJournalDir(root);err==nil{
        t.Fatal("existing non-sealed recovery directory accepted")
    }
    if fi,err:=os.Lstat(untrusted);err!=nil||!fi.IsDir(){
        t.Fatal("unsafe existing directory was altered or removed")
    }
}

func TestWindowsResidentJournalRejectsWeakenedIntentACL(t *testing.T) {
    if !isAdmin(){t.Skip("elevated Windows CI required")}
    root:=t.TempDir()
    intent:=prepareDisposableResidentFallback(t,root)
    if _,err:=armPreparedResidentJournal(context.Background(),root,intent);err!=nil{
        t.Fatal(err)
    }
    dir:=filepath.Join(root,localRecoveryFolder,localRecoveryJournal)
    intentFile:=filepath.Join(dir,motorupdate.ResidentIntentFile)
    out,err:=exec.Command("icacls.exe",intentFile,"/grant","*S-1-1-0:W").CombinedOutput()
    if err!=nil{t.Fatalf("could not weaken disposable intent: %v %s",err,out)}
    if err:=checkSealedResidentJournalACL(intentFile);err==nil{
        t.Fatal("writable resident recovery intent considered secure")
    }
    if err:=motorupdate.FinishResidentRecoveryIntent(context.Background(),dir,
        "committed",sealNewResidentJournalNode,checkSealedResidentJournalACL);err==nil{
        t.Fatal("corrupted ACL permitted terminal success receipt")
    }
    if _,err:=os.Lstat(filepath.Join(dir,motorupdate.ResidentResultFile));!os.IsNotExist(err){
        t.Fatalf("unsafe journal published committed result: %v",err)
    }
}

func TestWindowsResidentJournalRequiresMatchingSealedBackupBeforeArming(t *testing.T){
    if !isAdmin(){t.Skip("elevated Windows CI required")}
    root:=t.TempDir()
    // Missing protected fallback must fail without creating a journal.
    if _,err:=armPreparedResidentJournal(context.Background(),root,residentWindowsIntent());err==nil{
        t.Fatal("journal armed without an original recovery snapshot")
    }
    intent:=prepareDisposableResidentFallback(t,root)
    for _,kind:=range []string{"wrong-old-exe","wrong-system-task"}{
        t.Run(kind,func(t *testing.T){
            invalid:=intent
            if kind=="wrong-old-exe"{invalid.LegacySHA256=strings.Repeat("0",64)
            }else{invalid.TaskXMLSHA256=strings.Repeat("0",64)}
            if _,err:=armPreparedResidentJournal(context.Background(),root,invalid);err==nil{
                t.Fatalf("journal for mismatched %s armed",kind)
            }
            dir:=filepath.Join(root,localRecoveryFolder,localRecoveryJournal)
            if _,err:=os.Lstat(dir);!os.IsNotExist(err){
                t.Fatalf("invalid journal created directory: %v",err)
            }
        })
    }
}
