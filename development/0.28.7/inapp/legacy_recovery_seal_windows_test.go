//go:build windows

package main

// Windows integration: actual new local snapshot creator -> separate compiled
// resident watchdog audit, with no task changes, DNS, network or registry.
import (
    "context"
    "fmt"
    "os"
    "os/exec"
    "path/filepath"
    "strings"
    "testing"

    "volve-browser-protection/motorupdate"
)

func TestSealedRecoveryPathAllowlist(t *testing.T) {
    root:=filepath.Join(os.Getenv("WINDIR"),"VOLVE-CI")
    parent:=filepath.Join(root,localRecoveryFolder)
    tmp:=filepath.Join(parent,".legacy-recovery-ci123")
    for _,p:=range []string{
        parent,tmp,
        filepath.Join(tmp,"VOLVE_DNS_Legacy_Recovery.exe"),
        filepath.Join(tmp,"VOLVE_DNS_Legacy_Task.xml"),
        filepath.Join(tmp,"VOLVE_DNS_Legacy_Recovery.json"),
    } {
        if !isNewLegacyRecoveryNode(p){t.Fatalf("fresh snapshot path unexpectedly refused: %s",p)}
    }
    for _,p:=range []string{
        filepath.Join(root,"VOLVE_DNS_Server_0270.exe"),
        filepath.Join(parent,localRecoverySnapshot),
        filepath.Join(root,"unrelated.txt"),
        filepath.Join(parent,".legacy-recovery-ci123","payload.ps1"),
        "relative/path",
    } {
        if isNewLegacyRecoveryNode(p){t.Fatalf("unrelated/existing recovery path would be mutable: %s",p)}
    }
}

func TestWindowsSealedLegacyBackupAcceptedByIndependentWatchdog(t *testing.T) {
    if !isAdmin(){t.Skip("elevated Windows CI required")}
    helper:=os.Getenv("VOLVE_CI_MANAGED_WATCHDOG_EXE")
    if helper==""{t.Fatal("standalone compiled watchdog required")}
    if stat,err:=os.Lstat(helper);err!=nil||!stat.Mode().IsRegular(){
        t.Fatalf("standalone watchdog executable unavailable: %v",err)
    }
    root:=t.TempDir()
    parent,err:=ensureSecureLegacyRecoveryParent(root)
    if err!=nil{t.Fatal(err)}
    exe:=filepath.Join(root,dnsServiceFile)
    if err:=os.WriteFile(exe,[]byte("MZ_CI_ONLY_NOT_A_REAL_DNS_SERVER"),0600);err!=nil{t.Fatal(err)}
    xml:=[]byte(fmt.Sprintf(
        "<?xml version=\"1.0\" encoding=\"UTF-16\"?>"+
        "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">"+
        "<RegistrationInfo><Author>VOLVE CI only</Author></RegistrationInfo>"+
        "<Principals><Principal id=\"Author\"><UserId>S-1-5-18</UserId></Principal></Principals>"+
        "<Actions Context=\"Author\"><Exec><Command>%s</Command><Arguments>--dns-service</Arguments></Exec></Actions></Task>",exe))
    target:=filepath.Join(parent,localRecoverySnapshot)
    record,err:=motorupdate.PrepareUnversionedLegacyRecoveryWithSealing(
        context.Background(),exe,xml,target,checkSealedLegacyRecoveryACL,sealNewLegacyRecoveryNode)
    if err!=nil{t.Fatal(err)}
    if _,err:=motorupdate.VerifyUnversionedLegacyRecovery(target,checkSealedLegacyRecoveryACL);err!=nil{
        t.Fatal(err)
    }
    cmd:=exec.Command(helper,"--audit-resident-rollback",root)
    out,err:=cmd.CombinedOutput()
    if err!=nil || !strings.Contains(string(out),record.ExeSHA256) ||
       !strings.Contains(string(out),"SOLO LECTURA") {
        t.Fatalf("independent watchdog rejected sealed snapshot: %v %s",err,string(out))
    }
    // A writable external ACL invalidates the whole backup even though the
    // original hashes are unchanged. The audit must not repair it.
    bad:=filepath.Join(target,"VOLVE_DNS_Legacy_Task.xml")
    out,err=exec.Command("icacls.exe",bad,"/grant","*S-1-1-0:W").CombinedOutput()
    if err!=nil{t.Fatalf("cannot simulate untrusted snapshot ACL: %v %s",err,string(out))}
    cmd=exec.Command(helper,"--audit-resident-rollback",root)
    out,err=cmd.CombinedOutput()
    if err==nil || !strings.Contains(string(out),"NO VERIFICADO"){
        t.Fatalf("independent watchdog accepted writable recovery XML: %v %s",err,string(out))
    }
    active,err:=os.ReadFile(exe)
    if err!=nil || string(active)!="MZ_CI_ONLY_NOT_A_REAL_DNS_SERVER" {
        t.Fatal("read-only watchdog audit changed original motor")
    }
}
