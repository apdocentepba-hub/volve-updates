//go:build windows

package main

import (
    "context"
    "os"
    "os/exec"
    "path/filepath"
    "strings"
    "testing"

    "volve-browser-protection/motorupdate"
)

// This Windows test touches ONLY t.TempDir. It does not access the user's
// installRoot, real DNS tasks, service, network, hosts or registry.
func TestWindowsProtectedLocalLegacyRollbackBackup(t *testing.T) {
    if !isAdmin(){t.Skip("requires CI elevated Windows runner")}
    root:=t.TempDir()
    parent,err:=ensureSecureLegacyRecoveryParent(root)
    if err!=nil{
        inspected:=filepath.Join(root,localRecoveryFolder)
        check:=`$ErrorActionPreference='Stop';$p=`+labQuote(inspected)+`;
            & icacls.exe $p;
            $a=Get-Acl -LiteralPath $p;
            foreach($entry in $a.Access){Write-Output ('ACL '+$entry.IdentityReference+'; '+$entry.FileSystemRights+'; '+$entry.AccessControlType+'; inherited='+$entry.IsInherited)};
            Write-Output ('Owner='+$a.Owner)`
        details,detailErr:=labPS(check)
        t.Logf("SAFE ACL diagnosis of disposable folder only: details=%s diagnostic_error=%v",details,detailErr)
        t.Fatal(err)
    }
    if err:=checkLegacyRecoveryACL(parent);err!=nil{t.Fatal(err)}
    oldExe:=filepath.Join(root,dnsServiceFile)
    if err:=os.WriteFile(oldExe,[]byte("MZ-CI-only-DNS-legacy-fixed-image"),0600);err!=nil{t.Fatal(err)}
    xml:=[]byte(strings.Repeat("<Task><Principal>SYSTEM</Principal><Exec>test</Exec></Task>",3))
    target:=filepath.Join(parent,localRecoverySnapshot)
    record,err:=motorupdate.PrepareUnversionedLegacyRecovery(
        context.Background(),oldExe,xml,target,checkLegacyRecoveryACL)
    if err!=nil{t.Fatal(err)}
    verified,err:=motorupdate.VerifyUnversionedLegacyRecovery(target,checkLegacyRecoveryACL)
    if err!=nil{t.Fatal(err)}
    if verified!=record{t.Fatalf("Windows ACL protected backup differs: %#v %#v",record,verified)}
    if _,err:=motorupdate.PrepareUnversionedLegacyRecovery(
        context.Background(),oldExe,xml,target,checkLegacyRecoveryACL);err==nil{
        t.Fatal("tried to overwrite original SYSTEM fallback")
    }
    t.Log("PASS: legacy engine and original task XML copied and verified inside private Windows ACL rollback directory; original untouched")
}
func TestWindowsLegacyRollbackRejectsUnexpectedExistingDestination(t *testing.T) {
    if !isAdmin(){t.Skip("requires CI elevated Windows runner")}
    root:=t.TempDir()
    parent:=filepath.Join(root,localRecoveryFolder)
    if err:=os.WriteFile(parent,[]byte("unrecognized"),0600);err!=nil{t.Fatal(err)}
    if _,err:=ensureSecureLegacyRecoveryParent(root);err==nil {
        t.Fatal("unexpected existing rollback target accepted")
    }
}

// TestWindowsLegacyRollbackRejectsUnsafeChildFileACL demonstrates that a
// perfectly intact SHA256 is NOT sufficient if an untrusted user can change
// the recovery EXE, task XML or its receipt. Every fixture is under t.TempDir;
// no production Windows task, DNS, registry or installed VOLVÉ file is used.
func TestWindowsLegacyRollbackRejectsUnsafeChildFileACL(t *testing.T) {
    if !isAdmin() { t.Skip("requires CI elevated Windows runner") }
    for _,filename:=range []string{
        "VOLVE_DNS_Legacy_Recovery.exe",
        "VOLVE_DNS_Legacy_Task.xml",
        "VOLVE_DNS_Legacy_Recovery.json",
    } {
        t.Run(filename,func(t *testing.T){
            root:=t.TempDir()
            parent,err:=ensureSecureLegacyRecoveryParent(root)
            if err!=nil { t.Fatal(err) }
            installed:=filepath.Join(root,dnsServiceFile)
            if err:=os.WriteFile(installed,[]byte("MZ-LAB-DNS"),0600);err!=nil{t.Fatal(err)}
            xml:=[]byte(strings.Repeat("<Task><Principal>SYSTEM</Principal></Task>",4))
            backup:=filepath.Join(parent,localRecoverySnapshot)
            _,err=motorupdate.PrepareUnversionedLegacyRecovery(
                context.Background(),installed,xml,backup,checkLegacyRecoveryACL)
            if err!=nil { t.Fatal(err) }
            // Prove that the existing protected backup is accepted first.
            if _,err:=motorupdate.VerifyUnversionedLegacyRecovery(backup,checkLegacyRecoveryACL);err!=nil {
                t.Fatal(err)
            }
            target:=filepath.Join(backup,filename)
            out,err:=exec.Command("icacls.exe",target,"/grant","*S-1-1-0:W").CombinedOutput()
            if err!=nil { t.Fatalf("cannot add disposable Everyone write ACE: %v %s",err,string(out)) }
            // No bytes were edited. Only the file DACL was weakened.
            if err:=checkLegacyRecoveryACL(backup);err==nil {
                t.Fatal("file-level unsafe NTFS writer was trusted")
            }
            if _,err:=motorupdate.VerifyUnversionedLegacyRecovery(backup,checkLegacyRecoveryACL);err==nil {
                t.Fatal("hash-valid but world-writable rollback file was trusted")
            }
        })
    }
}
