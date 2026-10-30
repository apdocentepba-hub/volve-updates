//go:build windows

package main

import (
    "context"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "os"
    "os/exec"
    "path/filepath"
    "strings"
    "testing"
)

// TestProgramDataRecoveryAclLab uses a unique disposable subdirectory only.
// It never touches ProgramData/VOLVE-Browser-Filter, any production task or
// the machine's network adapter.
func TestProgramDataRecoveryAclLab(t *testing.T) {
    programData:=filepath.Clean(os.Getenv("ProgramData"))
    if !filepath.IsAbs(programData) || !strings.EqualFold(filepath.Base(programData),"ProgramData") {
        t.Fatalf("refusing unexpected ProgramData root: %q",programData)
    }
    info,err:=os.Lstat(programData)
    if err!=nil || !info.IsDir() || info.Mode()&os.ModeSymlink!=0 {
        t.Fatalf("unsafe ProgramData root: %v",err)
    }
    root,err:=os.MkdirTemp(programData,"VOLVE-CI-MotorRecovery-")
    if err!=nil{t.Fatal(err)}
    if !strings.HasPrefix(filepath.Base(root),"VOLVE-CI-MotorRecovery-") || !strings.EqualFold(filepath.Dir(root),programData) {
        t.Fatalf("refusing unexpected CI recovery directory: %q",root)
    }
    t.Cleanup(func(){
        if err:=os.RemoveAll(root);err!=nil{t.Errorf("could not remove disposable ProgramData lab: %v",err)}
    })
    snapshot:=filepath.Join(root,"original-task.xml")
    raw:=[]byte("<Task>disposable never imported</Task>")
    if err:=os.WriteFile(snapshot,raw,0600);err!=nil{t.Fatal(err)}
    sum:=sha256.Sum256(raw)
    j:=journal{Schema:1,Phase:"pending",
        TaskName:"VOLVE-CI-ManagedMotor-1793321319528439500",
        OriginalExe:filepath.Join(os.Getenv("WINDIR"),"System32","cmd.exe"),
        OriginalArgs:"/C exit 0",SnapshotFile:snapshot,SnapshotSHA256:hex.EncodeToString(sum[:])}
    record,err:=json.Marshal(j);if err!=nil{t.Fatal(err)}
    state:=filepath.Join(root,"transaction.json")
    if err:=os.WriteFile(state,record,0600);err!=nil{t.Fatal(err)}
    if err:=verifyRecoveryACL(context.Background(),state,snapshot);err==nil {
        t.Fatal("ordinary, freshly created ProgramData directory unexpectedly trusted")
    }
    // Harden only the disposable directory/files, preserving an existing
    // installation and the root ProgramData security descriptors.
    hardenedTestACL(t,state,snapshot)
    if err:=verifyRecoveryACL(context.Background(),state,snapshot);err!=nil {
        t.Fatalf("protected ProgramData recovery directory rejected: %v",err)
    }
    loaded,err:=readJournal(state)
    if err!=nil || loaded.TaskName!=j.TaskName {
        t.Fatalf("protected journal unreadable: %v",err)
    }
    // Demonstrate fail-closed rejection of an explicit Everyone WRITE ACE.
    out,err:=exec.Command("icacls.exe",state,"/grant","*S-1-1-0:W").CombinedOutput()
    if err!=nil {t.Fatalf("could not simulate an unsafe journal: %v %s",err,string(out))}
    if err:=verifyRecoveryACL(context.Background(),state,snapshot);err==nil {
        t.Fatal("Everyone write permission was not rejected in ProgramData")
    }
}
