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

    "volve-browser-protection/motorupdate"
)

// Disposable evidence only: no actual Windows task is installed or touched.
func chainFixture(t *testing.T,wrongJournal bool)(string,string,func(string)error,func(string)error){
    t.Helper()
    root,backupDir:=makeResidentFixture(t,residentTestXML("C:\\placeholder.exe","SYSTEM","--dns-service",false))
    xmlBytes:=residentTestXML(filepath.Join(root,residentLegacyExe),"SYSTEM","--dns-service",false)
    xmlSHA:=sha256.Sum256(xmlBytes)
    receiptPath:=filepath.Join(backupDir,residentRecoveryReceipt)
    raw,err:=os.ReadFile(receiptPath);if err!=nil{t.Fatal(err)}
    var record motorupdate.LegacyRecoveryRecord
    if err=json.Unmarshal(raw,&record);err!=nil{t.Fatal(err)}
    record.XMLSHA256=hex.EncodeToString(xmlSHA[:])
    record.XMLSize=int64(len(xmlBytes))
    data,err:=json.Marshal(record);if err!=nil{t.Fatal(err)}
    if err=os.WriteFile(filepath.Join(backupDir,residentRecoveryTask),xmlBytes,0600);err!=nil{t.Fatal(err)}
    if err=os.WriteFile(receiptPath,data,0600);err!=nil{t.Fatal(err)}
    // Copy the fixture's inert bytes to a dummy "installed" EXE, so the
    // chain verifies original==protected backup without touching actual DNS.
    copyBytes,err:=os.ReadFile(filepath.Join(backupDir,residentRecoveryExe))
    if err!=nil{t.Fatal(err)}
    if err=os.WriteFile(filepath.Join(root,residentLegacyExe),copyBytes,0600);err!=nil{t.Fatal(err)}
    hardenResidentFixture(t,root,backupDir)

    journalDir:=filepath.Join(root,residentRecoveryParent,residentJournalDirName)
    if err=os.Mkdir(journalDir,0700);err!=nil{t.Fatal(err)}
    guard:=filepath.Join(filepath.Dir(journalDir),"CI-chain-guard.tmp")
    if err=os.WriteFile(guard,[]byte("CI"),0600);err!=nil{t.Fatal(err)}
    hardenedTestACL(t,guard,journalDir)
    if err=os.Remove(guard);err!=nil{t.Fatal(err)}
    seal:=func(path string)error{hardenedTestACL(t,path,path);return nil}
    protect:=func(path string)error{return checkResidentJournalNTFS(context.Background(),path)}
    target:=sha256.Sum256([]byte("publisher-signed candidate CI bytes"))
    oldSHA:=record.ExeSHA256
    if wrongJournal {oldSHA=strings.Repeat("0",64)}
    journal:=motorupdate.ResidentRecoveryIntent{
       Schema:1,Component:"dns-engine-recovery-intent",
       Task:"VOLVE-DNS-SERVER-0270",LegacySHA256:oldSHA,
       TaskXMLSHA256:record.XMLSHA256,TargetSHA256:hex.EncodeToString(target[:]),
       TargetVersion:"0.28.7",
    }
    if _,err=motorupdate.ArmResidentRecoveryIntent(context.Background(),journalDir,journal,seal,protect);err!=nil{t.Fatal(err)}
    return root,journalDir,seal,protect
}

func TestResidentChainPendingRequiresSameOldMotorAndSYSTEMTask(t *testing.T){
    root,_,_,_:=chainFixture(t,false)
    evidence,err:=auditPendingResidentChain(context.Background(),root)
    if err!=nil{t.Fatalf("coherent protected recovery chain rejected: %v",err)}
    if evidence.LegacySHA256==""||evidence.TaskXMLSHA256==""||evidence.IntentNonce==""||
       evidence.TargetVersion!="0.28.7" {
        t.Fatalf("incomplete read-only chain evidence: %+v",evidence)
    }
    // No Task Scheduler, network adapter or product files were modified.
    if bytes,err:=os.ReadFile(filepath.Join(root,residentLegacyExe));err!=nil||
       string(bytes)!="CI-ONLY-NOT-A-REAL-DNS-SERVER-EXECUTABLE"{
        t.Fatalf("read-only chain audit changed legacy test motor: %v",err)
    }
}

func TestResidentChainRejectsIndependentValidButMismatchedArtifacts(t *testing.T){
    root,_,_,_:=chainFixture(t,true)
    if _,err:=auditPendingResidentChain(context.Background(),root);err==nil||
       !strings.Contains(err.Error(),"different original motor"){
        t.Fatalf("valid journal for different backup was trusted: %v",err)
    }
}

func TestResidentChainRejectsChangedInstalledMotor(t *testing.T){
    root,_,_,_:=chainFixture(t,false)
    if err:=os.WriteFile(filepath.Join(root,residentLegacyExe),
        []byte("MZ different locally installed motor"),0600);err!=nil{t.Fatal(err)}
    if _,err:=auditPendingResidentChain(context.Background(),root);err==nil||
       !strings.Contains(err.Error(),"installed motor differs"){
        t.Fatalf("installed motor mismatch was trusted: %v",err)
    }
}

func TestResidentChainRejectsAlreadyCommittedTransaction(t *testing.T){
    root,dir,seal,protect:=chainFixture(t,false)
    if err:=motorupdate.FinishResidentRecoveryIntent(context.Background(),dir,
        "committed",seal,protect);err!=nil{t.Fatal(err)}
    if _,err:=auditPendingResidentChain(context.Background(),root);err==nil||
       !strings.Contains(err.Error(),"committed"){
        t.Fatalf("committed journal incorrectly authorized new switch: %v",err)
    }
}

func TestResidentChainRejectsRecoveryBackupTampering(t *testing.T){
    root,_,_,_:=chainFixture(t,false)
    path:=filepath.Join(root,residentRecoveryParent,residentRecoveryFolder,residentRecoveryTask)
    if err:=os.WriteFile(path,[]byte("corrupted XML"),0600);err!=nil{t.Fatal(err)}
    if _,err:=auditPendingResidentChain(context.Background(),root);err==nil{
       t.Fatal("altered SYSTEM task backup was trusted")
    }
}

func TestResidentChainRequiresExistingProtectedJournal(t *testing.T){
    root,dir,_,_:=chainFixture(t,false)
    if err:=os.Remove(filepath.Join(dir,motorupdate.ResidentIntentFile));err!=nil{t.Fatal(err)}
    if _,err:=auditPendingResidentChain(context.Background(),root);err==nil{
        t.Fatal("missing recovery intent accepted")
    }
}


// Exercise the actual independent command entry point as another process,
// with an intact bundle followed by a changed original motor. It is not a
// production update or a real reboot and never touches Task Scheduler.
func TestResidentChainCLIChild(t *testing.T) {
    if os.Getenv("VOLVE_CI_CHAIN_CHILD")!="yes"{return}
    root:=os.Getenv("VOLVE_CI_CHAIN_ROOT")
    if root==""{t.Fatal("missing disposable CI root")}
    os.Args=[]string{os.Args[0],"--audit-resident-chain",root}
    main()
}
func TestResidentChainAuditedFromSeparateProcess(t *testing.T) {
    root,_,_,_:=chainFixture(t,false)
    invoke:=func()([]byte,error){
        cmd:=exec.Command(os.Args[0],"-test.run=^TestResidentChainCLIChild$","-test.v")
        cmd.Env=append(os.Environ(),"VOLVE_CI_CHAIN_CHILD=yes","VOLVE_CI_CHAIN_ROOT="+root)
        return cmd.CombinedOutput()
    }
    out,err:=invoke()
    if err!=nil || !strings.Contains(string(out),"CADENA DE RESCATE COHERENTE") ||
        !strings.Contains(string(out),"SOLO LECTURA"){
        t.Fatalf("separate watchdog did not verify bound recovery: %v %s",err,out)
    }
    path:=filepath.Join(root,residentLegacyExe)
    if err:=os.WriteFile(path,[]byte("MZ changed simulated installed motor"),0600);err!=nil{t.Fatal(err)}
    out,err=invoke()
    if err==nil || !strings.Contains(string(out),"CADENA DE RESCATE NO VERIFICADA"){
        t.Fatalf("separate watchdog accepted changed resident motor: %v %s",err,out)
    }
}
