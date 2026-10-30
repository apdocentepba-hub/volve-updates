//go:build windows

package main

import (
    "context"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "os"
    "path/filepath"
    "strings"
    "testing"
    "time"
    "unicode/utf16"

    "volve-browser-protection/motorupdate"
)

func residentTestXML(exe,principal,args string,extra bool) []byte {
    action:="<Exec><Command>"+exe+"</Command><Arguments>"+args+"</Arguments></Exec>"
    if extra {action+="<Exec><Command>powershell.exe</Command></Exec>"}
    return []byte("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"+
        "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">"+
        "<RegistrationInfo><Author>VOLVE test only</Author></RegistrationInfo>"+
        "<Principals><Principal id=\"Author\"><UserId>"+principal+"</UserId></Principal></Principals>"+
        "<Actions Context=\"Author\">"+action+"</Actions></Task>")
}

func makeResidentFixture(t *testing.T,xmlPayload []byte) (string,string) {
    t.Helper()
    root:=t.TempDir()
    parent:=filepath.Join(root,residentRecoveryParent)
    dir:=filepath.Join(parent,residentRecoveryFolder)
    if err:=os.MkdirAll(dir,0700);err!=nil{t.Fatal(err)}
    motor:=[]byte("CI-ONLY-NOT-A-REAL-DNS-SERVER-EXECUTABLE")
    exeDigest:=sha256.Sum256(motor)
    xmlDigest:=sha256.Sum256(xmlPayload)
    record:=motorupdate.LegacyRecoveryRecord{
        Schema:1,Component:"dns-engine-legacy-recovery",
        OriginalTask:"VOLVE-DNS-SERVER-0270",OriginalArgs:"--dns-service",
        OriginalName:residentLegacyExe,
        ExeSHA256:hex.EncodeToString(exeDigest[:]),ExeSize:int64(len(motor)),
        XMLSHA256:hex.EncodeToString(xmlDigest[:]),XMLSize:int64(len(xmlPayload)),
        CapturedUTC:time.Now().UTC().Format(time.RFC3339Nano),
    }
    receipt,err:=json.Marshal(record);if err!=nil{t.Fatal(err)}
    for name,data:=range map[string][]byte{
        residentRecoveryExe:motor,residentRecoveryTask:xmlPayload,
        residentRecoveryReceipt:append(receipt,'\n'),
    } {
        if err:=os.WriteFile(filepath.Join(dir,name),data,0600);err!=nil{t.Fatal(err)}
    }
    return root,dir
}

func hardenResidentFixture(t *testing.T,root,dir string) {
    t.Helper()
    // Reuse the proven disposable-only ACL helper without granting permissions
    // to any production path. All ancestors within the backup are hardened.
    parent:=filepath.Join(root,residentRecoveryParent)
    guard:=filepath.Join(parent,"CI-owner-guard.tmp")
    if err:=os.WriteFile(guard,[]byte("CI"),0600);err!=nil{t.Fatal(err)}
    hardenedTestACL(t,guard,dir)
    hardenedTestACL(t,filepath.Join(dir,residentRecoveryReceipt),filepath.Join(dir,residentRecoveryTask))
    hardenedTestACL(t,filepath.Join(dir,residentRecoveryReceipt),filepath.Join(dir,residentRecoveryExe))
    if err:=os.Remove(guard);err!=nil{t.Fatal(err)}
}

func TestResidentTaskXMLRequiresExactSYSTEMAction(t *testing.T) {
    exe:=filepath.Join(os.Getenv("WINDIR"),"ProgramData","VOLVE-CI","VOLVE_DNS_Server_0270.exe")
    if err:=validateResidentTaskXML(residentTestXML(exe,"S-1-5-18","--dns-service",false),exe);err!=nil{
        t.Fatalf("valid exported task XML rejected: %v",err)
    }
    taskSchedulerText:=strings.Replace(string(residentTestXML(exe,"SYSTEM","--dns-service",false)),
        "encoding=\"UTF-8\"","encoding=\"UTF-16\"",1)
    if err:=validateResidentTaskXML([]byte(taskSchedulerText),exe);err!=nil{
        t.Fatalf("Task Scheduler UTF-16 declaration over UTF-8 transport rejected: %v",err)
    }
    units:=utf16.Encode([]rune(taskSchedulerText))
    utf16LE:=[]byte{0xff,0xfe}
    for _,unit:=range units {utf16LE=append(utf16LE,byte(unit),byte(unit>>8))}
    if err:=validateResidentTaskXML(utf16LE,exe);err!=nil{
        t.Fatalf("actual UTF-16LE Task Scheduler XML rejected: %v",err)
    }
    if err:=validateResidentTaskXML(utf16LE[:len(utf16LE)-1],exe);err==nil{
        t.Fatal("truncated UTF-16LE Task Scheduler XML accepted")
    }
    hidden:=string(residentTestXML(exe,"SYSTEM","--dns-service",false))
    hidden=strings.Replace(hidden,"</Actions>","<ComHandler><ClassId>{00000000-0000-0000-0000-000000000000}</ClassId></ComHandler></Actions>",1)
    if err:=validateResidentTaskXML([]byte(hidden),exe);err==nil{
        t.Fatal("extra ComHandler task action accepted beside DNS Exec")
    }
    for _,tc:=range []struct{name,principal,args,exe string;extra bool}{
        {"user-principal","S-1-5-21-1234","--dns-service",exe,false},
        {"wrong-argument","SYSTEM","--disable-protection",exe,false},
        {"wrong-executable","SYSTEM","--dns-service",filepath.Join(os.Getenv("WINDIR"),"System32","cmd.exe"),false},
        {"second-command","SYSTEM","--dns-service",exe,true},
    } {
        t.Run(tc.name,func(t *testing.T){
            if err:=validateResidentTaskXML(residentTestXML(tc.exe,tc.principal,tc.args,tc.extra),exe);err==nil{
                t.Fatal("untrusted resident task XML accepted")
            }
        })
    }
}

func TestResidentRecoveryAuditProtectedLocalBundle(t *testing.T) {
    // Nothing in this test runs the motor or changes any real SYSTEM task.
    root:=t.TempDir()
    expected:=filepath.Join(root,residentLegacyExe)
    xmlPayload:=residentTestXML(expected,"S-1-5-18","--dns-service",false)
    // Fixture builder creates its own root: bind the XML to that root by
    // obtaining it first, then writing a fully consistent, hash-bound bundle.
    fixtureRoot,dir:=makeResidentFixture(t,residentTestXML("C:\\placeholder.exe","SYSTEM","--dns-service",false))
    xmlPayload=residentTestXML(filepath.Join(fixtureRoot,residentLegacyExe),"SYSTEM","--dns-service",false)
    digest:=sha256.Sum256(xmlPayload)
    recordPath:=filepath.Join(dir,residentRecoveryReceipt)
    raw,err:=os.ReadFile(recordPath);if err!=nil{t.Fatal(err)}
    var record motorupdate.LegacyRecoveryRecord
    if err:=json.Unmarshal(raw,&record);err!=nil{t.Fatal(err)}
    record.XMLSHA256=hex.EncodeToString(digest[:]);record.XMLSize=int64(len(xmlPayload))
    newRecord,err:=json.Marshal(record);if err!=nil{t.Fatal(err)}
    if err:=os.WriteFile(filepath.Join(dir,residentRecoveryTask),xmlPayload,0600);err!=nil{t.Fatal(err)}
    if err:=os.WriteFile(recordPath,newRecord,0600);err!=nil{t.Fatal(err)}
    // Verify user-owned/inherited temp snapshots are rejected, even with
    // correct SHA256 values. A local digest is not authorization.
    if _,err:=auditResidentRollback(context.Background(),fixtureRoot);err==nil{
        t.Fatal("ordinary user-owned recovery directory passed the ACL gate")
    }
    hardenResidentFixture(t,fixtureRoot,dir)
    result,err:=auditResidentRollback(context.Background(),fixtureRoot)
    if err!=nil{t.Fatalf("protected resident backup rejected: %v",err)}
    if result.LegacySHA256!=record.ExeSHA256 || result.TaskXMLSHA256!=record.XMLSHA256{
        t.Fatal("resident backup identity not preserved")
    }
    if err:=os.WriteFile(filepath.Join(dir,residentRecoveryTask),[]byte("ADULTERATED"),0600);err!=nil{t.Fatal(err)}
    if _,err:=auditResidentRollback(context.Background(),fixtureRoot);err==nil{
        t.Fatal("modified SYSTEM XML accepted after a successful audit")
    }
}

func TestResidentRecoveryAuditNeverTrustsUnprotectedOrExtraFiles(t *testing.T) {
    root:=t.TempDir()
    if _,err:=auditResidentRollback(context.Background(),root);err==nil{
        t.Fatal("missing protected snapshot accepted")
    }
    ctx,cancel:=context.WithCancel(context.Background())
    cancel()
    if _,err:=auditResidentRollback(ctx,root);err==nil{
        t.Fatal("cancelled audit accepted")
    }
    if err:=validateResidentTaskXML([]byte(strings.Repeat("x",120)),filepath.Join(root,residentLegacyExe));err==nil{
        t.Fatal("non-XML recovery accepted")
    }
}
