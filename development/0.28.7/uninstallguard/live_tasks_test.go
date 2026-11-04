package uninstallguard

import (
    "context"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "strings"
    "testing"
)

func signedTaskFixture()(InstalledReceipt,ObservedTask){
    r:=testReceipt()
    action:=TaskActionIdentity{
        Execute:`C:\Program Files\VOLVE\VOLVE_Managed_Watchdog.exe`,
        Arguments:"--dns-resident",
        WorkingDirectory:`C:\Program Files\VOLVE`,
    }
    obs:=ObservedTask{
        Name:"VOLVE-MANAGED-DNS-0287",
        TaskPath:"\\",
        Principal:"S-1-5-18",
        XML:`<?xml version="1.0"?><Task version="1.4"><Principals><Principal id="System">SYSTEM</Principal></Principals></Task>`,
        Action:action,
    }
    a,_:=json.Marshal(action)
    hashXML:=sha256.Sum256([]byte(obs.XML))
    hashAction:=sha256.Sum256(a)
    r.Tasks[0].XMLSHA256=hex.EncodeToString(hashXML[:])
    r.Tasks[0].ActionSHA256=hex.EncodeToString(hashAction[:])
    return r,obs
}

func TestExactSignedScheduledTaskReadOnlyMatchNeverAuthorizes(t *testing.T) {
    r,o:=signedTaskFixture()
    a,err:=auditReceiptTasksAgainstObservation(context.Background(),r,[]ObservedTask{o})
    if err!=nil || a.CheckedTasks!=1||a.MatchedTasks!=1 {
        t.Fatalf("exact SYSTEM task receipt refused: %+v %v",a,err)
    }
    if a.CanUninstall||a.CanStopMotor||a.CanChangeDNS||a.CanDeleteTasks||a.CanDeleteFiles {
        t.Fatalf("a task hash granted destructive permissions: %+v",a)
    }
}

func TestSignedTaskAuditRejectsAlterationForeignTaskAndLegacyTask(t *testing.T) {
    for _,scenario:=range []string{
        "xml-changed","action-arguments-changed","action-executable-changed",
        "foreign-principal","other-task-path","task-removed","unexpected-task",
        "task-case-changed","blank-action","untrusted-xml",
    }{
        t.Run(scenario,func(t *testing.T){
            r,o:=signedTaskFixture()
            tasks:=[]ObservedTask{o}
            switch scenario{
            case "xml-changed": tasks[0].XML+=" "
            case "action-arguments-changed":tasks[0].Action.Arguments="--uninstall"
            case "action-executable-changed":tasks[0].Action.Execute=`C:\Windows\System32\cmd.exe`
            case "foreign-principal":tasks[0].Principal="Users"
            case "other-task-path":tasks[0].TaskPath=`\Other\`
            case "task-removed":tasks=nil
            case "unexpected-task":
                tasks=append(tasks,ObservedTask{Name:"VOLVE-OTHER",TaskPath:"\\",Principal:"SYSTEM",XML:o.XML,Action:o.Action})
            case "task-case-changed":tasks[0].Name="volve-managed-dns-0287"
            case "blank-action":tasks[0].Action.Execute=""
            case "untrusted-xml":tasks[0].XML="short"
            }
            audit,err:=auditReceiptTasksAgainstObservation(context.Background(),r,tasks)
            if err==nil || audit.MatchedTasks!=0{
                t.Fatalf("different Task Scheduler observation accepted: %+v %v",audit,err)
            }
        })
    }
    r,o:=signedTaskFixture()
    r.Tasks[0].Name="VOLVE-DNS-SERVER-0270"
    if _,err:=auditReceiptTasksAgainstObservation(context.Background(),r,[]ObservedTask{o});err==nil {
        t.Fatal("legacy SYSTEM task falsely accepted as 0.28.7")
    }
}

func TestSignedTaskAuditRejectsAmbiguousOwnershipAndCancelledOperation(t *testing.T) {
    r,o:=signedTaskFixture()
    if _,err:=auditReceiptTasksAgainstObservation(nil,r,[]ObservedTask{o});err==nil{t.Fatal("nil context accepted")}
    ctx,cancel:=context.WithCancel(context.Background());cancel()
    if _,err:=auditReceiptTasksAgainstObservation(ctx,r,[]ObservedTask{o});err==nil{t.Fatal("cancelled context accepted")}
    copyTask:=o;copyTask.Name=strings.ToLower(o.Name)
    if _,err:=auditReceiptTasksAgainstObservation(context.Background(),r,[]ObservedTask{o,copyTask});err==nil{
        t.Fatal("case-insensitive task alias was accepted")
    }
}
