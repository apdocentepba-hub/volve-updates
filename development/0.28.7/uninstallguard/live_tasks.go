package uninstallguard

// Pure task-identity comparison: the observed data must come from an
// independent native Windows read-only census. No scheduler mutations here.
import (
    "context"
    "crypto/sha256"
    "crypto/subtle"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "strings"
)

type TaskActionIdentity struct {
    Execute string `json:"execute"`
    Arguments string `json:"arguments"`
    WorkingDirectory string `json:"working_directory"`
}

type ObservedTask struct {
    Name string `json:"name"`
    TaskPath string `json:"task_path"`
    Principal string `json:"principal"`
    XML string `json:"xml"`
    Action TaskActionIdentity `json:"action"`
}

type InstalledTasksAudit struct {
    Schema int `json:"schema"`
    Component string `json:"component"`
    CheckedTasks int `json:"checked_tasks"`
    MatchedTasks int `json:"matched_tasks"`
    Status string `json:"status"`
    CanUninstall bool `json:"can_uninstall"`
    CanStopMotor bool `json:"can_stop_motor"`
    CanChangeDNS bool `json:"can_change_dns"`
    CanDeleteTasks bool `json:"can_delete_tasks"`
    CanDeleteFiles bool `json:"can_delete_files"`
}

func isSystemPrincipal(p string) bool {
    return strings.EqualFold(p,"SYSTEM") ||
        strings.EqualFold(p,"NT AUTHORITY\\SYSTEM") ||
        strings.EqualFold(p,"S-1-5-18")
}

// auditReceiptTasksAgainstObservation is a PURE matching decision, not a
// source of trustworthy observations. The native caller obtains observations
// directly from Windows Task Scheduler and re-verifies immediately before
// any future privileged transaction. Matching alone is never authorization.
func auditReceiptTasksAgainstObservation(ctx context.Context,r InstalledReceipt,observed []ObservedTask)(InstalledTasksAudit,error) {
    var rejected InstalledTasksAudit
    if ctx==nil {return rejected,errors.New("non-nil task review context required")}
    if err:=ctx.Err();err!=nil{return rejected,err}
    if err:=validateReceipt(r);err!=nil{return rejected,err}
    if len(observed)!=len(r.Tasks){return rejected,errors.New("installed scheduled-task inventory differs from signed receipt")}
    byName:=make(map[string]ObservedTask,len(observed))
    for _,o:=range observed {
        if o.Name=="" || o.TaskPath!="\\" || !strings.HasPrefix(o.Name,"VOLVE-") {
            return rejected,errors.New("unrecognized task path or ownership name")
        }
        key:=strings.ToUpper(o.Name)
        if _,exists:=byName[key];exists {return rejected,errors.New("duplicate scheduled-task name")}
        byName[key]=o
    }
    audit:=InstalledTasksAudit{
        Schema:1,Component:"VOLVE-0287-SIGNED-TASK-OWNERSHIP-READONLY",
        CheckedTasks:len(r.Tasks),
        Status:"READ_ONLY_TASK_HASHES_MATCH_PROCESS_DNS_AND_UNINSTALL_UNVERIFIED",
    }
    for _,expected:=range r.Tasks {
        if err:=ctx.Err();err!=nil{return rejected,err}
        current,ok:=byName[strings.ToUpper(expected.Name)]
        if !ok || current.Name!=expected.Name || !isSystemPrincipal(current.Principal){
            return rejected,fmt.Errorf("signed SYSTEM task %s not owned exactly as expected",expected.Name)
        }
        if len(current.XML)<20 || len(current.XML)>1<<20 ||
            len(current.Action.Execute)==0 || len(current.Action.Execute)>2048 ||
            len(current.Action.Arguments)>4096 || len(current.Action.WorkingDirectory)>2048 {
            return rejected,errors.New("task XML or action size untrusted")
        }
        xmlExpected,_:=hex.DecodeString(expected.XMLSHA256)
        xmlHash:=sha256.Sum256([]byte(current.XML))
        if subtle.ConstantTimeCompare(xmlHash[:],xmlExpected)!=1 {
            return rejected,fmt.Errorf("SYSTEM task %s XML changed",expected.Name)
        }
        actionBytes,err:=json.Marshal(current.Action)
        if err!=nil{return rejected,err}
        actExpected,_:=hex.DecodeString(expected.ActionSHA256)
        actHash:=sha256.Sum256(actionBytes)
        if subtle.ConstantTimeCompare(actHash[:],actExpected)!=1{
            return rejected,fmt.Errorf("SYSTEM task %s executable action changed",expected.Name)
        }
        audit.MatchedTasks++
    }
    return audit,nil
}
