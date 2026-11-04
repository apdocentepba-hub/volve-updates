//go:build windows

package uninstallguard

// Combined native Windows read-only ownership audit. This is a prerequisite
// review, NOT an uninstall permit and NOT an installer/rollback transaction.
import (
    "context"
    "crypto/ed25519"
    "errors"
)

type SignedLiveOwnershipAudit struct {
    Schema int `json:"schema"`
    Component string `json:"component"`
    InstallationID string `json:"installation_id"`
    Files InstalledFilesAudit `json:"files"`
    Tasks InstalledTasksAudit `json:"tasks"`
    Status string `json:"status"`
    CanUninstall bool `json:"can_uninstall"`
    CanStopMotor bool `json:"can_stop_motor"`
    CanChangeDNS bool `json:"can_change_dns"`
    CanDeleteTasks bool `json:"can_delete_tasks"`
    CanDeleteFiles bool `json:"can_delete_files"`
}

// AuditSignedInstalledOwnershipReadOnly requires an exact Ed25519-signed
// receipt, independent native host census, eight disk hashes, and live
// Task Scheduler XML/action hashes. Any missing evidence yields NO report.
// Even success does not verify the running DNS process or permit removal.
func AuditSignedInstalledOwnershipReadOnly(ctx context.Context,raw,signature []byte,trusted ed25519.PublicKey)(SignedLiveOwnershipAudit,error){
    var rejected SignedLiveOwnershipAudit
    if ctx==nil{return rejected,errors.New("Windows ownership audit context missing")}
    if err:=ctx.Err();err!=nil{return rejected,err}
    receipt,err:=VerifySignedInstalledReceipt(raw,signature,trusted)
    if err!=nil{return rejected,err}
    host,err:=InspectWindowsReadOnly(ctx)
    if err!=nil{return rejected,err}
    plan,err:=Review(host)
    if err!=nil{return rejected,err}
    if host.LegacyTasks!=0 || host.RecoveryJournalPresent {
        return rejected,errors.New("legacy 0.28.6 or pending recovery requires preservation and prevents ownership admission")
    }
    if plan.CanUninstall||plan.CanStopMotor||plan.CanDeleteTasks||plan.CanChangeDNS||plan.CanDeleteFiles {
        return rejected,errors.New("read-only host plan unexpectedly allowed mutation")
    }
    files,err:=auditReceiptFilesAtRoots(ctx,receipt,receipt.InstallRoot,receipt.DataRoot)
    if err!=nil{return rejected,err}
    tasks,err:=liveWindowsVolveTasks(ctx)
    if err!=nil{return rejected,err}
    taskProof,err:=auditReceiptTasksAgainstObservation(ctx,receipt,tasks)
    if err!=nil{return rejected,err}
    if err:=ctx.Err();err!=nil{return rejected,err}
    return SignedLiveOwnershipAudit{
        Schema:1,Component:"VOLVE-0287-LIVE-SIGNED-OWNERSHIP-REVIEW-ONLY",
        InstallationID:receipt.InstallationID,
        Files:files,Tasks:taskProof,
        Status:"SIGNED_FILES_AND_TASKS_MATCH_BUT_PROCESS_DNS_LOCK_UNINSTALL_PERMIT_UNVERIFIED",
    },nil
}
