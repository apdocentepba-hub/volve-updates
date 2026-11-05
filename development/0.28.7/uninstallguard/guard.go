// Package uninstallguard validates read-only uninstallation plans for a
// future VOLVE 0.28.7 installer. No code in this package uninstalls anything.
package uninstallguard

import (
    "errors"
)

type Evidence struct {
    Schema int `json:"schema"`
    Complete bool `json:"complete"`
    Elevated bool `json:"elevated"`
    LegacyTasks int `json:"legacy_tasks"`
    OtherVolveTasks int `json:"other_volve_tasks"`
    VolveServices int `json:"volve_services"`
    UDP53 int `json:"udp53_listeners"`
    TCP53 int `json:"tcp53_listeners"`
    DNSLoopback bool `json:"dns_loopback"`
    ProgramFilesRoot bool `json:"programfiles_root"`
    ProgramDataResidues int `json:"programdata_residues"`
    BrowserPolicyStores int `json:"browser_policy_stores"`
    RecoveryJournalPresent bool `json:"recovery_journal_present"`
}

type Plan struct {
    Schema int `json:"schema"`
    Component string `json:"component"`
    TargetRelease string `json:"target_release"`
    Mode string `json:"mode"`
    Reason string `json:"reason"`
    Requirements []string `json:"unmet_requirements"`
    CanUninstall bool `json:"can_uninstall"`
    CanStopMotor bool `json:"can_stop_motor"`
    CanChangeDNS bool `json:"can_change_dns"`
    CanDeleteTasks bool `json:"can_delete_tasks"`
    CanRemoveBrowserPolicies bool `json:"can_remove_browser_policies"`
    CanDeleteFiles bool `json:"can_delete_files"`
    Status string `json:"status"`
}

var requiredProofs = []string{
    "signed-installed-0287-receipt-and-approved-publisher",
    "exact-ownership-of-SYSTEM-task-and-DNS-process",
    "separate-signed-uninstall-authorization",
    "original-DNS-and-SYSTEM-task-XML-backup",
    "exclusive-protected-lock-and-durable-journal",
    "independent-boot-watchdog-and-rollback-verified",
    "explicit-user-uninstall-approval",
}

// Review NEVER produces an authorization. In particular, a supposedly clean
// host or a claim that a 0.28.7 receipt exists is not evidence of permission.
func Review(e Evidence) (Plan, error) {
    if e.Schema!=1 || !e.Complete || !e.Elevated {
        return Plan{}, errors.New("complete elevated Windows inventory required")
    }
    for _,n := range []int{e.LegacyTasks,e.OtherVolveTasks,e.VolveServices,e.UDP53,e.TCP53,e.ProgramDataResidues,e.BrowserPolicyStores} {
        if n<0 || n>100000 {return Plan{},errors.New("untrusted Windows inventory counts")}
    }
    p:=Plan{
        Schema:1, Component:"VOLVE-0287-UNINSTALL-REVIEW-ONLY",
        TargetRelease:"0.28.7", Status:"NO_UNINSTALL_OR_HOST_CHANGES",
        Requirements:append([]string(nil), requiredProofs...),
    }
    switch {
    case e.RecoveryJournalPresent:
        p.Mode="STOP_RECOVERY_JOURNAL_PRESENT"
        p.Reason="Durable DNS recovery evidence exists; preserve the motor, task and original DNS."
    case e.LegacyTasks>0:
        p.Mode="STOP_LEGACY_0286_PROTECTION_PRESENT"
        p.Reason="Existing VOLVE legacy SYSTEM tasks must not be removed by a 0.28.7 uninstaller."
    case e.OtherVolveTasks>0 || e.VolveServices>0 || e.ProgramFilesRoot || e.ProgramDataResidues>0 || e.BrowserPolicyStores>0 || e.DNSLoopback:
        p.Mode="STOP_0287_SIGNED_OWNERSHIP_AND_ROLLBACK_NOT_PROVEN"
        p.Reason="Observed VOLVE or browser/network protection is not a signed, privileged uninstall permit."
    case e.UDP53>0 || e.TCP53>0:
        p.Mode="STOP_UNOWNED_DNS53_LISTENER"
        p.Reason="Never terminate or alter an unrelated DNS listener."
    default:
        p.Mode="STOP_NO_CONFIRMED_VOLVE_INSTALL"
        p.Reason="No proven installed VOLVE owner; do not remove arbitrary files or network settings."
    }
    return p,nil
}
