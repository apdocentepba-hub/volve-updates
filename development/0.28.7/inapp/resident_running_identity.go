package motorupdate

import (
 "errors"
 "fmt"
 "path/filepath"
 "strings"
)

// ResidentRunningEvidence is a READ-ONLY observation of Windows Task Scheduler
// and Win32_Process. A process with a matching path is NOT itself proof of
// parentage by Task Scheduler, a publisher signature, or a healthy DNS server.
// Exact signed migration permission, protected backup and DNS probes remain
// independent mandatory gates.
type ResidentRunningEvidence struct {
 TaskName string `json:"task_name"`
 TaskFolder string `json:"task_folder"`
 TaskPrincipal string `json:"task_principal"`
 TaskState string `json:"task_state"`
 TaskActionExecute string `json:"task_action_execute"`
 TaskActionArguments string `json:"task_action_arguments"`
 ProcessCount int `json:"process_count"`
 ProcessPath string `json:"process_path"`
 ProcessCommandLine string `json:"process_command_line"`
 ProcessOwnerSID string `json:"process_owner_sid"`
 DiskSHA256 string `json:"disk_sha256"`
}

const residentRunningTask = "VOLVE-DNS-SERVER-0270"

// CheckResidentRunningEvidence rejects ambiguous task/process/command-line
// identity before running any health probe. It NEVER modifies Windows.
func CheckResidentRunningEvidence(observed ResidentRunningEvidence, expectedPath, expectedSHA string) error {
 if !filepath.IsAbs(expectedPath) || filepath.Base(expectedPath)=="." {
  return errors.New("expected resident motor path must be absolute")
 }
 if len(expectedSHA)!=64 || !isResidentLowerSHA(expectedSHA) {
  return errors.New("expected motor SHA-256 not canonical")
 }
 if observed.TaskName!=residentRunningTask || observed.TaskFolder!=`\` ||
    (observed.TaskPrincipal!="SYSTEM" && observed.TaskPrincipal!="S-1-5-18") ||
    observed.TaskState!="Running" {
  return errors.New("resident SYSTEM task not running with expected identity")
 }
 if observed.TaskActionArguments!="--dns-service" ||
    !strings.EqualFold(observed.TaskActionExecute,expectedPath) ||
    observed.ProcessCount!=1 || observed.ProcessOwnerSID!="S-1-5-18" ||
    !strings.EqualFold(observed.ProcessPath,expectedPath) ||
    observed.DiskSHA256!=expectedSHA {
  return errors.New("running motor task/process/path/disk SHA-256 mismatch")
 }
 if observed.ProcessCommandLine!=expectedPath+" --dns-service" &&
    observed.ProcessCommandLine!=`"`+expectedPath+`" --dns-service` {
  return fmt.Errorf("resident process does not have exact --dns-service invocation")
 }
 return nil
}
func isResidentLowerSHA(s string)bool {
 for _,c:=range s {if c<'0'||c>'9' {if c<'a'||c>'f' {return false}}}
 return true
}
