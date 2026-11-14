package motorupdate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	legacyThreeTaskReceiptName = "recibo-tres-tareas.json"
	legacyThreeTaskComponent   = "VOLVE-THREE-LEGACY-TASKS-DIRECT-ACTIONS-BACKUP-V1"
	legacyThreeTaskState       = "PRIVATE_BACKUP_ONLY_NO_CLEANUP_NO_INSTALL"
)

var (
	legacyInitialBackupPattern = regexp.MustCompile(`(?i)^VOLVE-Migration-Backup-[0-9a-f]{32}$`)
	legacyThreeTaskDirPattern  = regexp.MustCompile(`(?i)^VOLVE-Legacy-Three-Recovery-[0-9a-f]{32}$`)
	legacySHA256Pattern        = regexp.MustCompile(`(?i)^[0-9a-f]{64}$`)
	legacyRescueFileArgPattern = regexp.MustCompile(`(?i)(?:^|\s)-File\s+(?:"([^"]+)"|(\S+))\s*$`)
	legacyEnvVarPattern        = regexp.MustCompile(`%([^%]+)%`)
)

type LegacyTaskRecoveryReadOptions struct {
	ProgramDataRoot      string
	InitialBackupPath    string
	ThreeTaskBackupPath  string
	WindowsPowerShellPath string
	AllowedSourceRoots   []string
	TaskInventoryJSON    []byte
	VerifyProtectedACL   func(string) error
}

type legacyInitialManifest struct {
	Schema      int    `json:"schema"`
	Component   string `json:"component"`
	State       string `json:"state"`
	CurrentTasks []struct {
		TaskName     string `json:"task_name"`
		TaskPath     string `json:"task_path"`
		PrincipalSID string `json:"principal_sid"`
		XMLBackup    string `json:"xml_backup"`
		XMLSHA256    string `json:"xml_sha256"`
	} `json:"current_tasks"`
	Files []struct {
		Name   string `json:"name"`
		Bytes  int64  `json:"bytes"`
		SHA256 string `json:"sha256"`
	} `json:"files"`
	Safeguard struct {
		DNSModified                  bool `json:"dns_modified"`
		TasksModified                bool `json:"tasks_modified"`
		RegistryModified             bool `json:"registry_modified"`
		HostsModified                bool `json:"hosts_modified"`
		InstallAuthorized            bool `json:"install_authorized"`
		CleanupAuthorized            bool `json:"cleanup_authorized"`
		SignedProductionRollbackReady bool `json:"signed_production_rollback_ready"`
	} `json:"safeguard"`
}

type legacyThreeTaskReceipt struct {
	Schema                          int    `json:"schema"`
	Component                       string `json:"component"`
	State                           string `json:"state"`
	OriginalManifestSHA256          string `json:"original_manifest_sha256"`
	Records                         []struct {
		Task           string `json:"task"`
		Kind           string `json:"kind"`
		Artifact       string `json:"artifact"`
		SourcePath     string `json:"source_path"`
		OriginalSHA256 string `json:"original_sha256"`
		OriginalSize   int64  `json:"original_size"`
		TaskXMLSHA256  string `json:"task_xml_sha256"`
	} `json:"records"`
	DirectActionsOnly             bool `json:"direct_actions_only"`
	TransitiveDependenciesCertified bool `json:"transitive_dependencies_certified"`
	RecoveryAfterRebootVerified   bool `json:"recovery_after_reboot_verified"`
	PublisherAuthorizationVerified bool `json:"publisher_authorization_verified"`
	CleanupAuthorized             bool `json:"cleanup_authorized"`
	InstallAuthorized             bool `json:"install_authorized"`
}

type legacyRecoveryInventory struct {
	Name             string `json:"Name"`
	TaskPath         string `json:"TaskPath"`
	Principal        string `json:"Principal"`
	Actions          []struct {
		Execute          string  `json:"Execute"`
		Arguments        string  `json:"Arguments"`
		WorkingDirectory *string `json:"WorkingDirectory"`
	} `json:"Actions"`
	DefinitionSHA256 string `json:"DefinitionSHA256"`
}

// ReadLegacyTaskRecoverySnapshot independently re-reads the private initial
// backup, the three direct-action copies and a fresh Windows Task Scheduler
// inventory. The caller must obtain TaskInventoryJSON while holding the same
// cross-process migration lease used by the transaction. This function is
// read-only: it never launches a task or writes files, DNS, registry or ACLs.
func ReadLegacyTaskRecoverySnapshot(ctx context.Context, o LegacyTaskRecoveryReadOptions) (LegacyTaskRecoverySnapshot, error) {
	var empty LegacyTaskRecoverySnapshot
	if err := ctx.Err(); err != nil { return empty, err }
	if o.VerifyProtectedACL == nil { return empty, errors.New("legacy recovery reader lacks protected ACL verifier") }
	if !filepath.IsAbs(o.ProgramDataRoot) || filepath.Clean(o.ProgramDataRoot) != o.ProgramDataRoot ||
		!filepath.IsAbs(o.InitialBackupPath) || filepath.Clean(o.InitialBackupPath) != o.InitialBackupPath ||
		!filepath.IsAbs(o.ThreeTaskBackupPath) || filepath.Clean(o.ThreeTaskBackupPath) != o.ThreeTaskBackupPath {
		return empty, errors.New("legacy recovery paths must be canonical absolute paths")
	}
	if filepath.Dir(o.InitialBackupPath) != o.ProgramDataRoot ||
		filepath.Dir(o.ThreeTaskBackupPath) != o.ProgramDataRoot ||
		!legacyInitialBackupPattern.MatchString(filepath.Base(o.InitialBackupPath)) ||
		!legacyThreeTaskDirPattern.MatchString(filepath.Base(o.ThreeTaskBackupPath)) {
		return empty, errors.New("legacy recovery folders are outside the approved ProgramData layout")
	}
	if len(o.TaskInventoryJSON) < 2 || len(o.TaskInventoryJSON) > 1<<20 {
		return empty, errors.New("fresh Task Scheduler inventory absent or oversized")
	}
	programDataInfo, err := os.Lstat(o.ProgramDataRoot)
	if err != nil || !programDataInfo.IsDir() || programDataInfo.Mode()&os.ModeSymlink != 0 {
		return empty, errors.New("ProgramData root is not a local directory")
	}
	if err := verifyLegacyProtectedNode(o.InitialBackupPath, true, o.VerifyProtectedACL); err != nil { return empty, err }
	if err := verifyLegacyProtectedNode(o.ThreeTaskBackupPath, true, o.VerifyProtectedACL); err != nil { return empty, err }

	manifestPath := filepath.Join(o.InitialBackupPath, "manifest.json")
	manifestBytes, err := readLegacyBoundedFile(manifestPath, 262144, o.VerifyProtectedACL)
	if err != nil { return empty, fmt.Errorf("initial recovery manifest rejected: %w", err) }
	manifestHash := digestLegacyBytes(manifestBytes)
	var manifest legacyInitialManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil { return empty, errors.New("initial recovery manifest is not valid JSON") }
	if manifest.Schema != 1 || manifest.Component != "VOLVE-LOCAL-PRE-MIGRATION-BACKUP" ||
		manifest.State != "PREPARED_ONLY_NO_CLEANUP_NO_INSTALL" ||
		manifest.Safeguard.DNSModified || manifest.Safeguard.TasksModified ||
		manifest.Safeguard.RegistryModified || manifest.Safeguard.HostsModified ||
		manifest.Safeguard.InstallAuthorized || manifest.Safeguard.CleanupAuthorized ||
		manifest.Safeguard.SignedProductionRollbackReady {
		return empty, errors.New("initial recovery manifest has an unsupported or unsafe state")
	}
	if len(manifest.Files) < 2 || len(manifest.Files) > 100 || len(manifest.CurrentTasks) != len(requiredLegacyRecoveryTasks) {
		return empty, errors.New("initial recovery manifest does not cover the required task set")
	}

	baseFiles := make(map[string]struct {
		size int64
		hash string
	}, len(manifest.Files))
	for _, file := range manifest.Files {
		if !allowedLegacyInitialFile(file.Name) || file.Bytes < 0 || file.Bytes > 4<<20 || !legacySHA256Pattern.MatchString(file.SHA256) {
			return empty, errors.New("initial recovery manifest contains an unsupported file record")
		}
		if _, exists := baseFiles[file.Name]; exists { return empty, errors.New("initial recovery manifest contains duplicate files") }
		baseFiles[file.Name] = struct { size int64; hash string }{file.Bytes, strings.ToLower(file.SHA256)}
	}
	if _, ok := baseFiles["original-dns-private.json"]; !ok { return empty, errors.New("initial recovery lacks the private DNS snapshot") }
	if _, ok := baseFiles["original-hosts.bin"]; !ok { return empty, errors.New("initial recovery lacks the HOSTS snapshot") }
	taskFileCount := 0
	for name := range baseFiles { if regexpTaskXMLName(name) { taskFileCount++ } }
	if taskFileCount != 3 || len(baseFiles) != 5 { return empty, errors.New("initial recovery must contain exactly three task XMLs, DNS and HOSTS") }
	if err := verifyLegacyDirectoryEntries(o.InitialBackupPath, append(legacyMapKeys(baseFiles), "manifest.json")); err != nil { return empty, err }
	for name, saved := range baseFiles {
		if err := ctx.Err(); err != nil { return empty, err }
		raw, err := readLegacyBoundedFile(filepath.Join(o.InitialBackupPath, name), 4<<20, o.VerifyProtectedACL)
		if err != nil { return empty, errors.New("initial recovery file could not be read back safely") }
		if int64(len(raw)) != saved.size || !strings.EqualFold(digestLegacyBytes(raw), saved.hash) {
			return empty, errors.New("initial recovery file differs from its manifest")
		}
	}

	taskRows := make(map[string]legacyInitialManifestTask, len(manifest.CurrentTasks))
	for _, row := range manifest.CurrentTasks {
		name, ok := requiredLegacyTaskName(strings.ToUpper(strings.TrimSpace(row.TaskName)))
		if !ok || row.TaskPath != "\\" || !legacySHA256Pattern.MatchString(row.XMLSHA256) ||
			!regexpTaskXMLName(row.XMLBackup) {
			return empty, errors.New("initial recovery contains an unknown or malformed task record")
		}
		key := strings.ToUpper(name)
		if _, exists := taskRows[key]; exists { return empty, errors.New("initial recovery contains duplicate task records") }
		taskRows[key] = legacyInitialManifestTask{principal: row.PrincipalSID, xmlBackup: row.XMLBackup, xmlHash: strings.ToLower(row.XMLSHA256)}
	}
	for _, required := range requiredLegacyRecoveryTasks {
		if _, ok := taskRows[required]; !ok { return empty, errors.New("initial recovery is missing a required SYSTEM task") }
	}
	if len(taskRows) != len(requiredLegacyRecoveryTasks) { return empty, errors.New("initial recovery contains extra VOLVE tasks") }

	receiptPath := filepath.Join(o.ThreeTaskBackupPath, legacyThreeTaskReceiptName)
	receiptBytes, err := readLegacyBoundedFile(receiptPath, 8192, o.VerifyProtectedACL)
	if err != nil { return empty, fmt.Errorf("three-task recovery receipt rejected: %w", err) }
	var receipt legacyThreeTaskReceipt
	if err := decodeLegacyStrictJSON(receiptBytes, &receipt); err != nil { return empty, errors.New("three-task recovery receipt is not strict JSON") }
	if receipt.Schema != 1 || receipt.Component != legacyThreeTaskComponent || receipt.State != legacyThreeTaskState ||
		!receipt.DirectActionsOnly || receipt.TransitiveDependenciesCertified || receipt.RecoveryAfterRebootVerified ||
		receipt.PublisherAuthorizationVerified || receipt.CleanupAuthorized || receipt.InstallAuthorized ||
		!strings.EqualFold(receipt.OriginalManifestSHA256, manifestHash) || len(receipt.Records) != 3 {
		return empty, errors.New("three-task receipt is unpinned or claims an unsupported capability")
	}
	expectedArtifacts := []string{"accion-000.exe", "accion-001.ps1", "accion-002.exe"}
	expectedKinds := []string{"catalog-executable", "rescue-powershell-script", "dns-server-executable"}
	for i, name := range requiredLegacyRecoveryTasks {
		row := receipt.Records[i]
		if row.Task != name || row.Kind != expectedKinds[i] || row.Artifact != expectedArtifacts[i] ||
			!legacySHA256Pattern.MatchString(row.OriginalSHA256) || !legacySHA256Pattern.MatchString(row.TaskXMLSHA256) ||
			row.OriginalSize < 1 || row.OriginalSize > 80<<20 {
			return empty, errors.New("three-task receipt does not match the fixed task/action allowlist")
		}
		manifestRow, ok := taskRows[name]
		if !ok || !strings.EqualFold(manifestRow.xmlHash, row.TaskXMLSHA256) {
			return empty, errors.New("three-task receipt is not bound to the original SYSTEM XML")
		}
		xmlFile, err := readLegacyBoundedFile(filepath.Join(o.InitialBackupPath, manifestRow.xmlBackup), 1<<20, o.VerifyProtectedACL)
		if err != nil || !strings.EqualFold(digestLegacyBytes(xmlFile), manifestRow.xmlHash) {
			return empty, errors.New("original SYSTEM task XML backup is missing or altered")
		}
		if !sameSystemPrincipal(manifestRow.principal) { return empty, errors.New("original task principal was not SYSTEM") }
	}
	if err := verifyLegacyDirectoryEntries(o.ThreeTaskBackupPath, append(expectedArtifacts, legacyThreeTaskReceiptName)); err != nil { return empty, err }

	inventory, err := decodeLegacyTaskInventory(o.TaskInventoryJSON)
	if err != nil { return empty, err }
	if len(inventory) != len(requiredLegacyRecoveryTasks) { return empty, errors.New("live Task Scheduler inventory is incomplete or contains extra VOLVE tasks") }
	byTask := make(map[string]legacyRecoveryInventory, len(inventory))
	for _, item := range inventory {
		if item.TaskPath != "\\" || item.Name == "" || !sameSystemPrincipal(item.Principal) ||
			!legacySHA256Pattern.MatchString(item.DefinitionSHA256) {
			return empty, errors.New("live task identity is not a verified SYSTEM task")
		}
		name, ok := requiredLegacyTaskName(strings.ToUpper(item.Name))
		if !ok { return empty, errors.New("live Task Scheduler returned an unknown VOLVE task") }
		if _, exists := byTask[name]; exists { return empty, errors.New("live Task Scheduler returned duplicate task identity") }
		byTask[name] = item
	}
	if len(byTask) != len(requiredLegacyRecoveryTasks) { return empty, errors.New("live Task Scheduler task set is incomplete") }

	roots := append([]string{o.ProgramDataRoot}, o.AllowedSourceRoots...)
	roots = canonicalLegacyRoots(roots)
	evidence := LegacyTaskRecoverySnapshot{
		ExpectedManifestSHA256: strings.ToLower(receipt.OriginalManifestSHA256),
		ObservedManifestSHA256: manifestHash,
		IndependentVerifierPassed: true,
		Tasks: make([]LegacyTaskRecoveryEvidence, 0, len(requiredLegacyRecoveryTasks)),
	}
	for i, name := range requiredLegacyRecoveryTasks {
		if err := ctx.Err(); err != nil { return empty, err }
		item := byTask[name]
		manifestRow := taskRows[name]
		receiptRow := receipt.Records[i]
		if !strings.EqualFold(item.DefinitionSHA256, manifestRow.xmlHash) {
			return empty, errors.New("live SYSTEM task XML changed since the initial backup")
		}
		sourcePath, err := legacyTaskDirectSource(name, item, o.WindowsPowerShellPath)
		if err != nil { return empty, err }
		if !sameLegacyPath(sourcePath, receiptRow.SourcePath) || !pathWithinLegacyRoots(sourcePath, roots) {
			return empty, errors.New("live task action is not the pinned local dependency")
		}
		if err := verifyLegacyRegularFileWithin(sourcePath, roots); err != nil { return empty, err }
		sourceBytes, err := readLegacyBoundedFile(sourcePath, 80<<20, nil)
		if err != nil || int64(len(sourceBytes)) != receiptRow.OriginalSize ||
			!strings.EqualFold(digestLegacyBytes(sourceBytes), receiptRow.OriginalSHA256) {
			return empty, errors.New("live direct task action differs from the protected backup")
		}
		backupBytes, err := readLegacyBoundedFile(filepath.Join(o.ThreeTaskBackupPath, receiptRow.Artifact), 80<<20, o.VerifyProtectedACL)
		if err != nil || int64(len(backupBytes)) != receiptRow.OriginalSize ||
			!strings.EqualFold(digestLegacyBytes(backupBytes), receiptRow.OriginalSHA256) {
			return empty, errors.New("direct task action backup failed independent readback")
		}
		// Re-read the live source after the copy to reject a concurrent change.
		sourceAfter, err := readLegacyBoundedFile(sourcePath, 80<<20, nil)
		if err != nil || !strings.EqualFold(digestLegacyBytes(sourceAfter), receiptRow.OriginalSHA256) {
			return empty, errors.New("live direct task action changed during verification")
		}
		evidence.Tasks = append(evidence.Tasks, LegacyTaskRecoveryEvidence{
			Name: name, PrincipalSID: legacyTaskSystemSID,
			SourceXMLSHA256: item.DefinitionSHA256, BackupXMLSHA256: receiptRow.TaskXMLSHA256,
			SourceActionSHA256: digestLegacyBytes(sourceBytes), BackupActionSHA256: digestLegacyBytes(backupBytes),
			SourceStillUnchanged: true, BackupACLVerified: true, BackupReadbackVerified: true,
			DirectActionAllowlisted: true,
		})
	}
	if err := ctx.Err(); err != nil { return empty, err }
	// Recheck protected directories after all bytes were read; never repair ACLs.
	if err := o.VerifyProtectedACL(o.InitialBackupPath); err != nil { return empty, err }
	if err := o.VerifyProtectedACL(o.ThreeTaskBackupPath); err != nil { return empty, err }
	review := ReviewLegacyTaskRecoveryCoverage(evidence)
	if !review.RecoverySetComplete { return empty, fmt.Errorf("three-task recovery review incomplete: %s", strings.Join(review.Blockers, ",")) }
	return evidence, nil
}

type legacyInitialManifestTask struct { principal, xmlBackup, xmlHash string }

func allowedLegacyInitialFile(name string) bool {
	if name == "original-dns-private.json" || name == "original-hosts.bin" { return true }
	return regexpTaskXMLName(name)
}

func regexpTaskXMLName(name string) bool {
	if len(name) != len("task-000.xml") || !strings.HasPrefix(name, "task-") || !strings.HasSuffix(name, ".xml") { return false }
	for _, r := range name[len("task-") : len("task-")+3] { if r < '0' || r > '9' { return false } }
	return true
}

func sameSystemPrincipal(value string) bool {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "SYSTEM", "NT AUTHORITY\\SYSTEM", "S-1-5-18":
		return true
	default:
		return false
	}
}

func decodeLegacyStrictJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil { return err }
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF { return errors.New("trailing JSON data") }
	return nil
}

func decodeLegacyTaskInventory(raw []byte) ([]legacyRecoveryInventory, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var tasks []legacyRecoveryInventory
	if err := decoder.Decode(&tasks); err != nil { return nil, errors.New("live Task Scheduler inventory is invalid") }
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF { return nil, errors.New("live Task Scheduler inventory has trailing data") }
	if tasks == nil || len(tasks) > 64 { return nil, errors.New("live Task Scheduler inventory is absent or oversized") }
	return tasks, nil
}

func legacyTaskDirectSource(task string, item legacyRecoveryInventory, windowsPowerShellPath string) (string, error) {
	if len(item.Actions) != 1 { return "", errors.New("legacy SYSTEM task must have exactly one direct action") }
	action := item.Actions[0]
	executable := expandLegacyEnvironment(strings.Trim(strings.TrimSpace(action.Execute), "\""))
	if !filepath.IsAbs(executable) || filepath.Clean(executable) != executable { return "", errors.New("legacy direct action executable is not canonical and absolute") }
	switch task {
	case "VOLVE-CATALOGO-0230":
		if filepath.Base(executable) != "VOLVE_Motor_0210.exe" { return "", errors.New("catalog action is not allowlisted") }
		return executable, nil
	case "VOLVE-DNS-SERVER-0270":
		if filepath.Base(executable) != "VOLVE_DNS_Server_0270.exe" || strings.TrimSpace(action.Arguments) != "--dns-service" { return "", errors.New("DNS server action is not allowlisted") }
		return executable, nil
	case "VOLVE-DNS-RESCUE-0270":
		if windowsPowerShellPath == "" || !filepath.IsAbs(windowsPowerShellPath) || !sameLegacyPath(executable, windowsPowerShellPath) {
			return "", errors.New("rescue task does not use the trusted Windows PowerShell")
		}
		if regexp.MustCompile(`(?i)-(?:command|encodedcommand|enc)\b`).MatchString(action.Arguments) { return "", errors.New("rescue task embeds a command instead of a pinned script") }
		m := legacyRescueFileArgPattern.FindStringSubmatch(strings.TrimSpace(action.Arguments))
		if len(m) != 3 { return "", errors.New("rescue task script path is not allowlisted") }
		script := expandLegacyEnvironment(strings.Trim(strings.TrimSpace(firstLegacyNonEmpty(m[1], m[2])), "\""))
		if !filepath.IsAbs(script) || filepath.Clean(script) != script || !strings.EqualFold(filepath.Ext(script), ".ps1") ||
			!strings.HasPrefix(strings.ToUpper(filepath.Base(script)), "VOLVE") {
			return "", errors.New("rescue task script is not a local VOLVE PowerShell file")
		}
		return script, nil
	default:
		return "", errors.New("unrecognized legacy task")
	}
}

func firstLegacyNonEmpty(a, b string) string { if a != "" { return a }; return b }

func expandLegacyEnvironment(value string) string {
	return legacyEnvVarPattern.ReplaceAllStringFunc(value, func(match string) string {
		sub := legacyEnvVarPattern.FindStringSubmatch(match)
		if len(sub) != 2 { return match }
		if v, ok := os.LookupEnv(sub[1]); ok { return v }
		return match
	})
}

func canonicalLegacyRoots(roots []string) []string {
	out := make([]string, 0, len(roots))
	seen := map[string]bool{}
	for _, root := range roots {
		if !filepath.IsAbs(root) || filepath.Clean(root) != root { continue }
		key := strings.ToLower(root)
		if !seen[key] { seen[key] = true; out = append(out, root) }
	}
	return out
}

func pathWithinLegacyRoots(path string, roots []string) bool {
	for _, root := range roots {
		rel, err := filepath.Rel(root, path)
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) { continue }
		return true
	}
	return false
}

func sameLegacyPath(a, b string) bool { return strings.EqualFold(filepath.Clean(a), filepath.Clean(b)) }

func verifyLegacyRegularFileWithin(path string, roots []string) error {
	if !pathWithinLegacyRoots(path, roots) { return errors.New("legacy dependency is outside approved local roots") }
	if len(roots) == 0 { return errors.New("no trusted roots for legacy dependencies") }
	root := ""
	for _, candidate := range roots { if pathWithinLegacyRoots(path, []string{candidate}) { root = candidate; break } }
	if root == "" { return errors.New("legacy dependency root is ambiguous") }
	cursor := path
	for {
		info, err := os.Lstat(cursor)
		if err != nil { return err }
		if info.Mode()&os.ModeSymlink != 0 { return errors.New("legacy dependency traverses a link") }
		if cursor == root { break }
		parent := filepath.Dir(cursor)
		if parent == cursor { return errors.New("legacy dependency escaped its trusted root") }
		cursor = parent
	}
	info, err := os.Lstat(path)
	if err != nil { return err }
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 80<<20 { return errors.New("legacy dependency is not a bounded regular file") }
	return nil
}

func readLegacyBoundedFile(path string, max int64, verifyACL func(string) error) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path { return nil, errors.New("recovery file path is not canonical") }
	if verifyACL != nil { if err := verifyACL(path); err != nil { return nil, err } }
	before, err := os.Lstat(path)
	if err != nil { return nil, err }
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() < 0 || before.Size() > max {
		return nil, errors.New("recovery file is linked, special or outside size limit")
	}
	file, err := os.Open(path)
	if err != nil { return nil, err }
	raw, readErr := io.ReadAll(io.LimitReader(file, max+1))
	closeErr := file.Close()
	if readErr != nil { return nil, readErr }
	if closeErr != nil { return nil, closeErr }
	if int64(len(raw)) != before.Size() || int64(len(raw)) > max { return nil, errors.New("recovery file changed or exceeded bound while reading") }
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return nil, errors.New("recovery file identity changed while reading")
	}
	return raw, nil
}

func verifyLegacyProtectedNode(path string, directory bool, verifyACL func(string) error) error {
	info, err := os.Lstat(path)
	if err != nil { return err }
	if info.Mode()&os.ModeSymlink != 0 || (directory && !info.IsDir()) || (!directory && !info.Mode().IsRegular()) {
		return errors.New("protected recovery node is a link or special type")
	}
	if err := verifyACL(path); err != nil { return fmt.Errorf("protected recovery ACL rejected: %w", err) }
	return nil
}

func verifyLegacyDirectoryEntries(dir string, expected []string) error {
	entries, err := os.ReadDir(dir)
	if err != nil { return err }
	want := make(map[string]bool, len(expected))
	for _, name := range expected {
		if name == "" || want[name] { return errors.New("invalid or duplicate recovery directory entry") }
		want[name] = true
	}
	if len(entries) != len(want) { return errors.New("recovery directory has missing or unexpected entries") }
	for _, entry := range entries {
		if !want[entry.Name()] || entry.IsDir() { return errors.New("recovery directory has an unexpected entry") }
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() { return errors.New("recovery directory entry is not a regular file") }
	}
	return nil
}

func legacyMapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m { keys = append(keys, k) }
	return keys
}

func digestLegacyBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
