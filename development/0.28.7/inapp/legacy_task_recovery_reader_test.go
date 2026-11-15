package motorupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type legacyReaderFixtureTask struct {
	Name             string `json:"Name"`
	TaskPath         string `json:"TaskPath"`
	Principal        string `json:"Principal"`
	Actions          []legacyReaderFixtureAction `json:"Actions"`
	DefinitionSHA256 string `json:"DefinitionSHA256"`
}
type legacyReaderFixtureAction struct {
	Execute          string  `json:"Execute"`
	Arguments        string  `json:"Arguments"`
	WorkingDirectory *string `json:"WorkingDirectory"`
}
type legacyReaderFixtureManifest struct {
	Schema int `json:"schema"`
	Component string `json:"component"`
	State string `json:"state"`
	CurrentTasks []legacyReaderFixtureManifestTask `json:"current_tasks"`
	Files []legacyReaderFixtureFile `json:"files"`
	Safeguard map[string]bool `json:"safeguard"`
}
type legacyReaderFixtureManifestTask struct {
	TaskName string `json:"task_name"`
	TaskPath string `json:"task_path"`
	PrincipalSID string `json:"principal_sid"`
	XMLBackup string `json:"xml_backup"`
	XMLSHA256 string `json:"xml_sha256"`
}
type legacyReaderFixtureFile struct {
	Name string `json:"name"`
	Bytes int64 `json:"bytes"`
	SHA256 string `json:"sha256"`
}
type legacyReaderFixtureReceipt struct {
	Schema int `json:"schema"`
	Component string `json:"component"`
	State string `json:"state"`
	OriginalManifestSHA256 string `json:"original_manifest_sha256"`
	Records []legacyReaderFixtureRecord `json:"records"`
	DirectActionsOnly bool `json:"direct_actions_only"`
	TransitiveDependenciesCertified bool `json:"transitive_dependencies_certified"`
	RecoveryAfterRebootVerified bool `json:"recovery_after_reboot_verified"`
	PublisherAuthorizationVerified bool `json:"publisher_authorization_verified"`
	CleanupAuthorized bool `json:"cleanup_authorized"`
	InstallAuthorized bool `json:"install_authorized"`
}
type legacyReaderFixtureRecord struct {
	Task string `json:"task"`
	Kind string `json:"kind"`
	Artifact string `json:"artifact"`
	SourcePath string `json:"source_path"`
	OriginalSHA256 string `json:"original_sha256"`
	OriginalSize int64 `json:"original_size"`
	TaskXMLSHA256 string `json:"task_xml_sha256"`
}

func legacyReaderHash(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func newLegacyTaskRecoveryReaderFixture(t *testing.T) (LegacyTaskRecoveryReadOptions, []legacyReaderFixtureTask, map[string][]byte) {
	t.Helper()
	root := t.TempDir()
	initial := filepath.Join(root, "VOLVE-Migration-Backup-0123456789abcdef0123456789abcdef")
	three := filepath.Join(root, "VOLVE-Legacy-Three-Recovery-abcdef0123456789abcdef0123456789")
	sources := filepath.Join(root, "sources")
	ps := filepath.Join(root, "Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	for _, p := range []string{initial, three, sources, filepath.Dir(ps)} {
		if err := os.MkdirAll(p, 0700); err != nil { t.Fatal(err) }
	}
	sourceBytes := [][]byte{
		[]byte("MZ synthetic catalog action"),
		[]byte("# synthetic rescue script"),
		[]byte("MZ synthetic DNS server action"),
	}
	sourcePaths := []string{
		filepath.Join(sources, "VOLVE_Motor_0210.exe"),
		filepath.Join(sources, "VOLVE_DNS_Rescue_0270.ps1"),
		filepath.Join(sources, "VOLVE_DNS_Server_0270.exe"),
	}
	for i := range sourcePaths {
		if err := os.WriteFile(sourcePaths[i], sourceBytes[i], 0600); err != nil { t.Fatal(err) }
	}
	actionArgs := []string{"--catalog-historical", "-NoProfile -NonInteractive -File \"" + sourcePaths[1] + "\"", "--dns-service"}
	taskXML := [][]byte{
		[]byte("<Task><Actions><Exec>catalog</Exec></Actions></Task>"),
		[]byte("<Task><Actions><Exec>rescue</Exec></Actions></Task>"),
		[]byte("<Task><Actions><Exec>server</Exec></Actions></Task>"),
	}
	inventory := make([]legacyReaderFixtureTask, 0, 3)
	manifest := legacyReaderFixtureManifest{
		Schema: 1,
		Component: "VOLVE-LOCAL-PRE-MIGRATION-BACKUP",
		State: "PREPARED_ONLY_NO_CLEANUP_NO_INSTALL",
		Safeguard: map[string]bool{
			"dns_modified": false, "tasks_modified": false, "registry_modified": false,
			"hosts_modified": false, "install_authorized": false, "cleanup_authorized": false,
			"signed_production_rollback_ready": false,
		},
	}
	baseData := map[string][]byte{
		"original-dns-private.json": []byte("{\"fixture\":\"private dns data\"}"),
		"original-hosts.bin": []byte("# synthetic hosts snapshot\n"),
	}
	records := make([]legacyReaderFixtureRecord, 0, 3)
	artifacts := []string{"accion-000.exe", "accion-001.ps1", "accion-002.exe"}
	kinds := []string{"catalog-executable", "rescue-powershell-script", "dns-server-executable"}
	for i, taskName := range requiredLegacyRecoveryTasks {
		xmlName := "task-00" + string(rune('0'+i)) + ".xml"
		xmlHash := legacyReaderHash(taskXML[i])
		baseData[xmlName] = taskXML[i]
		manifest.CurrentTasks = append(manifest.CurrentTasks, legacyReaderFixtureManifestTask{
			TaskName: taskName, TaskPath: "\\", PrincipalSID: "SYSTEM", XMLBackup: xmlName, XMLSHA256: xmlHash,
		})
		execute := sourcePaths[i]
		if i == 1 { execute = ps }
		args := actionArgs[i]
		working := ""
		inventory = append(inventory, legacyReaderFixtureTask{
			Name: taskName, TaskPath: "\\", Principal: "SYSTEM",
			Actions: []legacyReaderFixtureAction{{Execute: execute, Arguments: args, WorkingDirectory: &working}},
			DefinitionSHA256: xmlHash,
		})
		records = append(records, legacyReaderFixtureRecord{
			Task: taskName, Kind: kinds[i], Artifact: artifacts[i], SourcePath: sourcePaths[i],
			OriginalSHA256: legacyReaderHash(sourceBytes[i]), OriginalSize: int64(len(sourceBytes[i])), TaskXMLSHA256: xmlHash,
		})
		if err := os.WriteFile(filepath.Join(three, artifacts[i]), sourceBytes[i], 0600); err != nil { t.Fatal(err) }
	}
	for name, data := range baseData {
		if err := os.WriteFile(filepath.Join(initial, name), data, 0600); err != nil { t.Fatal(err) }
		manifest.Files = append(manifest.Files, legacyReaderFixtureFile{Name: name, Bytes: int64(len(data)), SHA256: legacyReaderHash(data)})
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil { t.Fatal(err) }
	if err := os.WriteFile(filepath.Join(initial, "manifest.json"), manifestBytes, 0600); err != nil { t.Fatal(err) }
	receipt := legacyReaderFixtureReceipt{
		Schema: 1, Component: legacyThreeTaskComponent, State: legacyThreeTaskState,
		OriginalManifestSHA256: legacyReaderHash(manifestBytes), Records: records, DirectActionsOnly: true,
		TransitiveDependenciesCertified: false, RecoveryAfterRebootVerified: false,
		PublisherAuthorizationVerified: false, CleanupAuthorized: false, InstallAuthorized: false,
	}
	receiptBytes, err := json.Marshal(receipt)
	if err != nil { t.Fatal(err) }
	if err := os.WriteFile(filepath.Join(three, legacyThreeTaskReceiptName), receiptBytes, 0600); err != nil { t.Fatal(err) }
	inventoryBytes, err := json.Marshal(inventory)
	if err != nil { t.Fatal(err) }
	opts := LegacyTaskRecoveryReadOptions{
		ProgramDataRoot: root, ExpectedManifestSHA256: legacyReaderHash(manifestBytes), InitialBackupPath: initial, ThreeTaskBackupPath: three,
		WindowsPowerShellPath: ps, AllowedSourceRoots: []string{root}, TaskInventoryJSON: inventoryBytes,
		VerifyProtectedACL: func(path string) error {
			info, err := os.Lstat(path)
			if err != nil { return err }
			if info.Mode()&os.ModeSymlink != 0 { return errors.New("fixture link refused") }
			return nil
		},
	}
	return opts, inventory, sourceBytesMap(sourcePaths, sourceBytes)
}

func sourceBytesMap(paths []string, contents [][]byte) map[string][]byte {
	out := make(map[string][]byte, len(paths))
	for i := range paths { out[paths[i]] = append([]byte(nil), contents[i]...) }
	return out
}

func TestReadLegacyTaskRecoverySnapshotAcceptsCompleteReadOnlyEvidence(t *testing.T) {
	opts, _, originals := newLegacyTaskRecoveryReaderFixture(t)
	before := make(map[string]string, len(originals))
	for path, data := range originals { before[path] = legacyReaderHash(data) }
	got, err := ReadLegacyTaskRecoverySnapshot(context.Background(), opts)
	if err != nil { t.Fatal(err) }
	review := ReviewLegacyTaskRecoveryCoverage(got)
	if !review.RecoverySetComplete || !review.InitialSnapshotManifestVerified ||
		review.TransitiveDependenciesCertified || review.RecoveryAfterRebootVerified ||
		review.InstallAuthorized || review.CleanupAuthorized ||
		len(review.MigrationBlockers) != 2 ||
		review.MigrationBlockers[0] != "recovery_after_reboot_unverified" ||
		review.MigrationBlockers[1] != "transitive_dependencies_uncertified" {
		t.Fatalf("direct backup review did not expose migration blockers: %+v", review)
	}
	for path, want := range before {
		actual, err := os.ReadFile(path)
		if err != nil || legacyReaderHash(actual) != want { t.Fatalf("reader changed or lost a live source file: %v", err) }
	}
}

func TestReadLegacyTaskRecoverySnapshotRejectsChangedCopyLiveActionAndACL(t *testing.T) {
	t.Run("changed backup bytes", func(t *testing.T) {
		opts, _, _ := newLegacyTaskRecoveryReaderFixture(t)
		path := filepath.Join(opts.ThreeTaskBackupPath, "accion-001.ps1")
		if err := os.WriteFile(path, []byte("modified rescue script"), 0600); err != nil { t.Fatal(err) }
		if _, err := ReadLegacyTaskRecoverySnapshot(context.Background(), opts); err == nil { t.Fatal("altered direct-action backup accepted") }
	})
	t.Run("changed live action", func(t *testing.T) {
		opts, inventory, _ := newLegacyTaskRecoveryReaderFixture(t)
		inventory[0].Actions[0].Execute = filepath.Join(opts.ProgramDataRoot, "foreign.exe")
		opts.TaskInventoryJSON, _ = json.Marshal(inventory)
		if _, err := ReadLegacyTaskRecoverySnapshot(context.Background(), opts); err == nil { t.Fatal("foreign task action accepted") }
	})
	t.Run("ACL rejection", func(t *testing.T) {
		opts, _, _ := newLegacyTaskRecoveryReaderFixture(t)
		opts.VerifyProtectedACL = func(string) error { return errors.New("untrusted DACL") }
		if _, err := ReadLegacyTaskRecoverySnapshot(context.Background(), opts); err == nil { t.Fatal("untrusted recovery ACL accepted") }
	})
}

func TestReadLegacyTaskRecoverySnapshotRejectsUnpinnedManifestExtrasAndCancellation(t *testing.T) {
	t.Run("manifest pin mismatch", func(t *testing.T) {
		opts, _, _ := newLegacyTaskRecoveryReaderFixture(t)
		path := filepath.Join(opts.ThreeTaskBackupPath, legacyThreeTaskReceiptName)
		raw, err := os.ReadFile(path)
		if err != nil { t.Fatal(err) }
		changed := strings.Replace(string(raw), `"original_manifest_sha256":"`, `"original_manifest_sha256":"0`, 1)
		if err := os.WriteFile(path, []byte(changed), 0600); err != nil { t.Fatal(err) }
		if _, err := ReadLegacyTaskRecoverySnapshot(context.Background(), opts); err == nil { t.Fatal("receipt for another initial manifest accepted") }
	})
	t.Run("external manifest pin mismatch", func(t *testing.T) {
		opts, _, _ := newLegacyTaskRecoveryReaderFixture(t)
		opts.ExpectedManifestSHA256 = strings.Repeat("0", 64)
		if _, err := ReadLegacyTaskRecoverySnapshot(context.Background(), opts); err == nil { t.Fatal("manifest differing from external pin accepted") }
	})
	t.Run("unexpected private file", func(t *testing.T) {
		opts, _, _ := newLegacyTaskRecoveryReaderFixture(t)
		if err := os.WriteFile(filepath.Join(opts.ThreeTaskBackupPath, "extra.bin"), []byte("x"), 0600); err != nil { t.Fatal(err) }
		if _, err := ReadLegacyTaskRecoverySnapshot(context.Background(), opts); err == nil { t.Fatal("extra backup entry accepted") }
	})
	t.Run("cancelled", func(t *testing.T) {
		opts, _, _ := newLegacyTaskRecoveryReaderFixture(t)
		ctx, cancel := context.WithCancel(context.Background()); cancel()
		if _, err := ReadLegacyTaskRecoverySnapshot(ctx, opts); !errors.Is(err, context.Canceled) { t.Fatalf("cancelled reader did not stop: %v", err) }
	})
}
