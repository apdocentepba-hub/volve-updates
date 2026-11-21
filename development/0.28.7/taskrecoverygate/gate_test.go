package taskrecoverygate

import (
	"reflect"
	"testing"
)

const manifestHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const xmlHash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const actionHash = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

func completeEvidence() []TaskEvidence {
	items := make([]TaskEvidence, 0, len(requiredTasks))
	for _, name := range requiredTasks {
		items = append(items, TaskEvidence{
			Name: name, PrincipalSID: systemSID,
			SourceXMLSHA256: xmlHash, BackupXMLSHA256: xmlHash,
			SourceActionSHA256: actionHash, BackupActionSHA256: actionHash,
			SourceStillUnchanged: true, BackupACLVerified: true,
			BackupReadbackVerified: true, DirectActionAllowlisted: true,
		})
	}
	return items
}

func verifiedSnapshot() InitialSnapshotEvidence {
	return InitialSnapshotEvidence{
		ExpectedManifestSHA256: manifestHash, ObservedManifestSHA256: manifestHash,
		IndependentVerifierPassed: true,
	}
}

func TestInspectAcceptsOnlyCompleteThreeTaskBackupCoverage(t *testing.T) {
	got := Inspect(verifiedSnapshot(), completeEvidence())
	if !got.RecoverySetComplete || !got.InitialSnapshotManifestVerified ||
		got.TransitiveDependenciesCertified || got.RecoveryAfterRebootVerified ||
		got.InstallAuthorized || got.CleanupAuthorized || len(got.Blockers) != 0 ||
		!reflect.DeepEqual(got.MigrationBlockers, []string{"recovery_after_reboot_unverified", "transitive_dependencies_uncertified"}) {
		t.Fatalf("unexpected review: %+v", got)
	}
}

func TestInspectFailsClosedForIncompleteOrUntrustedEvidence(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]TaskEvidence, InitialSnapshotEvidence) ([]TaskEvidence, InitialSnapshotEvidence)
		want   string
	}{
		{"missing task", func(v []TaskEvidence, s InitialSnapshotEvidence) ([]TaskEvidence, InitialSnapshotEvidence) { return v[:2], s }, "missing_"},
		{"unknown task", func(v []TaskEvidence, s InitialSnapshotEvidence) ([]TaskEvidence, InitialSnapshotEvidence) { v[0].Name = "VOLVE-UNKNOWN"; return v, s }, "unknown_task_in_snapshot"},
		{"duplicate task", func(v []TaskEvidence, s InitialSnapshotEvidence) ([]TaskEvidence, InitialSnapshotEvidence) { v[1].Name = v[0].Name; return v, s }, "duplicate_task_evidence"},
		{"wrong principal", func(v []TaskEvidence, s InitialSnapshotEvidence) ([]TaskEvidence, InitialSnapshotEvidence) { v[0].PrincipalSID = "Administrators"; return v, s }, "non_system_principal"},
		{"xml mismatch", func(v []TaskEvidence, s InitialSnapshotEvidence) ([]TaskEvidence, InitialSnapshotEvidence) { v[0].BackupXMLSHA256 = actionHash; return v, s }, "task_xml_backup_mismatch"},
		{"action mismatch", func(v []TaskEvidence, s InitialSnapshotEvidence) ([]TaskEvidence, InitialSnapshotEvidence) { v[0].BackupActionSHA256 = xmlHash; return v, s }, "direct_action_backup_mismatch"},
		{"source changed", func(v []TaskEvidence, s InitialSnapshotEvidence) ([]TaskEvidence, InitialSnapshotEvidence) { v[0].SourceStillUnchanged = false; return v, s }, "source_task_changed_or_missing"},
		{"acl absent", func(v []TaskEvidence, s InitialSnapshotEvidence) ([]TaskEvidence, InitialSnapshotEvidence) { v[0].BackupACLVerified = false; return v, s }, "backup_acl_unverified"},
		{"readback absent", func(v []TaskEvidence, s InitialSnapshotEvidence) ([]TaskEvidence, InitialSnapshotEvidence) { v[0].BackupReadbackVerified = false; return v, s }, "backup_readback_unverified"},
		{"action not allowlisted", func(v []TaskEvidence, s InitialSnapshotEvidence) ([]TaskEvidence, InitialSnapshotEvidence) { v[0].DirectActionAllowlisted = false; return v, s }, "direct_action_not_allowlisted"},
		{"manifest mismatch", func(v []TaskEvidence, s InitialSnapshotEvidence) ([]TaskEvidence, InitialSnapshotEvidence) {
			s.ObservedManifestSHA256 = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
			return v, s
		}, "initial_snapshot_manifest_unverified"},
		{"manifest verifier absent", func(v []TaskEvidence, s InitialSnapshotEvidence) ([]TaskEvidence, InitialSnapshotEvidence) {
			s.IndependentVerifierPassed = false
			return v, s
		}, "initial_snapshot_manifest_unverified"},
		{"malformed digest", func(v []TaskEvidence, s InitialSnapshotEvidence) ([]TaskEvidence, InitialSnapshotEvidence) { v[0].SourceActionSHA256 = "not-a-hash"; return v, s }, "direct_action_backup_mismatch"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			items, snapshot := tt.mutate(completeEvidence(), verifiedSnapshot())
			got := Inspect(snapshot, items)
			if got.RecoverySetComplete || got.InstallAuthorized || got.CleanupAuthorized {
				t.Fatalf("unsafe review: %+v", got)
			}
			if tt.want == "missing_" {
				for _, blocker := range got.Blockers {
					if len(blocker) >= len(tt.want) && blocker[:len(tt.want)] == tt.want { return }
				}
				t.Fatalf("expected a missing-task blocker, got %v", got.Blockers)
			}
			for _, blocker := range got.Blockers {
				if blocker == tt.want { return }
			}
			t.Fatalf("expected blocker %q, got %v", tt.want, got.Blockers)
		})
	}
}

func TestInspectBlockerListIsStable(t *testing.T) {
	items := completeEvidence()
	items[0].BackupACLVerified = false
	items[1].BackupReadbackVerified = false
	a := Inspect(verifiedSnapshot(), items)
	b := Inspect(verifiedSnapshot(), items)
	if !reflect.DeepEqual(a, b) { t.Fatalf("nondeterministic review: %+v != %+v", a, b) }
}
