package motorupdate

import (
	"reflect"
	"testing"
)

const testLegacyManifestSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const testLegacyTaskXMLSHA256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const testLegacyActionSHA256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

func completeLegacyTaskRecoverySnapshot() LegacyTaskRecoverySnapshot {
	snapshot := LegacyTaskRecoverySnapshot{
		ExpectedManifestSHA256: testLegacyManifestSHA256,
		ObservedManifestSHA256: testLegacyManifestSHA256,
		IndependentVerifierPassed: true,
		TransitiveDependenciesCertified: true,
		RecoveryAfterRebootVerified: true,
	}
	for _, name := range requiredLegacyRecoveryTasks {
		snapshot.Tasks = append(snapshot.Tasks, LegacyTaskRecoveryEvidence{
			Name: name, PrincipalSID: legacyTaskSystemSID,
			SourceXMLSHA256: testLegacyTaskXMLSHA256, BackupXMLSHA256: testLegacyTaskXMLSHA256,
			SourceActionSHA256: testLegacyActionSHA256, BackupActionSHA256: testLegacyActionSHA256,
			SourceStillUnchanged: true, BackupACLVerified: true,
			BackupReadbackVerified: true, DirectActionAllowlisted: true,
		})
	}
	return snapshot
}

func testLegacyTaskRecoverySnapshotForProof(snapshot LegacyTaskRecoverySnapshot, proof VerifiedLegacyMigrationProof) LegacyTaskRecoverySnapshot {
	for i := range snapshot.Tasks {
		if snapshot.Tasks[i].Name == "VOLVE-DNS-SERVER-0270" {
			snapshot.Tasks[i].SourceXMLSHA256 = proof.LegacyTaskXMLSHA256
			snapshot.Tasks[i].BackupXMLSHA256 = proof.LegacyTaskXMLSHA256
			snapshot.Tasks[i].SourceActionSHA256 = proof.LegacySHA256
			snapshot.Tasks[i].BackupActionSHA256 = proof.LegacySHA256
		}
	}
	return snapshot
}

func TestBindLegacyRecoverySnapshotToMigrationProof(t *testing.T) {
	snapshot := completeLegacyTaskRecoverySnapshot()
	proof := VerifiedLegacyMigrationProof{
		LegacySHA256: testLegacyActionSHA256,
		LegacyTaskXMLSHA256: testLegacyTaskXMLSHA256,
	}
	if err := bindLegacyRecoverySnapshotToMigrationProof(snapshot, proof); err != nil {
		t.Fatalf("matching signed legacy server task rejected: %v", err)
	}
	for _, field := range []string{"source xml", "backup xml", "source action", "backup action"} {
		t.Run(field, func(t *testing.T) {
			candidate := completeLegacyTaskRecoverySnapshot()
			for i := range candidate.Tasks {
				if candidate.Tasks[i].Name != "VOLVE-DNS-SERVER-0270" { continue }
				switch field {
				case "source xml": candidate.Tasks[i].SourceXMLSHA256 = testLegacyManifestSHA256
				case "backup xml": candidate.Tasks[i].BackupXMLSHA256 = testLegacyManifestSHA256
				case "source action": candidate.Tasks[i].SourceActionSHA256 = testLegacyManifestSHA256
				case "backup action": candidate.Tasks[i].BackupActionSHA256 = testLegacyManifestSHA256
				}
			}
			if err := bindLegacyRecoverySnapshotToMigrationProof(candidate, proof); err == nil {
				t.Fatal("unrelated DNS server task identity accepted")
			}
		})
	}
}

func TestReviewLegacyTaskRecoveryCoverageRequiresAllThreeExactTasks(t *testing.T) {
	got := ReviewLegacyTaskRecoveryCoverage(completeLegacyTaskRecoverySnapshot())
	if !got.RecoverySetComplete || !got.InitialSnapshotManifestVerified ||
		!got.TransitiveDependenciesCertified || !got.RecoveryAfterRebootVerified ||
		got.InstallAuthorized || got.CleanupAuthorized || len(got.Blockers) != 0 || len(got.MigrationBlockers) != 0 {
		t.Fatalf("unexpected review: %+v", got)
	}
}

func TestReviewLegacyTaskRecoveryCoverageReportsMissingMigrationEvidence(t *testing.T) {
	snapshot := completeLegacyTaskRecoverySnapshot()
	snapshot.TransitiveDependenciesCertified = false
	snapshot.RecoveryAfterRebootVerified = false
	got := ReviewLegacyTaskRecoveryCoverage(snapshot)
	if !got.RecoverySetComplete || got.TransitiveDependenciesCertified || got.RecoveryAfterRebootVerified ||
		!reflect.DeepEqual(got.MigrationBlockers, []string{"recovery_after_reboot_unverified", "transitive_dependencies_uncertified"}) {
		t.Fatalf("direct task coverage did not report separate migration blockers: %+v", got)
	}
}

func TestReviewLegacyTaskRecoveryCoverageFailsClosed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*LegacyTaskRecoverySnapshot)
		want   string
	}{
		{"missing task", func(s *LegacyTaskRecoverySnapshot) { s.Tasks = s.Tasks[:2] }, "missing_"},
		{"unknown task", func(s *LegacyTaskRecoverySnapshot) { s.Tasks[0].Name = "VOLVE-UNKNOWN" }, "unknown_task_in_snapshot"},
		{"duplicate task", func(s *LegacyTaskRecoverySnapshot) { s.Tasks[1].Name = s.Tasks[0].Name }, "duplicate_task_evidence"},
		{"wrong principal", func(s *LegacyTaskRecoverySnapshot) { s.Tasks[0].PrincipalSID = "Administrators" }, "non_system_principal"},
		{"XML mismatch", func(s *LegacyTaskRecoverySnapshot) { s.Tasks[0].BackupXMLSHA256 = testLegacyActionSHA256 }, "task_xml_backup_mismatch"},
		{"action mismatch", func(s *LegacyTaskRecoverySnapshot) { s.Tasks[0].BackupActionSHA256 = testLegacyTaskXMLSHA256 }, "direct_action_backup_mismatch"},
		{"source missing", func(s *LegacyTaskRecoverySnapshot) { s.Tasks[0].SourceStillUnchanged = false }, "source_task_changed_or_missing"},
		{"ACL missing", func(s *LegacyTaskRecoverySnapshot) { s.Tasks[0].BackupACLVerified = false }, "backup_acl_unverified"},
		{"readback missing", func(s *LegacyTaskRecoverySnapshot) { s.Tasks[0].BackupReadbackVerified = false }, "backup_readback_unverified"},
		{"action not allowlisted", func(s *LegacyTaskRecoverySnapshot) { s.Tasks[0].DirectActionAllowlisted = false }, "direct_action_not_allowlisted"},
		{"manifest mismatch", func(s *LegacyTaskRecoverySnapshot) {
			s.ObservedManifestSHA256 = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
		}, "initial_snapshot_manifest_unverified"},
		{"independent verifier absent", func(s *LegacyTaskRecoverySnapshot) { s.IndependentVerifierPassed = false }, "initial_snapshot_manifest_unverified"},
		{"malformed digest", func(s *LegacyTaskRecoverySnapshot) { s.Tasks[0].SourceActionSHA256 = "not-a-hash" }, "direct_action_backup_mismatch"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			snapshot := completeLegacyTaskRecoverySnapshot()
			tt.mutate(&snapshot)
			got := ReviewLegacyTaskRecoveryCoverage(snapshot)
			if got.RecoverySetComplete || got.InstallAuthorized || got.CleanupAuthorized {
				t.Fatalf("unsafe review: %+v", got)
			}
			if tt.want == "missing_" {
				for _, blocker := range got.Blockers {
					if len(blocker) >= len(tt.want) && blocker[:len(tt.want)] == tt.want {
						return
					}
				}
				t.Fatalf("expected missing-task blocker, got %v", got.Blockers)
			}
			for _, blocker := range got.Blockers {
				if blocker == tt.want {
					return
				}
			}
			t.Fatalf("expected blocker %q, got %v", tt.want, got.Blockers)
		})
	}
}

func TestReviewLegacyTaskRecoveryCoverageBlockersAreStable(t *testing.T) {
	snapshot := completeLegacyTaskRecoverySnapshot()
	snapshot.Tasks[0].BackupACLVerified = false
	snapshot.Tasks[1].BackupReadbackVerified = false
	a := ReviewLegacyTaskRecoveryCoverage(snapshot)
	b := ReviewLegacyTaskRecoveryCoverage(snapshot)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("nondeterministic review: %+v != %+v", a, b)
	}
}
