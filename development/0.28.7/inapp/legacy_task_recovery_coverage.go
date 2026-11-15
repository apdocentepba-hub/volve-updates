package motorupdate

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const legacyTaskSystemSID = "S-1-5-18"

var requiredLegacyRecoveryTasks = []string{
	"VOLVE-CATALOGO-0230",
	"VOLVE-DNS-RESCUE-0270",
	"VOLVE-DNS-SERVER-0270",
}

// LegacyTaskRecoveryEvidence is returned by the OS driver only after it
// re-reads the live task, its exact XML/action bytes and the sealed local
// backup under the transaction-wide mutex.
type LegacyTaskRecoveryEvidence struct {
	Name                    string
	PrincipalSID            string
	SourceXMLSHA256         string
	BackupXMLSHA256         string
	SourceActionSHA256      string
	BackupActionSHA256      string
	SourceStillUnchanged    bool
	BackupACLVerified       bool
	BackupReadbackVerified  bool
	DirectActionAllowlisted bool
}

// LegacyTaskRecoverySnapshot binds those three task records to the initial
// private snapshot. IndependentVerifierPassed must reflect a separate
// read-only verifier of the NTFS files, not merely matching hash strings.
// The two migration gates below must come from independent, auditable evidence;
// the direct-action reader deliberately leaves them false.
type LegacyTaskRecoverySnapshot struct {
	ExpectedManifestSHA256       string
	ObservedManifestSHA256       string
	IndependentVerifierPassed    bool
	TransitiveDependenciesCertified bool
	RecoveryAfterRebootVerified  bool
	Tasks                        []LegacyTaskRecoveryEvidence
}

// LegacyTaskRecoveryReview reports direct task coverage separately from
// migration readiness. MigrationBlockers identifies missing dependency/reboot
// evidence; neither list validates provenance or authorizes installation.
type LegacyTaskRecoveryReview struct {
	RecoverySetComplete             bool     `json:"recovery_set_complete"`
	InitialSnapshotManifestVerified bool     `json:"initial_snapshot_manifest_verified"`
	TransitiveDependenciesCertified bool     `json:"transitive_dependencies_certified"`
	RecoveryAfterRebootVerified     bool     `json:"recovery_after_reboot_verified"`
	InstallAuthorized               bool     `json:"install_authorized"`
	CleanupAuthorized               bool     `json:"cleanup_authorized"`
	Blockers                        []string `json:"blockers"`
	MigrationBlockers               []string `json:"migration_blockers"`
}

// ReviewLegacyTaskRecoveryCoverage is pure validation. All booleans and hashes
// are evidence supplied by the locked OS reader; this function performs no
// filesystem, Task Scheduler, DNS or registry operation.
func ReviewLegacyTaskRecoveryCoverage(snapshot LegacyTaskRecoverySnapshot) LegacyTaskRecoveryReview {
	blockers := make(map[string]struct{})
	manifestVerified := snapshot.IndependentVerifierPassed &&
		validLegacyTaskSHA256(snapshot.ExpectedManifestSHA256) &&
		validLegacyTaskSHA256(snapshot.ObservedManifestSHA256) &&
		strings.EqualFold(snapshot.ExpectedManifestSHA256, snapshot.ObservedManifestSHA256)
	if !manifestVerified {
		blockers["initial_snapshot_manifest_unverified"] = struct{}{}
	}

	byName := make(map[string]LegacyTaskRecoveryEvidence, len(snapshot.Tasks))
	for _, item := range snapshot.Tasks {
		key := strings.ToUpper(strings.TrimSpace(item.Name))
		if _, ok := requiredLegacyTaskName(key); !ok {
			blockers["unknown_task_in_snapshot"] = struct{}{}
			continue
		}
		if _, exists := byName[key]; exists {
			blockers["duplicate_task_evidence"] = struct{}{}
			continue
		}
		byName[key] = item
	}
	for _, name := range requiredLegacyRecoveryTasks {
		item, ok := byName[name]
		if !ok {
			blockers["missing_"+strings.ToLower(strings.ReplaceAll(name, "-", "_"))] = struct{}{}
			continue
		}
		if item.PrincipalSID != legacyTaskSystemSID {
			blockers["non_system_principal"] = struct{}{}
		}
		if !matchingLegacyTaskSHA256(item.SourceXMLSHA256, item.BackupXMLSHA256) {
			blockers["task_xml_backup_mismatch"] = struct{}{}
		}
		if !matchingLegacyTaskSHA256(item.SourceActionSHA256, item.BackupActionSHA256) {
			blockers["direct_action_backup_mismatch"] = struct{}{}
		}
		if !item.SourceStillUnchanged {
			blockers["source_task_changed_or_missing"] = struct{}{}
		}
		if !item.BackupACLVerified {
			blockers["backup_acl_unverified"] = struct{}{}
		}
		if !item.BackupReadbackVerified {
			blockers["backup_readback_unverified"] = struct{}{}
		}
		if !item.DirectActionAllowlisted {
			blockers["direct_action_not_allowlisted"] = struct{}{}
		}
	}
	migrationBlockers := make([]string, 0, 2)
	if !snapshot.TransitiveDependenciesCertified {
		migrationBlockers = append(migrationBlockers, "transitive_dependencies_uncertified")
	}
	if !snapshot.RecoveryAfterRebootVerified {
		migrationBlockers = append(migrationBlockers, "recovery_after_reboot_unverified")
	}
	sort.Strings(migrationBlockers)
	result := LegacyTaskRecoveryReview{
		InitialSnapshotManifestVerified: manifestVerified,
		TransitiveDependenciesCertified: snapshot.TransitiveDependenciesCertified,
		RecoveryAfterRebootVerified:     snapshot.RecoveryAfterRebootVerified,
		InstallAuthorized:               false,
		CleanupAuthorized:               false,
		Blockers:                        make([]string, 0, len(blockers)),
		MigrationBlockers:               migrationBlockers,
	}
	for blocker := range blockers {
		result.Blockers = append(result.Blockers, blocker)
	}
	sort.Strings(result.Blockers)
	result.RecoverySetComplete = len(result.Blockers) == 0
	return result
}

func requireLegacyTaskRecoveryCoverage(
	ctx context.Context,
	driver SignedLegacySwitchDriver,
	proof VerifiedLegacyMigrationProof,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	snapshot, err := driver.VerifyLegacyTaskRecoveryCoverage(ctx, proof)
	if err != nil {
		return fmt.Errorf("locked three-task recovery review failed: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	review := ReviewLegacyTaskRecoveryCoverage(snapshot)
	if !review.RecoverySetComplete {
		return fmt.Errorf("three-task recovery coverage incomplete: %s", strings.Join(review.Blockers, ","))
	}
	if err := bindLegacyRecoverySnapshotToMigrationProof(snapshot, proof); err != nil {
		return fmt.Errorf("three-task recovery is not bound to the signed migration proof: %w", err)
	}
	if len(review.MigrationBlockers) != 0 {
		return fmt.Errorf("legacy migration readiness blocked: %s", strings.Join(review.MigrationBlockers, ","))
	}
	if review.InstallAuthorized || review.CleanupAuthorized {
		return errors.New("coverage review attempted to authorize installation or cleanup")
	}
	return nil
}

// bindLegacyRecoverySnapshotToMigrationProof prevents a complete but unrelated
// task backup from satisfying the signed motor transition. The DNS server task
// XML and executable bytes must be exactly the ones covered by the signed grant.
func bindLegacyRecoverySnapshotToMigrationProof(snapshot LegacyTaskRecoverySnapshot, proof VerifiedLegacyMigrationProof) error {
	if !validLegacyTaskSHA256(proof.LegacySHA256) || !validLegacyTaskSHA256(proof.LegacyTaskXMLSHA256) {
		return errors.New("signed legacy motor/task identity is missing or malformed")
	}
	for _, item := range snapshot.Tasks {
		if strings.EqualFold(strings.TrimSpace(item.Name), "VOLVE-DNS-SERVER-0270") {
			if !matchingLegacyTaskSHA256(item.SourceXMLSHA256, proof.LegacyTaskXMLSHA256) ||
				!matchingLegacyTaskSHA256(item.BackupXMLSHA256, proof.LegacyTaskXMLSHA256) {
				return errors.New("DNS server task XML differs from the signed migration proof")
			}
			if !matchingLegacyTaskSHA256(item.SourceActionSHA256, proof.LegacySHA256) ||
				!matchingLegacyTaskSHA256(item.BackupActionSHA256, proof.LegacySHA256) {
				return errors.New("DNS server executable differs from the signed migration proof")
			}
			return nil
		}
	}
	return errors.New("signed DNS server task evidence is absent")
}

func requiredLegacyTaskName(name string) (string, bool) {
	for _, required := range requiredLegacyRecoveryTasks {
		if strings.EqualFold(name, required) {
			return required, true
		}
	}
	return "", false
}

func matchingLegacyTaskSHA256(a, b string) bool {
	return validLegacyTaskSHA256(a) && validLegacyTaskSHA256(b) && strings.EqualFold(a, b)
}

func validLegacyTaskSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
