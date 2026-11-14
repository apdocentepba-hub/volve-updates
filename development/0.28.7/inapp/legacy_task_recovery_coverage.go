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
type LegacyTaskRecoverySnapshot struct {
	ExpectedManifestSHA256    string
	ObservedManifestSHA256    string
	IndependentVerifierPassed bool
	Tasks                     []LegacyTaskRecoveryEvidence
}

// LegacyTaskRecoveryReview describes coverage of direct task actions only.
// It cannot authorize installation or cleanup, and it does not certify
// transitive dependencies or recovery after reboot.
type LegacyTaskRecoveryReview struct {
	RecoverySetComplete             bool     `json:"recovery_set_complete"`
	InitialSnapshotManifestVerified bool     `json:"initial_snapshot_manifest_verified"`
	TransitiveDependenciesCertified bool     `json:"transitive_dependencies_certified"`
	RecoveryAfterRebootVerified     bool     `json:"recovery_after_reboot_verified"`
	InstallAuthorized               bool     `json:"install_authorized"`
	CleanupAuthorized               bool     `json:"cleanup_authorized"`
	Blockers                        []string `json:"blockers"`
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
	result := LegacyTaskRecoveryReview{
		InitialSnapshotManifestVerified: manifestVerified,
		TransitiveDependenciesCertified: false,
		RecoveryAfterRebootVerified:     false,
		InstallAuthorized:               false,
		CleanupAuthorized:               false,
		Blockers:                        make([]string, 0, len(blockers)),
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
	if review.InstallAuthorized || review.CleanupAuthorized ||
		review.TransitiveDependenciesCertified || review.RecoveryAfterRebootVerified {
		return errors.New("coverage review attempted to claim a capability it cannot certify")
	}
	return nil
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
