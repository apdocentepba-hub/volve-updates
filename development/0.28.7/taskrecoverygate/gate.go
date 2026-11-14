// Package taskrecoverygate reviews whether a local, already-created recovery
// snapshot covers every known legacy SYSTEM task before a later migration review.
// It is a pure read-only gate: it performs no Windows operation and can never
// authorize installation, task deletion, DNS writes, or cleanup.
package taskrecoverygate

import (
	"encoding/hex"
	"sort"
	"strings"
)

const systemSID = "S-1-5-18"

var requiredTasks = []string{
	"VOLVE-CATALOGO-0230",
	"VOLVE-DNS-RESCUE-0270",
	"VOLVE-DNS-SERVER-0270",
}

// InitialSnapshotEvidence must come from the separate read-only snapshot
// verifier. Matching hash strings alone are not considered verified evidence.
type InitialSnapshotEvidence struct {
	ExpectedManifestSHA256    string
	ObservedManifestSHA256    string
	IndependentVerifierPassed bool
}

// TaskEvidence describes independently verified facts about one task and its
// protected backup. Hashes must be SHA-256 hex digests of the exact XML and
// direct action bytes, not of a normalized or reconstructed representation.
type TaskEvidence struct {
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

// Review reports direct-action backup coverage only. The transitive
// dependencies and post-reboot recovery are not certified by this gate.
// Authorization fields are deliberately always false.
type Review struct {
	RecoverySetComplete               bool     `json:"recovery_set_complete"`
	InitialSnapshotManifestVerified   bool     `json:"initial_snapshot_manifest_verified"`
	TransitiveDependenciesCertified    bool     `json:"transitive_dependencies_certified"`
	RecoveryAfterRebootVerified        bool     `json:"recovery_after_reboot_verified"`
	InstallAuthorized                  bool     `json:"install_authorized"`
	CleanupAuthorized                  bool     `json:"cleanup_authorized"`
	Blockers                           []string `json:"blockers"`
}

// Inspect validates independently verified manifest evidence and exact
// coverage of all three known legacy SYSTEM tasks. Unknown or duplicate tasks
// fail closed. This does not certify transitive dependencies of the actions.
func Inspect(snapshot InitialSnapshotEvidence, items []TaskEvidence) Review {
	blockers := make(map[string]struct{})
	manifestVerified := snapshot.IndependentVerifierPassed &&
		validSHA256(snapshot.ExpectedManifestSHA256) &&
		validSHA256(snapshot.ObservedManifestSHA256) &&
		strings.EqualFold(snapshot.ExpectedManifestSHA256, snapshot.ObservedManifestSHA256)
	if !manifestVerified {
		blockers["initial_snapshot_manifest_unverified"] = struct{}{}
	}

	byName := make(map[string]TaskEvidence, len(items))
	for _, item := range items {
		key := strings.ToUpper(strings.TrimSpace(item.Name))
		if _, ok := requiredName(key); !ok {
			blockers["unknown_task_in_snapshot"] = struct{}{}
			continue
		}
		if _, exists := byName[key]; exists {
			blockers["duplicate_task_evidence"] = struct{}{}
			continue
		}
		byName[key] = item
	}
	for _, name := range requiredTasks {
		item, ok := byName[name]
		if !ok {
			blockers["missing_"+strings.ToLower(strings.ReplaceAll(name, "-", "_"))] = struct{}{}
			continue
		}
		if item.PrincipalSID != systemSID {
			blockers["non_system_principal"] = struct{}{}
		}
		if !matchingSHA256(item.SourceXMLSHA256, item.BackupXMLSHA256) {
			blockers["task_xml_backup_mismatch"] = struct{}{}
		}
		if !matchingSHA256(item.SourceActionSHA256, item.BackupActionSHA256) {
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

	result := Review{
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

func requiredName(name string) (string, bool) {
	for _, required := range requiredTasks {
		if strings.EqualFold(name, required) {
			return required, true
		}
	}
	return "", false
}

func matchingSHA256(a, b string) bool {
	return validSHA256(a) && validSHA256(b) && strings.EqualFold(a, b)
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
