//go:build windows

package motorupdate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// ReadLegacyTaskRecoverySnapshotWindows collects a fresh read-only Windows
// Task Scheduler inventory and validates the private backup with real NTFS
// DACL inspection. The caller must hold the migration's named OS mutex while
// collecting evidence. It does not register, run, stop or delete tasks.
func ReadLegacyTaskRecoverySnapshotWindows(
	ctx context.Context,
	initialBackupPath string,
	threeTaskBackupPath string,
) (LegacyTaskRecoverySnapshot, error) {
	var empty LegacyTaskRecoverySnapshot
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	programData := os.Getenv("ProgramData")
	systemRoot := os.Getenv("SystemRoot")
	if programData == "" || systemRoot == "" ||
		!filepath.IsAbs(programData) || !filepath.IsAbs(systemRoot) ||
		strings.HasPrefix(programData, `\\`) || strings.HasPrefix(systemRoot, `\\`) {
		return empty, errors.New("trusted local Windows roots unavailable")
	}
	programData = filepath.Clean(programData)
	systemRoot = filepath.Clean(systemRoot)
	powershell := filepath.Join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	psInfo, err := os.Lstat(powershell)
	if err != nil || !psInfo.Mode().IsRegular() || psInfo.Mode()&os.ModeSymlink != 0 {
		return empty, errors.New("trusted Windows PowerShell is unavailable")
	}
	inventory, err := DefaultWindowsFreshTaskInspect(ctx, WindowsVOLVETaskInventoryQuery)
	if err != nil {
		return empty, err
	}
	acl := func(path string) error {
		_, err := DefaultWindowsDNSProtectedACLInspect(ctx, path)
		return err
	}
	roots := []string{programData}
	if p := os.Getenv("ProgramFiles"); p != "" && filepath.IsAbs(p) {
		roots = append(roots, filepath.Clean(p))
	}
	if p := os.Getenv("ProgramFiles(x86)"); p != "" && filepath.IsAbs(p) {
		roots = append(roots, filepath.Clean(p))
	}
	return ReadLegacyTaskRecoverySnapshot(ctx, LegacyTaskRecoveryReadOptions{
		ProgramDataRoot:       programData,
		InitialBackupPath:     initialBackupPath,
		ThreeTaskBackupPath:   threeTaskBackupPath,
		WindowsPowerShellPath: powershell,
		AllowedSourceRoots:    roots,
		TaskInventoryJSON:     inventory,
		VerifyProtectedACL:    acl,
	})
}
