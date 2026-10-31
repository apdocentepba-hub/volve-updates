//go:build windows

package motorupdate

// Read-only inventory of Windows services linked to VOLVE. A renamed or
// stopped service still prevents treating an installation as new. This module
// NEVER starts, stops, registers or deletes services, DNS settings or tasks.
import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// Fixed, non-interpolated, read-only Win32_Service query. Service Name,
// DisplayName AND executable command line are checked, because the service
// name can change while the executable keeps running.
const WindowsVOLVEServiceInventoryQuery = `$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';
$items=@(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop | Where-Object {
  ([string]$_.Name -match '(?i)^VOLVE(?:[-_. ]|[0-9]|$)') -or
  ([string]$_.DisplayName -match '(?i)^VOLVE(?:[-_. ]|[0-9]|$)') -or
  ([string]$_.PathName -match '(?i)[\\/]VOLVE(?:[\\/]|[-_. ]|[0-9]|$)')
} | ForEach-Object {
  [pscustomobject]@{
    Name=[string]$_.Name;
    DisplayName=[string]$_.DisplayName;
    PathName=[string]$_.PathName;
    StartName=[string]$_.StartName;
    State=[string]$_.State
  }
});ConvertTo-Json -InputObject $items -Compress -Depth 5`

type WindowsFreshServiceInspect func(context.Context, string) ([]byte, error)

func DefaultWindowsFreshServiceInspect(ctx context.Context, query string) ([]byte, error) {
	if query != WindowsVOLVEServiceInventoryQuery {
		return nil, errors.New("only fixed read-only VOLVE service inventory allowed")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root := os.Getenv("SystemRoot")
	if !filepath.IsAbs(root) {
		return nil, errors.New("Windows system root unavailable")
	}
	ps := filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	out, err := exec.CommandContext(ctx, ps, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", query).Output()
	if err != nil {
		return nil, fmt.Errorf("Windows VOLVE service inventory unavailable: %w", err)
	}
	return out, nil
}

type windowsVOLVEServiceRecord struct {
	Name        string `json:"Name"`
	DisplayName string `json:"DisplayName"`
	PathName    string `json:"PathName"`
	StartName   string `json:"StartName"`
	State       string `json:"State"`
}

type WindowsFreshVOLVEServiceInventory struct {
	VOLVEServiceCount int
	ServiceNames      []string
}

var (
	volveServiceNamePattern = regexp.MustCompile(`(?i)^volve(?:[-_. ]|[0-9]|$)`)
	volveServicePathPattern = regexp.MustCompile(`(?i)[\\/]volve(?:[\\/]|[-_. ]|[0-9]|$)`)
)

// InspectWindowsVOLVEServicesReadOnly counts ALL VOLVE-linked Win32 services,
// including STOPPED services, without whitelisting any. A return value of
// count=0 is valid only after the fixed query succeeds with a genuine JSON [].
// The caller MUST independently verify admin access and the other inventories
// before using the separate fresh-install policy.
func InspectWindowsVOLVEServicesReadOnly(ctx context.Context, inspect WindowsFreshServiceInspect) (WindowsFreshVOLVEServiceInventory, error) {
	var zero WindowsFreshVOLVEServiceInventory
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if inspect == nil {
		return zero, errors.New("missing independent Windows service inspector")
	}
	raw, err := inspect(ctx, WindowsVOLVEServiceInventoryQuery)
	if err != nil {
		return zero, err
	}
	if len(raw) < 2 || len(raw) > 1<<20 {
		return zero, errors.New("VOLVE service inventory absent or oversized")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var records []windowsVOLVEServiceRecord
	if err := decoder.Decode(&records); err != nil {
		return zero, fmt.Errorf("invalid Windows service inventory: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return zero, errors.New("trailing or invalid Windows service inventory")
	}
	if records == nil || len(records) > 64 {
		return zero, errors.New("missing/overlarge Windows VOLVE service inventory")
	}
	result := WindowsFreshVOLVEServiceInventory{VOLVEServiceCount: len(records)}
	seen := map[string]bool{}
	for _, svc := range records {
		name := strings.TrimSpace(svc.Name)
		if name == "" || len(name) > 256 || strings.TrimSpace(svc.PathName) == "" || len(svc.PathName) > 8192 ||
			strings.TrimSpace(svc.StartName) == "" || strings.TrimSpace(svc.State) == "" {
			return zero, errors.New("incomplete Windows VOLVE service evidence")
		}
		if !volveServiceNamePattern.MatchString(name) &&
			!volveServiceNamePattern.MatchString(svc.DisplayName) &&
			!volveServicePathPattern.MatchString(svc.PathName) {
			return zero, errors.New("unmatched Windows service in VOLVE inventory")
		}
		key := strings.ToLower(name)
		if seen[key] {
			return zero, errors.New("duplicate Windows service identity")
		}
		seen[key] = true
		// No service exception: even a STOPPED catalog service could restart.
		result.ServiceNames = append(result.ServiceNames, name)
	}
	return result, nil
}
