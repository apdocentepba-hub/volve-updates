//go:build windows

package motorupdate

// A fail-closed read-only partial host census. This is intentionally NOT the
// production installer and never marks the remaining three OS inventories as
// inspected. Nothing here can authorize a fresh DNS motor installation.
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
)

const WindowsFreshElevatedTokenQuery = `$ErrorActionPreference='Stop';$p=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent());$e=$p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);ConvertTo-Json -InputObject ([pscustomobject]@{Elevated=[bool]$e}) -Compress`

type WindowsFreshAdminInspect func(context.Context, string) ([]byte, error)

func DefaultWindowsFreshAdminInspect(ctx context.Context, query string) ([]byte, error) {
	if query != WindowsFreshElevatedTokenQuery {
		return nil, errors.New("only fixed Windows token query allowed")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root := os.Getenv("SystemRoot")
	if !filepath.IsAbs(root) {
		return nil, errors.New("Windows system root unavailable")
	}
	ps := filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	result, err := exec.CommandContext(ctx, ps, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", query).Output()
	if err != nil {
		return nil, fmt.Errorf("cannot inspect Windows token: %w", err)
	}
	return result, nil
}

func InspectWindowsElevatedTokenReadOnly(ctx context.Context, inspect WindowsFreshAdminInspect) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if inspect == nil {
		return false, errors.New("missing independent Windows token inspector")
	}
	raw, err := inspect(ctx, WindowsFreshElevatedTokenQuery)
	if err != nil {
		return false, err
	}
	if len(raw) < 2 || len(raw) > 256 {
		return false, errors.New("Windows token evidence missing or oversized")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var record struct {
		Elevated *bool `json:"Elevated"`
	}
	if err := decoder.Decode(&record); err != nil {
		return false, fmt.Errorf("malformed Windows token evidence: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return false, errors.New("trailing Windows token evidence")
	}
	if record.Elevated == nil {
		return false, errors.New("Windows token status not demonstrated")
	}
	return *record.Elevated, nil
}

type WindowsFreshPartialHostInspectors struct {
	Admin    WindowsFreshAdminInspect
	Tasks    WindowsFreshTaskInspect
	Services WindowsFreshServiceInspect
	DNS      WindowsFreshDNSAdapterInspect
}

type WindowsFreshPartialHostEvidence struct {
	Evidence       FreshMotorInstallEvidence
	TaskNames      []string
	ServiceNames   []string
	DNSAdapterRecords int
}

// InspectWindowsFreshPartialHostReadOnly binds the current elevated token,
// Task Scheduler, Win32_Service and DNS adapter inventories. It returns a PARTIAL
// evidence record: motor files, port53 listeners and rollback state remain
// explicitly UNKNOWN and must be independently collected under a later
// privileged transaction lock immediately before any installation.
// Injection is for tests; the production caller must supply Default* inspectors.
func InspectWindowsFreshPartialHostReadOnly(
	ctx context.Context, expectedCatalogExe, expectedCatalogArgs string,
	inspect WindowsFreshPartialHostInspectors,
) (WindowsFreshPartialHostEvidence, error) {
	var zero WindowsFreshPartialHostEvidence
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if inspect.Admin == nil || inspect.Tasks == nil || inspect.Services == nil || inspect.DNS == nil {
		return zero, errors.New("all four independent Windows inspectors required")
	}
	admin, err := InspectWindowsElevatedTokenReadOnly(ctx, inspect.Admin)
	if err != nil {
		return zero, err
	}
	if !admin {
		return zero, errors.New("Windows host census requires an elevated administrator token")
	}
	tasks, err := InspectWindowsVOLVETasksReadOnly(ctx, expectedCatalogExe, expectedCatalogArgs, inspect.Tasks)
	if err != nil {
		return zero, fmt.Errorf("Task Scheduler evidence incomplete: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	services, err := InspectWindowsVOLVEServicesReadOnly(ctx, inspect.Services)
	if err != nil {
		return zero, fmt.Errorf("Win32_Service evidence incomplete: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	dns, err := InspectWindowsFreshDNSAdaptersReadOnly(ctx, inspect.DNS)
	if err != nil {
		return zero, fmt.Errorf("Windows DNS adapter evidence incomplete: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	return WindowsFreshPartialHostEvidence{
		Evidence: FreshMotorInstallEvidence{
			InspectedAsAdministrator: true,
			InspectedTaskScheduler:     true,
			InspectedServices:          true,
			InspectedDNSAdapters:       true,
			VOLVETaskCount:            tasks.VOLVETaskCount,
			VerifiedCatalogTask:       tasks.VerifiedCatalogTask,
			VOLVEServiceCount:         services.VOLVEServiceCount,
			LocalIPv4DNSConfigured:     dns.LocalIPv4DNSConfigured,
			LocalIPv6DNSConfigured:     dns.LocalIPv6DNSConfigured,
			// All three remaining required inventories MUST remain false.
		},
		TaskNames:    append([]string(nil), tasks.UnknownTaskNames...),
		ServiceNames: append([]string(nil), services.ServiceNames...),
		DNSAdapterRecords: dns.AdapterFamilyRecords,
	}, nil
}
