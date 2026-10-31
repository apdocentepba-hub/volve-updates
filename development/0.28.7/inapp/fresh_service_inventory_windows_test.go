//go:build windows

package motorupdate

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func freshServiceJSON(t *testing.T, rows []windowsVOLVEServiceRecord) []byte {
	t.Helper()
	b, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestFreshServiceInventoryConservativeClassification(t *testing.T) {
	original := windowsVOLVEServiceRecord{
		Name: "VOLVE-DNS", DisplayName: "VOLVE DNS protection",
		PathName: `C:\Program Files\VOLVE\motor.exe --dns-service`,
		StartName: "LocalSystem", State: "Stopped",
	}
	renamed := windowsVOLVEServiceRecord{
		Name: "UnrelatedBackup", DisplayName: "Legacy protection",
		PathName: `C:\Program Files\VOLVE\motor-legacy.exe`,
		StartName: "LocalSystem", State: "Running",
	}
	alias := windowsVOLVEServiceRecord{
		Name: "Maintenance", DisplayName: "VOLVE Service",
		PathName: `C:\Windows\System32\cmd.exe /c test`,
		StartName: "LocalSystem", State: "Running",
	}
	for _, tc := range []struct {
		name    string
		records []windowsVOLVEServiceRecord
		want    int
	}{
		{"empty", []windowsVOLVEServiceRecord{}, 0},
		{"stopped-still-blocks", []windowsVOLVEServiceRecord{original}, 1},
		{"renamed-still-blocks", []windowsVOLVEServiceRecord{renamed}, 1},
		{"display-name-still-blocks", []windowsVOLVEServiceRecord{alias}, 1},
		{"multiple", []windowsVOLVEServiceRecord{original, renamed, alias}, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := InspectWindowsVOLVEServicesReadOnly(context.Background(), func(_ context.Context, query string) ([]byte, error) {
				if query != WindowsVOLVEServiceInventoryQuery {
					t.Fatal("unexpected privileged query")
				}
				return freshServiceJSON(t, tc.records), nil
			})
			if err != nil || result.VOLVEServiceCount != tc.want || len(result.ServiceNames) != tc.want {
				t.Fatalf("inventory=%+v err=%v", result, err)
			}
			// These OTHER five inventories are synthetic, NOT Windows evidence.
			evidence := freshCompleteObservation()
			evidence.VOLVEServiceCount = result.VOLVEServiceCount
			accepted := CheckFreshMotorInstallReadiness(context.Background(), evidence) == nil
			if accepted != (tc.want == 0) {
				t.Fatal("service residue was ignored or clean-host fixture rejected")
			}
		})
	}
}

func TestFreshServiceInventoryRejectsUntrustedOutput(t *testing.T) {
	good := windowsVOLVEServiceRecord{
		Name: "VOLVE-DNS", DisplayName: "VOLVE DNS",
		PathName: `C:\VOLVE\motor.exe`, StartName: "LocalSystem", State: "Stopped",
	}
	invalid := good
	invalid.Name = "WindowsUpdate"
	invalid.DisplayName = "Normal Update"
	invalid.PathName = `C:\Windows\System32\svchost.exe`
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"nil", nil}, {"null", []byte("null")}, {"object", []byte("{}")},
		{"trailing", []byte("[] true")}, {"partial", []byte("[")},
		{"oversized", []byte(strings.Repeat(" ", 1<<20+1))},
		{"missing-path", freshServiceJSON(t, []windowsVOLVEServiceRecord{{Name: "VOLVE-DNS", StartName: "LocalSystem", State: "Running"}})},
		{"missing-principal", freshServiceJSON(t, []windowsVOLVEServiceRecord{{Name: "VOLVE-DNS", PathName: `C:\VOLVE\motor.exe`, State: "Running"}})},
		{"duplicate", freshServiceJSON(t, []windowsVOLVEServiceRecord{good, good})},
		{"unrelated-injected-record", freshServiceJSON(t, []windowsVOLVEServiceRecord{invalid})},
		{"extra-field", []byte(`[{"Name":"VOLVE-DNS","DisplayName":"VOLVE DNS","PathName":"C:\\VOLVE\\motor.exe","StartName":"LocalSystem","State":"Stopped","Extra":true}]`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := InspectWindowsVOLVEServicesReadOnly(context.Background(),
				func(context.Context, string) ([]byte, error) { return tc.raw, nil }); err == nil {
				t.Fatal("unsafe service inventory accepted")
			}
		})
	}
}

func TestFreshServiceInventoryQueryCannotBeReplacedOrCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	_, err := InspectWindowsVOLVEServicesReadOnly(ctx, func(context.Context, string) ([]byte, error) {
		called = true
		return []byte("[]"), nil
	})
	if !errors.Is(err, context.Canceled) || called {
		t.Fatalf("cancelled query ran: %v", err)
	}
	if _, err := DefaultWindowsFreshServiceInspect(context.Background(), "Stop-Service -Name VOLVE"); err == nil {
		t.Fatal("unapproved PowerShell command was accepted")
	}
	if !strings.Contains(WindowsVOLVEServiceInventoryQuery, "Win32_Service") ||
		!strings.Contains(WindowsVOLVEServiceInventoryQuery, "PathName") {
		t.Fatal("query no longer covers service execution paths")
	}
}

func TestFreshServiceInventoryActualWindowsReadOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("native Windows service inventory integration")
	}
	result, err := InspectWindowsVOLVEServicesReadOnly(context.Background(), DefaultWindowsFreshServiceInspect)
	if err != nil {
		t.Fatalf("real Windows service inventory unavailable: %v", err)
	}
	if len(result.ServiceNames) != result.VOLVEServiceCount {
		t.Fatal("service inventory inconsistent")
	}
	t.Logf("READ ONLY: enumerated %d VOLVE-linked Windows services (no service, task or DNS writes)", result.VOLVEServiceCount)
}
