//go:build windows

package motorupdate

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func partialHostInspectors(t *testing.T, admin bool, taskRows []windowsVOLVETaskRecord, serviceRows []windowsVOLVEServiceRecord) WindowsFreshPartialHostInspectors {
	t.Helper()
	token := []byte(`{"Elevated":true}`)
	if !admin {
		token = []byte(`{"Elevated":false}`)
	}
	return WindowsFreshPartialHostInspectors{
		Admin: func(_ context.Context, query string) ([]byte, error) {
			if query != WindowsFreshElevatedTokenQuery {
				t.Fatal("unapproved admin query")
			}
			return token, nil
		},
		Tasks: func(_ context.Context, query string) ([]byte, error) {
			if query != WindowsVOLVETaskInventoryQuery {
				t.Fatal("unapproved Task Scheduler query")
			}
			return freshWindowsTaskJSON(t, taskRows), nil
		},
		Services: func(_ context.Context, query string) ([]byte, error) {
			if query != WindowsVOLVEServiceInventoryQuery {
				t.Fatal("unapproved Win32_Service query")
			}
			return freshServiceJSON(t, serviceRows), nil
		},
		DNS: func(_ context.Context, query string) ([]byte, error) {
			if query != WindowsFreshDNSAdapterQuery {
				t.Fatal("unapproved Windows adapter query")
			}
			return freshDNSRows(t, []windowsFreshDNSAdapterRow{
				{InterfaceIndex: 17, Family: "IPv4", Servers: []string{"8.8.8.8"}},
				{InterfaceIndex: 17, Family: "IPv6", Servers: []string{"2606:4700:4700::1111"}},
			}), nil
		},
	}
}

func TestWindowsPartialHostNeverGrantsFreshInstall(t *testing.T) {
	goodCatalog := freshTaskFixture()
	legacyMotor := windowsVOLVETaskRecord{
		Name: "VOLVE-DNS-SERVER-0270", TaskPath: "\\",
		Principal: "SYSTEM", DefinitionSHA256: strings.Repeat("b", 64),
	}
	legacyService := windowsVOLVEServiceRecord{
		Name: "InvisibleOldService", DisplayName: "Legacy",
		PathName: `C:\Program Files\VOLVE\motor.exe --dns-service`,
		StartName: "LocalSystem", State: "Stopped",
	}
	expectedExe := filepath.Clean(`C:\Program Files\VOLVE\VOLVE_Catalog.exe`)
	for _, tc := range []struct {
		name         string
		tasks        []windowsVOLVETaskRecord
		services     []windowsVOLVEServiceRecord
		wantTasks    int
		wantServices int
	}{
		{"no-tasks-no-services", []windowsVOLVETaskRecord{}, []windowsVOLVEServiceRecord{}, 0, 0},
		{"catalog-only", []windowsVOLVETaskRecord{goodCatalog}, []windowsVOLVEServiceRecord{}, 1, 0},
		{"legacy-task", []windowsVOLVETaskRecord{goodCatalog, legacyMotor}, []windowsVOLVEServiceRecord{}, 2, 0},
		{"hidden-stopped-service", []windowsVOLVETaskRecord{}, []windowsVOLVEServiceRecord{legacyService}, 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := InspectWindowsFreshPartialHostReadOnly(context.Background(), expectedExe, "--catalog",
				partialHostInspectors(t, true, tc.tasks, tc.services))
			if err != nil {
				t.Fatal(err)
			}
			e := result.Evidence
			if !e.InspectedAsAdministrator || !e.InspectedTaskScheduler || !e.InspectedServices || !e.InspectedDNSAdapters ||
				e.VOLVETaskCount != tc.wantTasks || e.VOLVEServiceCount != tc.wantServices {
				t.Fatalf("wrong combined evidence: %+v", e)
			}
			if e.InspectedMotorFiles || e.InspectedPort53Listeners || e.InspectedRecoveryState {
				t.Fatal("partial census fabricated other three OS checks")
			}
			if err := CheckFreshMotorInstallReadiness(context.Background(), e); err == nil {
				t.Fatal("partial OS census was incorrectly accepted as a clean installation")
			}
		})
	}
}

func TestWindowsPartialHostRetainsBothLocalDNSWarnings(t *testing.T) {
	inspectors := partialHostInspectors(t, true, []windowsVOLVETaskRecord{}, []windowsVOLVEServiceRecord{})
	inspectors.DNS = func(_ context.Context, query string) ([]byte, error) {
		if query != WindowsFreshDNSAdapterQuery { t.Fatal("unapproved DNS query") }
		return freshDNSRows(t, []windowsFreshDNSAdapterRow{
			{InterfaceIndex: 7, Family: "IPv4", Servers: []string{"127.0.0.2"}},
			{InterfaceIndex: 7, Family: "IPv6", Servers: []string{"::1"}},
		}), nil
	}
	result, err := InspectWindowsFreshPartialHostReadOnly(context.Background(), "", "", inspectors)
	if err != nil { t.Fatal(err) }
	if !result.Evidence.LocalIPv4DNSConfigured || !result.Evidence.LocalIPv6DNSConfigured {
		t.Fatal("partial host census lost DNS loopback evidence")
	}
	if err := CheckFreshMotorInstallReadiness(context.Background(), result.Evidence); err == nil {
		t.Fatal("loopback adapter observation incorrectly authorized install")
	}
}

func TestWindowsPartialHostFailClosedOnNonAdminOrFailure(t *testing.T) {
	for _, tc := range []struct {
		name  string
		token []byte
	}{
		{"not-elevated", []byte(`{"Elevated":false}`)},
		{"missing-field", []byte(`{}`)},
		{"missing-object", []byte(`null`)},
		{"unknown-field", []byte(`{"Elevated":true,"Faked":true}`)},
		{"trailing-data", []byte(`{"Elevated":true} true`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tasksCalled := false
			scanners := partialHostInspectors(t, true, []windowsVOLVETaskRecord{}, []windowsVOLVEServiceRecord{})
			scanners.Admin = func(context.Context, string) ([]byte, error) { return tc.token, nil }
			scanners.Tasks = func(context.Context, string) ([]byte, error) {
				tasksCalled = true
				return []byte("[]"), nil
			}
			if _, err := InspectWindowsFreshPartialHostReadOnly(context.Background(), "", "", scanners); err == nil || tasksCalled {
				t.Fatal("non-admin or invalid token advanced into service/task inventory")
			}
		})
	}
	inspectors := partialHostInspectors(t, true, []windowsVOLVETaskRecord{}, []windowsVOLVEServiceRecord{})
	inspectors.Services = func(context.Context, string) ([]byte, error) {
		return nil, errors.New("Win32_Service unavailable")
	}
	if evidence, err := InspectWindowsFreshPartialHostReadOnly(context.Background(), "", "", inspectors); err == nil ||
		evidence.Evidence.InspectedTaskScheduler || evidence.Evidence.InspectedServices {
		t.Fatal("partial failure leaked a success-shaped inventory")
	}
	inspectors = partialHostInspectors(t, true, []windowsVOLVETaskRecord{}, []windowsVOLVEServiceRecord{})
	inspectors.DNS = func(context.Context, string) ([]byte, error) {
		return nil, errors.New("DNS adapter enumeration unavailable")
	}
	if evidence, err := InspectWindowsFreshPartialHostReadOnly(context.Background(), "", "", inspectors); err == nil ||
		evidence.Evidence.InspectedDNSAdapters || evidence.Evidence.InspectedTaskScheduler {
		t.Fatal("DNS read-only inventory failure leaked successful evidence")
	}
	if _, err := DefaultWindowsFreshAdminInspect(context.Background(), "Start-Service VOLVE"); err == nil {
		t.Fatal("unapproved privileged Windows token query accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	scanners := partialHostInspectors(t, true, []windowsVOLVETaskRecord{}, []windowsVOLVEServiceRecord{})
	scanners.Admin = func(context.Context, string) ([]byte, error) {
		called = true
		return []byte(`{"Elevated":true}`), nil
	}
	if _, err := InspectWindowsFreshPartialHostReadOnly(ctx, "", "", scanners); !errors.Is(err, context.Canceled) || called {
		t.Fatalf("cancelled request queried Windows: %v", err)
	}
}

func TestWindowsPartialHostNativeOSQueriesAreReadOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("Windows native inventory integration")
	}
	ctx := context.Background()
	elevated, err := InspectWindowsElevatedTokenReadOnly(ctx, DefaultWindowsFreshAdminInspect)
	if err != nil {
		t.Fatalf("real Windows token query: %v", err)
	}
	if !elevated {
		if _, err := InspectWindowsFreshPartialHostReadOnly(ctx, "", "", WindowsFreshPartialHostInspectors{
			Admin: DefaultWindowsFreshAdminInspect, Tasks: DefaultWindowsFreshTaskInspect,
			Services: DefaultWindowsFreshServiceInspect, DNS: DefaultWindowsFreshDNSAdapterInspect,
		}); err == nil {
			t.Fatal("non-admin Windows token was treated as elevated")
		}
		t.Log("READ ONLY: native runner lacks Administrator token; correctly refused combined census")
		return
	}
	result, err := InspectWindowsFreshPartialHostReadOnly(ctx, "", "", WindowsFreshPartialHostInspectors{
		Admin: DefaultWindowsFreshAdminInspect, Tasks: DefaultWindowsFreshTaskInspect,
		Services: DefaultWindowsFreshServiceInspect, DNS: DefaultWindowsFreshDNSAdapterInspect,
	})
	if err != nil {
		t.Fatalf("real Windows partial host census: %v", err)
	}
	if err := CheckFreshMotorInstallReadiness(ctx, result.Evidence); err == nil {
		t.Fatal("real partial OS census authorized an unverified DNS installation")
	}
	t.Logf("READ ONLY: Windows elevated; %d tasks; %d services; %d DNS adapter families; three inventories remain unknown",
		result.Evidence.VOLVETaskCount, result.Evidence.VOLVEServiceCount, result.DNSAdapterRecords)
}
