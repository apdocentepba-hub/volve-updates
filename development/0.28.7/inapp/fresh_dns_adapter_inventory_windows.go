//go:build windows

package motorupdate

// Host-wide read-only Windows DNS adapter census for the future fresh motor
// installer. Never changes an adapter, DNS settings, hosts file or service.
// Evidence from this check is NOT sufficient to authorize a fresh install.
import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const WindowsFreshDNSAdapterQuery = `$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';
$items=@(Get-DnsClientServerAddress -ErrorAction Stop | ForEach-Object {
  $family=switch ([string]$_.AddressFamily) {
    '2' {'IPv4'} '23' {'IPv6'} 'IPv4' {'IPv4'} 'IPv6' {'IPv6'}
    'InterNetwork' {'IPv4'} 'InterNetworkV6' {'IPv6'}
    default {'Unknown'}
  };
  [pscustomobject]@{
    InterfaceIndex=[uint32]$_.InterfaceIndex;
    Family=[string]$family;
    Servers=@($_.ServerAddresses | Where-Object { $null -ne $_ -and [string]$_ -ne '' })
  }
});ConvertTo-Json -InputObject $items -Compress -Depth 5`

type WindowsFreshDNSAdapterInspect func(context.Context, string) ([]byte, error)

func DefaultWindowsFreshDNSAdapterInspect(ctx context.Context, query string) ([]byte, error) {
	if query != WindowsFreshDNSAdapterQuery {
		return nil, errors.New("only fixed read-only Windows DNS adapter inventory allowed")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root := os.Getenv("SystemRoot")
	if !filepath.IsAbs(root) {
		return nil, errors.New("Windows system root unavailable")
	}
	ps := filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	output, err := exec.CommandContext(ctx, ps, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", query).Output()
	if err != nil {
		return nil, fmt.Errorf("Windows DNS adapter read-only inventory failed: %w", err)
	}
	return output, nil
}

type windowsFreshDNSAdapterRow struct {
	InterfaceIndex uint32   `json:"InterfaceIndex"`
	Family         string   `json:"Family"`
	Servers        []string `json:"Servers"`
}

type WindowsFreshDNSAdapterInventory struct {
	AdapterFamilyRecords int
	LocalIPv4DNSConfigured bool
	LocalIPv6DNSConfigured bool
}

// InspectWindowsFreshDNSAdaptersReadOnly scans every adapter and both address
// families (not just the first active adapter). Any loopback resolver,
// including 127.0.0.2, blocks the clean-install path. An unknown family,
// missing record, bad IP or contradictory duplicate FAILS CLOSED.
func InspectWindowsFreshDNSAdaptersReadOnly(ctx context.Context, inspect WindowsFreshDNSAdapterInspect) (WindowsFreshDNSAdapterInventory, error) {
	var zero WindowsFreshDNSAdapterInventory
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if inspect == nil {
		return zero, errors.New("missing independent Windows DNS adapter inspector")
	}
	raw, err := inspect(ctx, WindowsFreshDNSAdapterQuery)
	if err != nil {
		return zero, err
	}
	if len(raw) < 2 || len(raw) > 1<<20 {
		return zero, errors.New("DNS adapter evidence absent or oversized")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var rows []windowsFreshDNSAdapterRow
	if err := decoder.Decode(&rows); err != nil {
		return zero, fmt.Errorf("invalid Windows DNS adapter inventory: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return zero, errors.New("trailing DNS adapter inventory data")
	}
	if len(rows) == 0 || len(rows) > 512 {
		return zero, errors.New("missing or excessively large adapter family inventory")
	}
	seen := make(map[string]bool, len(rows))
	result := WindowsFreshDNSAdapterInventory{AdapterFamilyRecords: len(rows)}
	for _, row := range rows {
		if row.InterfaceIndex == 0 || (row.Family != "IPv4" && row.Family != "IPv6") || row.Servers == nil {
			return zero, errors.New("incomplete or unknown Windows adapter family record")
		}
		key := fmt.Sprintf("%d/%s", row.InterfaceIndex, row.Family)
		if seen[key] {
			return zero, errors.New("duplicate Windows adapter family record")
		}
		seen[key] = true
		for _, rawAddress := range row.Servers {
			if rawAddress == "" || strings.TrimSpace(rawAddress) != rawAddress {
				return zero, errors.New("malformed DNS server address")
			}
			ip, parseErr := netip.ParseAddr(rawAddress)
			if parseErr != nil || !ip.IsValid() {
				return zero, errors.New("unparseable Windows DNS server address")
			}
			if (row.Family == "IPv4" && !ip.Is4()) || (row.Family == "IPv6" && !ip.Is6()) {
				return zero, errors.New("DNS server address family disagrees with adapter")
			}
			if ip.Unmap().IsLoopback() {
				if row.Family == "IPv4" {
					result.LocalIPv4DNSConfigured = true
				} else {
					result.LocalIPv6DNSConfigured = true
				}
			}
		}
	}
	return result, nil
}
