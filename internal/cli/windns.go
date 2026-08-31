// windns — the OS resolver wiring for Windows. Model: the daemon listens
// DIRECTLY on 127.0.0.1:53 (Windows has no privileged-port concept), so
// setup replaces each network adapter's DNS server list with the loopback —
// no port-53 redirect, no resolv.conf. Conventional names are forwarded by
// the daemon to the upstream servers captured from these same adapters at
// setup time (freens.conf [upstream]).
//
// All adapter work goes through PowerShell cmdlets (Get/Set-
// DnsClientServerAddress, see windps_*.go): present on every Windows 10/11
// and admin-gated exactly like the rest of setup. Only adapters that HAD
// DNS servers are touched — a blank-slate adapter (rare) keeps its
// defaults, and the captured pre-freens lists are saved to
// <home>/dns-backup.json so `setup -uninstall` restores exactly what was
// there (the resolv.conf backup convention, per-adapter).
//
// The orchestration lives here untagged and runs everywhere through the
// winPowerShell indirection (a real PowerShell runner on windows, an error
// stub elsewhere) so tests exercise the whole flow on any GOOS.

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/camalolo/freens/internal/home"
)

// winPowerShell runs a PowerShell snippet (-NoProfile -NonInteractive) and
// returns its stdout. Real implementation on windows; stub elsewhere.
var winPowerShell = func(script string) (string, error) {
	return "", fmt.Errorf("windows only (called with: %s)", script)
}

// dnsLoopbackServer is the DNS server setup points every adapter at: the
// daemon's own listener.
const dnsLoopbackServer = "127.0.0.1"

// dnsAdapter is one network adapter's DNS server list as freens captures
// (and restores) it.
type dnsAdapter struct {
	Alias   string   `json:"alias"`
	Servers []string `json:"servers"`
}

// dnsBackupJSON is the <home>/dns-backup.json wire form.
type dnsBackupJSON struct {
	SavedAt  int64        `json:"saved_at"`
	Adapters []dnsAdapter `json:"adapters"`
}

// psAdapter is the PowerShell wire shape (ConvertTo-Json of Select-Object
// InterfaceAlias,ServerAddresses).
type psAdapter struct {
	InterfaceAlias  string   `json:"InterfaceAlias"`
	ServerAddresses []string `json:"ServerAddresses"`
}

// parseAdapterDNSJSON parses `Get-DnsClientServerAddress | Select-Object
// InterfaceAlias,ServerAddresses | ConvertTo-Json` output, keeping only
// adapters that HAVE servers (blank slates are never touched). PowerShell
// emits a bare OBJECT when the pipeline holds exactly one element — both
// shapes parse.
func parseAdapterDNSJSON(data string) ([]dnsAdapter, error) {
	var raw []psAdapter
	if err := json.Unmarshal([]byte(data), &raw); err != nil {
		var one psAdapter
		if err2 := json.Unmarshal([]byte(data), &one); err2 != nil {
			return nil, fmt.Errorf("parsing adapter DNS output: %w (raw: %.200s)", err, data)
		}
		raw = []psAdapter{one}
	}
	var kept []dnsAdapter
	for _, a := range raw {
		alias := strings.TrimSpace(a.InterfaceAlias)
		if alias == "" {
			continue
		}
		var servers []string
		for _, s := range a.ServerAddresses {
			if s = strings.TrimSpace(s); s != "" {
				servers = append(servers, s)
			}
		}
		if len(servers) > 0 {
			kept = append(kept, dnsAdapter{Alias: alias, Servers: servers})
		}
	}
	return kept, nil
}

// windowsCaptureAdapterDNS returns every adapter that HAS DNS servers
// configured (both families, grouped by InterfaceAlias).
func windowsCaptureAdapterDNS() ([]dnsAdapter, error) {
	out, err := winPowerShell("Get-DnsClientServerAddress | Select-Object InterfaceAlias,ServerAddresses | ConvertTo-Json -Compress")
	if err != nil {
		return nil, fmt.Errorf("reading adapter DNS (Get-DnsClientServerAddress): %w", err)
	}
	return parseAdapterDNSJSON(out)
}

// windowsDNSSuffix is the connection-specific suffix setup sets alongside
// the DNS wiring: the project's own namespace, so a name reads naturally
// as "desktop.freens" in every app. The Windows resolver resolves
// single-label names ONLY by appending a suffix and querying DNS
// ("desktop" → "desktop.freens") — with no suffix configured it never
// sends those queries at all (found live: ping/nslookup-of-record worked
// while every real app failed). The daemon's [options] suffix-rescue
// answers the suffixed form (the freens-first route's miss borrows the
// bare name); see setupwin.go's config template for the full story.
const windowsDNSSuffix = "freens"

// windowsSetAdapterDNS points every adapter that currently carries DNS
// servers at server (the daemon loopback) and gives it the rescue suffix.
// Setting the complete server list per adapter also clears any IPv6
// resolver entries — the daemon serves both families from its v4 loopback
// listener.
func windowsSetAdapterDNS(server string) error {
	adapters, err := windowsCaptureAdapterDNS()
	if err != nil {
		return err
	}
	for _, a := range adapters {
		script := fmt.Sprintf("Set-DnsClientServerAddress -InterfaceAlias '%s' -ServerAddresses @('%s'); Set-DnsClient -InterfaceAlias '%s' -ConnectionSpecificSuffix '%s'",
			psQuote(a.Alias), psQuote(server), psQuote(a.Alias), psQuote(windowsDNSSuffix))
		if _, err := winPowerShell(script); err != nil {
			return fmt.Errorf("wiring adapter %q DNS to %s: %w", a.Alias, server, err)
		}
	}
	return nil
}

// windowsRestoreAdapterDNS puts back captured per-adapter server lists (and
// asks the DHCP-provided defaults for anything captured empty), resetting
// the rescue suffix setup added.
func windowsRestoreAdapterDNS(adapters []dnsAdapter) error {
	for _, a := range adapters {
		items := make([]string, 0, len(a.Servers))
		for _, s := range a.Servers {
			items = append(items, "'"+psQuote(s)+"'")
		}
		script := fmt.Sprintf("Set-DnsClientServerAddress -InterfaceAlias '%s' -ServerAddresses @(%s); Set-DnsClient -InterfaceAlias '%s' -ResetConnectionSpecificSuffix",
			psQuote(a.Alias), strings.Join(items, ","), psQuote(a.Alias))
		if _, err := winPowerShell(script); err != nil {
			return fmt.Errorf("restoring DNS on %q: %w", a.Alias, err)
		}
	}
	return nil
}

// psQuote escapes a string for embedding inside PowerShell single quotes
// (double the single quotes).
func psQuote(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

// saveDNSBackup persists the captured lists (best effort — its absence
// only degrades uninstall to a DHCP reset).
func saveDNSBackup(adapters []dnsAdapter) error {
	if len(adapters) == 0 {
		return nil
	}
	b, err := json.MarshalIndent(dnsBackupJSON{SavedAt: time.Now().Unix(), Adapters: adapters}, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic0600(dnsBackupPath(), b)
}

// loadDNSBackup reads the captured lists (nil when absent/corrupt).
func loadDNSBackup() []dnsAdapter {
	b, err := os.ReadFile(dnsBackupPath())
	if err != nil {
		return nil
	}
	var bk dnsBackupJSON
	if json.Unmarshal(b, &bk) != nil {
		return nil
	}
	return bk.Adapters
}

// dnsBackupPath is <home>/dns-backup.json.
func dnsBackupPath() string { return filepath.Join(home.Dir(), "dns-backup.json") }

// windowsAdapterDNSWired reports whether at least one adapter's server
// list contains addr (the setup "already wired" / doctor check).
func windowsAdapterDNSWired(addr string) bool {
	adapters, err := windowsCaptureAdapterDNS()
	if err != nil {
		return false
	}
	for _, a := range adapters {
		for _, s := range a.Servers {
			if s == addr {
				return true
			}
		}
	}
	return false
}
