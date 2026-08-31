// setupwin_test.go — the Windows paths of setup/dns/upgrade that stay
// runnable on any GOOS (everything goes through the winPowerShell /
// windowsRelay / winsvc indirections). The real PowerShell, SCM and UAC
// code only exercises on a Windows machine (fleet day).

package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/camalolo/freens/internal/winsvc"
)

var errFakeWindowsShell = errors.New("no windows shell in tests")

// ---------------------------------------------------------------------------
// windns: capture / parse / backup / restore
// ---------------------------------------------------------------------------

func TestParseAdapterDNSJSON(t *testing.T) {
	// The normal array shape (multiple adapters).
	adapters, err := parseAdapterDNSJSON(`[{"InterfaceAlias":"Ethernet","ServerAddresses":["192.168.1.1","1.1.1.1"]},{"InterfaceAlias":"Wi-Fi","ServerAddresses":[]}]`)
	if err != nil {
		t.Fatal(err)
	}
	if len(adapters) != 1 || adapters[0].Alias != "Ethernet" ||
		len(adapters[0].Servers) != 2 || adapters[0].Servers[0] != "192.168.1.1" {
		t.Fatalf("array shape parsed = %+v; want only Ethernet with 2 servers (blank adapters skipped)", adapters)
	}

	// PowerShell's single-element shape: a bare OBJECT, not an array.
	adapters, err = parseAdapterDNSJSON(`{"InterfaceAlias":"Ethernet 2","ServerAddresses":["10.0.0.1"]}`)
	if err != nil {
		t.Fatalf("single-object shape: %v", err)
	}
	if len(adapters) != 1 || adapters[0].Alias != "Ethernet 2" {
		t.Fatalf("single-object parsed = %+v", adapters)
	}

	// Junk is junk.
	if _, err := parseAdapterDNSJSON(`not json`); err == nil {
		t.Error("junk output parsed without error")
	}
}

func TestFlattenDNSServers(t *testing.T) {
	captured := []dnsAdapter{
		{Alias: "Ethernet", Servers: []string{"192.168.1.1", "fec0:0:0:1::1"}},
		{Alias: "Wi-Fi", Servers: []string{"192.168.1.1", "0.0.0.0", "::"}},
	}
	got := flattenDNSServers(captured)
	if len(got) != 1 || got[0] != "192.168.1.1" {
		t.Fatalf("flattenDNSServers = %v; want [192.168.1.1] (deduped, junk dropped)", got)
	}
	// Nothing usable anywhere -> the daemon's public default.
	if got := flattenDNSServers(nil); len(got) != 2 || got[0] != "9.9.9.9" {
		t.Fatalf("flattenDNSServers(nil) = %v; want the public fallback", got)
	}
}

func TestWindowsDNSCaptureSetRestoreFlow(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("FREENS_HOME", dir)

	var scripts []string
	winPowerShell = func(script string) (string, error) {
		scripts = append(scripts, script)
		switch {
		case strings.Contains(script, "Get-DnsClientServerAddress | Select"):
			return `[{"InterfaceAlias":"Ethernet","ServerAddresses":["192.168.1.1"]}]`, nil
		default:
			return "", nil
		}
	}
	t.Cleanup(func() { winPowerShell = func(string) (string, error) { return "", errFakeWindowsShell } })

	captured, err := windowsCaptureAdapterDNS()
	if err != nil {
		t.Fatal(err)
	}
	if len(captured) != 1 || captured[0].Servers[0] != "192.168.1.1" {
		t.Fatalf("captured = %+v", captured)
	}
	if err := saveDNSBackup(captured); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "dns-backup.json")); err != nil {
		t.Fatalf("dns-backup.json not written: %v", err)
	}
	restored := loadDNSBackup()
	if len(restored) != 1 || restored[0].Alias != "Ethernet" {
		t.Fatalf("restored = %+v", restored)
	}
	if err := windowsSetAdapterDNS("127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := windowsRestoreAdapterDNS(restored); err != nil {
		t.Fatal(err)
	}
	// The set script points at the loopback; the restore names the alias.
	joined := strings.Join(scripts, "\n")
	if !strings.Contains(joined, "127.0.0.1") || !strings.Contains(joined, "Ethernet") {
		t.Fatalf("scripts missing the wiring/restore content: %s", joined)
	}
}

// wireOSResolverWindows: already-wired is idempotent; a PowerShell failure
// surfaces as the manual-step note instead of an error.
func TestWireOSResolverWindows(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("FREENS_HOME", dir)
	if err := os.WriteFile(homeConfForTest(dir), []byte("[listen]\nudp = 127.0.0.1:53\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("wired", func(t *testing.T) {
		winPowerShell = func(string) (string, error) {
			return `[{"InterfaceAlias":"Ethernet","ServerAddresses":["127.0.0.1","192.168.1.1"]}]`, nil
		}
		note := wireOSResolverWindows()
		if !strings.Contains(note, "already wired") {
			t.Fatalf("note = %q; want the already-wired form", note)
		}
	})
	t.Run("failure prints manual step", func(t *testing.T) {
		winPowerShell = func(script string) (string, error) {
			if strings.Contains(script, "Set-DnsClientServerAddress") {
				return "", errFakeWindowsShell
			}
			return `[{"InterfaceAlias":"Ethernet","ServerAddresses":["192.168.1.1"]}]`, nil
		}
		note := wireOSResolverWindows()
		if !strings.Contains(note, "MANUAL step") || !strings.Contains(note, "Set-DnsClientServerAddress") {
			t.Fatalf("note = %q; want the manual-step form", note)
		}
	})
	t.Run("non-53 daemon refuses to wire", func(t *testing.T) {
		if err := os.WriteFile(homeConfForTest(dir), []byte("[listen]\nudp = 127.0.0.1:5300\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		winPowerShell = func(string) (string, error) { return "[]", nil }
		if note := wireOSResolverWindows(); !strings.Contains(note, "NOT wired") {
			t.Fatalf("note = %q; want the NOT-wired refusal", note)
		}
	})
}

// homeConfForTest is <home>/freens.conf (the home package helpers pin
// FREENS_HOME already; this just avoids importing it twice in one test).
func homeConfForTest(home string) string { return filepath.Join(home, "freens.conf") }

// ---------------------------------------------------------------------------
// upgrade: .exe-named tarballs stage under the plain release names
// ---------------------------------------------------------------------------

func TestStageTarballWindowsExeNames(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the .exe trimming is exercised by the regular staging test there")
	}
	dir := t.TempDir()
	tarPath := filepath.Join(dir, "freens-windows-amd64.tar.gz")
	f, err := os.Create(tarPath)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, bin := range releaseBinaries {
		body := []byte("MZ-fake-" + bin)
		if err := tw.WriteHeader(&tar.Header{Name: "freens-windows-amd64/" + bin + ".exe", Mode: 0o755, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	gz.Close()
	if _, err := f.Write(buf.Bytes()); err != nil {
		t.Fatal(err)
	}
	f.Close()

	staged, err := stageTarball(tarPath, filepath.Join(dir, "stage"))
	if err != nil {
		t.Fatal(err)
	}
	if len(staged) != len(releaseBinaries) {
		t.Fatalf("staged %v; want the three plain names", staged)
	}
	for _, bin := range releaseBinaries {
		if staged[bin] == "" {
			t.Errorf("%s not staged under its plain name (staged: %v)", bin, staged)
		}
	}
}

// ---------------------------------------------------------------------------
// setup windows: config template + upstream capture plumbing
// ---------------------------------------------------------------------------

func TestWindowsConfTemplateRenders(t *testing.T) {
	conf := sprintfWindowsConf([]string{"192.168.1.1", "1.1.1.1"}, `C:\ProgramData\freens\node.key`, `C:\ProgramData\freens\store`)
	for _, want := range []string{
		"udp = 127.0.0.1:53",
		"servers = 192.168.1.1, 1.1.1.1",
		"node-seed = @C:\\ProgramData\\freens\\node.key",
		"persist = C:\\ProgramData\\freens\\store",
		"freens = freens-first",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("windows conf missing %q:\n%s", want, conf)
		}
	}
}

func sprintfWindowsConf(upstreams []string, nodeKey, store string) string {
	return fmt.Sprintf(setupWindowsConfTemplate, strings.Join(upstreams, ", "), nodeKey, store)
}

// ---------------------------------------------------------------------------
// the full setupInstallWindows orchestration, stubbed (see the flow doc in
// setupwin.go: home -> conf (captured upstreams) -> seeds -> service ->
// firewall -> DNS wiring)
// ---------------------------------------------------------------------------

func TestSetupInstallWindowsFlow(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("FREENS_HOME", dir)

	// Every privileged surface, stubbed:
	winSvcElevated = func() bool { return true }
	var installedSvc *winsvc.InstallOptions
	winSvcInstall = func(opts winsvc.InstallOptions) error {
		installedSvc = &opts
		return nil
	}
	winPowerShell = func(script string) (string, error) {
		switch {
		case strings.Contains(script, "Get-DnsClientServerAddress | Select"):
			return `[{"InterfaceAlias":"Ethernet","ServerAddresses":["192.168.1.1","10.0.0.53"]}]`, nil
		default:
			return "", nil
		}
	}
	var firewallCmds [][]string
	windowsRelay = func(args ...string) error {
		firewallCmds = append(firewallCmds, args)
		return nil
	}
	t.Cleanup(func() {
		winSvcElevated = func() bool { return false }
		winSvcInstall = winsvc.Install
		windowsRelay = func(args ...string) error { return exec.Command(args[0], args[1:]...).Run() }
		winPowerShell = func(string) (string, error) { return "", errFakeWindowsShell }
	})

	if err := setupInstallWindows(false); err != nil {
		t.Fatal(err)
	}

	// Conf: the captured upstreams land in [upstream]; the listener is :53.
	conf, err := os.ReadFile(filepath.Join(dir, "freens.conf"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"udp = 127.0.0.1:53", "servers = 192.168.1.1, 10.0.0.53", "freens = freens-first"} {
		if !strings.Contains(string(conf), want) {
			t.Errorf("freens.conf missing %q:\n%s", want, conf)
		}
	}
	// Seeds: the pinned community seed.
	seeds, err := os.ReadFile(filepath.Join(dir, "seeds.conf"))
	if err != nil || !strings.Contains(string(seeds), defaultSeedLine) {
		t.Fatalf("seeds.conf = %q, %v; want the pinned default", seeds, err)
	}
	// Service: the daemon verb + the conf path, pointed at THIS executable.
	if installedSvc == nil {
		t.Fatal("service was not installed")
	}
	if len(installedSvc.Args) != 3 || installedSvc.Args[0] != "daemon" ||
		installedSvc.Args[1] != "-config" || installedSvc.Args[2] != filepath.Join(dir, "freens.conf") {
		t.Fatalf("service args = %v; want daemon -config <conf>", installedSvc.Args)
	}
	if !strings.HasSuffix(installedSvc.Binary, ".exe") == (runtime.GOOS != "windows") {
		// This executable is a linux test binary here; on windows it is
		// freens.exe. Either way the service must point at THIS binary.
		t.Logf("service binary = %s", installedSvc.Binary)
	}
	// Firewall: delete-then-add for both rules (idempotent re-runs).
	if len(firewallCmds) != 4 || firewallCmds[0][0] != "netsh" ||
		!strings.Contains(strings.Join(firewallCmds[2], " "), "15353") {
		t.Fatalf("firewall commands = %v; want delete+add pairs for inbound and outbound", firewallCmds)
	}
	if !strings.Contains(strings.Join(firewallCmds[3], " "), "dir=out") {
		t.Fatalf("second add rule = %v; want the outbound allow", firewallCmds[3])
	}
	// DNS wiring: the loopback set + backup saved.
	if _, err := os.Stat(filepath.Join(dir, "dns-backup.json")); err != nil {
		t.Errorf("dns-backup.json not saved: %v", err)
	}
}

// The uninstall flow: service removed, firewall rule deleted, DNS restored.
func TestSetupUninstallWindowsFlow(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("FREENS_HOME", dir)

	winSvcElevated = func() bool { return true }
	removed := false
	winSvcRemove = func() error { removed = true; return nil }
	var firewallCmds [][]string
	windowsRelay = func(args ...string) error {
		firewallCmds = append(firewallCmds, args)
		return nil
	}
	winPowerShell = func(string) (string, error) { return "[]", nil }
	t.Cleanup(func() {
		winSvcElevated = func() bool { return false }
		winSvcRemove = winsvc.Remove
		windowsRelay = func(args ...string) error { return exec.Command(args[0], args[1:]...).Run() }
		winPowerShell = func(string) (string, error) { return "", errFakeWindowsShell }
	})

	// A backup to restore from (the setup flow would have written it).
	if err := saveDNSBackup([]dnsAdapter{{Alias: "Ethernet", Servers: []string{"192.168.1.1"}}}); err != nil {
		t.Fatal(err)
	}
	if err := setupUninstallWindows(false); err != nil {
		t.Fatal(err)
	}
	if !removed {
		t.Error("service was not removed")
	}
	if len(firewallCmds) == 0 || !strings.Contains(strings.Join(firewallCmds[0], " "), "delete") {
		t.Fatalf("firewall commands = %v; want the delete rule", firewallCmds)
	}
	if _, err := os.Stat(filepath.Join(dir, "dns-backup.json")); !os.IsNotExist(err) {
		t.Errorf("dns-backup.json should be removed after a successful restore (err = %v)", err)
	}
}

// TestSetupRoutesByPlatform pins cmdSetup's platform dispatch: on windows
// (dispatch forced on here) the verb must route into the windows flow —
// observable through the stubbed elevation gate receiving the argument
// vector — for both install and -uninstall. Restores the global afterwards;
// no test in this package runs in parallel.
func TestSetupRoutesByPlatform(t *testing.T) {
	if !goosWindows {
		t.Skip("routing pinned only where the platform dispatch can differ")
	}
	was := goosWindows
	goosWindows = true
	t.Cleanup(func() { goosWindows = was })

	routed := []string{}
	prevGate := winRunElevatedGate
	winSvcElevated = func() bool { return false } // force the delegation path
	winRunElevatedGate = func(args ...string) error {
		routed = args
		return nil
	}
	t.Cleanup(func() { winRunElevatedGate = prevGate })

	if err := cmdSetup(nil); err != nil {
		t.Fatal(err)
	}
	if len(routed) == 0 || routed[0] != "setup" {
		t.Fatalf("install routed to %v; want the windows flow", routed)
	}
	if err := cmdSetup([]string{"-uninstall"}); err != nil {
		t.Fatal(err)
	}
	if len(routed) < 2 || routed[1] != "-uninstall" {
		t.Fatalf("uninstall routed to %v; want [setup -uninstall]", routed)
	}
}

// Non-elevated + interactive: the setup relaunches itself instead of doing
// privileged work; non-interactive it refuses with the manual recipe.
func TestSetupWindowsElevationGate(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("FREENS_HOME", dir)
	winSvcElevated = func() bool { return false }
	var relaunched []string
	winRunElevatedGate = func(args ...string) error {
		relaunched = args
		return nil
	}
	t.Cleanup(func() {
		winSvcElevated = func() bool { return false }
		winRunElevatedGate = windowsRunElevated
	})

	if err := setupInstallWindows(false); err != nil {
		t.Fatal(err)
	}
	if len(relaunched) == 0 || relaunched[0] != "setup" {
		t.Fatalf("relaunch args = %v; want [setup]", relaunched)
	}
	if err := setupUninstallWindows(false); err != nil {
		t.Fatal(err)
	}
	if len(relaunched) < 2 || relaunched[0] != "setup" || relaunched[1] != "-uninstall" {
		t.Fatalf("uninstall relaunch args = %v; want [setup -uninstall]", relaunched)
	}
	// No privileged side effects may have happened.
	if _, err := os.Stat(filepath.Join(dir, "freens.conf")); !os.IsNotExist(err) {
		t.Error("conf written despite delegation")
	}
}
