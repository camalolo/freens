// setup_windows.go — `setup` on Windows 10/11: the same one-command
// installer as the Linux path, against the OS primitives Windows actually
// has. The goal is identical: from "nothing installed" to "freens resolves
// names system-wide, survives reboot, restarts when it crashes":
//
//	(a) home.Ensure()                      — the state dir (%ProgramData%\freens)
//	(b) <home>\freens.conf  (if absent)    — daemon config: resolver DIRECTLY on
//	      127.0.0.1:53 (Windows has no privileged-port concept), upstream
//	      servers captured from this machine's adapters, [tld-routes] as on
//	      Linux, DHT listener + node identity + persistent store
//	(c) <home>\seeds.conf   (if absent)    — the pinned default community seed
//	(d) SCM service "freens"               — LocalSystem, automatic start,
//	      restart-on-failure recovery; the Windows analogue of the systemd
//	      system unit (boots with the machine, no login, no linger)
//	(e) OS resolver wiring                 — every adapter that carries DNS
//	      servers is pointed at 127.0.0.1 (captured lists saved to
//	      dns-backup.json for uninstall), plus a program-scoped inbound
//	      firewall rule for the DHT port
//
// --uninstall reverses (d)/(e) and KEEPS keys + store (says so).
//
// Everything privileged (SCM, Set-DnsClientServerAddress, netsh firewall)
// needs the elevated token. A non-elevated interactive run relaunches
// ITSELF via UAC (Start-Process -Verb RunAs); the elevated child keeps its
// console open at the end (-console-wait) so the output stays readable.
// A non-interactive non-elevated run prints the exact manual steps.
package cli

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/home"
	"github.com/camalolo/freens/internal/winsvc"
)

// windowsFirewallRuleName is the inbound rule setup manages (program-
// scoped, DHT UDP port only). setup -uninstall deletes it by name.
const windowsFirewallRuleName = "freens DHT"

// windowsFirewallOutboundRuleName is the outbound twin (program-scoped,
// all protocols) — hardened machines run BlockOutbound by default, and the
// daemon must reach upstream resolvers, DHT peers and GitHub.
const windowsFirewallOutboundRuleName = "freens outbound"

// winRunElevatedGate var-gates the elevation relaunch for tests.
var winRunElevatedGate = windowsRunElevated

// The winsvc entries used by the setup flows, as vars so linux tests can
// run the whole orchestration with stubs (the real SCM calls only exist
// on windows).
var (
	winSvcInstall  = winsvc.Install
	winSvcRemove   = winsvc.Remove
	winSvcElevated = winsvc.IsElevated
	winSvcRunning  = winsvc.Running
	winSvcStop     = winsvc.Stop
	winSvcStart    = winsvc.Start
)

// platform is the effective platform for dispatch decisions (testable:
// TestMain pins windows dev boxes to the linux flows so the linux-era
// tests keep testing the linux code — real file naming and OS effects
// still follow runtime.GOOS). goosWindows is its windows test.
var platform = runtime.GOOS

// goosWindows routes setup's platform dispatch (var so tests can force the
// windows branch on linux).
var goosWindows = platform == "windows"

// windowsRelay relays a command line through the PowerShell indirection
// (netsh etc.). Swapped by tests.
var windowsRelay = func(args ...string) error {
	c := exec.Command(args[0], args[1:]...)
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	return c.Run()
}

// ---------------------------------------------------------------------------
// setup (install)
// ---------------------------------------------------------------------------

func setupInstallWindows(consoleWait bool) error {
	// Elevation: SCM writes, adapter DNS and netsh all need the admin
	// token. A UAC relaunch delegates the whole verb to an elevated copy
	// of this same binary and waits for it.
	if !winSvcElevated() {
		return winRunElevatedGate("setup")
	}

	var written []string

	// (a) state dir layout.
	if err := home.Ensure(); err != nil {
		return err
	}

	// (b) daemon config (+ node identity), only when absent.
	confPath := home.ConfPath()
	if !sysStatExists(confPath) {
		nodeKey := filepath.Join(home.Dir(), "node.key")
		if !sysStatExists(nodeKey) {
			nkp, err := crypto.Generate()
			if err != nil {
				return err
			}
			if err := writeKeyFile(nodeKey, nkp); err != nil {
				return fmt.Errorf("writing node key: %w", err)
			}
			written = append(written, nodeKey)
		}
		upstreams, err := windowsCaptureAdapterDNS()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: warning: could not read the current DNS servers (%v); using public resolvers\n", ProgName, err)
		}
		conf := fmt.Sprintf(setupWindowsConfTemplate,
			strings.Join(flattenDNSServers(upstreams), ", "), nodeKey, home.StoreDir())
		if err := os.WriteFile(confPath, []byte(conf), 0o600); err != nil {
			return fmt.Errorf("writing %s: %w", confPath, err)
		}
		written = append(written, confPath)
	}

	// (c) pinned default seeds, only when absent.
	seedsPath := home.SeedsPath()
	if !sysStatExists(seedsPath) {
		seeds := fmt.Sprintf(setupSeedsTemplate, home.PeersDir(), defaultSeedLine)
		if err := os.WriteFile(seedsPath, []byte(seeds), 0o600); err != nil {
			return fmt.Errorf("writing %s: %w", seedsPath, err)
		}
		written = append(written, seedsPath)
	}

	// (d) the SCM service — boots at power-on, restarts on failure.
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locating the service binary: %w", err)
	}
	exe, _ = filepath.Abs(exe)
	fmt.Printf("installing service %q (%s daemon -config %s)…\n", winsvc.Name, exe, confPath)
	if err := winSvcInstall(winsvc.InstallOptions{
		Binary: exe,
		Args:   []string{"daemon", "-config", confPath},
	}); err != nil {
		return fmt.Errorf("installing the service: %w", err)
	}
	written = append(written, "service "+winsvc.Name+" (LocalSystem, automatic start, restart-on-failure)")

	// (e1) firewall: a program-scoped inbound rule for the DHT port so the
	// node is reachable (UDP inbound is silently dropped by Windows
	// Defender otherwise — the node would gossip out but never hear
	// answers).
	if err := windowsFirewallRule("add", exe); err != nil {
		fmt.Fprintf(os.Stderr, "%s: warning: could not add the inbound firewall rule (%v) — the DHT may be unreachable (outbound still works)\n", ProgName, err)
	} else {
		fmt.Printf("firewall: inbound UDP 15353 + outbound (both scoped to %s) allowed\n", exe)
	}

	// (e2) OS resolver wiring (capture + backup first).
	resolverNote := wireOSResolverWindows()

	// Summary — mirror the Linux wording so docs stay one story.
	fmt.Println()
	fmt.Println("setup complete. Installed:")
	for _, w := range written {
		fmt.Printf("    %s\n", w)
	}
	fmt.Println(resolverNote)
	fmt.Printf("next: `freens register <you>` to claim a namespace, then `freens name www.<you>`\n")
	fmt.Printf("      (or let `freens start <you>` do all of it)\n")
	fmt.Printf("check health any time with `freens doctor`; protect your keys with `freens backup`\n")

	windowsConsoleWait(consoleWait)
	return nil
}

// wireOSResolverWindows is the Windows half of (e): backup the current
// per-adapter DNS lists once, then point them at the daemon loopback.
// Idempotent like its Linux sibling (returns an "already wired" note).
func wireOSResolverWindows() string {
	port := portOfAddr(effectiveDNSAddr())
	if port != "53" {
		return fmt.Sprintf("OS resolver: NOT wired — the daemon listens on %s, but this wiring model needs :53 (set [listen] udp = 127.0.0.1:53)", effectiveDNSAddr())
	}
	cur, err := windowsCaptureAdapterDNS()
	if err != nil {
		return fmt.Sprintf("OS resolver: could not read the adapter DNS (%v) — point every adapter's DNS server at %s manually", err, dnsLoopbackServer)
	}
	if windowsAdapterDNSWired(dnsLoopbackServer) {
		// Already wired — still (re)apply: windowsSetAdapterDNS is
		// idempotent per adapter and this is what converges older installs
		// onto new wiring details (e.g. the rescue suffix added in the
		// v0.11.0 single-label fix).
		if err := windowsSetAdapterDNS(dnsLoopbackServer); err != nil {
			return fmt.Sprintf("OS resolver: wired, but the re-apply failed (%v) — existing wiring kept", err)
		}
		if err := saveDNSBackup(cur); err != nil {
			fmt.Fprintf(os.Stderr, "%s: warning: dns backup not saved: %v\n", ProgName, err)
		}
		return fmt.Sprintf("OS resolver: already wired (adapter DNS -> %s, suffix %q; conventional names forward upstream through the daemon)", dnsLoopbackServer, windowsDNSSuffix)
	}
	if err := saveDNSBackup(cur); err != nil {
		fmt.Fprintf(os.Stderr, "%s: warning: dns backup not saved: %v\n", ProgName, err)
	}
	if err := windowsSetAdapterDNS(dnsLoopbackServer); err != nil {
		return fmt.Sprintf(`OS resolver: MANUAL step needed (%v) — in an elevated PowerShell:
    Get-DnsClientServerAddress | Where-Object {$_.ServerAddresses} | Set-DnsClientServerAddress -ServerAddresses @('%s')`, err, dnsLoopbackServer)
	}
	return fmt.Sprintf("OS resolver: adapter DNS -> %s (previous lists in %s; conventional names forward upstream through the daemon)",
		dnsLoopbackServer, dnsBackupPath())
}

// windowsFirewallRule adds/deletes the program-scoped firewall rules.
// Two of them:
//
//	inbound  "freens DHT"      — UDP 15353 to this binary (Defender
//	                             silently drops DHT inbound otherwise)
//	outbound "freens outbound" — all traffic FROM this binary (upstream
//	                             DNS, DHT peers, `upgrade` downloads).
//	                             Hardened machines ship BlockOutbound by
//	                             default (found live on the desktop test
//	                             box: every unsigned binary's connect()
//	                             fails with WSAEACCES until allow-listed
//	                             per program — curl etc. worked, so this
//	                             was invisible until a real daemon ran).
//
// Both are scoped to the freens executable, so the machine's default-deny
// posture stays intact for everything else. netsh via windowsRelay so
// tests (and exotic shells) can intercept.
func windowsFirewallRule(addOrDelete, exe string) error {
	var ruleSets [][]string
	if addOrDelete == "add" {
		// Delete-then-add: netsh "add" happily creates DUPLICATE rules on a
		// setup re-run (same name), so make every install idempotent the
		// same way the systemd unit write is.
		for _, name := range []string{windowsFirewallRuleName, windowsFirewallOutboundRuleName} {
			_ = windowsRelay("netsh", "advfirewall", "firewall", "delete", "rule", "name="+name)
		}
		ruleSets = [][]string{
			{"netsh", "advfirewall", "firewall", "add", "rule",
				"name=" + windowsFirewallRuleName,
				"dir=in", "action=allow",
				"program=" + exe,
				"protocol=udp", "localport=15353",
				"profile=any"},
			{"netsh", "advfirewall", "firewall", "add", "rule",
				"name=" + windowsFirewallOutboundRuleName,
				"dir=out", "action=allow",
				"program=" + exe,
				"profile=any"},
		}
	} else {
		ruleSets = [][]string{
			{"netsh", "advfirewall", "firewall", "delete", "rule",
				"name=" + windowsFirewallRuleName},
			{"netsh", "advfirewall", "firewall", "delete", "rule",
				"name=" + windowsFirewallOutboundRuleName},
		}
	}
	var errs []string
	for _, args := range ruleSets {
		if err := windowsRelay(args...); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// windowsRunElevated relaunches THIS binary through UAC with the given
// arguments and waits for it. Only meaningful on an interactive console
// (the UAC prompt IS the consent); elsewhere it fails with the manual
// instructions instead.
func windowsRunElevated(args ...string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locating this executable: %w", err)
	}
	if !sysIsTerminal() {
		return fmt.Errorf("%s needs Windows admin rights (elevation) — open an elevated PowerShell (right-click -> Run as administrator) and run `%s %s` there",
			ProgName, filepath.Base(exe), strings.Join(args, " "))
	}
	// The elevated child gets its own console window: -console-wait keeps
	// it open at the end so the user can read the summary.
	child := append(append([]string{}, args...), "-console-wait")
	quoted := make([]string, 0, len(child))
	for _, a := range child {
		quoted = append(quoted, "'"+psQuote(a)+"'")
	}
	script := fmt.Sprintf("Start-Process -FilePath '%s' -Verb RunAs -Wait -ArgumentList @(%s)",
		psQuote(exe), strings.Join(quoted, ","))
	fmt.Printf("requesting admin rights (UAC) to run: %s %s…\n", filepath.Base(exe), strings.Join(child, " "))
	c := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	c.Stdout, c.Stderr, c.Stdin = os.Stdout, os.Stderr, os.Stdin
	if err := c.Run(); err != nil {
		return fmt.Errorf("elevated relaunch declined or failed (%v) — run `%s %s` from an elevated PowerShell instead", err, filepath.Base(exe), strings.Join(args, " "))
	}
	fmt.Println("elevated run finished — verify with `freens doctor`.")
	return nil
}

// windowsConsoleWait keeps an elevated child's console open until Enter so
// its output is readable (no-op for normal runs and non-TTY sessions).
func windowsConsoleWait(wait bool) {
	if !wait || !sysIsTerminal() {
		return
	}
	fmt.Print("\nPress Enter to close this window…")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
}

// flattenDNSServers dedups the captured per-adapter servers into the
// [upstream] list (capped at 4 — more is noise, fewer is fine).
func flattenDNSServers(adapters []dnsAdapter) []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range adapters {
		for _, s := range a.Servers {
			// Skip site-local junk Windows sometimes lists (fec0:… legacy
			// "site" addresses) and the wildcard.
			if s == "0.0.0.0" || s == "::" || strings.HasPrefix(s, "fec0:") {
				continue
			}
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
		if len(out) >= 4 {
			break
		}
	}
	if len(out) == 0 {
		out = []string{"9.9.9.9", "1.1.1.1"} // the daemon's own default
	}
	return out
}

// ---------------------------------------------------------------------------
// setup (uninstall)
// ---------------------------------------------------------------------------

func setupUninstallWindows(consoleWait bool) error {
	if !winSvcElevated() {
		return winRunElevatedGate("setup", "-uninstall")
	}
	uninstallWindowsCore()
	windowsConsoleWait(consoleWait)
	return nil
}

// uninstallWindowsCore is the machine-changing heart of the Windows
// uninstall: service removal, firewall rules, adapter DNS restore. Shared
// by `setup -uninstall` and `freens uninstall` (both call it elevated).
func uninstallWindowsCore() {
	// Service off + removed.
	fmt.Printf("removing service %q…\n", winsvc.Name)
	if err := winSvcRemove(); err != nil {
		fmt.Fprintf(os.Stderr, "%s: warning: service removal failed (%v)\n", ProgName, err)
	} else {
		fmt.Println("removed: service " + winsvc.Name)
	}

	// Firewall rule.
	if err := windowsFirewallRule("delete", ""); err != nil {
		fmt.Fprintf(os.Stderr, "%s: warning: firewall rule removal failed (%v)\n", ProgName, err)
	} else {
		fmt.Printf("removed: firewall rule %q\n", windowsFirewallRuleName)
	}

	// Adapter DNS restore (captured lists; best effort).
	if adapters := loadDNSBackup(); len(adapters) > 0 {
		if err := windowsRestoreAdapterDNS(adapters); err != nil {
			fmt.Fprintf(os.Stderr, "%s: warning: DNS restore failed (%v) — reset adapters manually with:\n    Get-NetAdapter | Set-DnsClientServerAddress -ResetServerAddresses\n", ProgName, err)
		} else {
			fmt.Printf("restored: adapter DNS (from %s)\n", dnsBackupPath())
			_ = os.Remove(dnsBackupPath())
		}
	}

	fmt.Println()
	fmt.Println("uninstalled: service + OS resolver wiring removed.")
	fmt.Printf("KEPT (your keys, names, and store): %s\n", home.Dir())
	fmt.Printf("delete everything with: Remove-Item -Recurse -Force %s\n", home.Dir())
}

// ---------------------------------------------------------------------------
// templates
// ---------------------------------------------------------------------------

// setupWindowsConfTemplate mirrors the Linux one with the two Windows
// deltas: the resolver listens DIRECTLY on :53 (no redirect scheme, no
// high-port fallback) and the upstream servers are the ones captured from
// this machine's adapters (a DHCP/router change means editing this file —
// the comment says so).
const setupWindowsConfTemplate = `; freens daemon configuration — written by ` + "`freens setup`" + ` (Windows); edit freely.
; The resolver listens DIRECTLY on 127.0.0.1:53 (Windows has no
; privileged-port concept) — setup points every network adapter's DNS at
; it. Conventional names are forwarded to the upstream servers below
; (captured from this machine's adapters at setup time; if your router or
; ISP changes them, update this list — ` + "`freens doctor`" + `'s DNS check will tell).
[listen]
udp = 127.0.0.1:53
tcp = 127.0.0.1:53

[upstream]
servers = %s

; Routing: dns-first is the SAFE default (spec line 772) — conventional
; names go to the upstream resolvers. The freens community namespace is NOT
; an ICANN TLD: asking upstreams for it first only leaks freens names in
; plaintext (and lets a spoofed upstream answer shadow the DHT one), so it
; gets an explicit freens-first route — freens first, DNS on a miss.
[tld-routes]
freens = freens-first
* = dns-first

; Windows single-label rescue: the OS resolver never resolves bare names
; ("ping desktop") — it appends the connection suffix (setup sets
; "freens") and never retries the bare form. This option makes an
; upstream NXDOMAIN for <name>.<unknown-suffix> — and the community
; namespace's own miss, <name>.freens — fall back to the freens name
; <name>. Ordinary DNS is untouched (real domains answer upstream before
; the rescue runs; custom routes other than freens-first never rescue).
[options]
suffix-rescue = true

; DHT side (spec 6): public listener, node identity, persistent store.
; UPnP port mapping is ON by default — write 'upnp = false' to disable.
[dht]
listen = 0.0.0.0:15353
node-seed = @%s
persist = %s
`
