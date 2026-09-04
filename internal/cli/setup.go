// setup.go — `setup`: the installer. One command takes a machine from
// "nothing installed" to "freens resolves names system-wide":
//
//	(a) home.Ensure()                      — the state dir layout
//	(b) <home>/freens.conf  (if absent)    — daemon config: resolver on the
//	      high port 127.0.0.1:5300, [tld-routes] * = dns-first, [dht] public
//	      listener + generated node identity (<home>/node.key, 0600) +
//	      persistent store
//	(c) <home>/seeds.conf   (if absent)    — the pinned default community seed
//	(d) systemd SYSTEM unit                — ExecStart=<this executable>
//	      daemon -config <home>/freens.conf, User=<invoking user>,
//	      Restart=on-failure, WantedBy=multi-user.target: the resolver is
//	      machine infrastructure — it boots at power-on with NO login and
//	      no linger. A pre-v0.3.0 --user unit is migrated away first.
//	(e) OS resolver wiring (sudo where allowed; exact commands printed
//	      otherwise): loopback :53 -> daemon-port nft/iptables redirect +
//	      plain `nameserver 127.0.0.1` resolv.conf.
//
// --uninstall reverses (d)/(e) and KEEPS keys + store (says so).
//
// All OS side effects (commands, privileged writes) go through the sys*
// indirections so tests run setup end-to-end against a temp home without
// touching the machine.
package cli

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/home"
)

// defaultSeedLine is the pinned community bootstrap seed written to
// seeds.conf (host:port#node-pubkey-hex). Updated v0.3.7: the promoted
// community node on freens.camalolo.com (the machine holds its public IP
// directly — no NAT between it and the internet).
const defaultSeedLine = "freens.camalolo.com:15353#38c5d5b399d3df19c33c7de69c06054f9b608b1a84782508879f8454b6195fd6"

// daemonDNSAddr is the high port the daemon's resolver listens on (53 needs
// privileges; the OS is pointed here instead).
const daemonDNSAddr = "127.0.0.1:5300"

// privileged paths setup/uninstall touch (vars for tests).
var (
	pathResolvConf     = "/etc/resolv.conf"
	pathResolvBackup   = "/etc/resolv.conf.freens.bak"
	pathNsswitch       = "/etc/nsswitch.conf"
	pathNsswitchBackup = "/etc/nsswitch.conf.freens-pre"
	pathResolvedDrop   = "/etc/systemd/resolved.conf.d/freens.conf"
	pathSystemctlUnit  = "" // set in tests to a temp path
	pathLegacyUserUnit = "" // set in tests to a temp path (pre-v0.3.0 unit)
)

// sysRun executes a system command; nil error = exit 0. Swapped out by tests.
var sysRun = func(name string, args ...string) error {
	c := exec.Command(name, args...)
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	return c.Run()
}

// sysSudo runs a command via NON-INTERACTIVE sudo (sudo -n): it either
// succeeds without a password prompt or fails fast — the callers fall back
// to sudoRun (interactive) / printManualCommands.
var sysSudo = func(args ...string) error {
	return sysRun("sudo", append([]string{"-n"}, args...)...)
}

// sysSudoInteractive runs sudo WITH terminal IO so it can ask for the
// admin password itself — used by sudoRun when sudo -n fails on a TTY.
// Swapped out by tests.
var sysSudoInteractive = func(args ...string) error {
	c := exec.Command("sudo", args...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	return c.Run()
}

// sysIsTerminal reports whether stdin is an interactive terminal — the gate
// for password prompts (never prompt into a pipe/script). Swapped by tests.
var sysIsTerminal = func() bool {
	st, err := os.Stdin.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// sudoRun is the fix-it path for privileged steps: passwordless sudo
// first (cached credentials), and when that fails on an interactive
// terminal, ONE real sudo that asks for the admin password itself. Only
// when both fail does the caller print the manual commands.
func sudoRun(why string, args ...string) error {
	err := sysSudo(args...)
	if err == nil {
		return nil
	}
	if sysIsTerminal() {
		fmt.Printf("%s — this needs your admin password (sudo):\n", why)
		return sysSudoInteractive(args...)
	}
	return err
}

// sysStatExists reports whether path exists (any error = no).
var sysStatExists = func(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// etcStagingSuffix names sysWriteEtc's staging file: content lands at
// <dest><etcStagingSuffix> first and is mv'd over the destination from the
// SAME directory (same filesystem => rename(2), i.e. atomic).
const etcStagingSuffix = ".freens.new"

// sysWriteEtc writes content to a privileged path (mode) via sudo -n,
// ATOMICALLY: temp file -> mkdir -p -> cp to <path>.freens.new (staged
// next to the destination) -> chmod -> mv -f over the destination. The
// rename replaces the old file with NO gap — at every instant the box
// holds either the old or the new file, so a crash or sudo failure
// mid-sequence can never leave the machine without /etc/resolv.conf. The
// mv also replaces a resolved-stub SYMLINK at the destination rather
// than writing through it (a plain write would land in /run and be
// regenerated on the next restart). On failure the staged file is
// removed (best effort) and the error returned — callers then print the
// manual commands.
var sysWriteEtc = func(path string, content []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp("", "freens-setup-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	staging := path + etcStagingSuffix
	cleanupStaging := func() { _ = sudoRun("wiring the OS resolver", "rm", "-f", staging) }
	if err := sudoRun("wiring the OS resolver", "mkdir", "-p", filepath.Dir(path)); err != nil {
		return err
	}
	if err := sudoRun("wiring the OS resolver", "cp", tmpName, staging); err != nil {
		cleanupStaging()
		return err
	}
	if err := sudoRun("wiring the OS resolver", "chmod", fmt.Sprintf("%04o", uint32(mode)), staging); err != nil {
		cleanupStaging()
		return err
	}
	if err := sudoRun("wiring the OS resolver", "mv", "-f", staging, path); err != nil {
		cleanupStaging()
		return err
	}
	return nil
}

// sysReadFile is os.ReadFile as a var for tests.
var sysReadFile = os.ReadFile

// ---------------------------------------------------------------------------
// setup
// ---------------------------------------------------------------------------

func cmdSetup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	uninstall := fs.Bool("uninstall", false, "reverse setup: disable the service and OS resolver wiring (keys and store are KEPT)")
	// -console-wait: internal — set on the UAC-elevated relaunch so the
	// child's console window stays open long enough to read the summary.
	consoleWait := fs.Bool("console-wait", false, "pause before exit (used when setup relaunches itself elevated via UAC)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return usageErr("setup takes no positional arguments")
	}
	if *uninstall {
		if goosWindows {
			return setupUninstallWindows(*consoleWait)
		}
		if goosDarwin {
			uninstallWebUIDarwin()
			return nil
		}
		return setupUninstall()
	}
	if goosWindows {
		return setupInstallWindows(*consoleWait)
	}
	if goosDarwin {
		return setupWebUIDarwin(*consoleWait)
	}
	return setupInstall()
}

func setupInstall() error {
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
			written = append(written, nodeKey+" (0600, node identity)")
		}
		conf := fmt.Sprintf(setupConfTemplate, nodeKey, home.StoreDir())
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

	// (d) systemd SYSTEM service (boots at power-on, no login, no linger).
	// Migrate any pre-v0.3.0 --user unit away first so exactly one daemon runs.
	migrateLegacyUserUnit()
	unitPath, unit, err := systemdUnit()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: warning: no systemd unit written (%v)\n", ProgName, err)
	} else {
		if !sysStatExists(unitPath) {
			if err := sysWriteEtc(unitPath, []byte(unit), 0o644); err != nil {
				printManualCommands("system unit", []string{
					"sudo cp <freens-unit> " + unitPath + "   (unit content below)",
					"---\n" + unit + "---",
					"sudo systemctl daemon-reload && sudo systemctl enable --now freens.service",
				})
			} else {
				written = append(written, unitPath)
			}
		}
		fmt.Println("running: systemctl daemon-reload")
		if err := sudoRun("reloading systemd", "systemctl", "daemon-reload"); err != nil {
			fmt.Fprintf(os.Stderr, "%s: warning: systemctl daemon-reload failed (%v)\n", ProgName, err)
		}
		fmt.Println("running: systemctl enable --now freens.service")
		if err := sudoRun("enabling freens.service (starts the daemon now, at boot, no login needed)", "systemctl", "enable", "--now", "freens.service"); err != nil {
			fmt.Fprintf(os.Stderr, "%s: warning: could not enable freens.service (%v); start it manually:\n    sudo systemctl start freens.service\n", ProgName, err)
		}
	}

	// (d2) freens-web systemd unit — the LAN management UI boots with the
	// machine too. Only when the binary is next to this one (the release
	// tarballs ship all three; a hand-built freens without freens-web is
	// not an error). An existing unit is left alone (idempotent like the
	// daemon unit — hand-tuned fleet units survive re-setups).
	if err := installWebUIUnit(&written); err != nil {
		fmt.Fprintf(os.Stderr, "%s: warning: freens-web unit not installed (%v) — the daemon is unaffected\n", ProgName, err)
	}

	// (e) OS resolver wiring.
	resolverNote := wireOSResolver()

	// (f) §9.5 TLS trust bridge: the privileged half of trust sync (spool →
	// system CA bundle). Best-effort like the rest of setup.
	installTrustBridge()

	// Summary.
	fmt.Println()
	fmt.Println("setup complete. Files written:")
	for _, w := range written {
		fmt.Printf("    %s\n", w)
	}
	fmt.Println(resolverNote)
	fmt.Printf("next: `freens register <you>` to claim a namespace, then `freens name www.<you>`\n")
	fmt.Printf("      (or let `freens start <you>` do all of it)\n")
	fmt.Printf("check health any time with `freens doctor`; protect your keys with `freens backup`\n")
	return nil
}

// wireOSResolver wires the OS stub to the daemon. There is exactly ONE
// working model on Linux for freens' names (found live on three boxes):
//
//	nft/iptables NAT: 127.0.0.1:53 -> 127.0.0.1:<daemon port>
//	/etc/resolv.conf: nameserver 127.0.0.1     (bare — resolv.conf has NO
//	                                             port syntax; a "host:port"
//	                                             value makes dig reject the
//	                                             whole file)
//
// The daemon (high port, unprivileged) then answers :53 for every app and
// forwards conventional names upstream (dns-first).
//
// Why NOT systemd-resolved's DNS=127.0.0.1:5300 (the v0.2.0 path): resolved
// NEVER forwards single-label names to upstream resolvers, and every freens
// name IS a single-label TLD — the stub swallowed "laurent" with NXDOMAIN
// while the daemon happily answered direct queries. The drop-in branch is
// gone; resolv.conf is replaced as a PLAIN FILE (not through resolved's
// stub symlink, which a resolved restart would regenerate).
func wireOSResolver() string {
	if goosWindows {
		return wireOSResolverWindows()
	}
	addr := effectiveDNSAddr() // e.g. 127.0.0.1:5300 (the daemon's configured listener)
	_, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" || port == "53" {
		port = strings.TrimSuffix(strings.TrimPrefix(addr, "127.0.0.1:"), "")
	}
	manual := port53ManualCommands(port)

	// 0) nsswitch shadowing: systemd-resolved's `resolve [!UNAVAIL=return]`
	//    entry answers single-label lookups with NXDOMAIN and TERMINATES the
	//    glibc chain before `dns` — resolv.conf and the redirect can be
	//    perfect and every application still sees "Name or service not
	//    known" while dig works (found live 2026-09-01, fresh VPS). Fix it
	//    on every setup path, including the already-wired early return.
	nss := fixNsswitchShadowing()
	withNote := func(msg string) string {
		if nss == "" {
			return msg
		}
		return msg + "; " + nss
	}

	// 1) The :53 -> port redirect FIRST (never leave resolv.conf pointing
	//    at a port that nothing answers on).
	if err := installPort53Redirect(port); err != nil {
		printManualCommands("port-53 redirect (nft/iptables)", manual[:len(manual)-1])
		return withNote("OS resolver: MANUAL step printed above (sudo failed) — port-53 redirect to " + addr)
	}

	// 2) resolv.conf -> plain "nameserver 127.0.0.1" (backup alongside,
	//    taken only when ABSENT: a re-run after DHCP/NetworkManager
	//    rewrote resolv.conf must not clobber the one pristine pre-freens
	//    backup with an intermediate version — os.Stat suffices, /etc is
	//    searchable and stat needs no read permission on the file).
	cur, _ := sysReadFile(pathResolvConf)
	if strings.HasPrefix(string(cur), "nameserver 127.0.0.1\n") {
		return withNote("OS resolver: already wired (resolv.conf -> 127.0.0.1, :53 -> " + addr + " redirect)")
	}
	if !sysStatExists(pathResolvBackup) {
		if err := sudoRun("backing up "+pathResolvConf, "cp", pathResolvConf, pathResolvBackup); err != nil {
			printManualCommands("resolv.conf backup + rewrite", manual[len(manual)-1:])
			return withNote("OS resolver: MANUAL step printed above (sudo failed) — resolv.conf nameserver 127.0.0.1")
		}
	}
	// Replace the file atomically (sysWriteEtc: cp to <path>.freens.new ->
	// chmod -> mv -f). There is no rm-first gap without /etc/resolv.conf
	// anymore, and the mv still bypasses a resolved stub symlink (it
	// replaces the symlink itself; writing through it would land in /run
	// and be regenerated on the next restart).
	if err := sysWriteEtc(pathResolvConf, []byte("nameserver 127.0.0.1\n"), 0o644); err != nil {
		printManualCommands("resolv.conf rewrite", manual[len(manual)-1:])
		return withNote("OS resolver: MANUAL step printed above (sudo failed) — resolv.conf nameserver 127.0.0.1")
	}
	return withNote("OS resolver: resolv.conf -> 127.0.0.1, :53 -> " + addr + " via nft/iptables redirect (backup: " + pathResolvBackup + "; conventional names go upstream through the daemon)")
}

// nftTableName is our NAT table for the :53 redirect.
const nftTableName = "freens_dns"

// fixHostsLine rewrites an nsswitch "hosts:" line that would shadow freens
// names: the `resolve` module (systemd-resolved) with a restricting action
// like [!UNAVAIL=return] answers single-label lookups with NXDOMAIN from the
// ORIGINAL upstream config — resolv.conf points at the freens daemon, but
// glibc never gets there (dig works, ping/applications don't; found live
// 2026-09-01 on a fresh VPS). The fixed line drops `resolve` and its
// attached bracketed action and ensures `dns` is present so lookups fall
// through to resolv.conf. changed=false when the line needs no fix.
func fixHostsLine(line string) (string, bool) {
	tokens := strings.Fields(line)
	if len(tokens) == 0 || tokens[0] != "hosts:" {
		return line, false
	}
	hasResolve := false
	for _, t := range tokens[1:] {
		if t == "resolve" {
			hasResolve = true
			break
		}
	}
	if !hasResolve {
		return line, false
	}
	out := []string{"hosts:"}
	skipNextAction := false
	for _, t := range tokens[1:] {
		if t == "resolve" {
			hasResolve = true
			skipNextAction = true
			continue
		}
		if strings.HasPrefix(t, "[") && skipNextAction {
			skipNextAction = false // the action bound to `resolve` goes with it
			continue
		}
		skipNextAction = false
		out = append(out, t)
	}
	hasDNS := false
	for _, t := range out[1:] {
		if t == "dns" {
			hasDNS = true
		}
	}
	if !hasDNS {
		out = append(out, "dns")
	}
	return strings.Join(out, " "), true
}

// fixNsswitchShadowing applies fixHostsLine to /etc/nsswitch.conf, with a
// backup beside the resolv.conf one. Best-effort: when the privileged write
// fails, the manual commands are printed with a LOUD warning — a shadowing
// nsswitch is the difference between "dig works" and "every application
// works", and users give up exactly there. Returns a human-readable status
// note ("" when there was nothing to do).
func fixNsswitchShadowing() string {
	if goosWindows {
		return ""
	}
	raw, err := sysReadFile(pathNsswitch)
	if err != nil {
		return "" // no nsswitch.conf (musl/minimal): glibc defaults include dns
	}
	lines := strings.Split(string(raw), "\n")
	hostIdx := -1
	for i, ln := range lines {
		if strings.HasPrefix(ln, "hosts:") {
			hostIdx = i
			break
		}
	}
	if hostIdx < 0 {
		return ""
	}
	fixed, changed := fixHostsLine(lines[hostIdx])
	if !changed {
		return ""
	}
	orig := lines[hostIdx]
	lines[hostIdx] = fixed
	manual := []string{
		"sudo cp " + pathNsswitch + " " + pathNsswitchBackup,
		fmt.Sprintf("sudo sed -i 's|^%s|%s|' %s", orig, fixed, pathNsswitch),
	}
	if !sysStatExists(pathNsswitchBackup) {
		if err := sudoRun("backing up "+pathNsswitch, "cp", pathNsswitch, pathNsswitchBackup); err != nil {
			printManualCommands("nsswitch.conf hosts fix", manual)
			return "nsswitch: MANUAL step printed above — WARNING: applications cannot resolve freens names until applied (dig works, ping/apps don't)"
		}
	}
	if err := sysWriteEtc(pathNsswitch, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		printManualCommands("nsswitch.conf hosts fix", manual)
		return "nsswitch: MANUAL step printed above — WARNING: applications cannot resolve freens names until applied (dig works, ping/apps don't)"
	}
	return "nsswitch: hosts line fixed — 'resolve [!UNAVAIL=return]' was shadowing freens names for applications (dig worked, ping didn't); backup: " + pathNsswitchBackup
}

// installPort53Redirect installs the daddr-scoped NAT rules
// 127.0.0.1:53 -> :port, idempotently (our table is flushed first). nft is
// preferred, iptables the fallback. daddr-scoping needs no uid exclusion:
// only loopback-destined :53 traffic matches, and the daemon's own upstream
// queries go to external resolvers — the v0.2.0 uid-exclusion design broke
// single-user machines (every app shares the daemon's uid and escaped the
// redirect).
func installPort53Redirect(port string) error {
	// nft path: (re)create table + chain + rule atomically enough for setup.
	if sudoRun("installing the port-53 redirect (nft)", "nft", "add", "table", "ip", nftTableName) == nil ||
		sysStatNftTable() {
		_ = sudoRun("installing the port-53 redirect (nft)", "nft", "flush", "table", "ip", nftTableName)
		if sudoRun("installing the port-53 redirect (nft)", "nft", "add", "chain", "ip", nftTableName, "output",
			"{ type nat hook output priority -100 ; }") == nil {
			if sudoRun("installing the port-53 redirect (nft)", "nft", "add", "rule", "ip", nftTableName, "output",
				"ip", "daddr", "127.0.0.1", "meta", "l4proto", "{ tcp, udp }",
				"th", "dport", "53", "redirect", "to", ":"+port) == nil {
				return nil
			}
		}
	}
	// iptables fallback: check-then-add per family.
	for _, proto := range []string{"udp", "tcp"} {
		base := []string{"-t", "nat", "-p", proto, "-d", "127.0.0.1", "--dport", "53", "-j", "REDIRECT", "--to-ports", port}
		chk := append([]string{"-C", "OUTPUT"}, base...)
		add := append([]string{"-A", "OUTPUT"}, base...)
		if err := sudoRun("installing the port-53 redirect (iptables)", append([]string{"iptables"}, chk...)...); err != nil {
			if err := sudoRun("installing the port-53 redirect (iptables)", append([]string{"iptables"}, add...)...); err != nil {
				return err
			}
		}
	}
	return nil
}

// sysStatNftTable reports whether our nft table exists (swapped in tests).
var sysStatNftTable = func() bool {
	c := exec.Command("sudo", "-n", "nft", "list", "table", "ip", nftTableName)
	return c.Run() == nil
}

// port53ManualCommands is the copy-paste fallback when sudo is unavailable:
// the exact nft rules (iptables variant), then the resolv.conf rewrite.
func port53ManualCommands(port string) []string {
	return []string{
		"sudo nft add table ip " + nftTableName,
		"sudo nft 'add chain ip " + nftTableName + " output { type nat hook output priority -100 ; }'",
		"sudo nft add rule ip " + nftTableName + " output ip daddr 127.0.0.1 meta l4proto '{ tcp, udp }' th dport 53 redirect to :" + port,
		"# (no nft? iptables -t nat -A OUTPUT -p udp -d 127.0.0.1 --dport 53 -j REDIRECT --to-ports " + port + "  # and again with -p tcp)",
		"sudo cp " + pathResolvConf + " " + pathResolvBackup + " && sudo rm -f " + pathResolvConf + " && echo 'nameserver 127.0.0.1' | sudo tee " + pathResolvConf,
	}
}

// migrateLegacyUserUnit converts a pre-v0.3.0 `--user` install: stop and
// disable the user unit, remove its file, reload. The system unit
// installed right after takes over the same ports/state — one daemon.
func migrateLegacyUserUnit() {
	legacy := legacyUserUnitPath()
	if legacy == "" || !sysStatExists(legacy) {
		return
	}
	fmt.Println("migrating: pre-v0.3.0 systemd --user service -> system service")
	fmt.Println("running: systemctl --user disable --now freens.service")
	if err := systemctlUser("disable", "--now", "freens.service"); err != nil {
		fmt.Fprintf(os.Stderr, "%s: warning: could not stop the user service (%v)\n", ProgName, err)
	}
	if err := os.Remove(legacy); err != nil {
		fmt.Fprintf(os.Stderr, "%s: warning: could not remove %s (%v)\n", ProgName, legacy, err)
	} else {
		fmt.Printf("removed: %s\n", legacy)
	}
	fmt.Println("running: systemctl --user daemon-reload")
	_ = systemctlUser("daemon-reload")
}

// printManualCommands is the sudo-needs-a-password path: print exactly what
// the user should run, keep going.
func printManualCommands(what string, cmds []string) {
	fmt.Fprintf(os.Stderr, "\n%s: sudo is not available non-interactively; run these commands yourself (%s):\n", ProgName, what)
	for _, c := range cmds {
		fmt.Fprintf(os.Stderr, "    %s\n", c)
	}
	fmt.Fprintln(os.Stderr, "setup continues; re-run `doctor` after the manual step.")
	fmt.Fprintln(os.Stderr)
}

// ---------------------------------------------------------------------------
// uninstall
// ---------------------------------------------------------------------------

func setupUninstall() error {
	uninstallServices()
	removeUnitFiles()
	unwireOSResolver()

	fmt.Println()
	fmt.Printf("uninstalled: service + OS resolver wiring removed.\n")
	fmt.Printf("KEPT (your keys, names, and store): %s\n", home.Dir())
	fmt.Printf("delete everything with: rm -rf %s\n", home.Dir())
	return nil
}

// uninstallServices stops and disables every ACTIVE freens* systemd unit —
// services AND timers (the daemon, freens-web, comm chairs, the doctor
// timer) — then reloads the manager. On a box without systemd it says so.
// Shared by `setup -uninstall` and `freens uninstall`.
func uninstallServices() {
	units := activeFreensUnits()
	timers := listFreensTimers()
	if len(units) == 0 && len(timers) == 0 {
		fmt.Println("no active freens* systemd units found")
		return
	}
	for _, u := range units {
		fmt.Println("running: systemctl disable --now " + u)
		if err := sudoRun("stopping "+u, "systemctl", "disable", "--now", u); err != nil {
			fmt.Fprintf(os.Stderr, "%s: warning: disable failed for %s (%v)\n", ProgName, u, err)
		}
	}
	for _, u := range timers {
		fmt.Println("running: systemctl disable --now " + u)
		if err := sudoRun("stopping "+u, "systemctl", "disable", "--now", u); err != nil {
			fmt.Fprintf(os.Stderr, "%s: warning: disable failed for %s (%v)\n", ProgName, u, err)
		}
	}
	fmt.Println("running: systemctl daemon-reload")
	if err := sudoRun("reloading systemd", "systemctl", "daemon-reload"); err != nil {
		fmt.Fprintf(os.Stderr, "%s: warning: daemon-reload failed (%v)\n", ProgName, err)
	}
}

// removeUnitFiles deletes every freens* unit file from the systemd unit
// directory (only regular files — glob hits like freens.service.wants
// directories are left alone), plus any pre-v0.3.0 --user unit. Shared by
// `setup -uninstall` and `freens uninstall`.
func removeUnitFiles() {
	files, err := filepath.Glob(filepath.Join(sysUnitDir(), "freens*"))
	if err == nil {
		for _, f := range files {
			if !sysStatExists(f) {
				continue
			}
			if info, err := os.Stat(f); err != nil || !info.Mode().IsRegular() {
				continue
			}
			if err := sudoRun("removing the unit file", "rm", "-f", f); err != nil {
				printManualCommands("remove unit file "+f, []string{"sudo rm -f " + f})
				continue
			}
			fmt.Printf("removed: %s\n", f)
		}
	}
	// Any pre-v0.3.0 user unit goes too.
	if legacy := legacyUserUnitPath(); legacy != "" && sysStatExists(legacy) {
		_ = systemctlUser("disable", "--now", "freens.service")
		if err := os.Remove(legacy); err == nil {
			fmt.Printf("removed: %s (legacy user unit)\n", legacy)
		}
		_ = systemctlUser("daemon-reload")
	}
}

// sysUnitDir is the systemd unit directory the verbs manage (var-gated for
// tests via pathSystemctlUnit, which stubSysForTest points into a temp dir).
var sysUnitDir = func() string {
	if pathSystemctlUnit != "" {
		return filepath.Dir(pathSystemctlUnit)
	}
	return "/etc/systemd/system"
}

// unwireOSResolver reverses wireOSResolver: the :53 NAT redirect table,
// the legacy v0.2.0 systemd-resolved drop-in, and the resolv.conf restore
// (kept when present — the one pristine pre-freens backup). Shared by
// `setup -uninstall` and `freens uninstall`.
func unwireOSResolver() {
	// NAT redirect rules: drop our table (iptables variants are per-rule;
	// printed as manual steps if the table path fails).
	if err := sudoRun("removing the port-53 redirect rules", "nft", "delete", "table", "ip", nftTableName); err != nil {
		printManualCommands("remove port-53 redirect", []string{
			"sudo nft delete table ip " + nftTableName,
			"# iptables variant: sudo iptables -t nat -D OUTPUT -p udp -d 127.0.0.1 --dport 53 -j REDIRECT --to-ports <port>  # and -p tcp",
		})
	} else {
		fmt.Printf("removed: nft table ip %s (:53 redirect)\n", nftTableName)
	}

	// Legacy v0.2.0 systemd-resolved drop-in (if a previous install left one).
	if sysStatExists(pathResolvedDrop) {
		if err := sudoRun("removing the resolved drop-in", "rm", "-f", pathResolvedDrop); err != nil {
			printManualCommands("remove resolved drop-in", []string{
				"sudo rm -f " + pathResolvedDrop,
				"sudo systemctl restart systemd-resolved",
			})
		} else {
			fmt.Printf("removed: %s\n", pathResolvedDrop)
			if err := sudoRun("restarting systemd-resolved", "systemctl", "restart", "systemd-resolved"); err != nil {
				printManualCommands("restart systemd-resolved", []string{"sudo systemctl restart systemd-resolved"})
			}
		}
	}

	// resolv.conf restore.
	if sysStatExists(pathResolvBackup) {
		if err := sudoRun("restoring "+pathResolvConf, "cp", pathResolvBackup, pathResolvConf); err != nil {
			printManualCommands("restore resolv.conf", []string{"sudo cp " + pathResolvBackup + " " + pathResolvConf,
				"sudo rm -f " + pathResolvBackup,
			})
		} else {
			fmt.Printf("restored: %s (from %s)\n", pathResolvConf, pathResolvBackup)
			if err := sudoRun("removing the resolv.conf backup", "rm", "-f", pathResolvBackup); err != nil {
				printManualCommands("remove resolv.conf backup", []string{"sudo rm -f " + pathResolvBackup})
			}
		}
	} else if cur, err := sysReadFile(pathResolvConf); err == nil && (strings.Contains(string(cur), daemonDNSAddr) || strings.Contains(string(cur), effectiveDNSAddr())) {
		// Remove every freens address that might have been wired over the
		// install's lifetime (the config port may have changed since).
		var cmds []string
		for _, addr := range []string{daemonDNSAddr, effectiveDNSAddr()} {
			if strings.Contains(string(cur), addr) {
				cmds = append(cmds, "sudo sed -i '/"+addr+"/d' "+pathResolvConf)
			}
		}
		printManualCommands("remove freens from resolv.conf", cmds)
	}

	// nsswitch restore (setup may have fixed the hosts line; put the
	// original back so systemd-resolved resumes its distro-default role).
	if sysStatExists(pathNsswitchBackup) {
		if err := sudoRun("restoring "+pathNsswitch, "cp", pathNsswitchBackup, pathNsswitch); err != nil {
			printManualCommands("restore nsswitch.conf", []string{
				"sudo cp " + pathNsswitchBackup + " " + pathNsswitch,
				"sudo rm -f " + pathNsswitchBackup,
			})
		} else {
			fmt.Printf("restored: %s (from %s)\n", pathNsswitch, pathNsswitchBackup)
			if err := sudoRun("removing the nsswitch backup", "rm", "-f", pathNsswitchBackup); err != nil {
				printManualCommands("remove nsswitch backup", []string{"sudo rm -f " + pathNsswitchBackup})
			}
		}
	}
}

// ---------------------------------------------------------------------------
// systemd helpers
// ---------------------------------------------------------------------------

// systemdUnit returns the SYSTEM unit path and content. A DNS resolver is
// machine infrastructure: it must come up at BOOT, before any login — so
// the unit is system-wide (multi-user.target), running as the UNPRIVILEGED
// user whose ~/.freens holds the keys (User=; the daemon binds no
// privileged ports — the nft redirect carries :53). This also removes the
// linger dependency entirely: no login session is needed, ever.
func systemdUnit() (path, content string, err error) {
	dir := pathSystemctlUnit
	if dir == "" {
		dir = "/etc/systemd/system/freens.service"
	}
	exe, err := os.Executable()
	if err != nil {
		return "", "", err
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return "", "", err
	}
	u, err := user.Current()
	if err != nil {
		return "", "", err
	}
	unit := fmt.Sprintf(setupUnitTemplate, exe, home.ConfPath(), u.Username, unitEnvLine())
	return dir, unit, nil
}

// unitEnvLine is the FREENS_HOME Environment line for systemd units —
// relocated installs (FREENS_HOME set — the XDG layout) MUST carry the
// variable into the unit: the daemon runs under User=, but a system
// unit's environment is NOT the user's shell environment (%h expands
// to /root regardless of User=), and an unset FREENS_HOME silently
// points the state dir at ~/.freens — admin socket, keychain scanning
// (auto-renew!), and TLS state all misdirected while the -config path
// still looks right (found live 2026-09-01: re-running setup on the
// seed box forked a second daemon at ~/.freens because the unit had
// been hand-patched with the line setup never wrote). Empty string for
// the default home.
func unitEnvLine() string {
	if fh := os.Getenv("FREENS_HOME"); fh != "" {
		return "Environment=FREENS_HOME=" + fh + "\n"
	}
	return ""
}

// installWebUIUnit writes and enables the freens-web.service systemd unit
// ("the UI should be always there"): ExecStart at the freens-web binary
// next to this executable, same user + env conventions as the daemon
// unit. An existing unit is left untouched; a missing freens-web binary
// is a silent no-op (the CLI works fine without the UI).
func installWebUIUnit(written *[]string) error {
	exe, err := sysExecutable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	webBin := filepath.Join(filepath.Dir(exe), "freens-web")
	if !sysStatExists(webBin) {
		return nil
	}
	u, err := user.Current()
	if err != nil {
		return err
	}
	unit := fmt.Sprintf(webuiUnitTemplate, webBin, u.Username, unitEnvLine())
	unitPath := filepath.Join(sysUnitDir(), "freens-web.service")
	if !sysStatExists(unitPath) {
		if err := sysWriteEtc(unitPath, []byte(unit), 0o644); err != nil {
			printManualCommands("webui unit", []string{
				"sudo cp <freens-web-unit> " + unitPath + "   (unit content below)",
				"---\n" + unit + "---",
				"sudo systemctl daemon-reload && sudo systemctl enable --now freens-web.service",
			})
			return nil // manual-command path: setup continues
		}
		*written = append(*written, unitPath)
	}
	fmt.Println("running: systemctl enable --now freens-web.service")
	if err := sudoRun("enabling freens-web.service (starts the LAN management UI now, at boot)", "systemctl", "enable", "--now", "freens-web.service"); err != nil {
		return err
	}
	return nil
}

// legacyUserUnitPath is the pre-v0.3.0 `--user` unit location (~/.config/
// systemd/user/freens.service; "" when uncomputable). setup migrates it
// away; uninstall cleans it. Var-gated so tests never touch a real home.
func legacyUserUnitPath() string {
	if pathLegacyUserUnit != "" {
		return pathLegacyUserUnit
	}
	cfg, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(cfg, "systemd", "user", "freens.service")
}

// systemctlUser runs a systemctl --user command (legacy-unit migration only).
func systemctlUser(args ...string) error {
	return sysRun("systemctl", append([]string{"--user"}, args...)...)
}

// ---------------------------------------------------------------------------
// templates
// ---------------------------------------------------------------------------

const setupConfTemplate = `; freens daemon configuration — written by ` + "`freens setup`" + `; edit freely.
; The resolver listens on a HIGH port (53 needs privileges on most systems);
; the OS resolver is pointed at it by setup itself (systemd-resolved drop-in
; or /etc/resolv.conf — verify any time with ` + "`freens doctor`" + `).
[listen]
udp = 127.0.0.1:5300
tcp = 127.0.0.1:5300

; Routing: dns-first is the SAFE default (spec line 772) — conventional
; names go to the upstream resolvers. The freens community namespace is NOT
; an ICANN TLD: asking upstreams for it first only leaks freens names in
; plaintext (and lets a spoofed upstream answer shadow the DHT one), so it
; gets an explicit freens-first route — freens first, DNS on a miss.
; A plain "* = freens" route would make this daemon authoritative-only and
; NXDOMAIN the rest of the internet.
[tld-routes]
freens = freens-first
* = dns-first

; DHT side (spec 6): public listener, node identity, persistent store.
; UPnP port mapping is ON by default — write 'upnp = false' to disable.
[dht]
listen = 0.0.0.0:15353
node-seed = @%s
persist = %s
`

const setupSeedsTemplate = `# freens seed nodes — one per line: <host:port>#<64-hex-node-pubkey>
# This is the pinned default community seed; add your own nodes as you learn
# them. The daemon also remembers live peers in %s/book.json, so later boots
# do not depend on the seed being reachable.
%s
`

const setupUnitTemplate = `[Unit]
Description=freens daemon (self-certifying DNS)
Documentation=https://github.com/camalolo/freens
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%s daemon -config %s
User=%s
%sRestart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
`

// webuiUnitTemplate is the freens-web.service setup writes: the LAN
// management UI boots with the machine, as the same user/state-dir rules
// as the daemon unit (the UI reads the keychain and the admin socket).
const webuiUnitTemplate = `[Unit]
Description=freens web UI (LAN management)
Documentation=https://github.com/camalolo/freens
After=network-online.target freens.service
Wants=network-online.target

[Service]
ExecStart=%s
User=%s
%sRestart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
`
