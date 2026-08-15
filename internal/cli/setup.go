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
// seeds.conf (host:port#node-pubkey-hex).
const defaultSeedLine = "freens.camalolo.com:15353#780494a338d831d94b371c9a1d9351885753df071ba4e60e23283282d33fe2c7"

// daemonDNSAddr is the high port the daemon's resolver listens on (53 needs
// privileges; the OS is pointed here instead).
const daemonDNSAddr = "127.0.0.1:5300"

// privileged paths setup/uninstall touch (vars for tests).
var (
	pathResolvConf     = "/etc/resolv.conf"
	pathResolvBackup   = "/etc/resolv.conf.freens.bak"
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

// sysWriteEtc writes content to a privileged path (mode) via sudo -n
// (temp file + mkdir -p + cp + chmod). Returns an error when sudo could not
// run non-interactively — callers then print the manual commands.
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
	if err := sudoRun("wiring the OS resolver", "mkdir", "-p", filepath.Dir(path)); err != nil {
		return err
	}
	if err := sudoRun("wiring the OS resolver", "cp", tmpName, path); err != nil {
		return err
	}
	return sudoRun("wiring the OS resolver", "chmod", fmt.Sprintf("%04o", uint32(mode)), path)
}

// sysReadFile is os.ReadFile as a var for tests.
var sysReadFile = os.ReadFile

// ---------------------------------------------------------------------------
// setup
// ---------------------------------------------------------------------------

func cmdSetup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	uninstall := fs.Bool("uninstall", false, "reverse setup: disable the service and OS resolver wiring (keys and store are KEPT)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return usageErr("setup takes no positional arguments")
	}
	if *uninstall {
		return setupUninstall()
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

	// (e) OS resolver wiring.
	resolverNote := wireOSResolver()

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
	addr := effectiveDNSAddr() // e.g. 127.0.0.1:5300 (the daemon's configured listener)
	_, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" || port == "53" {
		port = strings.TrimSuffix(strings.TrimPrefix(addr, "127.0.0.1:"), "")
	}
	manual := port53ManualCommands(port)

	// 1) The :53 -> port redirect FIRST (never leave resolv.conf pointing
	//    at a port that nothing answers on).
	if err := installPort53Redirect(port); err != nil {
		printManualCommands("port-53 redirect (nft/iptables)", manual[:len(manual)-1])
		return "OS resolver: MANUAL step printed above (sudo failed) — port-53 redirect to " + addr
	}

	// 2) resolv.conf -> plain "nameserver 127.0.0.1" (backup alongside).
	cur, _ := sysReadFile(pathResolvConf)
	if strings.HasPrefix(string(cur), "nameserver 127.0.0.1\n") {
		return "OS resolver: already wired (resolv.conf -> 127.0.0.1, :53 -> " + addr + " redirect)"
	}
	if err := sudoRun("backing up "+pathResolvConf, "cp", pathResolvConf, pathResolvBackup); err != nil {
		printManualCommands("resolv.conf backup + rewrite", manual[len(manual)-1:])
		return "OS resolver: MANUAL step printed above (sudo failed) — resolv.conf nameserver 127.0.0.1"
	}
	// Replace the file (rm first: through a resolved stub symlink a plain
	// write would land in /run and be regenerated on the next restart).
	if err := sudoRun("rewriting "+pathResolvConf, "rm", "-f", pathResolvConf); err != nil {
		printManualCommands("resolv.conf backup + rewrite", manual[len(manual)-1:])
		return "OS resolver: MANUAL step printed above (sudo failed) — resolv.conf nameserver 127.0.0.1"
	}
	if err := sysWriteEtc(pathResolvConf, []byte("nameserver 127.0.0.1\n"), 0o644); err != nil {
		printManualCommands("resolv.conf rewrite", manual[len(manual)-1:])
		return "OS resolver: MANUAL step printed above (sudo failed) — resolv.conf nameserver 127.0.0.1"
	}
	return "OS resolver: resolv.conf -> 127.0.0.1, :53 -> " + addr + " via nft/iptables redirect (backup: " + pathResolvBackup + "; conventional names go upstream through the daemon)"
}

// nftTableName is our NAT table for the :53 redirect.
const nftTableName = "freens_dns"

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
	// System service off + unit removed.
	fmt.Println("running: systemctl disable --now freens.service")
	if err := sudoRun("stopping freens.service", "systemctl", "disable", "--now", "freens.service"); err != nil {
		fmt.Fprintf(os.Stderr, "%s: warning: disable failed (%v) — service not installed?\n", ProgName, err)
	}
	unitPath, _, err := systemdUnit()
	if err == nil && sysStatExists(unitPath) {
		if err := sudoRun("removing the unit file", "rm", "-f", unitPath); err != nil {
			printManualCommands("remove unit file", []string{"sudo rm -f " + unitPath})
		} else {
			fmt.Printf("removed: %s\n", unitPath)
		}
	}
	fmt.Println("running: systemctl daemon-reload")
	if err := sudoRun("reloading systemd", "systemctl", "daemon-reload"); err != nil {
		fmt.Fprintf(os.Stderr, "%s: warning: daemon-reload failed (%v)\n", ProgName, err)
	}
	// Any pre-v0.3.0 user unit goes too.
	if legacy := legacyUserUnitPath(); legacy != "" && sysStatExists(legacy) {
		_ = systemctlUser("disable", "--now", "freens.service")
		if err := os.Remove(legacy); err == nil {
			fmt.Printf("removed: %s (legacy user unit)\n", legacy)
		}
		_ = systemctlUser("daemon-reload")
	}

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
			printManualCommands("restore resolv.conf", []string{
				"sudo cp " + pathResolvBackup + " " + pathResolvConf,
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

	fmt.Println()
	fmt.Printf("uninstalled: service + OS resolver wiring removed.\n")
	fmt.Printf("KEPT (your keys, names, and store): %s\n", home.Dir())
	fmt.Printf("delete everything with: rm -rf %s\n", home.Dir())
	return nil
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
	unit := fmt.Sprintf(setupUnitTemplate, exe, home.ConfPath(), u.Username)
	return dir, unit, nil
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

// systemctlActive reports whether the system unit is active.
var systemctlActive = func(unit string) bool {
	return sysRun("systemctl", "is-active", "--quiet", unit) == nil
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
; names go to the upstream resolvers, freens names (unknown to DNS)
; still resolve through the freens branch. A plain "* = freens" route
; would make this daemon authoritative-only and NXDOMAIN the rest of
; the internet.
[tld-routes]
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
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
`
