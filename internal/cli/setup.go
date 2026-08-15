// setup.go — `setup`: the installer. One command takes a machine from
// "nothing installed" to "freens resolves names system-wide":
//
//	(a) home.Ensure()                      — the state dir layout
//	(b) <home>/freens.conf  (if absent)    — daemon config: resolver on the
//	      high port 127.0.0.1:5300, [tld-routes] * = dns-first, [dht] public
//	      listener + generated node identity (<home>/node.key, 0600) +
//	      persistent store
//	(c) <home>/seeds.conf   (if absent)    — the pinned default community seed
//	(d) systemd --user unit                — ExecStart=<this executable>
//	      daemon -config <home>/freens.conf, Restart=on-failure; then
//	      `systemctl --user daemon-reload && enable --now freens.service`
//	(e) OS resolver wiring (user decision: HIGH PORT + resolv.conf, fully
//	      automatic where sudo allows): systemd-resolved drop-in
//	      DNS=127.0.0.1:5300 Domains=~. (+ restart) when systemd-resolved
//	      runs, else prepend `nameserver 127.0.0.1:5300` to /etc/resolv.conf
//	      with a .freens.bak backup. When sudo needs a password the EXACT
//	      commands are printed for the user and setup continues.
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
	"os"
	"os/exec"
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
	pathResolvConf    = "/etc/resolv.conf"
	pathResolvBackup  = "/etc/resolv.conf.freens.bak"
	pathResolvedDrop  = "/etc/systemd/resolved.conf.d/freens.conf"
	pathSystemctlUnit = "" // set in tests to a temp path
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

	// (d) systemd --user service.
	unitPath, unit, err := systemdUnit()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: warning: no user systemd unit written (%v)\n", ProgName, err)
	} else {
		if !sysStatExists(unitPath) {
			if err := os.MkdirAll(filepath.Dir(unitPath), 0o700); err != nil {
				return fmt.Errorf("writing unit dir: %w", err)
			}
			if err := os.WriteFile(unitPath, []byte(unit), 0o644); err != nil {
				return fmt.Errorf("writing %s: %w", unitPath, err)
			}
			written = append(written, unitPath)
		}
		fmt.Println("running: systemctl --user daemon-reload")
		if err := systemctlUser("daemon-reload"); err != nil {
			fmt.Fprintf(os.Stderr, "%s: warning: systemctl --user daemon-reload failed (%v) — systemd user session missing?\n", ProgName, err)
		}
		fmt.Println("running: systemctl --user enable --now freens.service")
		if err := systemctlUser("enable", "--now", "freens.service"); err != nil {
			fmt.Fprintf(os.Stderr, "%s: warning: could not enable freens.service (%v); start it manually:\n    systemctl --user start freens.service\n", ProgName, err)
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

// wireOSResolver points the OS stub resolver at the daemon's high port:
// a systemd-resolved drop-in when systemd-resolved runs, else a prepended
// nameserver line in /etc/resolv.conf (backup alongside). Returns the
// human-readable outcome line for the setup summary.
func wireOSResolver() string {
	if systemctlActive("systemd-resolved") {
		dropIn := "[Resolve]\nDNS=" + daemonDNSAddr + "\nDomains=~.\n"
		if err := sysWriteEtc(pathResolvedDrop, []byte(dropIn), 0o644); err != nil {
			printManualCommands("systemd-resolved drop-in", []string{
				"sudo mkdir -p " + filepath.Dir(pathResolvedDrop),
				"sudo tee " + pathResolvedDrop + " >/dev/null <<'EOF'\n[Resolve]\nDNS=" + daemonDNSAddr + "\nDomains=~.\nEOF",
				"sudo systemctl restart systemd-resolved",
			})
			return "OS resolver: MANUAL step printed above (sudo failed) — systemd-resolved drop-in"
		}
		if err := sudoRun("restarting systemd-resolved", "systemctl", "restart", "systemd-resolved"); err != nil {
			printManualCommands("restart systemd-resolved", []string{"sudo systemctl restart systemd-resolved"})
		}
		return "OS resolver: systemd-resolved -> " + daemonDNSAddr + " (drop-in " + pathResolvedDrop + ")"
	}
	cur, err := sysReadFile(pathResolvConf)
	if err == nil && strings.Contains(string(cur), daemonDNSAddr) {
		return "OS resolver: " + pathResolvConf + " already points at " + daemonDNSAddr
	}
	backup := "sudo cp " + pathResolvConf + " " + pathResolvBackup
	prepend := "printf 'nameserver " + daemonDNSAddr + "\\n' | sudo tee /tmp/freens-resolv.new >/dev/null && cat " + pathResolvConf + " | sudo tee -a /tmp/freens-resolv.new >/dev/null && sudo cp /tmp/freens-resolv.new " + pathResolvConf
	if err := sudoRun("backing up "+pathResolvConf, "cp", pathResolvConf, pathResolvBackup); err != nil {
		printManualCommands("resolv.conf backup + prepend", []string{backup, prepend})
		return "OS resolver: MANUAL step printed above (sudo failed) — resolv.conf nameserver " + daemonDNSAddr
	}
	newResolv := "nameserver " + daemonDNSAddr + "\n" + string(cur)
	if err := sysWriteEtc(pathResolvConf, []byte(newResolv), 0o644); err != nil {
		printManualCommands("resolv.conf prepend", []string{prepend})
		return "OS resolver: MANUAL step printed above (sudo failed) — resolv.conf nameserver " + daemonDNSAddr
	}
	return "OS resolver: " + pathResolvConf + " prepended with nameserver " + daemonDNSAddr + " (backup: " + pathResolvBackup + ")"
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
	// Service off + unit removed.
	fmt.Println("running: systemctl --user disable --now freens.service")
	if err := systemctlUser("disable", "--now", "freens.service"); err != nil {
		fmt.Fprintf(os.Stderr, "%s: warning: disable failed (%v) — service not installed?\n", ProgName, err)
	}
	unitPath, _, err := systemdUnit()
	if err == nil {
		if sysStatExists(unitPath) {
			if err := os.Remove(unitPath); err != nil {
				fmt.Fprintf(os.Stderr, "%s: warning: could not remove %s (%v)\n", ProgName, unitPath, err)
			} else {
				fmt.Printf("removed: %s\n", unitPath)
			}
		}
	}
	fmt.Println("running: systemctl --user daemon-reload")
	if err := systemctlUser("daemon-reload"); err != nil {
		fmt.Fprintf(os.Stderr, "%s: warning: daemon-reload failed (%v)\n", ProgName, err)
	}

	// systemd-resolved drop-in.
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
	} else if cur, err := sysReadFile(pathResolvConf); err == nil && strings.Contains(string(cur), daemonDNSAddr) {
		printManualCommands("remove freens from resolv.conf", []string{
			"sudo sed -i '/" + daemonDNSAddr + "/d' " + pathResolvConf,
		})
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

// systemdUnit returns the user-unit path and the unit file content
// (ExecStart = the CURRENT executable, abs path, running `daemon -config`).
func systemdUnit() (path, content string, err error) {
	dir := pathSystemctlUnit
	if dir == "" {
		cfg, err := os.UserConfigDir() // ~/.config (XDG)
		if err != nil {
			return "", "", err
		}
		dir = filepath.Join(cfg, "systemd", "user", "freens.service")
	}
	exe, err := os.Executable()
	if err != nil {
		return "", "", err
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return "", "", err
	}
	unit := fmt.Sprintf(setupUnitTemplate, exe, home.ConfPath())
	return dir, unit, nil
}

// systemctlUser runs a systemctl --user command.
func systemctlUser(args ...string) error {
	return sysRun("systemctl", append([]string{"--user"}, args...)...)
}

// systemctlActive reports whether the system unit is active.
func systemctlActive(unit string) bool {
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

[Service]
ExecStart=%s daemon -config %s
Restart=on-failure
RestartSec=2

[Install]
WantedBy=default.target
`
