// setup_test.go — the installer's idempotency, file contents, uninstall
// path, and the sudo-needs-a-password fallback — all against a temp home and
// stubbed system operations (nothing on the machine is touched).
package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/camalolo/freens/internal/home"
)

// sysRecorder captures every stubbed system interaction.
type sysRecorder struct {
	cmds      [][]string // argv of each sysRun/sysSudo call
	etcWrites []etcWrite // privileged writes (stubbed sysWriteEtc)
}

type etcWrite struct {
	path    string
	content []byte
}

func (r *sysRecorder) ran(cmd ...string) bool {
	for _, c := range r.cmds {
		if len(c) == len(cmd) {
			match := true
			for i := range c {
				if c[i] != cmd[i] {
					match = false
					break
				}
			}
			if match {
				return true
			}
		}
	}
	return false
}

// stubSysForTest swaps every OS-level side effect of setup for recorders and
// temp paths: systemctl always succeeds EXCEPT is-active (so setup takes the
// resolv.conf branch, not the systemd-resolved drop-in), privileged writes
// land in the temp dir for real (so re-runs observe their own effects).
func stubSysForTest(t *testing.T) *sysRecorder {
	t.Helper()
	rec := &sysRecorder{}
	dir := t.TempDir()

	oldRun, oldWriteEtc := sysRun, sysWriteEtc
	oldUnit, oldResolv, oldBackup, oldDrop := pathSystemctlUnit, pathResolvConf, pathResolvBackup, pathResolvedDrop
	oldNftTable, oldRedirectProbe := sysStatNftTable, port53RedirectInstalled

	sysRun = func(name string, args ...string) error {
		argv := append([]string{name}, args...)
		rec.cmds = append(rec.cmds, argv)
		// systemd-resolved is "inactive" in tests: take the resolv.conf path.
		if name == "systemctl" && len(args) >= 2 && args[0] == "is-active" {
			if !strings.HasSuffix(argv[len(argv)-1], "freens.service") {
				return errStubInactive
			}
		}
		return nil
	}
	sysWriteEtc = func(path string, content []byte, mode os.FileMode) error {
		rec.etcWrites = append(rec.etcWrites, etcWrite{path, content})
		// The privileged paths point into the temp dir: write for real so a
		// SECOND setup run observes its own first-run effects.
		return os.WriteFile(path, content, mode)
	}
	pathSystemctlUnit = filepath.Join(dir, "freens.service")
	pathResolvConf = filepath.Join(dir, "resolv.conf")
	pathResolvBackup = filepath.Join(dir, "resolv.conf.freens.bak")
	pathResolvedDrop = filepath.Join(dir, "resolved-freens.conf")
	if err := os.WriteFile(pathResolvConf, []byte("nameserver 9.9.9.9\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// The nft table probe and the doctor redirect probe never hit the real
	// firewall from tests (redirect presence defaults to false; individual
	// tests override).
	sysStatNftTable = func() bool { return false }
	port53RedirectInstalled = func() bool { return false }

	t.Cleanup(func() {
		sysRun, sysWriteEtc = oldRun, oldWriteEtc
		pathSystemctlUnit, pathResolvConf, pathResolvBackup, pathResolvedDrop = oldUnit, oldResolv, oldBackup, oldDrop
		sysStatNftTable, port53RedirectInstalled = oldNftTable, oldRedirectProbe
	})
	return rec
}

var errStubInactive = &stubErr{"inactive"}

type stubErr struct{ msg string }

func (e *stubErr) Error() string { return e.msg }

// TestSetupIdempotent: two runs in a temp home; every file exists after the
// first and is byte-identical after the second; the unit file carries the
// config path; the systemd enable/reload commands ran.
func TestSetupIdempotent(t *testing.T) {
	h := tempHome(t)
	rec := stubSysForTest(t)

	out, err := captureStdout(t, func() error { return cmdSetup([]string{}) })
	if err != nil {
		t.Fatalf("setup: %v\n%s", err, out)
	}

	readFileOrDie := func(p string) []byte {
		t.Helper()
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("expected file %s: %v", p, err)
		}
		return b
	}
	conf1 := readFileOrDie(home.ConfPath())
	seeds1 := readFileOrDie(home.SeedsPath())
	nodeKey1 := readFileOrDie(filepath.Join(h, "node.key"))
	unit1 := readFileOrDie(pathSystemctlUnit)

	// Config content: high-port resolver, routes, [dht] keys, node key + store.
	conf := string(conf1)
	for _, want := range []string{
		"[listen]", "udp = 127.0.0.1:5300", "tcp = 127.0.0.1:5300",
		"[tld-routes]", "* = dns-first",
		"[dht]", "listen = 0.0.0.0:15353",
		"node-seed = @" + filepath.Join(h, "node.key"),
		"persist = " + home.StoreDir(),
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("freens.conf missing %q:\n%s", want, conf)
		}
	}
	// Seeds: the pinned community seed.
	if !strings.Contains(string(seeds1), defaultSeedLine) {
		t.Errorf("seeds.conf missing the pinned seed:\n%s", seeds1)
	}
	// Unit: current executable, daemon -config <home>/freens.conf.
	unit := string(unit1)
	if !strings.Contains(unit, "daemon -config "+home.ConfPath()) {
		t.Errorf("unit file does not reference the config path:\n%s", unit)
	}
	if !strings.Contains(unit, "Restart=on-failure") {
		t.Errorf("unit file missing Restart=on-failure:\n%s", unit)
	}
	// The systemd commands ran.
	if !rec.ran("systemctl", "--user", "daemon-reload") {
		t.Errorf("daemon-reload not run: %v", rec.cmds)
	}
	if !rec.ran("systemctl", "--user", "enable", "--now", "freens.service") {
		t.Errorf("enable --now not run: %v", rec.cmds)
	}
	// OS resolver: resolv.conf replaced with the plain loopback nameserver
	// (the :53 -> daemon-port redirect carries the port; resolv.conf itself
	// has no port syntax). The nft redirect commands ran via sudo.
	gotResolv := strings.TrimSpace(string(readFileOrDie(pathResolvConf)))
	if gotResolv != "nameserver 127.0.0.1" {
		t.Errorf("resolv.conf = %q, want exactly \"nameserver 127.0.0.1\"", gotResolv)
	}
	if !rec.ran("sudo", "-n", "nft", "add", "table", "ip", nftTableName) {
		t.Errorf("nft redirect table not installed: %v", rec.cmds)
	}
	if !rec.ran("sudo", "-n", "nft", "add", "rule", "ip", nftTableName, "output",
		"ip", "daddr", "127.0.0.1", "meta", "l4proto", "{ tcp, udp }",
		"th", "dport", "53", "redirect", "to", ":5300") {
		t.Errorf("nft redirect rule not installed: %v", rec.cmds)
	}
	if len(rec.etcWrites) != 1 {
		t.Errorf("privileged writes = %d, want 1 (resolv.conf)", len(rec.etcWrites))
	}

	// Second run: no bytes change anywhere.
	out2, err := captureStdout(t, func() error { return cmdSetup([]string{}) })
	if err != nil {
		t.Fatalf("setup (2nd): %v\n%s", err, out2)
	}
	if string(readFileOrDie(home.ConfPath())) != string(conf1) ||
		string(readFileOrDie(home.SeedsPath())) != string(seeds1) ||
		string(readFileOrDie(filepath.Join(h, "node.key"))) != string(nodeKey1) ||
		string(readFileOrDie(pathSystemctlUnit)) != string(unit1) {
		t.Error("second setup run changed existing files")
	}
	// resolv.conf already pointed at the daemon: no new privileged writes.
	if len(rec.etcWrites) != 1 {
		t.Errorf("second run performed %d total privileged writes, want still 1", len(rec.etcWrites))
	}
}

// TestSetupUninstall: the service file disappears, disable/daemon-reload
// run, the resolv.conf backup is restored, and keys+store are kept.
func TestSetupUninstall(t *testing.T) {
	tempHome(t)
	rec := stubSysForTest(t)

	if _, err := captureStdout(t, func() error { return cmdSetup([]string{}) }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(pathSystemctlUnit); err != nil {
		t.Fatalf("unit file after setup: %v", err)
	}
	// The stubbed sudo backup is a no-op on disk; create it as the real
	// uninstall path would see it.
	if err := os.WriteFile(pathResolvBackup, []byte("nameserver 9.9.9.9\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := captureStdout(t, func() error { return cmdSetup([]string{"--uninstall"}) })
	if err != nil {
		t.Fatalf("uninstall: %v\n%s", err, out)
	}
	if _, err := os.Stat(pathSystemctlUnit); !os.IsNotExist(err) {
		t.Errorf("unit file still present after uninstall: %v", err)
	}
	if !rec.ran("systemctl", "--user", "disable", "--now", "freens.service") {
		t.Errorf("disable --now not run: %v", rec.cmds)
	}
	if !rec.ran("sudo", "-n", "cp", pathResolvBackup, pathResolvConf) {
		t.Errorf("resolv.conf restore not attempted: %v", rec.cmds)
	}
	// Keys + store survive (and setup said so).
	if _, err := os.Stat(home.KeysDir()); err != nil {
		t.Errorf("keys dir removed by uninstall: %v", err)
	}
	if !strings.Contains(out, "KEPT") {
		t.Errorf("uninstall output does not say keys/store were kept:\n%s", out)
	}
}

// TestSetupInteractiveSudoFallback: when passwordless sudo fails on a
// terminal, setup retries the privileged step with a REAL sudo (which can
// prompt for the password) instead of falling through to manual commands.
func TestSetupInteractiveSudoFallback(t *testing.T) {
	tempHome(t)
	rec := stubSysForTest(t)
	// sudo -n fails from here on (systemctl still succeeds)…
	oldRun := sysRun
	inner := sysRun
	sysRun = func(name string, args ...string) error {
		if name == "sudo" {
			rec.cmds = append(rec.cmds, append([]string{name}, args...))
			return errStubInactive
		}
		return inner(name, args...)
	}
	// …we are "on a terminal"…
	oldTerm := sysIsTerminal
	sysIsTerminal = func() bool { return true }
	// …and interactive sudo succeeds.
	var interactive [][]string
	oldInter := sysSudoInteractive
	sysSudoInteractive = func(args ...string) error {
		interactive = append(interactive, append([]string{"sudo"}, args...))
		return nil
	}
	t.Cleanup(func() { sysRun, sysIsTerminal, sysSudoInteractive = oldRun, oldTerm, oldInter })

	out, err := captureStdout(t, func() error { return cmdSetup([]string{}) })
	if err != nil {
		t.Fatalf("setup: %v\n%s", err, out)
	}
	if len(interactive) == 0 {
		t.Fatalf("interactive sudo never attempted:\n%s", out)
	}
	// The backup cp ran interactively (the first privileged step of the
	// resolv.conf branch), and the summary does NOT drop to manual mode.
	ranBackup := false
	for _, c := range interactive {
		if len(c) >= 4 && c[1] == "cp" && c[3] == pathResolvBackup {
			ranBackup = true
		}
	}
	if !ranBackup {
		t.Errorf("interactive sudo did not cover the resolv.conf backup: %v", interactive)
	}
	if strings.Contains(out, "MANUAL") {
		t.Errorf("setup fell back to manual commands despite interactive sudo:\n%s", out)
	}
	if !strings.Contains(out, "admin password") {
		t.Errorf("the sudo prompt notice is missing from the output:\n%s", out)
	}
}

// TestSudoRunNonTerminalNeverPrompts: with no TTY the interactive attempt
// is never made — scripts/pipes get the manual-commands path, not a hang.
func TestSudoRunNonTerminalNeverPrompts(t *testing.T) {
	oldSudo, oldInter, oldTerm := sysSudo, sysSudoInteractive, sysIsTerminal
	sysSudo = func(args ...string) error { return errStubInactive }
	sysSudoInteractive = func(args ...string) error { t.Fatal("interactive sudo without a TTY"); return nil }
	sysIsTerminal = func() bool { return false }
	t.Cleanup(func() { sysSudo, sysSudoInteractive, sysIsTerminal = oldSudo, oldInter, oldTerm })

	if err := sudoRun("test step", "true"); err == nil {
		t.Fatal("sudoRun should report the failure when no TTY is present")
	}
}

// TestSetupSudoFallbackPrintsManualCommands: when privileged writes fail
// everywhere (no TTY, sudo refused), setup prints the exact commands and
// continues.
func TestSetupSudoFallbackPrintsManualCommands(t *testing.T) {
	tempHome(t)
	rec := stubSysForTest(t)
	// Make privileged writes fail from here on.
	oldWriteEtc := sysWriteEtc
	sysWriteEtc = func(path string, content []byte, mode os.FileMode) error {
		rec.etcWrites = append(rec.etcWrites, etcWrite{path, content})
		return errStubInactive
	}
	t.Cleanup(func() { sysWriteEtc = oldWriteEtc })

	out, err := captureStdout(t, func() error { return cmdSetup([]string{}) })
	if err != nil {
		t.Fatalf("setup must continue when sudo is unavailable: %v\n%s", err, out)
	}
	// The manual fallback prints the resolv.conf commands... on stderr, which
	// captureStdout does not grab; assert setup's summary notes the manual
	// step and that it still wrote every home file.
	if !strings.Contains(out, "MANUAL") {
		t.Errorf("setup summary missing the manual-step note:\n%s", out)
	}
	if _, err := os.Stat(home.ConfPath()); err != nil {
		t.Errorf("freens.conf not written: %v", err)
	}
}
