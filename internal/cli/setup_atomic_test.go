// setup_atomic_test.go — the atomic /etc write machinery: the resolv.conf
// replacement must never leave the box without /etc/resolv.conf (no
// rm-then-write gap — at every instant the OLD or the NEW file is in
// place), the pristine pre-freens backup is taken only once (a re-run
// after DHCP/NetworkManager rewrote resolv.conf keeps it), and a failed
// staging sequence cleans up after itself. Everything runs against a
// temp sandbox with the sys* runners stubbed to a recorder that
// SIMULATES the privileged file operations (mkdir/cp/chmod/mv/rm) — the
// real sysWriteEtc executes end-to-end, no real sudo is ever run.
package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// atomicSandbox is the temp /etc stand-in plus the recorded command log.
type atomicSandbox struct {
	rec  sysRecorder // setup_test.go's recorder (cmds + ran)
	dir  string
	fail func(argv []string) error // non-nil result = simulated failure
}

// stubAtomicSys swaps sysRun for a recorder that also SIMULATES the
// privileged file ops against a temp sandbox, so the real sysWriteEtc
// (cp -> chmod -> mv staging) runs end-to-end while nothing on the
// machine is touched. sysStatExists stays REAL: the backup-exists probe
// must see the files the simulation materializes.
func stubAtomicSys(t *testing.T) *atomicSandbox {
	t.Helper()
	sb := &atomicSandbox{dir: t.TempDir()}

	oldRun, oldNftTable, oldTerm := sysRun, sysStatNftTable, sysIsTerminal
	oldResolv, oldBackup, oldUnit, oldLegacy, oldDrop :=
		pathResolvConf, pathResolvBackup, pathSystemctlUnit, pathLegacyUserUnit, pathResolvedDrop

	sysRun = func(name string, args ...string) error {
		argv := append([]string{name}, args...)
		sb.rec.cmds = append(sb.rec.cmds, argv)
		if name != "sudo" || len(args) < 2 { // systemctl --user etc.: record, succeed
			return nil
		}
		if sb.fail != nil {
			if err := sb.fail(argv); err != nil {
				return err
			}
		}
		a := args[1:] // strip sudo's "-n"
		switch a[0] {
		case "mkdir": // mkdir -p <dir>
			return os.MkdirAll(a[len(a)-1], 0o755)
		case "cp": // cp <src> <dst>
			b, err := os.ReadFile(a[len(a)-2])
			if err != nil {
				return err
			}
			return os.WriteFile(a[len(a)-1], b, 0o644)
		case "chmod": // chmod <mode> <path>
			m, err := strconv.ParseUint(a[len(a)-2], 8, 32)
			if err != nil {
				return err
			}
			return os.Chmod(a[len(a)-1], os.FileMode(m))
		case "mv": // mv -f <src> <dst> (same directory here: plain replace)
			b, err := os.ReadFile(a[len(a)-2])
			if err != nil {
				return err
			}
			if err := os.WriteFile(a[len(a)-1], b, 0o644); err != nil {
				return err
			}
			return os.Remove(a[len(a)-2])
		case "rm": // rm -f <path> (a missing file is fine, like -f)
			_ = os.Remove(a[len(a)-1])
			return nil
		}
		return nil // nft/iptables/systemctl probes: succeed
	}
	// No firewall probes from tests; no password prompts (sudo failures
	// below must surface as errors, not interactive retries).
	sysStatNftTable = func() bool { return false }
	sysIsTerminal = func() bool { return false }

	pathResolvConf = filepath.Join(sb.dir, "resolv.conf")
	pathResolvBackup = filepath.Join(sb.dir, "resolv.conf.freens.bak")
	pathSystemctlUnit = filepath.Join(sb.dir, "systemd", "freens.service")
	pathLegacyUserUnit = filepath.Join(sb.dir, "legacy-user-unit.service")
	pathResolvedDrop = filepath.Join(sb.dir, "resolved-freens.conf")
	if err := os.WriteFile(pathResolvConf, []byte("nameserver 9.9.9.9\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		sysRun, sysStatNftTable, sysIsTerminal = oldRun, oldNftTable, oldTerm
		pathResolvConf, pathResolvBackup, pathSystemctlUnit, pathLegacyUserUnit, pathResolvedDrop =
			oldResolv, oldBackup, oldUnit, oldLegacy, oldDrop
	})
	return sb
}

// atomicTriple asserts the cp -> chmod -> mv staging sequence installing
// dest exists (in that order) and returns the indexes of the three steps.
func atomicTriple(t *testing.T, cmds [][]string, dest string) (iCp, iChmod, iMv int) {
	t.Helper()
	staging := dest + etcStagingSuffix
	iCp, iChmod, iMv = -1, -1, -1
	for i, c := range cmds {
		switch {
		case len(c) == 5 && c[0] == "sudo" && c[2] == "cp" && c[4] == staging:
			iCp = i
		case len(c) == 5 && c[0] == "sudo" && c[2] == "chmod" && c[4] == staging:
			iChmod = i
		case len(c) == 6 && c[0] == "sudo" && c[2] == "mv" && c[3] == "-f" && c[4] == staging && c[5] == dest:
			iMv = i
		}
	}
	if iCp < 0 || iChmod < 0 || iMv < 0 {
		t.Fatalf("atomic cp->chmod->mv staging sequence for %s not found (cp=%d chmod=%d mv=%d):\n%v",
			dest, iCp, iChmod, iMv, cmds)
	}
	if !(iCp < iChmod && iChmod < iMv) {
		t.Fatalf("staging steps out of order for %s: cp=%d chmod=%d mv=%d", dest, iCp, iChmod, iMv)
	}
	return iCp, iChmod, iMv
}

// TestWireOSResolverAtomicReplaceNoRmGap: the resolv.conf install never
// rm's the live file (the old design left the box with NO /etc/resolv.conf
// when anything failed between the rm and the rewrite) — it stages
// <dest>.freens.new and mv's it over atomically, so at every instant the
// old or the new file answers.
func TestWireOSResolverAtomicReplaceNoRmGap(t *testing.T) {
	tempHome(t)
	sb := stubAtomicSys(t)

	wireOSResolver()

	// NEVER a bare rm of the live resolv.conf.
	if sb.rec.ran("sudo", "-n", "rm", "-f", pathResolvConf) {
		t.Errorf("resolv.conf install still rm's the live file first:\n%v", sb.rec.cmds)
	}
	// The atomic triple: cp <tmp> <dest>.freens.new -> chmod 0644 <staging>
	// -> mv -f <staging> <dest>, in that order.
	_, iChmod, iMv := atomicTriple(t, sb.rec.cmds, pathResolvConf)
	if got := sb.rec.cmds[iChmod][3]; got != "0644" {
		t.Errorf("staged file chmod = %s, want 0644 (resolv.conf is world-readable)", got)
	}
	// Ordering guarantee, structurally: the ONLY command that may write
	// resolv.conf is the final mv (rename) — everything else either reads
	// it (the backup cp) or touches the staging sibling. Hence no instant
	// without a resolv.conf.
	for i, c := range sb.rec.cmds {
		if c[len(c)-1] == pathResolvConf && i != iMv {
			t.Errorf("command %d writes resolv.conf in place (%v) — only the atomic mv may", i, c)
		}
	}
	// First-time backup taken; no staging litter; content installed.
	if !sb.rec.ran("sudo", "-n", "cp", pathResolvConf, pathResolvBackup) {
		t.Errorf("initial resolv.conf backup not taken:\n%v", sb.rec.cmds)
	}
	if sysStatExists(pathResolvConf + etcStagingSuffix) {
		t.Errorf("staging file left behind: %s", pathResolvConf+etcStagingSuffix)
	}
	if got := string(mustRead(t, pathResolvConf)); got != "nameserver 127.0.0.1\n" {
		t.Errorf("resolv.conf = %q, want %q", got, "nameserver 127.0.0.1\n")
	}
}

// TestWireOSResolverBackupTakenOnce: the pristine backup is created only
// when absent — a re-run after DHCP/NetworkManager rewrote resolv.conf
// (the AGENTS.md gotcha) rewires the file but never overwrites the one
// true pre-freens backup with an intermediate version.
func TestWireOSResolverBackupTakenOnce(t *testing.T) {
	tempHome(t)
	sb := stubAtomicSys(t)

	wireOSResolver() // first run: backup of the pristine 9.9.9.9 file
	// Something else rewrote resolv.conf in between.
	if err := os.WriteFile(pathResolvConf, []byte("nameserver 8.8.8.8\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	wireOSResolver() // re-run: rewire, keep the pristine backup

	backups := 0
	for _, c := range sb.rec.cmds {
		if len(c) == 5 && c[2] == "cp" && c[3] == pathResolvConf && c[4] == pathResolvBackup {
			backups++
		}
	}
	if backups != 1 {
		t.Errorf("backup cp ran %d times, want exactly once", backups)
	}
	if got := string(mustRead(t, pathResolvBackup)); got != "nameserver 9.9.9.9\n" {
		t.Errorf("pristine backup clobbered: %q, want %q", got, "nameserver 9.9.9.9\n")
	}
	if got := string(mustRead(t, pathResolvConf)); got != "nameserver 127.0.0.1\n" {
		t.Errorf("resolv.conf not rewired on re-run: %q", got)
	}
}

// TestSysWriteEtcFailureCleansUpStaging: a failure at ANY staging step is
// reported as an error, the staged <dest>.freens.new is removed (best
// effort), and the destination keeps its OLD content — the no-gap
// guarantee means no restore is needed.
func TestSysWriteEtcFailureCleansUpStaging(t *testing.T) {
	for _, step := range []string{"cp", "chmod", "mv"} {
		t.Run(step, func(t *testing.T) {
			sb := stubAtomicSys(t)
			dest := filepath.Join(sb.dir, "resolv.conf")
			staging := dest + etcStagingSuffix
			if err := os.WriteFile(dest, []byte("nameserver 9.9.9.9\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			sb.fail = func(argv []string) error {
				if len(argv) >= 3 && argv[0] == "sudo" && argv[2] == step {
					return errStubInactive
				}
				return nil
			}

			if err := sysWriteEtc(dest, []byte("nameserver 127.0.0.1\n"), 0o644); err == nil {
				t.Fatalf("failure at the %s step was not reported", step)
			}
			if !sb.rec.ran("sudo", "-n", "rm", "-f", staging) {
				t.Errorf("staging file not cleaned up after %s failure:\n%v", step, sb.rec.cmds)
			}
			if got := string(mustRead(t, dest)); got != "nameserver 9.9.9.9\n" {
				t.Errorf("destination damaged by the failed install: %q", got)
			}
		})
	}
}

// TestSetupUnitInstallAtomicStaging: the systemd unit write goes through
// the same atomic staging (cp -> chmod -> mv over a .freens.new sibling;
// mkdir -p still prepares the directory) — no in-place rm of unit files
// on INSTALL (removal belongs to --uninstall).
func TestSetupUnitInstallAtomicStaging(t *testing.T) {
	tempHome(t)
	sb := stubAtomicSys(t)

	if _, err := captureStdout(t, func() error { return cmdSetup([]string{}) }); err != nil {
		t.Fatal(err)
	}

	if !sb.rec.ran("sudo", "-n", "mkdir", "-p", filepath.Dir(pathSystemctlUnit)) {
		t.Errorf("unit directory not prepared (mkdir -p lost):\n%v", sb.rec.cmds)
	}
	_, iChmod, _ := atomicTriple(t, sb.rec.cmds, pathSystemctlUnit)
	if got := sb.rec.cmds[iChmod][3]; got != "0644" {
		t.Errorf("unit staging chmod = %s, want 0644", got)
	}
	if sb.rec.ran("sudo", "-n", "rm", "-f", pathSystemctlUnit) {
		t.Errorf("install rm's the unit file in place:\n%v", sb.rec.cmds)
	}
	if sysStatExists(pathSystemctlUnit + etcStagingSuffix) {
		t.Errorf("staging file left behind: %s", pathSystemctlUnit+etcStagingSuffix)
	}
	unit := string(mustRead(t, pathSystemctlUnit))
	if !strings.Contains(unit, "daemon -config ") || !strings.Contains(unit, "Restart=on-failure") {
		t.Errorf("unit content wrong after the atomic install:\n%s", unit)
	}
}

// TestWireOSResolverFailurePrintsManualCommands: when the resolv.conf
// install fails mid-sequence, the box keeps its OLD resolv.conf (no gap,
// nothing to restore) and setup still prints the copy-paste manual
// repair commands, as it always did.
func TestWireOSResolverFailurePrintsManualCommands(t *testing.T) {
	tempHome(t)
	sb := stubAtomicSys(t)
	// The mv (the final, replacing step) fails.
	sb.fail = func(argv []string) error {
		if len(argv) == 6 && argv[0] == "sudo" && argv[2] == "mv" && argv[5] == pathResolvConf {
			return errStubInactive
		}
		return nil
	}

	var note string
	stderr := captureStderr(t, func() { note = wireOSResolver() })

	if !strings.Contains(note, "MANUAL") {
		t.Errorf("summary note does not flag the manual step: %q", note)
	}
	if !strings.Contains(stderr, "sudo") || !strings.Contains(stderr, pathResolvConf) {
		t.Errorf("manual repair commands not printed on failure:\n%s", stderr)
	}
	if !sb.rec.ran("sudo", "-n", "rm", "-f", pathResolvConf+etcStagingSuffix) {
		t.Errorf("staging file not cleaned up after the failed mv:\n%v", sb.rec.cmds)
	}
	// No gap and no restore needed: the old file is still there, intact.
	if got := string(mustRead(t, pathResolvConf)); got != "nameserver 9.9.9.9\n" {
		t.Errorf("old resolv.conf disturbed by the failed install: %q", got)
	}
}

// captureStderr is captureStdout's stderr twin (the manual-commands
// fallback prints there).
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	saved := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	fn()
	w.Close()
	os.Stderr = saved
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}
