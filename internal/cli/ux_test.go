// ux_test.go — tests for the non-technical-user surface added on top of
// setup/register: doctor --fix (daemon + OS resolver repair), the
// plain-language status, the start wizard's decision table, and
// backup/restore (incl. hostile-archive rejection). All against temp homes
// and stubbed system operations.
package cli

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/home"
)

// ---------------------------------------------------------------------------
// doctor --fix
// ---------------------------------------------------------------------------

// TestDoctorFixWiresResolverAndTriesDaemon: on a bare machine (no daemon,
// unwired resolver), doctor --fix re-runs setup (which wires the OS
// resolver as its last step) BEFORE checking — the fix lines appear and
// resolv.conf ends up pointing at the daemon.
func TestDoctorFixWiresResolverAndTriesDaemon(t *testing.T) {
	tempHome(t)
	stubSysForTest(t)
	oldAttempts, oldSleep := doctorFixWaitAttempts, doctorFixWaitSleep
	doctorFixWaitAttempts, doctorFixWaitSleep = 2, time.Millisecond
	t.Cleanup(func() { doctorFixWaitAttempts, doctorFixWaitSleep = oldAttempts, oldSleep })

	out, err := captureStdout(t, func() error { return cmdDoctor([]string{"-fix"}) })
	if err == nil {
		t.Fatal("doctor should still fail while no daemon is running (checks run after fixes)")
	}
	if !strings.Contains(out, "fix: daemon down or install incomplete") {
		t.Errorf("the daemon fix line is missing:\n%s", out)
	}
	// The fix actually wired the stubbed resolv.conf (setup's step (e)).
	b, rerr := os.ReadFile(pathResolvConf)
	if rerr != nil || !strings.Contains(string(b), "127.0.0.1:5300") {
		t.Errorf("resolv.conf not wired by doctor --fix: %v\n%s", rerr, b)
	}
}

// TestDoctorFixWiresResolverWhenDaemonUp: daemon healthy but the OS
// resolver unwired — --fix performs exactly the wiring step (no setup
// re-run, no daemon restart).
func TestDoctorFixWiresResolverWhenDaemonUp(t *testing.T) {
	h := tempHome(t)
	stubSysForTest(t)
	startStubAdmin(t, filepath.Join(h, "admin.sock"), nil)
	if err := os.WriteFile(home.ConfPath(), []byte("[listen]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(home.SeedsPath(), []byte(defaultSeedLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, _ := captureStdout(t, func() error { return cmdDoctor([]string{"-fix"}) })
	if !strings.Contains(out, "fix: OS resolver not pointing") {
		t.Errorf("the OS-resolver fix line is missing:\n%s", out)
	}
	if strings.Contains(out, "running `freens setup`") {
		t.Errorf("--fix re-ran setup although the daemon was up:\n%s", out)
	}
	b, err := os.ReadFile(pathResolvConf)
	if err != nil || !strings.Contains(string(b), "127.0.0.1:5300") {
		t.Errorf("resolv.conf not wired:\n%s", b)
	}
}

// TestDoctorFixNoopWhenHealthy: with the daemon up, conf/seeds present and
// the resolver wired, --fix must stay quiet (no spurious setup re-runs or
// sudo prompts).
func TestDoctorFixNoopWhenHealthy(t *testing.T) {
	h := tempHome(t)
	stubSysForTest(t)
	startStubAdmin(t, filepath.Join(h, "admin.sock"), nil)
	// Pre-wire the resolver so the fix path is not taken.
	if err := os.WriteFile(pathResolvConf, []byte("nameserver 127.0.0.1:5300\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(home.ConfPath(), []byte("[listen]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(home.SeedsPath(), []byte(defaultSeedLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, _ := captureStdout(t, func() error { return cmdDoctor([]string{"-fix"}) })
	if strings.Contains(out, "fix:") {
		t.Errorf("--fix ran repairs on a healthy install:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// status (plain language)
// ---------------------------------------------------------------------------

// TestStatusNotRunningHint: with no daemon, status says so in plain words
// and points at `freens start` (exit path errDaemonNotRunning).
func TestStatusNotRunningHint(t *testing.T) {
	tempHome(t)
	out, err := captureStdout(t, func() error { return cmdStatus(nil) })
	if err != errDaemonNotRunning {
		t.Fatalf("status (no daemon) error = %v, want errDaemonNotRunning", err)
	}
	for _, want := range []string{"daemon not running", "freens start"} {
		if !strings.Contains(out, want) {
			t.Errorf("status output missing %q:\n%s", want, out)
		}
	}
}

// TestStatusPlainLanguage: against a stub daemon the summary reads like a
// sentence; raw hex/counter fields appear ONLY behind -v.
func TestStatusPlainLanguage(t *testing.T) {
	h := tempHome(t)
	startStubAdmin(t, filepath.Join(h, "admin.sock"), map[string]string{
		"alice": resolvedJSON("alice", 4, "203.0.113.42"),
	})
	if err := writeKeyFile(filepath.Join(home.KeysDir(), "alice.key"), mustTestKeypair(t)); err != nil {
		t.Fatal(err)
	}

	out, err := captureStdout(t, func() error { return cmdStatus(nil) })
	if err != nil {
		t.Fatalf("status: %v\n%s", err, out)
	}
	for _, want := range []string{"daemon: running", "3 peers", "alice → 203.0.113.42 · healthy"} {
		if !strings.Contains(out, want) {
			t.Errorf("plain status missing %q:\n%s", want, out)
		}
	}
	for _, hidden := range []string{"node_pk=", "store_envs=", "tld_id"} {
		if strings.Contains(out, hidden) {
			t.Errorf("raw field %q leaked into the plain summary:\n%s", hidden, out)
		}
	}

	out, err = captureStdout(t, func() error { return cmdStatus([]string{"-v"}) })
	if err != nil {
		t.Fatalf("status -v: %v\n%s", err, out)
	}
	if !strings.Contains(out, "node_pk=") || !strings.Contains(out, "store_envs=") {
		t.Errorf("-v is missing the raw daemon fields:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// start wizard (decision table, no network)
// ---------------------------------------------------------------------------

// TestStartNeedsAName: non-interactive start without a name and with an
// empty keychain is a usage error that teaches the form.
func TestStartNeedsAName(t *testing.T) {
	tempHome(t)
	stubSysForTest(t)
	oldAttempts, oldSleep := doctorFixWaitAttempts, doctorFixWaitSleep
	doctorFixWaitAttempts, doctorFixWaitSleep = 1, time.Millisecond
	t.Cleanup(func() { doctorFixWaitAttempts, doctorFixWaitSleep = oldAttempts, oldSleep })
	oldTerm := sysIsTerminal
	sysIsTerminal = func() bool { return false }
	t.Cleanup(func() { sysIsTerminal = oldTerm })

	_, err := captureStdout(t, func() error { return cmdStart(nil) })
	if err == nil || !strings.Contains(err.Error(), "start <name>") {
		t.Fatalf("want `start <name>` usage error, got: %v", err)
	}
}

// TestStartInvalidName: a bad name fails fast with a plain-language
// explanation (before any network work).
func TestStartInvalidName(t *testing.T) {
	tempHome(t)
	stubSysForTest(t)
	oldAttempts, oldSleep := doctorFixWaitAttempts, doctorFixWaitSleep
	doctorFixWaitAttempts, doctorFixWaitSleep = 1, time.Millisecond
	t.Cleanup(func() { doctorFixWaitAttempts, doctorFixWaitSleep = oldAttempts, oldSleep })

	_, err := captureStdout(t, func() error { return cmdStart([]string{"Not A Name!"}) })
	if err == nil || !strings.Contains(err.Error(), "not a valid name") {
		t.Fatalf("want invalid-name error, got: %v", err)
	}
}

// TestStartIdempotentRerun: daemon up, alice owned + published — `start
// alice` must skip register and land on the plain summary.
func TestStartIdempotentRerun(t *testing.T) {
	h := tempHome(t)
	startStubAdmin(t, filepath.Join(h, "admin.sock"), map[string]string{
		"alice": resolvedJSON("alice", 4, "203.0.113.42"),
	})
	if err := writeKeyFile(filepath.Join(home.KeysDir(), "alice.key"), mustTestKeypair(t)); err != nil {
		t.Fatal(err)
	}

	out, err := captureStdout(t, func() error { return cmdStart([]string{"alice"}) })
	if err != nil {
		t.Fatalf("start alice (rerun): %v\n%s", err, out)
	}
	for _, want := range []string{"already yours", "3/3 all set", "alice → 203.0.113.42 · healthy"} {
		if !strings.Contains(out, want) {
			t.Errorf("start output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "mining claim") {
		t.Errorf("start re-registered an already-published name:\n%s", out)
	}
}

// TestStartNotFooledByForeignName: a name that resolves but has NO local
// owner key is somebody else's — start must NOT claim it is ours.
func TestStartNotFooledByForeignName(t *testing.T) {
	h := tempHome(t)
	stub := startStubAdmin(t, filepath.Join(h, "admin.sock"), map[string]string{
		"bob": resolvedJSON("bob", 2, "198.51.100.7"),
	})
	_ = stub

	out, err := captureStdout(t, func() error { return cmdStart([]string{"bob"}) })
	// register runs (no local key) and fails against the stub at the
	// witness step — never the "already yours" shortcut.
	if err == nil {
		t.Fatalf("start bob should fail (no witnesses from the stub), got success:\n%s", out)
	}
	if strings.Contains(out, "already yours") {
		t.Errorf("start treated someone else's published name as ours:\n%s", out)
	}
}

// TestStartTooManyNames: several owned names require an explicit choice.
func TestStartTooManyNames(t *testing.T) {
	tempHome(t)
	stubSysForTest(t)
	oldAttempts, oldSleep := doctorFixWaitAttempts, doctorFixWaitSleep
	doctorFixWaitAttempts, doctorFixWaitSleep = 1, time.Millisecond
	t.Cleanup(func() { doctorFixWaitAttempts, doctorFixWaitSleep = oldAttempts, oldSleep })
	oldTerm := sysIsTerminal
	sysIsTerminal = func() bool { return false }
	t.Cleanup(func() { sysIsTerminal = oldTerm })

	for _, a := range []string{"alice", "bob"} {
		if err := writeKeyFile(filepath.Join(home.KeysDir(), a+".key"), mustTestKeypair(t)); err != nil {
			t.Fatal(err)
		}
	}
	_, err := captureStdout(t, func() error { return cmdStart(nil) })
	if err == nil || !strings.Contains(err.Error(), "several names") {
		t.Fatalf("want several-names error, got: %v", err)
	}
}

// TestStartEndToEnd: the wizard against a REAL in-process witness network
// (mines actual 24-bit PoW): daemon "up" (stub), name fresh → register
// runs via -peers → the summary prints. The full `freens start alice`
// promise in one test.
func TestStartEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("mines real PoW")
	}
	h := tempHome(t)
	t.Chdir(t.TempDir()) // register writes <alias>.tld.cbor to the cwd
	_, peerArgs := startWitnessNet(t, 7)
	startStubAdmin(t, filepath.Join(h, "admin.sock"), nil)

	out, err := captureStdout(t, func() error {
		return cmdStart([]string{"alice", "-peers", peerArgs[0]})
	})
	if err != nil {
		t.Fatalf("start alice: %v\n%s", err, out)
	}
	for _, want := range []string{"1/3", "2/3 your name", "PUBLISHED", "3/3 all set"} {
		if !strings.Contains(out, want) {
			t.Errorf("start output missing %q:\n%s", want, out)
		}
	}
	if _, err := os.Stat(filepath.Join(home.KeysDir(), "alice.key")); err != nil {
		t.Errorf("owner key not in keychain after start: %v", err)
	}
}

// ---------------------------------------------------------------------------
// backup / restore
// ---------------------------------------------------------------------------

// TestBackupRoundTrip: register-shaped keychain -> backup file contains
// every key + RESTORE.txt; wiping the keychain and restoring brings all
// keys back at 0600.
func TestBackupRoundTrip(t *testing.T) {
	tempHome(t)
	if err := home.Ensure(); err != nil {
		t.Fatal(err)
	}
	owner := mustTestKeypair(t)
	if err := writeKeyFile(filepath.Join(home.KeysDir(), "alice.key"), owner); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		p := filepath.Join(home.KeysDir(), fmt.Sprintf("alice.rec%d.key", i))
		if err := writeKeyFile(p, mustTestKeypair(t)); err != nil {
			t.Fatal(err)
		}
	}

	backupPath := filepath.Join(t.TempDir(), "bk.tar.gz")
	out, err := captureStdout(t, func() error { return cmdBackup([]string{"-out", backupPath}) })
	if err != nil {
		t.Fatalf("backup: %v\n%s", err, out)
	}
	for _, want := range []string{"backup written", "alice.key", "OFF this machine"} {
		if !strings.Contains(out, want) {
			t.Errorf("backup output missing %q:\n%s", want, out)
		}
	}

	// The archive: 4 keys + RESTORE.txt, nothing else.
	names := tarNames(t, backupPath)
	wantSet := map[string]bool{"alice.key": true, "alice.rec1.key": true, "alice.rec2.key": true, "alice.rec3.key": true, "RESTORE.txt": true}
	if len(names) != len(wantSet) {
		t.Fatalf("archive contents = %v, want exactly %v", names, wantSet)
	}
	for _, n := range names {
		if !wantSet[n] {
			t.Fatalf("archive contains unexpected entry %q", n)
		}
	}

	// Wipe + restore -> keys are back, 0600, byte-identical.
	orig, err := os.ReadFile(filepath.Join(home.KeysDir(), "alice.key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(home.KeysDir()); err != nil {
		t.Fatal(err)
	}
	out, err = captureStdout(t, func() error { return cmdBackup([]string{"-restore", backupPath}) })
	if err != nil {
		t.Fatalf("restore: %v\n%s", err, out)
	}
	got, err := os.ReadFile(filepath.Join(home.KeysDir(), "alice.key"))
	if err != nil || string(got) != string(orig) {
		t.Errorf("restored alice.key differs: %v", err)
	}
	st, err := os.Stat(filepath.Join(home.KeysDir(), "alice.key"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("restored key mode = %v (err %v), want 0600", st, err)
	}
}

// TestBackupRestoreNoClobber: restore keeps existing keychain files unless
// -force says otherwise.
func TestBackupRestoreNoClobber(t *testing.T) {
	tempHome(t)
	if err := home.Ensure(); err != nil {
		t.Fatal(err)
	}
	kp := mustTestKeypair(t)
	if err := writeKeyFile(filepath.Join(home.KeysDir(), "alice.key"), kp); err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(t.TempDir(), "bk.tar.gz")
	if _, err := captureStdout(t, func() error { return cmdBackup([]string{"-out", backupPath}) }); err != nil {
		t.Fatal(err)
	}
	// Replace the live key with a DIFFERENT one; restoring must keep it.
	if err := writeKeyFile(filepath.Join(home.KeysDir(), "alice.key"), mustTestKeypair(t)); err != nil {
		t.Fatal(err)
	}
	out, err := captureStdout(t, func() error { return cmdBackup([]string{"-restore", backupPath}) })
	if err != nil {
		t.Fatalf("restore: %v\n%s", err, out)
	}
	if !strings.Contains(out, "kept existing") {
		t.Errorf("restore clobbered an existing key:\n%s", out)
	}
	out, err = captureStdout(t, func() error { return cmdBackup([]string{"-restore", backupPath, "-force"}) })
	if err != nil {
		t.Fatalf("restore -force: %v\n%s", err, out)
	}
	if strings.Contains(out, "kept existing") {
		t.Errorf("-force still refused to overwrite:\n%s", out)
	}
}

// TestBackupRejectsHostileArchive: a crafted archive with path traversal
// and foreign entries restores NOTHING outside the keychain.
func TestBackupRejectsHostileArchive(t *testing.T) {
	tempHome(t)
	if err := home.Ensure(); err != nil {
		t.Fatal(err)
	}
	evil := t.TempDir()
	archivePath := filepath.Join(evil, "hostile.tar.gz")
	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, name := range []string{"../../../home/laurent/.ssh/authorized_keys", "/etc/passwd", "normal.key"} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: 5}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte("pwn!\n")); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	gz.Close()
	f.Close()

	out, err := captureStdout(t, func() error { return cmdBackup([]string{"-restore", archivePath}) })
	if err != nil {
		t.Fatalf("restore should tolerate (skip) hostile entries: %v\n%s", err, out)
	}
	// Only the benign entry landed — and the keychain contains nothing else.
	if _, err := os.Stat(filepath.Join(home.KeysDir(), "normal.key")); err != nil {
		t.Errorf("benign entry not restored: %v", err)
	}
	entries, err := os.ReadDir(home.KeysDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "normal.key" {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Errorf("hostile archive smuggled entries into the keychain: %v", names)
	}
}

// TestBackupNothingToBackUp: an empty keychain is a clear usage error.
func TestBackupNothingToBackUp(t *testing.T) {
	tempHome(t)
	if err := home.Ensure(); err != nil {
		t.Fatal(err)
	}
	_, err := captureStdout(t, func() error { return cmdBackup([]string{"-out", filepath.Join(t.TempDir(), "x.tar.gz")}) })
	if err == nil || !strings.Contains(err.Error(), "nothing to back up") {
		t.Fatalf("want nothing-to-back-up error, got: %v", err)
	}
}

// tarNames lists the entry names of a tar.gz (test helper).
func tarNames(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var names []string
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		names = append(names, hdr.Name)
	}
	return names
}
