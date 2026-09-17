// certrenew_test.go — the CLI cert subcommands (issue → list → renew →
// forget) against a temp FREENS_HOME. The nginx verb is NOT exercised
// here on purpose: it would need either the real nginx binary/config of
// this box (absolutely not) or the runner seam, which the certmgr package
// already tests exhaustively.
package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/certmgr"
	"github.com/camalolo/freens/internal/keychain"
)

func TestCertIssueTracksAndRenews(t *testing.T) {
	home := tempHome(t)
	keys := filepath.Join(home, "keys")
	if err := os.MkdirAll(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	kp := lifecycleKeypair(t, 3)
	if err := keychain.Save(keychain.OwnerKeyPath(keys, "alice"), kp, ""); err != nil {
		t.Fatal(err)
	}

	// Issue + track (default), into a fixed export dir.
	out := filepath.Join(home, "out")
	got, err := captureStdout(t, func() error {
		return cmdCert([]string{"-out-dir", out, "www.alice"})
	})
	if err != nil {
		t.Fatalf("cert issue: %v", err)
	}
	if !strings.Contains(got, "tracked") || !strings.Contains(got, "www.alice") {
		t.Fatalf("issue output missing tracking line:\n%s", got)
	}
	st, err := certmgr.LoadState(home, "www.alice")
	if err != nil {
		t.Fatalf("not tracked: %v", err)
	}
	if st.CertPath != filepath.Join(out, "www.alice.crt") {
		t.Fatalf("tracked path = %s", st.CertPath)
	}

	// An apex name of an alias we don't own fails and tracks nothing.
	if _, err := captureStdout(t, func() error {
		return cmdCert([]string{"-out-dir", out, "camalolo"})
	}); err == nil {
		t.Fatalf("apex 'camalolo' under alias alice must fail")
	}
	if _, err := certmgr.LoadState(home, "camalolo"); err == nil {
		t.Fatal("a failed issue must not track anything")
	}

	// -no-track issues the apex leaf (wildcard SAN included) but records
	// no renewal state.
	got, err = captureStdout(t, func() error {
		return cmdCert([]string{"-out-dir", out, "-no-track", "alice"})
	})
	if err != nil {
		t.Fatalf("apex issue: %v", err)
	}
	if strings.Contains(got, "tracked") {
		t.Fatalf("-no-track must not print the tracking line:\n%s", got)
	}
	if _, err := certmgr.LoadState(home, "alice"); err == nil {
		t.Fatal("-no-track must not track")
	}
	if !strings.Contains(got, "sans=alice, *.alice") {
		t.Fatalf("apex leaf must carry the wildcard SAN:\n%s", got)
	}

	// Renew: not due → skip line, exit 0; -force → renewed.
	got, err = captureStdout(t, func() error {
		return cmdCertRenew([]string{"www.alice"})
	})
	if err != nil {
		t.Fatalf("renew (not due): %v", err)
	}
	if !strings.Contains(got, "still fresh") {
		t.Fatalf("renew output:\n%s", got)
	}
	if _, err := captureStdout(t, func() error {
		return cmdCertRenew([]string{"-force", "www.alice"})
	}); err != nil {
		t.Fatalf("forced renew: %v", err)
	}

	// List shows the tracked entry.
	got, err = captureStdout(t, func() error { return cmdCertList(nil) })
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if !strings.Contains(got, "www.alice") {
		t.Fatalf("list output:\n%s", got)
	}

	// Forget drops the state.
	if err := cmdCertForget([]string{"www.alice"}); err != nil {
		t.Fatalf("forget: %v", err)
	}
	if _, err := certmgr.LoadState(home, "www.alice"); err == nil {
		t.Fatal("state survived forget")
	}
}

func TestCertRenewQuietBulk(t *testing.T) {
	home := tempHome(t)
	keys := filepath.Join(home, "keys")
	if err := os.MkdirAll(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	kp := lifecycleKeypair(t, 4)
	if err := keychain.Save(keychain.OwnerKeyPath(keys, "bob"), kp, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := certmgr.TrackIssue(home, keys, "bob", "", "", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	// Fresh cert + quiet: exactly one cron-visible summary line (a run
	// that prints NOTHING is indistinguishable from a run that never
	// happened — found live 2026-09-17).
	got, err := captureStdout(t, func() error { return cmdCertRenew([]string{"-quiet"}) })
	if err != nil {
		t.Fatalf("quiet bulk renew: %v", err)
	}
	if !strings.Contains(got, "cert renew: 1 due, 0 renewed, 1 skipped") {
		t.Fatalf("quiet renew summary missing:\n%s", got)
	}
}

func TestCertSubcommandDispatch(t *testing.T) {
	tempHome(t)
	// The bare verb with two positionals explains the subcommands.
	_, err := captureStdout(t, func() error { return cmdCert([]string{"a", "b"}) })
	if err == nil || !strings.Contains(err.Error(), "subcommands") {
		t.Fatalf("usage error = %v", err)
	}
}

// TestCertUnknownSubcommandNeverBecomesAName: a typo'd subcommand (`cert
// rene`) must not reach the issuer as certificate NAME "rene" — it gets
// the usage listing instead. A REAL keychain name keeps issuing.
func TestCertUnknownSubcommandNeverBecomesAName(t *testing.T) {
	home := tempHome(t)
	keys := filepath.Join(home, "keys")
	if err := os.MkdirAll(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := keychain.Save(keychain.OwnerKeyPath(keys, "alice"), lifecycleKeypair(t, 9), ""); err != nil {
		t.Fatal(err)
	}

	// Typo'd subcommand, empty-ish keychain for "rene": refused with the
	// subcommand list, nothing issued.
	_, err := captureStdout(t, func() error { return cmdCert([]string{"rene"}) })
	if err == nil || !strings.Contains(err.Error(), "neither a subcommand nor a name") || !strings.Contains(err.Error(), "cert renew") {
		t.Fatalf("typo'd subcommand = %v, want the usage listing", err)
	}
	if _, serr := os.Stat(filepath.Join(home, "rene.crt")); serr == nil {
		t.Fatal("rene.crt was issued for a typo'd subcommand")
	}

	// A real keychain name still flows through to the issuer.
	out := filepath.Join(home, "out")
	got, err := captureStdout(t, func() error {
		return cmdCert([]string{"-out-dir", out, "-no-track", "alice"})
	})
	if err != nil {
		t.Fatalf("cert <owned name>: %v\n%s", err, got)
	}
	if _, serr := os.Stat(filepath.Join(out, "alice.crt")); serr != nil {
		t.Fatalf("owned-name issue produced no cert: %v", serr)
	}
}

// TestShortHash: the display clamp never panics on daemon-provided values
// shorter than the usual 64-hex fingerprint.
func TestShortHash(t *testing.T) {
	long := strings.Repeat("ab", 32) // 64 hex chars, the normal sha256 shape
	if got := shortHash(long); got != long[:16] {
		t.Errorf("shortHash(64 hex) = %q, want %q", got, long[:16])
	}
	if got := shortHash("abc"); got != "abc" {
		t.Errorf("shortHash(short) = %q, want it verbatim", got)
	}
	if got := shortHash(""); got != "" {
		t.Errorf("shortHash(empty) = %q, want empty", got)
	}
	if got := shortHash("0123456789abcdef0123"); got != "0123456789abcdef" {
		t.Errorf("shortHash(21 chars) = %q, want the 16-char clamp", got)
	}
}

func TestFlagsFirstLetsNamesLead(t *testing.T) {
	// The natural CLI order (name before flags) must parse — Go's flag
	// package stops at the first positional otherwise.
	got := flagsFirst([]string{"www.camalolo", "-clone", "camalolo.com", "-force"}, "clone", "config", "server")
	want := []string{"-clone", "camalolo.com", "-force", "www.camalolo"}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("flagsFirst = %q, want %q", got, want)
	}
	// =-joined values, bare value flags, and pure-flag args stay put.
	got = flagsFirst([]string{"-quiet", "name1", "-deploy-hook=echo hi", "name2", "-days", "3"}, "deploy-hook", "days")
	want = []string{"-quiet", "-deploy-hook=echo hi", "-days", "3", "name1", "name2"}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("flagsFirst = %q, want %q", got, want)
	}

	// End to end: cert -out-dir AFTER the name issues exactly the same.
	home := tempHome(t)
	keys := filepath.Join(home, "keys")
	if err := os.MkdirAll(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := keychain.Save(keychain.OwnerKeyPath(keys, "alice"), lifecycleKeypair(t, 7), ""); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(home, "out")
	if _, err := captureStdout(t, func() error {
		return cmdCert([]string{"-no-track", "www.alice", "-out-dir", out})
	}); err != nil {
		t.Fatalf("name-first issue: %v", err)
	}
	if _, err := os.Stat(filepath.Join(out, "www.alice.crt")); err != nil {
		t.Fatalf("cert file missing: %v", err)
	}
}
