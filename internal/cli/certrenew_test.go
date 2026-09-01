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
	// Fresh cert + quiet: no output at all, success.
	got, err := captureStdout(t, func() error { return cmdCertRenew([]string{"-quiet"}) })
	if err != nil {
		t.Fatalf("quiet bulk renew: %v", err)
	}
	if strings.TrimSpace(got) != "" {
		t.Fatalf("quiet renew printed:\n%s", got)
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
