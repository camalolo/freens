// certmgr_test.go — the renewal-state machine and issuance core: tracking,
// the due policy, renew-in-place (same paths, fresh leaf), deploy hooks,
// and the SAN policy the §9.5 leaf must carry. The nginx half is in
// nginx_test.go.
package certmgr

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/keychain"
)

// testEnv builds a throwaway freens home with one plaintext owner key.
type testEnv struct {
	t       *testing.T
	home    string
	keysDir string
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()
	e := &testEnv{t: t, home: dir, keysDir: filepath.Join(dir, "keys")}
	if err := os.MkdirAll(e.keysDir, 0o700); err != nil {
		t.Fatal(err)
	}
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := keychain.Save(keychain.OwnerKeyPath(e.keysDir, "camalolo"), kp, ""); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *testEnv) now() time.Time { return time.Unix(1_700_000_000, 0) }

func TestIssueApexGetsWildcardSAN(t *testing.T) {
	e := newTestEnv(t)
	iss, err := Issue(e.keysDir, "camalolo", filepath.Join(e.home, "out"), "", e.now())
	if err != nil {
		t.Fatalf("issue apex: %v", err)
	}
	want := []string{"camalolo", "*.camalolo"}
	if len(iss.SANs) != 2 || iss.SANs[0] != want[0] || iss.SANs[1] != want[1] {
		t.Fatalf("apex SANs = %v, want %v", iss.SANs, want)
	}
	// Serving chain: leaf + owner CA; key 0600, cert world-readable.
	for _, p := range []string{iss.CertPath, iss.KeyPath} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("missing %s: %v", p, err)
		}
	}
	if fi, _ := os.Stat(iss.KeyPath); fi.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %v, want 0600", fi.Mode().Perm())
	}
	if fi, _ := os.Stat(iss.CertPath); fi.Mode().Perm() != 0o644 {
		t.Fatalf("cert mode = %v, want 0644", fi.Mode().Perm())
	}
}

func TestIssueSubNameExplicitSAN(t *testing.T) {
	e := newTestEnv(t)
	iss, err := Issue(e.keysDir, "www.camalolo", filepath.Join(e.home, "out"), "", e.now())
	if err != nil {
		t.Fatalf("issue sub-name: %v", err)
	}
	// Windows clients ignore *.alias coverage for sub-names — the explicit
	// SAN is the whole point of issuing per sub-name.
	if len(iss.SANs) != 1 || iss.SANs[0] != "www.camalolo" {
		t.Fatalf("sub-name SANs = %v, want exactly [www.camalolo]", iss.SANs)
	}
}

func TestIssueUnknownAliasFails(t *testing.T) {
	e := newTestEnv(t)
	if _, err := Issue(e.keysDir, "www.nobody", filepath.Join(e.home, "out"), "", e.now()); err == nil {
		t.Fatal("issue for an unowned alias succeeded")
	}
}

func TestTrackIssueRoundTrip(t *testing.T) {
	e := newTestEnv(t)
	r, iss, err := TrackIssue(e.home, e.keysDir, "www.camalolo", "", "", "", e.now())
	if err != nil {
		t.Fatalf("track-issue: %v", err)
	}
	if r.CertPath != iss.CertPath || r.KeyPath != iss.KeyPath {
		t.Fatalf("state paths disagree with issued files")
	}
	if r.Alias != "camalolo" {
		t.Fatalf("alias = %q", r.Alias)
	}
	got, err := LoadState(e.home, "www.camalolo")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.NotAfter != r.NotAfter || got.Name != "www.camalolo" {
		t.Fatalf("round trip mismatch: %+v vs %+v", got, r)
	}
	list, err := ListState(e.home)
	if err != nil || len(list) != 1 || list[0].Name != "www.camalolo" {
		t.Fatalf("ListState = %v, %v", list, err)
	}
}

func TestRenewPolicy(t *testing.T) {
	e := newTestEnv(t)
	now := e.now()
	r, _, err := TrackIssue(e.home, e.keysDir, "www.camalolo", "", "", "", now)
	if err != nil {
		t.Fatal(err)
	}
	// Fresh leaf: 7 days of life, 2-day renew-before window ⇒ not due on
	// day 0, due only inside the last 48 h.
	if IsDue(r, now.Add(24*time.Hour)) {
		t.Fatal("due after one day — renew-before window too wide")
	}
	if !IsDue(r, now.Add(6*24*time.Hour)) {
		t.Fatal("not due 24 h before expiry — renew-before window too narrow")
	}
}

func TestRenewOneInPlace(t *testing.T) {
	e := newTestEnv(t)
	now := e.now()
	r0, _, err := TrackIssue(e.home, e.keysDir, "www.camalolo", "", "", "", now)
	if err != nil {
		t.Fatal(err)
	}
	oldCert, err := os.ReadFile(r0.CertPath)
	if err != nil {
		t.Fatal(err)
	}

	// Not due: refuses without force, changes nothing.
	if _, err := RenewOne(e.home, e.keysDir, "www.camalolo", "", RenewOpts{}, now.Add(24*time.Hour)); !errors.Is(err, ErrNotDue) {
		t.Fatalf("fresh renew err = %v, want ErrNotDue", err)
	}

	// Inside the renew-before window (day 6 of 7): renews in place.
	r1, err := RenewOne(e.home, e.keysDir, "www.camalolo", "", RenewOpts{}, now.Add(6*24*time.Hour))
	if err != nil {
		t.Fatalf("forced renew: %v", err)
	}
	if r1.CertPath != r0.CertPath {
		t.Fatalf("renew moved the cert: %s -> %s", r0.CertPath, r1.CertPath)
	}
	if r1.NotAfter <= r0.NotAfter {
		t.Fatalf("renew did not extend validity: %d -> %d", r0.NotAfter, r1.NotAfter)
	}
	newCert, err := os.ReadFile(r1.CertPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(newCert) == string(oldCert) {
		t.Fatal("renewed cert is byte-identical — leaf keys are fresh per §9.5.3, this cannot happen")
	}

	// Deployment continuity: a tracked nginx file survives the renewal.
	r1.NginxFiles = []string{"/etc/nginx/sites-enabled/app"}
	if err := Track(e.home, r1); err != nil {
		t.Fatal(err)
	}
	r2, err := RenewOne(e.home, e.keysDir, "www.camalolo", "", RenewOpts{Force: true, NoReload: true}, now.Add(2_000_000*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(r2.NginxFiles) != 1 || r2.NginxFiles[0] != "/etc/nginx/sites-enabled/app" {
		t.Fatalf("nginx deployment list lost on renew: %+v", r2.NginxFiles)
	}
}

func TestRenewUntracked(t *testing.T) {
	e := newTestEnv(t)
	if _, err := RenewOne(e.home, e.keysDir, "ghost.camalolo", "", RenewOpts{Force: true}, e.now()); !errors.Is(err, ErrNotTracked) {
		t.Fatalf("err = %v, want ErrNotTracked", err)
	}
}

func TestRenewDeployHookRunsAndReports(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell hook")
	}
	e := newTestEnv(t)
	now := e.now()
	mark := filepath.Join(e.home, "hook-ran")
	hook := "touch " + mark
	if _, _, err := TrackIssue(e.home, e.keysDir, "www.camalolo", "", "", hook, now); err != nil {
		t.Fatal(err)
	}
	if _, err := RenewOne(e.home, e.keysDir, "www.camalolo", "", RenewOpts{Force: true}, now.Add(1_000_000*time.Second)); err != nil {
		t.Fatalf("renew with hook: %v", err)
	}
	if _, err := os.Stat(mark); err != nil {
		t.Fatalf("deploy hook did not run: %v", err)
	}

	// A failing hook is REPORTED, but the renewal itself stands (the cert
	// files are already swapped; the hook had its chance).
	e2 := newTestEnv(t)
	if _, _, err := TrackIssue(e2.home, e2.keysDir, "www.camalolo", "", "", "exit 3", now); err != nil {
		t.Fatal(err)
	}
	r, err := RenewOne(e2.home, e2.keysDir, "www.camalolo", "", RenewOpts{Force: true}, now.Add(1_000_000*time.Second))
	if err == nil || r == nil {
		t.Fatalf("failing hook: err=%v r=%v — want renewal kept + error reported", err, r)
	}
	if !strings.Contains(err.Error(), "deploy hook") {
		t.Fatalf("error should name the deploy hook: %v", err)
	}
}

func TestRenewDueBulk(t *testing.T) {
	e := newTestEnv(t)
	now := e.now()
	if _, _, err := TrackIssue(e.home, e.keysDir, "camalolo", "", "", "", now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := TrackIssue(e.home, e.keysDir, "www.camalolo", "", "", "", now); err != nil {
		t.Fatal(err)
	}
	// Nothing due yet.
	renewed, err := RenewDue(e.home, e.keysDir, "", RenewOpts{}, now.Add(time.Hour))
	if err != nil || len(renewed) != 0 {
		t.Fatalf("RenewDue on fresh certs = %d renewed, err %v — want 0, nil", len(renewed), err)
	}
	// One day before expiry both are inside the window.
	renewed, err = RenewDue(e.home, e.keysDir, "", RenewOpts{}, now.Add(6*24*time.Hour))
	if err != nil {
		t.Fatalf("RenewDue: %v", err)
	}
	if len(renewed) != 2 {
		t.Fatalf("renewed %d, want 2", len(renewed))
	}
}

func TestEnsureTrackedIssuesWhenMissing(t *testing.T) {
	e := newTestEnv(t)
	now := e.now()
	if _, err := EnsureTracked(e.home, e.keysDir, "www.camalolo", "", now); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(e.home, "www.camalolo"); err != nil {
		t.Fatalf("EnsureTracked did not track: %v", err)
	}
	// Files removed: EnsureTracked re-issues instead of returning a state
	// pointing at nothing.
	os.Remove(filepath.Join(ExportDir(e.home), "www.camalolo.crt"))
	if _, err := EnsureTracked(e.home, e.keysDir, "www.camalolo", "", now); err != nil {
		t.Fatalf("re-issue after file loss: %v", err)
	}
	if _, err := os.Stat(filepath.Join(ExportDir(e.home), "www.camalolo.crt")); err != nil {
		t.Fatalf("cert not re-issued: %v", err)
	}
}

func TestForget(t *testing.T) {
	e := newTestEnv(t)
	now := e.now()
	if _, _, err := TrackIssue(e.home, e.keysDir, "www.camalolo", "", "", "", now); err != nil {
		t.Fatal(err)
	}
	if err := Forget(e.home, "www.camalolo"); err != nil {
		t.Fatalf("forget: %v", err)
	}
	if _, err := LoadState(e.home, "www.camalolo"); !errors.Is(err, ErrNotTracked) {
		t.Fatalf("load after forget = %v, want ErrNotTracked", err)
	}
	if err := Forget(e.home, "www.camalolo"); !errors.Is(err, ErrNotTracked) {
		t.Fatalf("double forget = %v, want ErrNotTracked", err)
	}
}
