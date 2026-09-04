// trust_ls_test.go — `freens trust ls` / `freens trust remove`: the §9.5.4
// operator inventory. The verbs read the <home>/tls state the daemon's
// trust-sync engine maintains; the tests drive the engine directly and
// assert the verbs surface it.
package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/tlsca"
	"github.com/camalolo/freens/internal/trustsync"
)

// trustFixture installs a cross-cert for alias into a temp home the way the
// daemon would (OnOwnerCA, mature claim), returning the engine's options.
func trustFixture(t *testing.T, alias string) trustsync.Options {
	t.Helper()
	dir := tempHome(t)
	opts := trustsync.Options{
		HomeDir:     dir,
		NSSInstall:  false,
		SystemStore: false,
	}
	e, err := trustsync.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = 7
	}
	caDER, _, err := tlsca.OwnerCA(seed, alias, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	e.OnOwnerCA(alias, []byte{1, 2, 3}, caDER, time.Now().Add(24*time.Hour).Unix(), false)
	if len(e.Snapshot()) != 1 {
		t.Fatal("fixture: install did not land")
	}
	return opts
}

func TestTrustListShowsInstalledNamespace(t *testing.T) {
	trustFixture(t, "bob")
	out, err := captureStdout(t, func() error { return cmdTrustList(nil) })
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"bob", "installed", "local trust root"} {
		if !strings.Contains(out, want) {
			t.Errorf("trust ls output missing %q:\n%s", want, out)
		}
	}
}

func TestTrustListEmptyHome(t *testing.T) {
	tempHome(t)
	out, err := captureStdout(t, func() error { return cmdTrustList(nil) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "no cross-certified namespaces") {
		t.Errorf("empty-home output unexpected:\n%s", out)
	}
}

func TestTrustRemovePurgesNamespace(t *testing.T) {
	opts := trustFixture(t, "bob")
	e, err := trustsync.New(opts) // sees the state the daemon wrote
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Snapshot()) != 1 {
		t.Fatal("fixture: state did not persist to the temp home")
	}

	out, fnErr := captureStdout(t, func() error { return cmdTrustRemove([]string{"bob"}) })
	if fnErr != nil {
		t.Fatal(fnErr)
	}
	if !strings.Contains(out, "purged") {
		t.Errorf("remove output unexpected:\n%s", out)
	}

	e2, err := trustsync.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(e2.Snapshot()) != 0 {
		t.Fatalf("alias survived trust remove: %+v", e2.Snapshot())
	}
}

func TestTrustRemoveUnknownAlias(t *testing.T) {
	trustFixture(t, "bob")
	out, fnErr := captureStdout(t, func() error { return cmdTrustRemove([]string{"alice"}) })
	if fnErr != nil {
		t.Fatal(fnErr)
	}
	if !strings.Contains(out, "nothing installed") {
		t.Errorf("unknown-alias output unexpected:\n%s", out)
	}
}

func TestTrustRemoveRequiresAlias(t *testing.T) {
	tempHome(t)
	if err := cmdTrustRemove(nil); err == nil {
		t.Fatal("trust remove without an alias must be a usage error")
	}
}
