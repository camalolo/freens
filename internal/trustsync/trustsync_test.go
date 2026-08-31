// trustsync_test.go — the §9.5.4 engine: mint-on-verified, dedupe, rotation
// and purge (real minting, real chain verification; exec-based installers
// self-skip in the test environment).
package trustsync

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/tlsca"
)

func testOpts(t *testing.T) Options {
	t.Helper()
	return Options{
		HomeDir: t.TempDir(),
		Logger:  nil,
		Now:     func() time.Time { return time.Now() },
		// NEVER touch the real user's stores from tests: both installers
		// exec into certutil / the system bundle. (Found live: an early
		// test run added freens-cross-bob to the developer's real NSS DB.)
		NSSInstall:  false,
		SystemStore: false,
	}
}

func ownerSeed(t *testing.T, b byte) []byte {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = b
	}
	return seed
}

func mustEngine(t *testing.T, opts Options) *Engine {
	t.Helper()
	e, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// ownerCA derives the CA AND its private key (leaf issuance needs the key).
func ownerCA(t *testing.T, seed []byte, alias string, now time.Time) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	der, key, err := tlsca.OwnerCA(seed, alias, now)
	if err != nil {
		t.Fatal(err)
	}
	return der, key
}

func TestLocalRootCreatedOnce(t *testing.T) {
	opts := testOpts(t)
	e1 := mustEngine(t, opts)
	fp1 := e1.RootFingerprint()

	// A SECOND engine over the same home must reuse the SAME root — not
	// silently rotate the installation's trust anchor.
	e2 := mustEngine(t, opts)
	if e2.RootFingerprint() != fp1 {
		t.Fatal("second engine generated a different local root")
	}
	// The key file must be 0600 — POSIX only: Windows maps os.Chmod to the
	// read-only attribute (0600-with-owner-write reports 0666) and access
	// is governed by ACLs instead.
	st, err := os.Stat(filepath.Join(opts.HomeDir, "tls", "root.key"))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Fatalf("root.key mode = %04o, want 0600", st.Mode().Perm())
	}
}

func TestOnOwnerCAInstallsAndDedupes(t *testing.T) {
	opts := testOpts(t)
	e := mustEngine(t, opts)
	seed := ownerSeed(t, 7)
	caDER, caKey := ownerCA(t, seed, "bob", time.Now())
	expires := time.Now().Add(24 * time.Hour).Unix()

	e.OnOwnerCA("bob", []byte{1, 2, 3}, caDER, expires)

	snap := e.Snapshot()
	if len(snap) != 1 || snap[0].Alias != "bob" {
		t.Fatalf("snapshot = %+v", snap)
	}
	// Spool file exists, is a CERTIFICATE PEM, and the chain leaf → cross →
	// root verifies locally with the name constraint enforced.
	pe, err := os.ReadFile(e.spoolPath("bob"))
	if err != nil {
		t.Fatalf("spool file: %v", err)
	}
	cross, err := tlsca.ParseCertPEM(pe)
	if err != nil {
		t.Fatal(err)
	}
	rootPEM, err := os.ReadFile(filepath.Join(opts.HomeDir, "tls", "root.crt"))
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := tlsca.ParseCertPEM(rootPEM)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, _, err := tlsca.Leaf(caDER, caKey, []string{"blog.bob"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	inters := x509.NewCertPool()
	inters.AddCert(cross)
	leafCert, err := tlsca.ParseCertDER(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leafCert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters}); err != nil {
		t.Fatalf("installed chain does not verify: %v", err)
	}

	// Duplicate notification: same identity, still fresh — no re-mint.
	st1 := e.Snapshot()[0]
	e.OnOwnerCA("bob", []byte{1, 2, 3}, caDER, expires)
	st2 := e.Snapshot()[0]
	if st1.NotAfter != st2.NotAfter {
		t.Fatal("duplicate notification re-minted the cross-cert")
	}
}

// TestOnOwnerCARotatesOnCAChange: same tld_id, NEW CA bytes (a CA rotation)
// must re-mint rather than dedupe.
func TestOnOwnerCARotatesOnCAChange(t *testing.T) {
	opts := testOpts(t)
	e := mustEngine(t, opts)
	expires := time.Now().Add(24 * time.Hour).Unix()

	ca1, _, err := tlsca.OwnerCA(ownerSeed(t, 7), "bob", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	e.OnOwnerCA("bob", []byte{1}, ca1, expires)
	before := e.Snapshot()[0]

	// A different derivation day ⇒ different cert bytes ⇒ a new ca_sha256.
	ca2, _, err := tlsca.OwnerCA(ownerSeed(t, 7), "bob", time.Now().Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if string(ca1) == string(ca2) {
		t.Skip("CA bytes identical across derivation days (test invariant broken)")
	}
	e.OnOwnerCA("bob", []byte{1}, ca2, expires+172800)
	after := e.Snapshot()[0]
	if after.CASha256 == before.CASha256 {
		t.Fatal("CA rotation did not update the recorded CA hash")
	}
	if after.NotAfter == before.NotAfter {
		t.Fatal("CA rotation did not re-mint the cross-cert")
	}
}

func TestOnAliasDeadPurges(t *testing.T) {
	opts := testOpts(t)
	e := mustEngine(t, opts)
	caDER, _ := ownerCA(t, ownerSeed(t, 7), "bob", time.Now())
	tldID := []byte{1, 2, 3}
	expires := time.Now().Add(24 * time.Hour).Unix()
	e.OnOwnerCA("bob", tldID, caDER, expires)
	if len(e.Snapshot()) != 1 {
		t.Fatal("fixture: nothing installed")
	}

	// A stale death signal for a DIFFERENT identity must not purge.
	e.OnAliasDead("bob", []byte{9, 9, 9})
	if len(e.Snapshot()) != 1 {
		t.Fatal("stale identity signal purged the live binding")
	}
	if _, err := os.Stat(e.spoolPath("bob")); err != nil {
		t.Fatal("spool file removed by a stale signal")
	}

	// The real death (matching tldID) purges the spool file and state.
	e.OnAliasDead("bob", tldID)
	if len(e.Snapshot()) != 0 {
		t.Fatal("dead alias still in state")
	}
	if _, err := os.Stat(e.spoolPath("bob")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("spool file survived the purge")
	}
	// Repeated death signals are no-ops.
	e.OnAliasDead("bob", tldID)
	if len(e.Snapshot()) != 0 {
		t.Fatal("state resurrected by a duplicate death")
	}
}

// TestOnOwnerCAValidatesScreen: a foreign CA whose CN mismatches the alias
// must be refused — the constraint/alias binding is the safety property.
func TestOnOwnerCAValidatesScreen(t *testing.T) {
	opts := testOpts(t)
	e := mustEngine(t, opts)
	caDER, _ := ownerCA(t, ownerSeed(t, 7), "bob", time.Now())
	e.OnOwnerCA("alice", []byte{1}, caDER, time.Now().Add(24*time.Hour).Unix())
	if len(e.Snapshot()) != 0 {
		t.Fatal("CN/alias mismatch was installed")
	}
	if _, err := os.Stat(e.spoolPath("alice")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("mismatched CA reached the spool")
	}
}

// Concurrent notifications for the same alias must not corrupt state.
func TestOnOwnerCAConcurrent(t *testing.T) {
	opts := testOpts(t)
	e := mustEngine(t, opts)
	caDER, _ := ownerCA(t, ownerSeed(t, 7), "bob", time.Now())
	expires := time.Now().Add(24 * time.Hour).Unix()
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			e.OnOwnerCA("bob", []byte{1}, caDER, expires)
			done <- struct{}{}
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
	if len(e.Snapshot()) != 1 {
		t.Fatalf("state entries = %d, want 1", len(e.Snapshot()))
	}
	if _, err := os.Stat(e.spoolPath("bob")); err != nil {
		t.Fatal("spool missing after concurrent mints")
	}
}

// The state file round-trips: a new engine over the same home sees bob.
func TestStatePersists(t *testing.T) {
	opts := testOpts(t)
	e1 := mustEngine(t, opts)
	caDER, _ := ownerCA(t, ownerSeed(t, 7), "bob", time.Now())
	e1.OnOwnerCA("bob", []byte{1, 2, 3}, caDER, time.Now().Add(24*time.Hour).Unix())

	e2 := mustEngine(t, opts)
	snap := e2.Snapshot()
	if len(snap) != 1 || snap[0].Alias != "bob" {
		t.Fatalf("restored state = %+v", snap)
	}
}
