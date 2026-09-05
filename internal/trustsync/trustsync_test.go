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
	"sync/atomic"
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

	e.OnOwnerCA("bob", []byte{1, 2, 3}, caDER, expires, false)

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
	e.OnOwnerCA("bob", []byte{1, 2, 3}, caDER, expires, false)
	st2 := e.Snapshot()[0]
	if st1.NotAfter != st2.NotAfter {
		t.Fatal("duplicate notification re-minted the cross-cert")
	}
}

// TestOnOwnerCARotationGate: same tld_id, NEW CA bytes (a CA rotation).
// The §9.5.4 observation gate defers the swap: the installed cross-cert
// stays authoritative for rotationGrace, the state shows "rotating" with
// the pending CA, and only a post-grace re-observation completes it.
func TestOnOwnerCARotationGate(t *testing.T) {
	clock := time.Now()
	opts := testOpts(t)
	opts.Now = func() time.Time { return clock }
	e := mustEngine(t, opts)
	expires := clock.Add(24 * time.Hour).Unix()

	ca1, _, err := tlsca.OwnerCA(ownerSeed(t, 7), "bob", clock)
	if err != nil {
		t.Fatal(err)
	}
	e.OnOwnerCA("bob", []byte{1}, ca1, expires, false)
	before := e.Snapshot()[0]
	pe0, err := os.ReadFile(e.spoolPath("bob"))
	if err != nil {
		t.Fatal(err)
	}
	oldCrossFP := tlsca.Fingerprint(pe0) // spool holds the CROSS-cert: fingerprint its bytes

	// A DIFFERENT SEED under the same alias: a different CA identity — the
	// tampered/stolen-key shape the §9.5.4 rotation gate exists for. (A
	// different derivation DAY with the same seed is NOT a rotation: the
	// key is deterministic, only the day-window bytes change — that path
	// dedupes, see TestSameKeyDifferentDayDedupes.)
	ca2, _, err := tlsca.OwnerCA(ownerSeed(t, 8), "bob", clock)
	if err != nil {
		t.Fatal(err)
	}
	if string(ca1) == string(ca2) {
		t.Skip("CA bytes identical across seeds (test invariant broken)")
	}
	newFP, icerr := tlsca.CAIdentity(ca2)
	if icerr != nil {
		t.Fatal(icerr)
	}
	if id1, _ := tlsca.CAIdentity(ca1); id1 == newFP {
		t.Fatal("fixture: different seeds produced the same CA identity")
	}

	// First sight of the new CA: DEFERRED — old cross-cert stays installed.
	e.OnOwnerCA("bob", []byte{1}, ca2, expires+172800, false)
	mid := e.Snapshot()[0]
	if mid.CASha256 != before.CASha256 {
		t.Fatal("rotation swapped the recorded CA before the grace elapsed")
	}
	if mid.Status != statusRotating || mid.PendingCASha256 != newFP {
		t.Fatalf("mid-rotation state = %+v, want rotating with pending", mid)
	}
	// The spool (bridge source of truth) still holds the OLD cross-cert.
	pe, err := os.ReadFile(e.spoolPath("bob"))
	if err != nil {
		t.Fatal(err)
	}
	if tlsca.Fingerprint(pe) != oldCrossFP {
		t.Fatal("spool cross-cert was swapped before the grace elapsed")
	}

	// Pre-grace re-observation: still deferred, grace does NOT restart.
	clock = clock.Add(rotationGrace / 2)
	e.OnOwnerCA("bob", []byte{1}, ca2, expires+172800, false)
	if s := e.Snapshot()[0]; s.Status != statusRotating {
		t.Fatalf("pre-grace re-observation completed the rotation (status %q)", s.Status)
	}

	// Post-grace re-observation: the rotation completes.
	clock = clock.Add(rotationGrace)
	e.OnOwnerCA("bob", []byte{1}, ca2, expires+172800, false)
	after := e.Snapshot()[0]
	if after.CASha256 != newFP {
		t.Fatal("post-grace observation did not complete the rotation")
	}
	if after.Status != statusInstalled || after.PendingCASha256 != "" {
		t.Fatalf("post-rotation state = %+v, want installed with no pending", after)
	}
	pe, err = os.ReadFile(e.spoolPath("bob"))
	if err != nil {
		t.Fatal(err)
	}
	if tlsca.Fingerprint(pe) == oldCrossFP {
		t.Fatal("post-rotation spool file still holds the old cross-cert")
	}
}

// TestOnOwnerCARotationAbortsOnRevert: while a rotation is pending, a
// notification reverting to the installed CA aborts it (the rrset flipped
// back — typical DHT propagation lag, and exactly what a flapping tamper
// looks like).
func TestOnOwnerCARotationAbortsOnRevert(t *testing.T) {
	clock := time.Now()
	opts := testOpts(t)
	opts.Now = func() time.Time { return clock }
	e := mustEngine(t, opts)
	expires := clock.Add(24 * time.Hour).Unix()

	ca1, _, err := tlsca.OwnerCA(ownerSeed(t, 7), "bob", clock)
	if err != nil {
		t.Fatal(err)
	}
	e.OnOwnerCA("bob", []byte{1}, ca1, expires, false)
	orig := e.Snapshot()[0]

	ca2, _, err := tlsca.OwnerCA(ownerSeed(t, 8), "bob", clock)
	if err != nil {
		t.Fatal(err)
	}
	if string(ca1) == string(ca2) {
		t.Skip("CA bytes identical across seeds (test invariant broken)")
	}
	e.OnOwnerCA("bob", []byte{1}, ca2, expires+172800, false) // pending
	e.OnOwnerCA("bob", []byte{1}, ca1, expires, false)        // flip back

	got := e.Snapshot()[0]
	if got.Status != statusInstalled || got.PendingCASha256 != "" {
		t.Fatalf("state after revert = %+v, want installed with no pending", got)
	}
	if got.CASha256 != orig.CASha256 {
		t.Fatal("revert changed the installed CA")
	}
}

// TestOnOwnerCARotationFastPathWhenExpired: when the INSTALLED cross-cert
// has already expired, a CA change swaps immediately — the routine
// post-expiry owner-CA re-mint (every 10 years) must not serve a pointless
// grace on top of an already-dead anchor.
func TestOnOwnerCARotationFastPathWhenExpired(t *testing.T) {
	clock := time.Now()
	opts := testOpts(t)
	opts.Now = func() time.Time { return clock }
	e := mustEngine(t, opts)

	ca1, _, err := tlsca.OwnerCA(ownerSeed(t, 7), "bob", clock)
	if err != nil {
		t.Fatal(err)
	}
	// 1-hour record ⇒ the cross-cert (capped by it) dies in 1 hour too.
	e.OnOwnerCA("bob", []byte{1}, ca1, clock.Add(time.Hour).Unix(), false)

	ca2, _, err := tlsca.OwnerCA(ownerSeed(t, 8), "bob", clock)
	if err != nil {
		t.Fatal(err)
	}
	if string(ca1) == string(ca2) {
		t.Skip("CA bytes identical across seeds (test invariant broken)")
	}

	clock = clock.Add(2 * time.Hour) // the installed cross-cert is now expired
	e.OnOwnerCA("bob", []byte{1}, ca2, clock.Add(24*time.Hour).Unix(), false)
	got := e.Snapshot()[0]
	if id, _ := tlsca.CAIdentity(ca2); got.CASha256 != id {
		t.Fatal("expired-anchor CA change served the grace instead of the fast path")
	}
	if got.Status != statusInstalled || got.PendingCASha256 != "" {
		t.Fatalf("fast-path state = %+v", got)
	}
}

// TestOnOwnerCAQuarantinesYoungClaim: a claim inside the §7.5 contest
// window is recorded but NOT trusted — no spool file, nothing to install —
// and the next mature notification installs (the quarantine lifts by claim
// age, with no timer needed).
func TestOnOwnerCAQuarantinesYoungClaim(t *testing.T) {
	clock := time.Now()
	opts := testOpts(t)
	opts.Now = func() time.Time { return clock }
	e := mustEngine(t, opts)
	caDER, _ := ownerCA(t, ownerSeed(t, 7), "bob", clock)
	expires := clock.Add(24 * time.Hour).Unix()

	e.OnOwnerCA("bob", []byte{1}, caDER, expires, true) // young
	snap := e.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("quarantine state = %+v", snap)
	}
	if snap[0].Status != statusQuarantined || snap[0].NotAfter != 0 {
		t.Fatalf("young-claim state = %+v, want quarantined with nothing installed", snap[0])
	}
	if _, err := os.Stat(e.spoolPath("bob")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("quarantined namespace reached the spool")
	}

	// Duplicate young notification: still held (dedup, no re-journal).
	e.OnOwnerCA("bob", []byte{1}, caDER, expires, true)
	if s := e.Snapshot()[0]; s.Status != statusQuarantined {
		t.Fatalf("young re-observation changed state: %+v", s)
	}

	// The claim matures: the SAME CA installs on the next notification.
	e.OnOwnerCA("bob", []byte{1}, caDER, expires, false)
	got := e.Snapshot()[0]
	if got.Status != statusInstalled || got.NotAfter == 0 {
		t.Fatalf("post-maturity state = %+v, want installed", got)
	}
	if _, err := os.Stat(e.spoolPath("bob")); err != nil {
		t.Fatalf("mature install missing from spool: %v", err)
	}
}

// TestQuarantineHoldsAcrossCAChange: a young namespace re-advertising a
// DIFFERENT CA stays quarantined (a young claim is exactly where CA
// tampering is cheapest) and installs whatever CA is current once mature.
func TestQuarantineHoldsAcrossCAChange(t *testing.T) {
	clock := time.Now()
	opts := testOpts(t)
	opts.Now = func() time.Time { return clock }
	e := mustEngine(t, opts)
	ca1, _, err := tlsca.OwnerCA(ownerSeed(t, 7), "bob", clock)
	if err != nil {
		t.Fatal(err)
	}
	ca2, _, err := tlsca.OwnerCA(ownerSeed(t, 8), "bob", clock)
	if err != nil {
		t.Fatal(err)
	}
	if string(ca1) == string(ca2) {
		t.Skip("CA bytes identical across seeds (test invariant broken)")
	}
	expires := clock.Add(24 * time.Hour).Unix()

	e.OnOwnerCA("bob", []byte{1}, ca1, expires, true)
	e.OnOwnerCA("bob", []byte{1}, ca2, expires, true) // young + different CA
	if id, _ := tlsca.CAIdentity(ca2); (func() bool { s := e.Snapshot()[0]; return s.Status != statusQuarantined || s.CASha256 != id })() {
		t.Fatalf("young CA-flip state = %+v", e.Snapshot()[0])
	}
	if _, err := os.Stat(e.spoolPath("bob")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("young CA-flip reached the spool")
	}

	// Maturity: the currently-advertised CA installs (no grace on top).
	e.OnOwnerCA("bob", []byte{1}, ca2, expires, false)
	got := e.Snapshot()[0]
	if id, _ := tlsca.CAIdentity(ca2); got.Status != statusInstalled || got.CASha256 != id {
		t.Fatalf("post-maturity state = %+v", got)
	}
}

// TestSweepPurgesExpiredStateAndSystem: the v0.16 liveness half — an
// expired cross-cert now purges the engine state AND the direct
// system-bundle entry (SysCAPath seam), not just the spool file. A
// namespace whose lease lapsed must leave zero trusted material behind.
func TestSweepPurgesExpiredStateAndSystem(t *testing.T) {
	clock := time.Now()
	opts := testOpts(t)
	opts.Now = func() time.Time { return clock }
	opts.SystemStore = true
	opts.SysCAPath = t.TempDir()
	e := mustEngine(t, opts)

	seed := ownerSeed(t, 9)
	caGone, _ := ownerCA(t, seed, "gone", clock)
	caLive, _ := ownerCA(t, seed, "live", clock)
	e.OnOwnerCA("gone", []byte{1}, caGone, clock.Add(time.Hour).Unix(), false)
	e.OnOwnerCA("live", []byte{1}, caLive, clock.Add(24*time.Hour).Unix(), false)

	goneSys := e.SystemCertPath("gone")
	if _, err := os.Stat(goneSys); err != nil {
		t.Fatalf("fixture: system copy missing: %v", err)
	}
	if _, err := os.Stat(e.SystemCertPath("live")); err != nil {
		t.Fatalf("fixture: live system copy missing: %v", err)
	}

	clock = clock.Add(2 * time.Hour) // "gone"'s lease lapsed, "live" holds
	e.sweepSpool()                   // the sweeper's tick calls exactly this

	if _, err := os.Stat(e.spoolPath("gone")); !os.IsNotExist(err) {
		t.Errorf("expired spool file survived (err=%v)", err)
	}
	if _, err := os.Stat(goneSys); !os.IsNotExist(err) {
		t.Errorf("expired SYSTEM copy survived the sweep (err=%v)", err)
	}
	for _, s := range e.Snapshot() {
		if s.Alias == "gone" {
			t.Error("expired alias still in engine state")
		}
	}
	// The live namespace is untouched.
	if _, err := os.Stat(e.spoolPath("live")); err != nil {
		t.Errorf("live entry was swept: %v", err)
	}
	if _, err := os.Stat(e.SystemCertPath("live")); err != nil {
		t.Errorf("live system copy was swept: %v", err)
	}
}

// TestRunSweeperStopsAndSweeps: the daemon-side timer sweep runs without
// traffic, converges an expired entry, and returns when stop closes.
func TestRunSweeperStopsAndSweeps(t *testing.T) {
	var clockNano atomic.Int64
	clockNano.Store(time.Now().UnixNano())
	opts := testOpts(t)
	opts.Now = func() time.Time { return time.Unix(0, clockNano.Load()) }
	e := mustEngine(t, opts)
	seed := ownerSeed(t, 9)
	now := time.Unix(0, clockNano.Load())
	der, err := tlsca.CrossCert(e.rootDER, e.rootKey, mustCA(t, seed, "gone", now), "gone", now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.spoolPath("gone"), tlsca.CertPEM(der), 0o644); err != nil {
		t.Fatal(err)
	}

	// The clock leaps past the entry's expiry while the sweeper runs.
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		e.RunSweeper(stop, 5*time.Millisecond)
		close(done)
	}()
	clockNano.Store(time.Now().Add(2 * time.Hour).UnixNano())
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(e.spoolPath("gone")); os.IsNotExist(err) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("sweeper never removed the expired entry")
		}
		time.Sleep(5 * time.Millisecond)
	}
	close(stop)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("sweeper did not stop")
	}
}

// TestRemoveAlias: the operator path (`freens trust remove`) purges
// spool + state + system regardless of identity signals.
func TestRemoveAlias(t *testing.T) {
	clock := time.Now()
	opts := testOpts(t)
	opts.Now = func() time.Time { return clock }
	opts.SystemStore = true
	opts.SysCAPath = t.TempDir()
	e := mustEngine(t, opts)
	caDER, _ := ownerCA(t, ownerSeed(t, 7), "bob", clock)
	e.OnOwnerCA("bob", []byte{1}, caDER, clock.Add(24*time.Hour).Unix(), false)

	if !e.RemoveAlias("bob") {
		t.Fatal("RemoveAlias reported nothing to remove")
	}
	if len(e.Snapshot()) != 0 {
		t.Fatal("state survived RemoveAlias")
	}
	if _, err := os.Stat(e.spoolPath("bob")); !os.IsNotExist(err) {
		t.Error("spool file survived RemoveAlias")
	}
	if _, err := os.Stat(e.SystemCertPath("bob")); !os.IsNotExist(err) {
		t.Error("system copy survived RemoveAlias")
	}
	if e.RemoveAlias("bob") {
		t.Fatal("second RemoveAlias reported work done")
	}
}

func TestOnAliasDeadPurges(t *testing.T) {
	opts := testOpts(t)
	e := mustEngine(t, opts)
	caDER, _ := ownerCA(t, ownerSeed(t, 7), "bob", time.Now())
	tldID := []byte{1, 2, 3}
	expires := time.Now().Add(24 * time.Hour).Unix()
	e.OnOwnerCA("bob", tldID, caDER, expires, false)
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
	e.OnOwnerCA("alice", []byte{1}, caDER, time.Now().Add(24*time.Hour).Unix(), false)
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
			e.OnOwnerCA("bob", []byte{1}, caDER, expires, false)
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
	e1.OnOwnerCA("bob", []byte{1, 2, 3}, caDER, time.Now().Add(24*time.Hour).Unix(), false)

	e2 := mustEngine(t, opts)
	snap := e2.Snapshot()
	if len(snap) != 1 || snap[0].Alias != "bob" {
		t.Fatalf("restored state = %+v", snap)
	}
}

// TestSweepSpoolRemovesExpired: an expired cross-cert (and an unparsable
// file) in the spool must disappear on engine start and on any OnOwnerCA
// notification, while fresh entries (this alias's own) stay. The expired
// copy in the system store is what poisoned minipc's self-visit (found
// live 2026-09-01) — the spool is the bridge's source of truth, so THIS is
// where the staleness has to die.
func TestSweepSpoolRemovesExpired(t *testing.T) {
	// CrossCert refuses to mint an already-expired cert (rightly), so the
	// "expired" entries are minted against a clock that then moves forward:
	// the engine's Now is a var, so the sweep sees them as expired exactly
	// the way a real box does after 24 h of not resolving a namespace.
	clock := time.Now()
	opts := testOpts(t)
	opts.Now = func() time.Time { return clock }
	e := mustEngine(t, opts)
	seed := ownerSeed(t, 9)

	// Mint three cross-certs the way OnOwnerCA would: fresh, soon-to-expire,
	// and garbage. Only the fresh one may survive the sweep.
	now := clock
	mk := func(alias string, notAfter time.Time) []byte {
		der, err := tlsca.CrossCert(e.rootDER, e.rootKey, mustCA(t, seed, alias, now), alias, notAfter, now)
		if err != nil {
			t.Fatal(err)
		}
		return tlsca.CertPEM(der)
	}
	writeSpool := func(alias string, pem []byte) {
		if err := os.WriteFile(e.spoolPath(alias), pem, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeSpool("fresh", mk("fresh", now.Add(time.Hour)))
	writeSpool("stale", mk("stale", now.Add(50*time.Millisecond)))
	writeSpool("junk", []byte("not a pem at all"))
	clock = clock.Add(time.Minute) // a day passes for the sweep

	// The sweep runs inside OnOwnerCA — a (deduped) notification is the
	// realistic trigger.
	caDER, _ := ownerCA(t, seed, "fresh", now)
	e.OnOwnerCA("fresh", []byte{1}, caDER, now.Add(24*time.Hour).Unix(), false)

	if _, err := os.Stat(e.spoolPath("fresh")); err != nil {
		t.Errorf("fresh entry was swept: %v", err)
	}
	if _, err := os.Stat(e.spoolPath("stale")); !os.IsNotExist(err) {
		t.Errorf("expired entry survived the sweep (err=%v)", err)
	}
	if _, err := os.Stat(e.spoolPath("junk")); !os.IsNotExist(err) {
		t.Errorf("unparsable entry survived the sweep (err=%v)", err)
	}

	// And at engine start: a stale entry written behind a running engine's
	// back is cleaned by the NEXT engine (every daemon restart).
	writeSpool("stale2", mk("stale2", now.Add(50*time.Millisecond)))
	clock = clock.Add(time.Hour)
	e2 := mustEngine(t, opts)
	if _, err := os.Stat(e2.spoolPath("stale2")); !os.IsNotExist(err) {
		t.Errorf("start-time sweep left an expired entry (err=%v)", err)
	}
}

// mustCA derives just the CA bytes.
func mustCA(t *testing.T, seed []byte, alias string, now time.Time) []byte {
	t.Helper()
	der, _ := ownerCA(t, seed, alias, now)
	return der
}

// TestSameKeyDifferentDayDedupes: the v0.16.2 identity fix — the owner CA's
// cert BYTES change with every derivation day (caValidUntil truncates the
// window to the UTC day) while the KEY stays deterministic. A next-day
// notification must dedupe like the same CA, NOT trip the rotation gate and
// NOT re-mint (found live: minipc's routine renewal tripped the gate at
// 10:10 with a benign same-key re-mint).
func TestSameKeyDifferentDayDedupes(t *testing.T) {
	clock := time.Now()
	opts := testOpts(t)
	opts.Now = func() time.Time { return clock }
	e := mustEngine(t, opts)
	expires := clock.Add(24 * time.Hour).Unix()

	caDay1, _, err := tlsca.OwnerCA(ownerSeed(t, 7), "bob", clock)
	if err != nil {
		t.Fatal(err)
	}
	e.OnOwnerCA("bob", []byte{1}, caDay1, expires, false)
	before := e.Snapshot()[0]

	// Next UTC day: different bytes, SAME key ⇒ same identity.
	caDay2, _, err := tlsca.OwnerCA(ownerSeed(t, 7), "bob", clock.Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if string(caDay1) == string(caDay2) {
		t.Skip("CA bytes identical across derivation days (test invariant broken)")
	}
	id1, _ := tlsca.CAIdentity(caDay1)
	id2, _ := tlsca.CAIdentity(caDay2)
	if id1 != id2 {
		t.Fatal("fixture: identity changed across derivation days (the invariant CAIdentity must protect is broken)")
	}

	e.OnOwnerCA("bob", []byte{1}, caDay2, expires, false)
	after := e.Snapshot()[0]
	if after.Status != statusInstalled || after.PendingCASha256 != "" {
		t.Fatalf("day-roll notification tripped the rotation gate: %+v", after)
	}
	if after.NotAfter != before.NotAfter {
		t.Fatal("day-roll notification re-minted the cross-cert")
	}
}

// TestMintThrottle: inside the last refreshWithin of the record's lease the
// refresh test is permanently true — the throttle is what stops a re-mint
// (and the installer exec storm) on EVERY resolution.
func TestMintThrottle(t *testing.T) {
	clock := time.Now()
	opts := testOpts(t)
	opts.Now = func() time.Time { return clock }
	e := mustEngine(t, opts)
	caDER, _ := ownerCA(t, ownerSeed(t, 7), "bob", clock)
	// 7 h lease: inside refreshWithin (6 h) from the first minute.
	e.OnOwnerCA("bob", []byte{1}, caDER, clock.Add(7*time.Hour).Unix(), false)

	// A second notification minutes later: throttled, no re-mint.
	clock = clock.Add(5 * time.Minute)
	e.OnOwnerCA("bob", []byte{1}, caDER, clock.Add(7*time.Hour).Unix(), false)
	if got := e.Snapshot()[0].NotAfter; got != e.Snapshot()[0].NotAfter {
		t.Fatal("unreachable")
	}
	minted := e.Snapshot()[0]
	if minted.Status != statusInstalled {
		t.Fatalf("throttled notification changed state: %+v", minted)
	}

	// An hour later: the throttle lifts, the refresh re-mint runs — and the
	// internal bookkeeping carries the fresh MintedAt stamp.
	clock = clock.Add(mintThrottle + time.Minute)
	e.OnOwnerCA("bob", []byte{1}, caDER, clock.Add(7*time.Hour).Unix(), false)
	if got := e.Snapshot()[0]; got.Status != statusInstalled {
		t.Fatalf("post-throttle refresh did not install: %+v", got)
	}
	e.mu.Lock()
	mintedAt := e.state["bob"].MintedAt
	e.mu.Unlock()
	if mintedAt != clock.Unix() {
		t.Fatalf("post-throttle re-mint did not stamp MintedAt: %d != %d", mintedAt, clock.Unix())
	}
}

// TestLegacyStateMigratesToIdentity: a pre-v0.16.2 state entry (ca_sha256 =
// whole-cert bytes, no ca_identity) adopts the identity from the first
// notification WITHOUT tripping the rotation gate — the installed
// cross-cert anchored the same deterministic key.
func TestLegacyStateMigratesToIdentity(t *testing.T) {
	clock := time.Now()
	opts := testOpts(t)
	opts.Now = func() time.Time { return clock }
	e := mustEngine(t, opts)
	caDay1, _, err := tlsca.OwnerCA(ownerSeed(t, 7), "bob", clock)
	if err != nil {
		t.Fatal(err)
	}
	e.OnOwnerCA("bob", []byte{1}, caDay1, clock.Add(24*time.Hour).Unix(), false)
	// Hand-roll a legacy state file: drop ca_identity + minted_at.
	legacy := map[string]crossState{
		"bob": {TldIDB32: e.Snapshot()[0].TldIDB32, CASha256: tlsca.Fingerprint(caDay1), NotAfter: e.Snapshot()[0].NotAfter},
	}
	e.mu.Lock()
	e.state = legacy
	e.mu.Unlock()
	if err := e.saveState(); err != nil {
		t.Fatal(err)
	}

	// Next day's bytes: the legacy entry must adopt, not rotate.
	caDay2, _, err := tlsca.OwnerCA(ownerSeed(t, 7), "bob", clock.Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if string(caDay1) == string(caDay2) {
		t.Skip("CA bytes identical across derivation days (test invariant broken)")
	}
	e.OnOwnerCA("bob", []byte{1}, caDay2, clock.Add(24*time.Hour).Unix(), false)
	got := e.Snapshot()[0]
	if got.Status != statusInstalled || got.PendingCASha256 != "" {
		t.Fatalf("legacy migration tripped the rotation gate: %+v", got)
	}
	if got.CAIdentity == "" {
		t.Fatal("legacy entry did not adopt the CA identity")
	}
}
