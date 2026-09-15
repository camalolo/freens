// reconcile_verify_test.go — the reconciler's reconciliation pass (b), the
// v0.18 consolidation of the old renewVerifyFresh/renewVerifyFreshAt verify
// paths and the confirm-retry queue. The incidents it covers: the
// 2026-09-02 camalolo phantom freshness (local store believed a lease
// fresh while the network had lost it — hours of NXDOMAIN while the owner
// saw nothing) and the v0.16.2 variant (K_tld confirmed while K_claim was
// lost silently). The pass network-GETs BOTH storage keys of every own
// envelope and re-puts the EXISTING signed envelope on a mismatch; a
// healthy result arms the 1 h per-(name,key) throttle, a repair leaves it
// open for the next tick to re-check (the ticks are the confirmation).
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/claims"
	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/dht"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/wire"
)

// freshRecord signs a claim-less apex record WELL INSIDE its lifetime
// (ShouldRenew false — the reconciliation pass's precondition; the pass
// verifies, it never re-signs).
func freshRecord(t *testing.T, kp *crypto.Keypair, seq uint64, now int64) (*wire.SignedEnvelope, []byte) {
	t.Helper()
	tldID, err := crypto.TldID(kp.Public())
	if err != nil {
		t.Fatal(err)
	}
	wn, err := naming.EncodeWireName(nil, "camalolo", tldID)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := wire.NewRecord(wn, kp.Public(), seq, uint64(now-60), uint64(now+int64(constants.RecordDefaultTTL)))
	if err != nil {
		t.Fatal(err)
	}
	env, err := wire.SignRecord(rec, kp)
	if err != nil {
		t.Fatal(err)
	}
	key, err := dht.KeyForWireName(wn)
	if err != nil {
		t.Fatal(err)
	}
	return env, key
}

// claimBearingRecord signs a claim-bearing apex record WELL INSIDE its
// lifetime: dht.StorageKeys yields BOTH K_tld and K_claim for it, so the
// reconciliation pass must verify (and, when lost, heal) both keyspaces.
// The claim is fully §7.4-valid (floor PoW + W witness attestations) — a
// put at K_claim must pass the storing node's §7.4 screen, so a witness-
// less claim would be refused by the peer and the K_claim leg would never
// heal (which is exactly what this test exists to prove healable).
func claimBearingRecord(t *testing.T, kp *crypto.Keypair, seq uint64, now int64) (*wire.SignedEnvelope, [][]byte) {
	t.Helper()
	// The hPut K_claim screen verifies the PoW at the floor (same recipe
	// as the dht package's claim fixtures).
	prevD := claims.PoWDifficultyInit.Load()
	claims.PoWDifficultyInit.Store(8)
	t.Cleanup(func() { claims.PoWDifficultyInit.Store(prevD) })

	tldID, err := crypto.TldID(kp.Public())
	if err != nil {
		t.Fatal(err)
	}
	wn, err := naming.EncodeWireName(nil, "camalolo", tldID)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := claims.MineAliasClaim("camalolo", kp, uint64(now), 8, 2_000_000, 16)
	if err != nil {
		t.Fatal(err)
	}
	ph, err := claim.PrefixHash()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < constants.W; i++ {
		wkp, err := crypto.Generate()
		if err != nil {
			t.Fatal(err)
		}
		w, err := claims.NewWitnessAttestation(wkp, uint64(now)+uint64(i), ph)
		if err != nil {
			t.Fatal(err)
		}
		claim.Witnesses = append(claim.Witnesses, w)
	}
	cb, err := claim.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	rec, err := wire.NewRecord(wn, kp.Public(), seq, uint64(now-60), uint64(now+int64(constants.RecordDefaultTTL)))
	if err != nil {
		t.Fatal(err)
	}
	rec.Claim = cb
	env, err := wire.SignRecord(rec, kp)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := dht.StorageKeys(env)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("claim-bearing fixture must have 2 storage keys, got %d", len(keys))
	}
	return env, keys
}

// connectTestPair cross-seeds daemon and peer so walks between them work.
func connectTestPair(t *testing.T, daemon, peer *dht.Node) {
	t.Helper()
	peerAddr, err := peer.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	if err := daemon.AddPeer(peer.PublicKey(), peerAddr.String()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := daemon.Ping(ctx, dht.Peer{Addr: peerAddr.String(), PublicKey: peer.PublicKey()}); err != nil {
		t.Fatalf("bootstrap ping: %v", err)
	}
}

// clearReconcileRate drops the (name, key) throttle entries for env's name
// from the package-global rate map and re-drops them at cleanup, so tests
// stay independent of each other and of the map's 1 h window.
func clearReconcileRate(t *testing.T, env *wire.SignedEnvelope) {
	t.Helper()
	nameKey := hex.EncodeToString(env.Record.Name)
	drop := func() {
		reconcileVerifyLast.Delete(nameKey + "/0")
		reconcileVerifyLast.Delete(nameKey + "/1")
	}
	drop()
	t.Cleanup(drop)
}

// renewTestLoggerBuf returns a Debug-level logger writing into a buffer —
// the reconciliation pass logs its verdicts at Debug (healthy) and Warn
// (repair), so the buffer is the observable for throttle/repair behavior.
func renewTestLoggerBuf() (*slog.Logger, *strings.Builder) {
	buf := &strings.Builder{}
	h := slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	return slog.New(h), buf
}

// TestReconcileRepublishesLostLease: local store fresh, network empty →
// the pass must re-publish the SAME envelope (no re-sign: the sequence
// must not move, locally or on the network). The old confirm-retry queue
// is gone; the next tick's GET would confirm this repair.
func TestReconcileRepublishesLostLease(t *testing.T) {
	kp := renewKeychain(t)
	daemon, daemonStore := renewTestNode(t)
	peer, peerStore := renewTestNode(t)
	connectTestPair(t, daemon, peer)

	now := time.Now().Unix()
	env, key := freshRecord(t, kp, 5, now)
	if ok, err := daemonStore.Put(key, env, now, false); !ok || err != nil {
		t.Fatalf("seeding the fresh record locally: %v, %v", ok, err)
	}
	clearReconcileRate(t, env)

	reconcileTick(daemon, daemonStore, renewTestLogger(), false)

	// The network (the peer's store) must now hold the SAME envelope —
	// re-published, not re-signed.
	got, err := peerStore.Get(key, time.Now().Unix())
	if err != nil || got == nil {
		t.Fatalf("the network did not receive the supposedly-fresh lease: %v, %v", got, err)
	}
	if got.Record.Sequence != 5 {
		t.Fatalf("network sequence = %d, want 5 (the reconciler re-publishes, never re-signs)", got.Record.Sequence)
	}
	nh, e1 := got.RecordHash()
	lh, e2 := env.RecordHash()
	if e1 != nil || e2 != nil || !bytes.Equal(nh, lh) {
		t.Fatal("the re-published envelope differs from the local one")
	}

	// The LOCAL sequence did not move either.
	local, err := daemonStore.Get(key, time.Now().Unix())
	if err != nil || local == nil || local.Record.Sequence != 5 {
		t.Fatalf("local store mutated by reconciliation: seq=%v, %v", local, err)
	}
}

// TestReconcileVerifiesBothKeys: a claim-bearing envelope lives at TWO
// storage keys (K_tld + K_claim) and BOTH must be healed — the K_claim leg
// is the one that historically failed silently (v0.14.0, v0.16.2).
func TestReconcileVerifiesBothKeys(t *testing.T) {
	kp := renewKeychain(t)
	daemon, daemonStore := renewTestNode(t)
	peer, peerStore := renewTestNode(t)
	connectTestPair(t, daemon, peer)

	now := time.Now().Unix()
	env, keys := claimBearingRecord(t, kp, 9, now)
	for _, k := range keys {
		if ok, err := daemonStore.Put(k, env, now, false); !ok || err != nil {
			t.Fatalf("seeding the local store at a key: %v, %v", ok, err)
		}
	}
	clearReconcileRate(t, env)

	reconcileTick(daemon, daemonStore, renewTestLogger(), false)

	for i, k := range keys {
		got, err := peerStore.Get(k, time.Now().Unix())
		if err != nil || got == nil {
			t.Fatalf("network (peer store) missing key %d after reconciliation: %v, %v", i, got, err)
		}
		nh, e1 := got.RecordHash()
		lh, e2 := env.RecordHash()
		if e1 != nil || e2 != nil || !bytes.Equal(nh, lh) {
			t.Fatalf("key %d holds a different envelope after reconciliation", i)
		}
	}
}

// TestReconcileRepublishesOlderGeneration: the network holds an OLDER
// envelope (the stale-pocket shape) — the pass re-puts the local envelope
// and, because a repair must not arm the throttle, the NEXT tick
// re-verifies the repair and reports it healthy ("the ticks are the
// confirmation" — no pending queue, no give-up counter).
func TestReconcileRepublishesOlderGeneration(t *testing.T) {
	kp := renewKeychain(t)
	daemon, daemonStore := renewTestNode(t)
	peer, peerStore := renewTestNode(t)
	connectTestPair(t, daemon, peer)

	now := time.Now().Unix()
	oldEnv, key := freshRecord(t, kp, 4, now)
	if ok, err := peerStore.Put(key, oldEnv, now, false); !ok || err != nil {
		t.Fatalf("seeding the stale network generation: %v, %v", ok, err)
	}
	env, _ := freshRecord(t, kp, 5, now)
	if ok, err := daemonStore.Put(key, env, now, false); !ok || err != nil {
		t.Fatalf("seeding the fresh record locally: %v, %v", ok, err)
	}
	clearReconcileRate(t, env)
	logger, buf := renewTestLoggerBuf()

	reconcileTick(daemon, daemonStore, logger, false)

	got, err := peerStore.Get(key, time.Now().Unix())
	if err != nil || got == nil || got.Record.Sequence != 5 {
		t.Fatalf("stale network generation not healed: seq=%v, %v", got, err)
	}
	if strings.Contains(buf.String(), "lease verified") {
		t.Fatal("tick 1 reported healthy while the network held an older generation")
	}

	// Tick 2, immediately: the repair did NOT arm the throttle, so this
	// tick re-verifies — and now finds the network healthy.
	buf.Reset()
	reconcileTick(daemon, daemonStore, logger, false)
	if n := strings.Count(buf.String(), "lease verified on the network"); n != 1 {
		t.Fatalf("tick 2 must re-verify a repaired lease (throttle open after repair); %d verify lines:\n%s", n, buf.String())
	}

	// Tick 3, immediately: now the healthy result HAS armed the throttle —
	// a healthy name must not churn every tick.
	buf.Reset()
	reconcileTick(daemon, daemonStore, logger, false)
	if strings.Contains(buf.String(), "lease verified") {
		t.Fatalf("tick 3 verified again despite the fresh throttle entry:\n%s", buf.String())
	}
}

// TestReconcileHealthyLeaseStaysQuiet: when the network already holds the
// fresh envelope, the pass must neither re-publish nor re-sign — and the
// healthy result arms the throttle so the name stays quiet for the hour.
func TestReconcileHealthyLeaseStaysQuiet(t *testing.T) {
	kp := renewKeychain(t)
	daemon, daemonStore := renewTestNode(t)
	peer, peerStore := renewTestNode(t)
	connectTestPair(t, daemon, peer)

	now := time.Now().Unix()
	env, key := freshRecord(t, kp, 3, now)
	for _, st := range []*dht.EnvelopeStore{daemonStore, peerStore} {
		if ok, err := st.Put(key, env, now, false); !ok || err != nil {
			t.Fatalf("seeding both stores: %v, %v", ok, err)
		}
	}
	clearReconcileRate(t, env)
	logger, buf := renewTestLoggerBuf()

	reconcileTick(daemon, daemonStore, logger, false)
	if n := strings.Count(buf.String(), "lease verified on the network"); n != 1 {
		t.Fatalf("want exactly one healthy-verify line, got %d:\n%s", n, buf.String())
	}
	got, err := peerStore.Get(key, time.Now().Unix())
	if err != nil || got == nil || got.Record.Sequence != 3 {
		t.Fatalf("healthy lease mutated: %v, %v", got, err)
	}

	// An immediate second tick is throttled (healthy names don't churn
	// every 10-minute tick) — no reconciler output, no mutation.
	buf.Reset()
	reconcileTick(daemon, daemonStore, logger, false)
	if strings.Contains(buf.String(), "reconciler") {
		t.Fatalf("throttled tick still produced reconciler output:\n%s", buf.String())
	}
}
