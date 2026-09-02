// renew_verify_test.go — the auto-renew lease verification (the 2026-09-02
// camalolo incident): the local store believed a lease fresh while the
// network had lost the envelope, so ShouldRenew never fired and every
// non-owner resolver NXDOMAINed the name for hours. The verify path
// (renewVerifyFresh) network-checks each apparently-fresh lease and
// re-publishes the exact local envelope when the network lost it.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/dht"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/wire"
)

// freshRecord signs a claim-less apex record WELL INSIDE its lifetime
// (ShouldRenew false — the verify path's precondition).
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

func resetVerifyRate(env *wire.SignedEnvelope) (cleanup func()) {
	nameKey := hex.EncodeToString(env.Record.Name)
	renewVerifyLast.Delete(nameKey)
	return func() { renewVerifyLast.Delete(nameKey) }
}

// TestRenewVerifyFreshRepublishesLostLease: local store fresh, network
// empty → the pass must re-publish the SAME envelope (no re-sign: the
// sequence must not move) and queue it for network-confirmed retry; the
// retry loop then confirms against the network and drains.
func TestRenewVerifyFreshRepublishesLostLease(t *testing.T) {
	kp := renewKeychain(t)
	daemon, daemonStore := renewTestNode(t)
	peer, peerStore := renewTestNode(t)
	connectTestPair(t, daemon, peer)

	now := time.Now().Unix()
	env, key := freshRecord(t, kp, 5, now)
	if ok, err := daemonStore.Put(key, env, now, false); !ok || err != nil {
		t.Fatalf("seeding the fresh record locally: %v, %v", ok, err)
	}
	defer resetVerifyRate(env)()

	renewOnce(daemon, daemonStore, renewTestLogger())

	// The network (the peer's store) must now hold the SAME envelope —
	// re-published, not re-signed.
	got, err := peerStore.Get(key, time.Now().Unix())
	if err != nil || got == nil {
		t.Fatalf("the network did not receive the supposedly-fresh lease: %v, %v", got, err)
	}
	if got.Record.Sequence != 5 {
		t.Fatalf("network sequence = %d, want 5 (verify re-publishes, never re-signs)", got.Record.Sequence)
	}
	nh, e1 := got.RecordHash()
	lh, e2 := env.RecordHash()
	if e1 != nil || e2 != nil || !bytes.Equal(nh, lh) {
		t.Fatal("the re-published envelope differs from the local one")
	}

	// The confirm-retry loop drains on the next tick.
	retryPendingPuts(daemon, renewTestLogger())
	renewPending.Lock()
	n := len(renewPending.m)
	renewPending.Unlock()
	if n != 0 {
		t.Fatalf("renewPending holds %d entries after confirmation, want 0", n)
	}

	// A second pass immediately after: the healthy lease is rate-limited
	// and the network copy is live — nothing re-queues, nothing re-signs.
	renewOnce(daemon, daemonStore, renewTestLogger())
	got2, err := peerStore.Get(key, time.Now().Unix())
	if err != nil || got2 == nil || got2.Record.Sequence != 5 {
		t.Fatalf("healthy lease churned: seq=%v, %v", got2, err)
	}
}

// TestRenewVerifyHealthyLeaseStaysQuiet: when the network already holds
// the fresh envelope, the verify path must not queue or re-publish.
func TestRenewVerifyHealthyLeaseStaysQuiet(t *testing.T) {
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
	defer resetVerifyRate(env)()

	renewOnce(daemon, daemonStore, renewTestLogger())
	retryPendingPuts(daemon, renewTestLogger())
	renewPending.Lock()
	n := len(renewPending.m)
	renewPending.Unlock()
	if n != 0 {
		t.Fatalf("renewPending holds %d entries for a healthy lease, want 0", n)
	}
	got, err := peerStore.Get(key, time.Now().Unix())
	if err != nil || got == nil || got.Record.Sequence != 3 {
		t.Fatalf("healthy lease mutated: %v, %v", got, err)
	}
}
