package dht

// advertise_publish_test.go — the 2026-09-02 follow-up hardening:
//   - advertiseableNodes keeps ghost one-shot contacts out of {nodes}
//     (confirmed or freshly-learned contacts only),
//   - the publish stats surface per-key storing-peer acceptance,
//   - CollectClaimsRemote gives the owner a network-only view of its own
//     lease (the camalolo incident: the local store held the fresh copy
//     while the network had lost it).

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
)

func advTestContact(t *testing.T, node *Node, confirmedAt, lastSeen int64) *NodeContact {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	id, err := crypto.NodeID(kp.Public())
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewNodeContact(id, kp.Public(), "203.0.113.7:15353", lastSeen)
	if err != nil {
		t.Fatal(err)
	}
	c.ConfirmedAt = confirmedAt
	return c
}

// TestAdvertiseableNodesDropsStaleUnconfirmed: a contact this node never
// confirmed stops being advertised after adFreshWindow — the ghost-circulation
// fix — while confirmed contacts and fresh learns still ride {nodes}.
func TestAdvertiseableNodesDropsStaleUnconfirmed(t *testing.T) {
	n, _ := startTestNode(t, nil)
	now := n.now()

	confirmed := advTestContact(t, n, now-3600, now-3600) // confirmed long ago: advertiseable
	fresh := advTestContact(t, n, 0, now)                 // fresh learn: advertiseable
	stale := advTestContact(t, n, 0, now-3600)            // never confirmed, stale: dropped
	staleConf := advTestContact(t, n, now-3600, now-3600)
	staleConf.ConfirmedAt = now - 60 // confirmed recently: advertiseable

	out := n.advertiseableNodes([]*NodeContact{confirmed, fresh, stale, staleConf})
	if len(out) != 3 {
		t.Fatalf("advertiseableNodes emitted %d entries, want 3 (stale unconfirmed dropped)", len(out))
	}
	// The dropped contact's entry must not appear under any encoding.
	got := map[string]bool{}
	for _, e := range out {
		ea := e.([]any)
		got[hex.EncodeToString(ea[2].([]byte))] = true
	}
	if got[hex.EncodeToString(stale.NodeID)] {
		t.Fatal("the stale unconfirmed ghost was advertised")
	}
	for _, keep := range []*NodeContact{confirmed, fresh, staleConf} {
		if !got[hex.EncodeToString(keep.NodeID)] {
			t.Fatalf("contact %x was dropped but is advertiseable", keep.NodeID)
		}
	}
}

// TestAdvertiseableNodesSkipsHostnameAddrs: the v0.14.2 rule (hostname-shaped
// contacts never ride {nodes}) holds through the new filter too.
func TestAdvertiseableNodesSkipsHostnameAddrs(t *testing.T) {
	n, _ := startTestNode(t, nil)
	now := n.now()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	id, _ := crypto.NodeID(kp.Public())
	seed, err := NewNodeContact(id, kp.Public(), "freens.camalolo.com:15353", now)
	if err != nil {
		t.Fatal(err)
	}
	seed.ConfirmedAt = now
	if got := n.advertiseableNodes([]*NodeContact{seed}); len(got) != 0 {
		t.Fatalf("hostname contact advertised: %d entries", len(got))
	}
}

// TestPublishStatsCountsAcceptance: the stats carry the key, the target
// count and the acceptance count of one keyed publish over a live pair.
func TestPublishStatsCountsAcceptance(t *testing.T) {
	a, b := peerPair(t)
	_ = b
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	env, key := makeTLDRecord(t, kp, "statstest")
	stats, err := a.PublishStats(context.Background(), env)
	if err != nil {
		t.Fatalf("PublishStats: %v", err)
	}
	if len(stats) != 1 {
		t.Fatalf("stats for %d keys, want 1", len(stats))
	}
	if stats[0].KeyHex != hex.EncodeToString(key) {
		t.Errorf("stats key = %s, want %s", stats[0].KeyHex, hex.EncodeToString(key))
	}
	if stats[0].Targets < 1 || stats[0].Accepted != stats[0].Targets {
		t.Errorf("stats = %+v; want Accepted == Targets >= 1 (single-peer table)", stats[0])
	}
	if stats[0].Targets > constants.RReplication {
		t.Errorf("targets %d exceed R=%d", stats[0].Targets, constants.RReplication)
	}
}

// TestCollectClaimsRemoteExcludesLocal: the remote variant must NOT count
// this node's own store copy as the network's answer (the camalolo
// verification hole), while a copy held by a PEER still shows up. The pair
// runs with refresh/republish timers disabled — the §6.4 republish loop
// would otherwise copy a's local envelope to b mid-test and defeat the
// "network lost it" premise.
func TestCollectClaimsRemoteExcludesLocal(t *testing.T) {
	a, b := quietPair(t)
	env, kClaim := contestedClaimEnv(t, "remoteview", uint64(time.Now().Unix()))

	// The local-only state: a's store holds the envelope, the network (b)
	// holds nothing.
	if ok, err := a.store.Put(kClaim, env, a.now(), false); !ok || err != nil {
		t.Fatalf("seeding a's store: %v, %v", ok, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	local, _, err := a.CollectClaims(ctx, "remoteview")
	if err != nil || len(local) != 1 {
		t.Fatalf("CollectClaims (local-inclusive) = %d envelopes, %v; want 1", len(local), err)
	}
	remote, _, err := a.CollectClaimsRemote(ctx, "remoteview")
	if err != nil {
		t.Fatalf("CollectClaimsRemote: %v", err)
	}
	if len(remote) != 0 {
		t.Fatalf("CollectClaimsRemote leaked the LOCAL copy: %d envelopes", len(remote))
	}

	// Now the network (b) actually holds it: the remote view must find it.
	if ok, err := b.store.Put(kClaim, env, b.now(), false); !ok || err != nil {
		t.Fatalf("seeding b's store: %v, %v", ok, err)
	}
	remote, _, err = a.CollectClaimsRemote(ctx, "remoteview")
	if err != nil {
		t.Fatalf("CollectClaimsRemote (network copy): %v", err)
	}
	if len(remote) != 1 {
		t.Fatalf("CollectClaimsRemote = %d envelopes with a network copy present, want 1", len(remote))
	}
}

// quietPair is peerPair with the background timers (bucket refresh, §6.4
// republish) disabled: for wire-level assertions the network must stay
// exactly as the test left it.
func quietPair(t *testing.T) (*Node, *Node) {
	t.Helper()
	mk := func() *Node {
		kp, err := crypto.Generate()
		if err != nil {
			t.Fatalf("gen keypair: %v", err)
		}
		n, err := NewNode(NodeConfig{
			Keypair:               kp,
			ListenAddr:            "127.0.0.1:0",
			Store:                 NewEnvelopeStore(0, nil),
			BucketRefreshInterval: -1,
			RepublishInterval:     -1,
		})
		if err != nil {
			t.Fatalf("NewNode: %v", err)
		}
		if err := n.Start(); err != nil {
			t.Fatalf("Start: %v", err)
		}
		t.Cleanup(func() { _ = n.Close() })
		return n
	}
	a, b := mk(), mk()
	aAddr, err := a.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	bAddr, err := b.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.AddPeer(b.PublicKey(), bAddr.String()); err != nil {
		t.Fatal(err)
	}
	if err := b.AddPeer(a.PublicKey(), aAddr.String()); err != nil {
		t.Fatal(err)
	}
	return a, b
}
