package dht

// eviction_test.go exercises the §6.2 live-eviction maintenance path (spec
// lines 410-424: "standard Kademlia eviction (ping-oldest, replace on
// failure)"): when a new contact's bucket is full, the transport pings the
// bucket's oldest entry on its background maintenance goroutine and replaces
// it with the newcomer iff the oldest fails to answer within
// NodeConfig.PingTimeout.
//
// Testability knobs (NodeConfig.BucketCapacity = 2, NodeConfig.PingTimeout
// shortened) let each test build one small contested bucket out of real nodes
// on loopback instead of minting K=20 peers per case.

import (
	"context"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
)

// startCfgNode starts a real node with an explicit NodeConfig (background
// refresh/republish loops disabled — these tests drive maintenance directly).
func startCfgNode(t *testing.T, cfg NodeConfig) *Node {
	t.Helper()
	if cfg.Keypair == nil {
		kp, err := crypto.Generate()
		if err != nil {
			t.Fatalf("gen keypair: %v", err)
		}
		cfg.Keypair = kp
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "127.0.0.1:0"
	}
	if cfg.Store == nil {
		cfg.Store = NewEnvelopeStore(0, nil)
	}
	cfg.BucketRefreshInterval = -1
	cfg.RepublishInterval = -1
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	if err := n.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	return n
}

// startNodeInBucket starts a real node whose Node ID lands in bucket bucketIdx
// of selfID (bucket index == common-prefix length, §6.2). Random keypairs hit
// bucket 0 with probability ~1/2, so this terminates quickly.
func startNodeInBucket(t *testing.T, selfID []byte, bucketIdx int) *Node {
	t.Helper()
	for i := 0; i < 1000; i++ {
		kp, err := crypto.Generate()
		if err != nil {
			t.Fatalf("gen keypair: %v", err)
		}
		id, err := crypto.NodeID(kp.Public())
		if err != nil {
			t.Fatal(err)
		}
		cpl, err := CommonPrefixLength(selfID, id)
		if err != nil {
			t.Fatal(err)
		}
		if cpl == bucketIdx {
			return startCfgNode(t, NodeConfig{Keypair: kp})
		}
	}
	t.Fatalf("no keypair found for bucket %d after 1000 tries", bucketIdx)
	return nil
}

// pollUntil runs check every 50ms until it returns true or the deadline
// passes (failure).
func pollUntil(t *testing.T, deadline time.Duration, what string, check func() bool) {
	t.Helper()
	t0 := time.Now()
	for time.Since(t0) < deadline {
		if check() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out after %v waiting for: %s", deadline, what)
}

// TestEvictionReplacesDeadOldest: the bucket's OLDEST entry is a node that has
// since gone offline; when a newcomer arrives for the full bucket, the
// maintenance ping to the oldest times out (shortened via NodeConfig
// .PingTimeout), the oldest is removed, and the newcomer takes the slot. The
// middle contact is untouched.
func TestEvictionReplacesDeadOldest(t *testing.T) {
	b := startCfgNode(t, NodeConfig{
		BucketCapacity: 2,
		PingTimeout:    300 * time.Millisecond,
	})
	defer b.Close()

	// Fill B's bucket 0 with [dead (oldest), live]; then kill `dead`.
	dead := startNodeInBucket(t, b.ID(), 0)
	live := startNodeInBucket(t, b.ID(), 0)
	defer live.Close()
	deadAddr, err := dead.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	liveAddr, err := live.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	if err := b.AddPeer(dead.PublicKey(), deadAddr.String()); err != nil {
		t.Fatal(err)
	}
	if err := b.AddPeer(live.PublicKey(), liveAddr.String()); err != nil {
		t.Fatal(err)
	}
	if got := b.RoutingTable().Size(); got != 2 {
		t.Fatalf("precondition: bucket should be full with 2 contacts, got %d", got)
	}
	if err := dead.Close(); err != nil { // black-hole the oldest
		t.Fatal(err)
	}

	// Present the K+1-th contact for the same bucket via real inbound traffic
	// (a signed ping), i.e. the readLoop→learnPeer→learn path.
	newcomer := startNodeInBucket(t, b.ID(), 0)
	defer newcomer.Close()
	bAddr, err := b.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	if err := newcomer.AddPeer(b.PublicKey(), bAddr.String()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := newcomer.Ping(ctx, Peer{Addr: bAddr.String(), PublicKey: b.PublicKey()}); err != nil {
		t.Fatalf("newcomer ping: %v", err)
	}

	// The maintenance ping (300ms budget) must evict `dead` and insert the
	// newcomer; `live` is retained.
	pollUntil(t, 5*time.Second, "dead evicted, newcomer inserted", func() bool {
		return b.RoutingTable().Get(dead.ID()) == nil &&
			b.RoutingTable().Get(newcomer.ID()) != nil
	})
	if got := b.RoutingTable().Get(live.ID()); got == nil {
		t.Error("live middle contact was wrongly evicted")
	}
	if got := b.RoutingTable().Size(); got != 2 {
		t.Errorf("post-eviction table size = %d, want 2 (capacity)", got)
	}
}

// TestEvictionKeepsAliveOldest: when the oldest answers the maintenance ping,
// §6.2 keeps it and the newcomer is NOT inserted. The ping's arrival is
// observed on the oldest's side (it learns B from the signed ping), which
// makes the "maintenance ran and the oldest won" outcome deterministic to
// assert.
func TestEvictionKeepsAliveOldest(t *testing.T) {
	b := startCfgNode(t, NodeConfig{
		BucketCapacity: 2,
		PingTimeout:    2 * time.Second,
	})
	defer b.Close()

	oldest := startNodeInBucket(t, b.ID(), 0)
	live := startNodeInBucket(t, b.ID(), 0)
	defer oldest.Close()
	defer live.Close()
	oldestAddr, err := oldest.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	liveAddr, err := live.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	if err := b.AddPeer(oldest.PublicKey(), oldestAddr.String()); err != nil {
		t.Fatal(err)
	}
	if err := b.AddPeer(live.PublicKey(), liveAddr.String()); err != nil {
		t.Fatal(err)
	}

	newcomer := startNodeInBucket(t, b.ID(), 0)
	defer newcomer.Close()
	bAddr, err := b.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	if err := newcomer.AddPeer(b.PublicKey(), bAddr.String()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := newcomer.Ping(ctx, Peer{Addr: bAddr.String(), PublicKey: b.PublicKey()}); err != nil {
		t.Fatalf("newcomer ping: %v", err)
	}

	// Wait until the maintenance ping actually reached the oldest: it learns
	// B from the signed inbound ping (B's table had only oldest+live before).
	pollUntil(t, 5*time.Second, "maintenance ping reached the oldest", func() bool {
		return oldest.RoutingTable().Get(b.ID()) != nil
	})
	// Give the (already-delivered) response a moment to be processed on B.
	time.Sleep(100 * time.Millisecond)

	// Oldest survived; newcomer lost; bucket still exactly the two incumbents.
	if got := b.RoutingTable().Get(oldest.ID()); got == nil {
		t.Error("alive oldest was wrongly evicted")
	}
	if got := b.RoutingTable().Get(newcomer.ID()); got != nil {
		t.Error("newcomer was inserted despite a responsive oldest (§6.2 keeps live contacts)")
	}
	if got := b.RoutingTable().Size(); got != 2 {
		t.Errorf("table size = %d, want 2", got)
	}
}

// TestEvictionCoalescesPerBucket: a flood of distinct newcomers for the same
// full bucket enqueues at most one maintenance request at a time — later
// candidates are dropped while one is pending. Observable: with a dead oldest
// and a queue of newcomers, the table never exceeds its capacity and the
// system settles (dead eventually evicted, some newcomer seated, size == 2).
func TestEvictionCoalescesPerBucket(t *testing.T) {
	b := startCfgNode(t, NodeConfig{
		BucketCapacity: 2,
		PingTimeout:    250 * time.Millisecond,
	})
	defer b.Close()

	dead := startNodeInBucket(t, b.ID(), 0)
	live := startNodeInBucket(t, b.ID(), 0)
	defer live.Close()
	deadAddr, _ := dead.LocalAddr()
	liveAddr, _ := live.LocalAddr()
	if err := b.AddPeer(dead.PublicKey(), deadAddr.String()); err != nil {
		t.Fatal(err)
	}
	if err := b.AddPeer(live.PublicKey(), liveAddr.String()); err != nil {
		t.Fatal(err)
	}
	if err := dead.Close(); err != nil {
		t.Fatal(err)
	}

	// Flood: 12 newcomers ping B back-to-back (each triggers learnPeer on a
	// full bucket). Capacity 2 must never be exceeded; the flood may not
	// spawn per-candidate work (coalescing) nor wedge the table.
	bAddr, _ := b.LocalAddr()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for i := 0; i < 12; i++ {
		nc := startNodeInBucket(t, b.ID(), 0)
		defer nc.Close()
		if err := nc.AddPeer(b.PublicKey(), bAddr.String()); err != nil {
			t.Fatal(err)
		}
		pctx, pcancel := context.WithTimeout(ctx, 2*time.Second)
		perr := nc.Ping(pctx, Peer{Addr: bAddr.String(), PublicKey: b.PublicKey()})
		pcancel()
		if perr != nil {
			t.Fatalf("flood ping %d: %v", i, perr)
		}
		if got := b.RoutingTable().Size(); got > 2 {
			t.Fatalf("table size %d exceeded bucket capacity mid-flood", got)
		}
	}

	// Settle: the dead oldest is gone and the table is at capacity with live
	// contacts only.
	pollUntil(t, 5*time.Second, "dead oldest evicted after flood", func() bool {
		return b.RoutingTable().Get(dead.ID()) == nil
	})
	pollUntil(t, 2*time.Second, "table settled at capacity with live contacts", func() bool {
		return b.RoutingTable().Size() == 2
	})
	if got := b.RoutingTable().Get(live.ID()); got == nil {
		t.Error("live contact lost during flood maintenance")
	}
}

// TestEvictionDisabledByDefaultCapacity guards the BucketCapacity contract:
// zero means constants.K, so an ordinary node holds K contacts per bucket
// without any maintenance firing.
func TestEvictionDisabledByDefaultCapacity(t *testing.T) {
	b := startCfgNode(t, NodeConfig{})
	defer b.Close()
	if got := b.rt.Capacity; got != constants.K {
		t.Errorf("default bucket capacity = %d, want constants.K = %d", got, constants.K)
	}
	if got := b.pingTimeout; got != rpcTimeout() {
		t.Errorf("default ping timeout = %v, want RPC_TIMEOUT %v", got, rpcTimeout())
	}
}
