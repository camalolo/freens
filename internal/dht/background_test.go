package dht

// background_test.go exercises the Node background machinery added on top of
// the §6.3 transport: the §6.2 bucket-refresh loop (spec lines 410-424), the
// §6.4 step 4 republish timer (spec lines 471-473), the §6.1 passive mode
// (lines 397-408), and the shutdown lifecycle (no goroutine leaks).
//
// Like transport_test.go these tests bind ephemeral loopback ports. Where a
// deterministic clock is needed (staleness, due-ness) the node's Now hook is
// injected, since contact LastSeen and record timestamps are all unix seconds.

import (
	"bytes"
	"context"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/wire"
)

// newBGNode builds and starts a Node with its own store, applying mutate to
// the NodeConfig first (intervals, Passive, Now, ...). The caller defers Close.
func newBGNode(t *testing.T, mutate func(*NodeConfig)) (*Node, *EnvelopeStore) {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatalf("gen keypair: %v", err)
	}
	store := NewEnvelopeStore(0, nil)
	cfg := NodeConfig{Keypair: kp, ListenAddr: "127.0.0.1:0", Store: store}
	if mutate != nil {
		mutate(&cfg)
	}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	if err := n.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	return n, store
}

// makeEnvAt builds a self-signed TLD-root envelope with explicit
// Created/Expires (unix seconds), returning it with its canonical DHT key.
// Each call generates a fresh keypair: a TLD-root record's wire name is derived
// from the owner key (TldID), so one keypair ⇒ one DHT key — distinct
// identities are needed for distinct keys.
func makeEnvAt(t *testing.T, alias string, created, expires int64) (*wire.SignedEnvelope, []byte) {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatalf("gen keypair: %v", err)
	}
	tid, err := crypto.TldID(kp.Public())
	if err != nil {
		t.Fatal(err)
	}
	wn, err := naming.EncodeWireName(nil, alias, tid)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := wire.NewRecord(wn, kp.Public(), 1, uint64(created), uint64(expires))
	if err != nil {
		t.Fatal(err)
	}
	rr, err := wire.A([]byte{203, 0, 113, 99}, 300)
	if err != nil {
		t.Fatal(err)
	}
	rec.RRset = []*wire.RR{rr}
	env, err := wire.SignRecord(rec, kp)
	if err != nil {
		t.Fatal(err)
	}
	key, err := KeyForWireName(wn)
	if err != nil {
		t.Fatal(err)
	}
	return env, key
}

// ---------------------------------------------------------------------------
// §6.1 passive mode
// ---------------------------------------------------------------------------

// TestPassiveNodeRejectsPutWith301 verifies the §6.1 passive semantics: hPut
// refuses even a well-formed put (valid token + valid signature) with error
// 301 "passive node", nothing lands in the passive store — while get still
// serves records the passive node holds.
func TestPassiveNodeRejectsPutWith301(t *testing.T) {
	a, aStore := newBGNode(t, func(c *NodeConfig) { c.Passive = true })
	b, _ := newBGNode(t, nil)
	defer a.Close()
	defer b.Close()
	aAddr, err := a.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	if err := b.AddPeer(a.PublicKey(), aAddr.String()); err != nil {
		t.Fatal(err)
	}

	env, key := makeEnvAt(t, "passive", time.Now().Unix(), time.Now().Unix()+3600)
	envBytes, err := env.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Passive nodes still mint tokens (get/ping are served).
	gResp, err := b.sendQuery(ctx, aAddr, a.ID(), "get", map[string]any{"key": key})
	if err != nil || gResp == nil || gResp.Y == wire.MsgTypeError {
		t.Fatalf("get against passive node failed: resp=%v err=%v", gResp, err)
	}
	token, _ := gResp.A["token"].([]byte)
	if len(token) == 0 {
		t.Fatal("passive node did not issue a write token")
	}

	// A perfectly valid put must still be refused with 301 "passive node".
	pResp, err := b.sendQuery(ctx, aAddr, a.ID(), "put", map[string]any{
		"token":    token,
		"envelope": envBytes,
	})
	if err != nil {
		t.Fatalf("put rpc: %v", err)
	}
	if pResp == nil || pResp.Y != wire.MsgTypeError {
		t.Fatalf("put to passive node: want y=e, got %+v", pResp)
	}
	if code, ok := asUint64(pResp.A["code"]); !ok || code != 301 {
		t.Errorf("put to passive node: want code 301, got %v", pResp.A["code"])
	}
	if msg, _ := pResp.A["msg"].(string); msg != "passive node" {
		t.Errorf("put to passive node: want msg %q, got %q", "passive node", msg)
	}
	if aStore.Has(key, time.Now().Unix()) {
		t.Error("passive node stored a put envelope")
	}

	// get still works: seed the passive store directly and fetch over the DHT.
	now := time.Now().Unix()
	if ok, err := aStore.Put(key, env, now, true); err != nil || !ok {
		t.Fatalf("seed passive store: accepted=%v err=%v", ok, err)
	}
	got, err := b.IterativeGet(ctx, key)
	if err != nil {
		t.Fatalf("IterativeGet from passive node: %v", err)
	}
	if got == nil {
		t.Fatal("passive node did not serve get over the DHT")
	}
	gh, _ := got.RecordHash()
	eh, _ := env.RecordHash()
	if !bytes.Equal(gh, eh) {
		t.Error("fetched envelope differs from the seeded one")
	}
}

// TestPassiveNodeSkipsRepublish verifies that a passive node never volunteers
// others' records: a due record in its store is NOT pushed to peers even after
// several republish ticks (the active-node counterpart is covered by
// TestRepublishTimerRepublishesDueEntries).
func TestPassiveNodeSkipsRepublish(t *testing.T) {
	now := time.Now().Unix()
	env, key := makeEnvAt(t, "ghost", now-1000, now+200) // past 80% of lifetime

	a, aStore := newBGNode(t, nil) // the peer that would receive the republication
	defer a.Close()
	aAddr, _ := a.LocalAddr()

	b, bStore := newBGNode(t, func(c *NodeConfig) {
		c.Passive = true
		c.RepublishInterval = 40 * time.Millisecond
	})
	defer b.Close()
	if err := b.AddPeer(a.PublicKey(), aAddr.String()); err != nil {
		t.Fatal(err)
	}
	if ok, err := bStore.Put(key, env, now, true); err != nil || !ok {
		t.Fatalf("seed passive republisher store: accepted=%v err=%v", ok, err)
	}

	time.Sleep(250 * time.Millisecond) // several republish ticks fire
	if aStore.Has(key, now) {
		t.Error("passive node republished a record to a peer")
	}
}

// ---------------------------------------------------------------------------
// §6.2 bucket refresh
// ---------------------------------------------------------------------------

// TestRandomTargetInBucket pins the target-ID construction: a target for
// bucket idx shares exactly idx leading bits with selfID (so find_node on it
// walks that bucket's range) and never equals selfID.
func TestRandomTargetInBucket(t *testing.T) {
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	selfID, err := crypto.NodeID(kp.Public())
	if err != nil {
		t.Fatal(err)
	}
	for _, idx := range []int{0, 1, 7, 8, 100, 254, 255} {
		for i := 0; i < 16; i++ { // randomness: exercise many draws
			target := randomTargetInBucket(selfID, idx)
			cpl, err := CommonPrefixLength(selfID, target)
			if err != nil {
				t.Fatal(err)
			}
			if cpl != idx {
				t.Fatalf("bucket %d: target common prefix = %d", idx, cpl)
			}
			if bytes.Equal(selfID, target) {
				t.Fatalf("bucket %d: target equals selfID", idx)
			}
		}
	}
}

// TestRefreshStaleBuckets drives one refresh pass with a fake clock: A knows
// only C (stale), C knows D. After the clock advances past the refresh period,
// refreshStaleBuckets (a) queries C and refreshes A's LastSeen for it, and
// (b) discovers D from C's find_node response. A fresh bucket (LastSeen
// recent) is left alone — verified by C not being re-stamped when nothing is
// stale.
func TestRefreshStaleBuckets(t *testing.T) {
	var clock atomic.Int64
	const T = int64(1_000_000)
	clock.Store(T)
	a, _ := newBGNode(t, func(c *NodeConfig) {
		c.Now = func() int64 { return clock.Load() }
		c.BucketRefreshInterval = 100 * time.Second
	})
	defer a.Close()
	c, _ := startTestNode(t, nil)
	d, _ := startTestNode(t, nil)
	defer c.Close()
	defer d.Close()
	cAddr, _ := c.LocalAddr()
	dAddr, _ := d.LocalAddr()
	// C knows D; A knows only C.
	if err := c.AddPeer(d.PublicKey(), dAddr.String()); err != nil {
		t.Fatal(err)
	}
	if err := a.AddPeer(c.PublicKey(), cAddr.String()); err != nil {
		t.Fatal(err)
	}
	if got := a.rt.Get(c.ID()).LastSeen; got != T {
		t.Fatalf("precondition: C LastSeen = %d, want %d", got, T)
	}

	// Nothing is stale yet: a refresh pass must not touch the network (C's
	// LastSeen stays at T — a response would stamp it with the clock).
	a.refreshStaleBuckets(context.Background())
	if got := a.rt.Get(c.ID()).LastSeen; got != T {
		t.Fatalf("fresh bucket was refreshed: LastSeen = %d, want %d", got, T)
	}

	// Advance past the refresh period: the bucket goes stale.
	clock.Store(T + 1000)
	a.refreshStaleBuckets(context.Background())

	// (a) C was refreshed by its own find_node response.
	if got := a.rt.Get(c.ID()).LastSeen; got != T+1000 {
		t.Errorf("stale contact not refreshed: LastSeen = %d, want %d", got, T+1000)
	}
	// (b) D was discovered via C's node list.
	if a.rt.Get(d.ID()) == nil {
		t.Error("refresh round did not discover new contact D")
	}
}

// TestBackgroundLoopsStopOnClose checks the lifecycle contract: the refresh
// and republish loops run while started, Close returns only after both have
// exited, and no goroutines linger afterwards (no leaks).
func TestBackgroundLoopsStopOnClose(t *testing.T) {
	runtime.GC()
	before := runtime.NumGoroutine()

	n, _ := newBGNode(t, func(c *NodeConfig) {
		c.BucketRefreshInterval = 20 * time.Millisecond
		c.RepublishInterval = 20 * time.Millisecond
	})
	time.Sleep(120 * time.Millisecond) // several ticks of both loops
	done := make(chan struct{})
	go func() { n.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Close did not return: background loops failed to stop")
	}

	// Close-without-Start must not panic either.
	n2, err := NewNode(NodeConfig{
		Keypair:    n.kp,
		ListenAddr: "127.0.0.1:0",
		Store:      NewEnvelopeStore(0, nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := n2.Close(); err != nil {
		t.Fatalf("Close before Start: %v", err)
	}

	// Drain check: allow a grace period for the runtime's own goroutines.
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > before+2 && time.Now().Before(deadline) {
		time.Sleep(25 * time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > before+2 {
		t.Errorf("possible goroutine leak: before=%d after=%d", before, after)
	}
}

// ---------------------------------------------------------------------------
// §6.4 step 4 republish timer
// ---------------------------------------------------------------------------

// TestRepublishTimerRepublishesDueEntries seeds a node with one record past
// RefreshFraction (80%) of its lifetime and one fresh record, then lets the
// republish timer fire: the due record must land on the peer's store while the
// fresh one must not.
func TestRepublishTimerRepublishesDueEntries(t *testing.T) {
	now := time.Now().Unix()
	dueEnv, dueKey := makeEnvAt(t, "due", now-1000, now+200)   // elapsed 1000 >= 0.8*1200
	freshEnv, freshKey := makeEnvAt(t, "fresh", now, now+3600) // elapsed 0

	a, aStore := newBGNode(t, nil) // storing peer
	defer a.Close()
	aAddr, _ := a.LocalAddr()

	b, bStore := newBGNode(t, func(c *NodeConfig) { c.RepublishInterval = 50 * time.Millisecond })
	defer b.Close()
	if err := b.AddPeer(a.PublicKey(), aAddr.String()); err != nil {
		t.Fatal(err)
	}
	for _, e := range []struct {
		env *wire.SignedEnvelope
		key []byte
	}{{dueEnv, dueKey}, {freshEnv, freshKey}} {
		if ok, err := bStore.Put(e.key, e.env, now, true); err != nil || !ok {
			t.Fatalf("seed store: accepted=%v err=%v", ok, err)
		}
	}

	// The due record must appear on the peer within a few ticks.
	deadline := time.Now().Add(5 * time.Second)
	for !aStore.Has(dueKey, now) && time.Now().Before(deadline) {
		time.Sleep(25 * time.Millisecond)
	}
	if !aStore.Has(dueKey, now) {
		t.Error("due record was not republished to the peer")
	}
	time.Sleep(150 * time.Millisecond) // let any (wrong) fresh republication fire
	if aStore.Has(freshKey, now) {
		t.Error("fresh record (under 80% of lifetime) was republished early")
	}
}

// TestRepublishDueBoundary pins the 80%-of-lifetime arithmetic of the scan
// itself (no timer; one scan is driven directly with a fake clock): a record
// exactly at the threshold is republished, one a second below is not.
func TestRepublishDueBoundary(t *testing.T) {
	now := int64(10_000)
	fakeClock := func() int64 { return now }
	// lifetime 1000s → threshold at elapsed >= 800s.
	atThreshold, atKey := makeEnvAt(t, "at", now-800, now+200)
	below, belowKey := makeEnvAt(t, "below", now-799, now+201)

	// Both nodes share the fake clock: the envelopes live around t=now, so a
	// real-clock peer would consider them long-expired and evict on store.
	a, aStore := newBGNode(t, func(c *NodeConfig) { c.Now = fakeClock }) // storing peer
	defer a.Close()
	aAddr, _ := a.LocalAddr()

	b, bStore := newBGNode(t, func(c *NodeConfig) {
		c.Now = fakeClock
		c.RepublishInterval = -1 // no loop; drive the scan directly
	})
	defer b.Close()
	if err := b.AddPeer(a.PublicKey(), aAddr.String()); err != nil {
		t.Fatal(err)
	}
	for _, e := range []struct {
		env *wire.SignedEnvelope
		key []byte
	}{{atThreshold, atKey}, {below, belowKey}} {
		if ok, err := bStore.Put(e.key, e.env, now, true); err != nil || !ok {
			t.Fatalf("seed: accepted=%v err=%v", ok, err)
		}
	}

	b.republishDue(context.Background())
	if !aStore.Has(atKey, now) {
		t.Error("record exactly at 80% of lifetime was not republished")
	}
	if aStore.Has(belowKey, now) {
		t.Error("record one second below 80% of lifetime was republished early")
	}
}
