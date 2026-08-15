package dht

// transport_test.go exercises the §6.3 UDP RPC transport end-to-end on the
// loopback interface: two real Nodes with real UDP sockets exchanging signed
// CBOR messages, plus the iterative GET and the DHTLookup cache-on-fetch path.
//
// These tests bind ephemeral loopback ports (127.0.0.1:0) and read the concrete
// address back via Node.LocalAddr, so they never collide and need no privileges.

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/wire"
)

// startTestNode builds a Node bound to an ephemeral loopback port and starts
// it, returning the node and its concrete local address. The caller defers Close.
func startTestNode(t *testing.T, store *EnvelopeStore) (*Node, *crypto.Keypair) {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatalf("gen keypair: %v", err)
	}
	if store == nil {
		store = NewEnvelopeStore(0, nil)
	}
	n, err := NewNode(NodeConfig{
		Keypair:    kp,
		ListenAddr: "127.0.0.1:0",
		Store:      store,
	})
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	if err := n.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	return n, kp
}

// peerPair starts two nodes A and B and cross-seeds their routing tables so each
// knows the other's (addr, pubkey). Returns (A, B).
func peerPair(t *testing.T) (*Node, *Node) {
	t.Helper()
	a, _ := startTestNode(t, nil)
	b, _ := startTestNode(t, nil)
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

// makeTLDRecord builds a self-signed TLD-root envelope for alias, owned by kp.
func makeTLDRecord(t *testing.T, kp *crypto.Keypair, alias string) (*wire.SignedEnvelope, []byte) {
	t.Helper()
	tid, err := crypto.TldID(kp.Public())
	if err != nil {
		t.Fatal(err)
	}
	wn, err := naming.EncodeWireName(nil, alias, tid)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	rec, err := wire.NewRecord(wn, kp.Public(), 1, uint64(now), uint64(now+3600))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rec.CanonicalBytes(); err != nil {
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

// TestPing verifies the signed ping/ping round-trip and that the responder
// learns the sender (its routing table gains the sender's contact). Only A is
// seeded with B's address, so B starts with an empty table and must learn A
// purely from the inbound signed ping.
func TestPing(t *testing.T) {
	a, _ := startTestNode(t, nil)
	b, _ := startTestNode(t, nil)
	defer a.Close()
	defer b.Close()

	aAddr, _ := a.LocalAddr()
	bAddr, _ := b.LocalAddr()
	// A knows B (so it can sign a query to B); B knows nobody yet.
	if err := a.AddPeer(b.PublicKey(), bAddr.String()); err != nil {
		t.Fatal(err)
	}
	if got := b.RoutingTable().Size(); got != 0 {
		t.Fatalf("precondition: B should start empty, got %d", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := a.Ping(ctx, Peer{Addr: bAddr.String(), PublicKey: b.PublicKey()}); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	// B learned A from the signed inbound ping.
	if got := b.RoutingTable().Size(); got != 1 {
		t.Errorf("responder did not learn sender: want 1, got %d", got)
	}
	_ = aAddr
}

func peerFor(n *Node) Peer {
	addr, _ := n.LocalAddr()
	return Peer{Addr: addr.String(), PublicKey: n.PublicKey()}
}

// TestIterativeGetFetchesFromPeer seeds an envelope in A's store, then has B
// fetch it via IterativeGet (B queries A over the DHT). This is the core
// cross-node path: A is an island whose record B reaches over the network.
func TestIterativeGetFetchesFromPeer(t *testing.T) {
	a, b := peerPair(t)
	defer a.Close()
	defer b.Close()

	owner, _ := crypto.Generate()
	env, key := makeTLDRecord(t, owner, "alpha")
	if accepted, err := a.store.Put(key, env, time.Now().Unix(), true); err != nil || !accepted {
		t.Fatalf("seed A store: accepted=%v err=%v", accepted, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := b.IterativeGet(ctx, key)
	if err != nil {
		t.Fatalf("IterativeGet: %v", err)
	}
	if got == nil {
		t.Fatal("IterativeGet returned nil envelope")
	}
	gh, _ := got.RecordHash()
	eh, _ := env.RecordHash()
	if !bytes.Equal(gh, eh) {
		t.Errorf("fetched envelope differs from seeded")
	}
}

// TestPublishStoresOnPeer exercises the §6.4 PUT path: A.Publish obtains a write
// token from B (via get) then puts the envelope, after which B's local store
// holds it.
func TestPublishStoresOnPeer(t *testing.T) {
	a, b := peerPair(t)
	defer a.Close()
	defer b.Close()

	owner, _ := crypto.Generate()
	env, key := makeTLDRecord(t, owner, "alphapub")
	now := time.Now().Unix()
	if b.store.Has(key, now) {
		t.Fatal("precondition: B should not yet hold the envelope")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.Publish(ctx, env); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	// Allow the async store to settle, then verify.
	if !b.store.Has(key, time.Now().Unix()) {
		t.Errorf("Publish did not store the envelope on the peer")
	}
}

// TestGetMissReturnsNodes verifies that a get for an absent key returns the
// closest known contacts (the iterative-lookup fuel), not an error.
func TestGetMissReturnsNodes(t *testing.T) {
	a, b := peerPair(t)
	defer a.Close()
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// A random key neither node stores.
	key := make([]byte, constants.SHA256Len)
	for i := range key {
		key[i] = 0xab
	}
	addr, _ := b.LocalAddr()
	resp, err := a.sendQuery(ctx, addr, b.ID(), "get", map[string]any{"key": key})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if resp.Y != wire.MsgTypeResponse {
		t.Fatalf("expected response, got %q", resp.Y)
	}
	nodes := parseNodes(resp.A["nodes"])
	if len(nodes) == 0 {
		t.Errorf("get-miss should return closest nodes, got none")
	}
	// B is its own closest... actually B returns its contacts (which includes A
	// once seeded); at minimum the nodes list should be non-empty and decodable.
	for _, c := range nodes {
		if len(c.NodeID) != constants.NodeIDLen || len(c.PublicKey) != constants.Ed25519PublicKeyLen {
			t.Errorf("malformed contact in nodes list: %+v", c)
		}
	}
}

// TestFindNode verifies find_node returns the K closest contacts to a target.
func TestFindNode(t *testing.T) {
	a, b := peerPair(t)
	defer a.Close()
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	target := b.ID() // ask B "who is closest to yourself"
	addr, _ := b.LocalAddr()
	resp, err := a.sendQuery(ctx, addr, b.ID(), "find_node", map[string]any{"target": target})
	if err != nil {
		t.Fatalf("find_node: %v", err)
	}
	if resp.Y != wire.MsgTypeResponse {
		t.Fatalf("expected response, got %q", resp.Y)
	}
	nodes := parseNodes(resp.A["nodes"])
	if len(nodes) == 0 {
		t.Fatal("find_node returned no nodes")
	}
}

// TestPutRejectsBadToken verifies the §6.3 write-token defense: a put whose
// token does not validate against the source IP is rejected with code 302.
func TestPutRejectsBadToken(t *testing.T) {
	a, b := peerPair(t)
	defer a.Close()
	defer b.Close()

	owner, _ := crypto.Generate()
	env, _ := makeTLDRecord(t, owner, "beta")
	envBytes, _ := env.Bytes()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	addr, _ := b.LocalAddr()
	resp, err := a.sendQuery(ctx, addr, b.ID(), "put", map[string]any{
		"token":    []byte("not-a-valid-token-32-bytes-long!!"), // 32 bytes, wrong
		"envelope": envBytes,
	})
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if resp.Y != wire.MsgTypeError {
		t.Fatalf("expected error for bad token, got %q", resp.Y)
	}
	code, _ := asUint64(resp.A["code"])
	if code != 302 {
		t.Errorf("expected code 302 (invalid token), got %v", resp.A["code"])
	}
	// And the envelope must NOT have been stored.
	key, _ := KeyForWireName(env.Record.Name)
	if b.store.Has(key, time.Now().Unix()) {
		t.Errorf("envelope was stored despite invalid token")
	}
}

// TestPutRejectsBadSignature verifies code 303 for a valid-token put whose
// envelope signature does not verify.
func TestPutRejectsBadSignature(t *testing.T) {
	a, b := peerPair(t)
	defer a.Close()
	defer b.Close()

	// Obtain a real token from B via a get.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	key := make([]byte, constants.SHA256Len)
	addr, _ := b.LocalAddr()
	getResp, err := a.sendQuery(ctx, addr, b.ID(), "get", map[string]any{"key": key})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	token, _ := getResp.A["token"].([]byte)
	if len(token) == 0 {
		t.Fatal("no token issued on get")
	}

	// Forge an envelope with a garbage signature.
	owner, _ := crypto.Generate()
	env, _ := makeTLDRecord(t, owner, "gamma")
	env.Sig = make([]byte, constants.Ed25519SignatureLen) // all-zero, invalid
	envBytes, _ := env.Bytes()

	resp, err := a.sendQuery(ctx, addr, b.ID(), "put", map[string]any{
		"token":    token,
		"envelope": envBytes,
	})
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if resp.Y != wire.MsgTypeError {
		t.Fatalf("expected error for bad sig, got %q", resp.Y)
	}
	code, _ := asUint64(resp.A["code"])
	if code != 303 {
		t.Errorf("expected code 303 (invalid signature), got %v", resp.A["code"])
	}
}

// TestDHTLookupFetchesAndCaches verifies the resolver adapter: a local-store
// miss triggers a network GET that fetches the envelope AND caches it locally so
// the second lookup is served from the cache (no further network IO).
func TestDHTLookupFetchesAndCaches(t *testing.T) {
	a, b := peerPair(t)
	defer a.Close()
	defer b.Close()

	owner, _ := crypto.Generate()
	env, key := makeTLDRecord(t, owner, "delta")
	// Seed A's store directly (simulating -load), NOT via Publish.
	if accepted, err := a.store.Put(key, env, time.Now().Unix(), true); err != nil || !accepted {
		t.Fatalf("seed A store: accepted=%v err=%v", accepted, err)
	}

	lookup := NewDHTLookup(b.store, b)
	now := time.Now().Unix()
	// B does not have it locally yet.
	if got, _ := b.store.Get(key, now); got != nil {
		t.Fatal("precondition: B should not have the envelope")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	got, err := lookup.Lookup(ctx, env.Record.Name, now)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got == nil {
		t.Fatal("Lookup returned nil (network GET failed)")
	}
	gh, _ := got.RecordHash()
	eh, _ := env.RecordHash()
	if !bytes.Equal(gh, eh) {
		t.Error("fetched envelope mismatch")
	}
	// Now cached in B's local store.
	if cached, _ := b.store.Get(key, now); cached == nil {
		t.Error("fetched envelope was not cached locally")
	}
}

// TestIterativeGetNoPeers confirms an island (no peers) returns nil without
// error rather than hanging.
func TestIterativeGetNoPeers(t *testing.T) {
	a, _ := startTestNode(t, nil)
	defer a.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	key := make([]byte, constants.SHA256Len)
	got, err := a.IterativeGet(ctx, key)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for island lookup, got envelope")
	}
}

// TestDHTLookupLocalHit confirms that when the local store has the envelope,
// no network IO occurs (the node is nil — proving the local path short-circuits
// before any IterativeGet).
func TestDHTLookupLocalHit(t *testing.T) {
	store := NewEnvelopeStore(0, nil)
	owner, _ := crypto.Generate()
	env, key := makeTLDRecord(t, owner, "epsilon")
	now := time.Now().Unix()
	if _, err := store.Put(key, env, now, true); err != nil {
		t.Fatal(err)
	}
	// node == nil: any network access would panic, so a return proves locality.
	lookup := NewDHTLookup(store, nil)
	got, err := lookup.Lookup(context.Background(), env.Record.Name, now)
	if err != nil || got == nil {
		t.Fatalf("local hit failed: got=%v err=%v", got, err)
	}
}

// TestUnverifiedMessageDropped confirms a message whose signature does not
// verify (or whose recipient_id is wrong) is silently dropped — never answered.
func TestUnverifiedMessageDropped(t *testing.T) {
	a, b := peerPair(t)
	defer a.Close()
	defer b.Close()

	// Craft a query addressed to the WRONG recipient (a random id, not B's), so
	// B's Verify (which uses its own id as recipient_id) fails.
	wrongRecipient := make([]byte, constants.NodeIDLen)
	for i := range wrongRecipient {
		wrongRecipient[i] = 0x07
	}
	addr, _ := b.LocalAddr()
	// Use a's keypair but sign for the wrong recipient.
	txid := []byte{1, 2, 3, 4}
	msg, err := wire.NewQuery("ping", map[string]any{}, a.kp, wrongRecipient, txid)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := msg.Bytes()
	if _, err := a.conn.WriteTo(data, addr); err != nil {
		t.Fatal(err)
	}
	// No response channel was registered (we bypassed sendQuery), so a dropped
	// message simply yields nothing. Give B a moment to (not) react, then
	// confirm B did NOT learn the wrong-recipient sender: its routing table
	// already has A from peerPair, so size should be unchanged.
	sizeBefore := b.RoutingTable().Size()
	time.Sleep(150 * time.Millisecond)
	// (We cannot easily assert "no reply" without a listener; the stronger
	// invariant is that verify-gated learning did not fire spuriously. The
	// real guarantee is structural: handle() returns before handleQuery when
	// Verify fails.)
	if b.RoutingTable().Size() != sizeBefore {
		t.Errorf("routing table changed despite unverified message")
	}
}

// TestIterativeGetEvictsDeadContacts verifies §6.2 failure handling: a contact
// whose probe times out is evicted from the routing table, and the lookup as a
// whole terminates well inside the 5s RPC_TIMEOUT (the 2s probe budget).
func TestIterativeGetEvictsDeadContacts(t *testing.T) {
	// B is the looker; A holds the record; D is a dead node B has learned.
	b, _ := startTestNode(t, nil)
	a, _ := startTestNode(t, nil)
	d, dkp := startTestNode(t, nil)
	defer a.Close()
	defer b.Close()

	aAddr, _ := a.LocalAddr()
	dAddr, _ := d.LocalAddr()
	if err := b.AddPeer(a.PublicKey(), aAddr.String()); err != nil {
		t.Fatal(err)
	}
	if err := b.AddPeer(d.PublicKey(), dAddr.String()); err != nil {
		t.Fatal(err)
	}
	_ = dkp

	// Seed a record on A.
	owner, _ := crypto.Generate()
	env, key := makeTLDRecord(t, owner, "evict-test")
	if ok, err := a.store.Put(key, env, time.Now().Unix(), true); err != nil || !ok {
		t.Fatalf("seed: %v %v", ok, err)
	}

	// Kill D AFTER B learned it, so its address is now a black hole.
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	if got := b.RoutingTable().Size(); got != 2 {
		t.Fatalf("precondition: B should know 2 contacts, got %d", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	start := time.Now()
	gotEnv, err := b.IterativeGet(ctx, key)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("IterativeGet: %v", err)
	}
	if gotEnv == nil {
		t.Fatal("expected the envelope from A despite the dead contact")
	}
	// The dead contact must be gone from B's routing table.
	if got := b.RoutingTable().Get(d.ID()); got != nil {
		t.Error("dead contact was not evicted from the routing table")
	}
	if got := b.RoutingTable().Size(); got != 1 {
		t.Errorf("post-lookup table size = %d, want 1 (only A)", got)
	}
	// The lookup must not have burned a full RPC_TIMEOUT on the dead probe.
	if elapsed > 4*time.Second {
		t.Errorf("lookup took %v despite the 2s probe budget (dead contact slowed it)", elapsed)
	}
}

// TestIterativeGetDeadOnlyMissesFast verifies the pure-miss case with only a
// dead contact: the lookup returns a DEGRADED miss (issue #1: probe failures
// mean the network could not be interrogated — not that the record is absent)
// promptly, evicts the contact, and penalizes it.
func TestIterativeGetDeadOnlyMissesFast(t *testing.T) {
	b, _ := startTestNode(t, nil)
	d, dkp := startTestNode(t, nil)
	defer b.Close()

	dAddr, _ := d.LocalAddr()
	if err := b.AddPeer(d.PublicKey(), dAddr.String()); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil { // black-hole the only contact
		t.Fatal(err)
	}
	_ = dkp

	key := make([]byte, constants.SHA256Len)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	start := time.Now()
	env, stats, err := b.IterativeGetDetailed(ctx, key)
	if env != nil {
		t.Error("expected nil envelope from a dead-only lookup")
	}
	if !errors.Is(err, ErrDegradedMiss) {
		t.Errorf("dead-only miss = %v, want ErrDegradedMiss", err)
	}
	if stats.ProbesFailed == 0 {
		t.Error("stats report no failed probes for a dead-only walk")
	}
	if b.RoutingTable().Size() != 0 {
		t.Error("dead contact was not evicted")
	}
	if el := time.Since(start); el > 4*time.Second {
		t.Errorf("dead-only miss took %v; want < 4s via probe budget", el)
	}
	// The penalty is active: a second walk must skip the corpse entirely
	// (no probes at all — every unqueried candidate is penalized).
	_, stats2, err2 := b.IterativeGetDetailed(ctx, key)
	if err2 != nil {
		t.Fatalf("second walk: %v", err2)
	}
	if stats2.ProbesSent != 0 {
		t.Errorf("second walk probed %d contact(s); the penalized corpse must be skipped", stats2.ProbesSent)
	}
}

// TestIterativeGetCleanMissIsNotDegraded: when every reachable holder
// ANSWERS "not held" (no probe failures), the miss is clean — (nil, nil),
// never ErrDegradedMiss — so the resolver may negative-cache it.
func TestIterativeGetCleanMissIsNotDegraded(t *testing.T) {
	a, _ := startTestNode(t, nil)
	b, _ := startTestNode(t, nil)
	defer a.Close()
	defer b.Close()

	aAddr, _ := a.LocalAddr()
	if err := b.AddPeer(a.PublicKey(), aAddr.String()); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, constants.SHA256Len) // nobody stores anything here
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	env, stats, err := b.IterativeGetDetailed(ctx, key)
	if env != nil || err != nil {
		t.Fatalf("clean miss = (%v, %v); want (nil, nil)", env, err)
	}
	if stats.ProbesFailed != 0 || stats.ProbesSent == 0 {
		t.Errorf("stats = %+v; want probes sent, none failed", stats)
	}
}

// TestIterativeGetPenaltySurvivesReadvertisement (issue #1): a corpse that
// live peers keep re-advertising (re-learned into the routing table) is NOT
// re-probed inside the penalty window — the churn loop that burned a 2 s
// budget per query in the field.
func TestIterativeGetPenaltySurvivesReadvertisement(t *testing.T) {
	b, _ := startTestNode(t, nil)
	a, _ := startTestNode(t, nil) // live holder
	d, _ := startTestNode(t, nil) // future corpse
	defer a.Close()
	defer b.Close()

	aAddr, _ := a.LocalAddr()
	dAddr, _ := d.LocalAddr()
	if err := b.AddPeer(a.PublicKey(), aAddr.String()); err != nil {
		t.Fatal(err)
	}
	if err := b.AddPeer(d.PublicKey(), dAddr.String()); err != nil {
		t.Fatal(err)
	}
	owner, _ := crypto.Generate()
	env, key := makeTLDRecord(t, owner, "penalty-test")
	if ok, err := a.store.Put(key, env, time.Now().Unix(), true); err != nil || !ok {
		t.Fatalf("seed: %v %v", ok, err)
	}
	if err := d.Close(); err != nil { // black-hole AFTER B learned it
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if got, _, err := b.IterativeGetDetailed(ctx, key); err != nil || got == nil {
		t.Fatalf("first walk: env=%v err=%v", got, err)
	}
	// Simulate re-advertisement: re-add the dead contact to B's table.
	if err := b.AddPeer(d.PublicKey(), dAddr.String()); err != nil {
		t.Fatal(err)
	}
	// A SECOND walk while the penalty is live must not probe the corpse.
	_, stats, err := b.IterativeGetDetailed(ctx, key)
	if err != nil {
		t.Fatalf("second walk: %v", err)
	}
	for _, id := range stats.ProbedNodeIDs {
		if string(id) == string(d.ID()) {
			t.Error("the penalized corpse was re-probed inside the penalty window")
		}
	}
}

// TestIterativeGetChurnFindsRecord (issue #1 field repro): with the nodes
// CLOSEST to the key dead, a walk from a surviving far node still finds the
// record (stored on every holder at publish time) — and does not classify
// the found result as degraded.
func TestIterativeGetChurnFindsRecord(t *testing.T) {
	if testing.Short() {
		t.Skip("multi-node timing-sensitive")
	}
	nodes := make([]*Node, 0, 6)
	for i := 0; i < 6; i++ {
		n, _ := startTestNode(t, nil)
		nodes = append(nodes, n)
	}
	// Full mesh (ring + 0).
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	addrs := make([]string, len(nodes))
	for i, n := range nodes {
		la, err := n.LocalAddr()
		if err != nil {
			t.Fatal(err)
		}
		addrs[i] = la.String()
	}
	for i := 1; i < len(nodes); i++ {
		targets := []int{0}
		if i > 1 {
			targets = append(targets, i-1)
		}
		for _, j := range targets {
			if err := nodes[i].AddPeer(nodes[j].PublicKey(), addrs[j]); err != nil {
				t.Fatal(err)
			}
		}
	}

	// The record: published from node 1 (peer-PUTs; also teaches node 0
	// about node 1) AND seeded explicitly into node 0's store so a live
	// holder exists on the far side regardless of PUT fan-out.
	owner, _ := crypto.Generate()
	env, key := makeTLDRecord(t, owner, "churn-test")
	if ok, err := nodes[0].store.Put(key, env, time.Now().Unix(), true); err != nil || !ok {
		t.Fatalf("seed node0: %v %v", ok, err)
	}
	pubCtx, pubCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer pubCancel()
	_ = nodes[1].Publish(pubCtx, env) // best-effort fan-out; node 0 is the guaranteed holder

	// Kill the 3 nodes (among 2..5) closest to the key.
	type di struct {
		i    int
		dist []byte
	}
	var order []di
	for i, n := range nodes {
		if i <= 1 {
			continue // keep the publisher + node 0 (both hold the record)
		}
		dist, err := XORBytes(key, n.ID())
		if err != nil {
			t.Fatal(err)
		}
		order = append(order, di{i, dist})
	}
	sort.Slice(order, func(a, b int) bool {
		return bytes.Compare(order[a].dist, order[b].dist) < 0
	})
	for _, k := range order[:3] {
		if err := nodes[k.i].Close(); err != nil {
			t.Fatal(err)
		}
	}

	// The searcher: a surviving node far from the key (the last in order).
	searcher := nodes[order[len(order)-1].i]
	start := time.Now()
	got, stats, err := searcher.IterativeGetDetailed(ctx, key)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("churn walk: %v", err)
	}
	if got == nil {
		t.Fatal("record not found despite live holders (issue #1 regression)")
	}
	if elapsed > 6*time.Second {
		t.Errorf("churn walk took %v (stats %+v); penalty+adaptive batch should reach live holders fast", elapsed, stats)
	}
}
