package dht

// turn_mode_test.go — TURN wiring of the §6.3 transport, exercised against
// the REAL internal/turn package: NodeConfig.TurnServer (community relay
// tier) + NodeConfig.TurnRelay (client relay mode) nodes in-process on
// loopback, the graceful fallback behind a dead relay, and the coexistence
// of the co-located TURN server with normal DHT serving while allocations
// are active. All nodes bind ephemeral loopback ports, so nothing collides.
//
// INTEGRATION NOTE: this file compiles only once internal/turn lands (the
// pinned API is being written in parallel); until then it is excluded from
// local runs and executes at integration time.

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/turn"
)

// startTurnServerNode starts a plain DHT node that ALSO runs a TURN server
// (NodeConfig.TurnServer) on an ephemeral loopback port, returning the node
// and its TURN server. The caller defers Close (which closes the TURN server
// before the transport, per Node.Close).
func startTurnServerNode(t *testing.T) (*Node, *turn.Server) {
	t.Helper()
	n, err := NewNode(NodeConfig{
		Keypair:    mustKeypair(t),
		ListenAddr: "127.0.0.1:0",
		Store:      NewEnvelopeStore(0, nil),
		TurnServer: &turn.ServerConfig{ListenAddr: "127.0.0.1:0"},
	})
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	if err := n.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	ts := n.TURNServer()
	if ts == nil {
		n.Close()
		t.Fatal("TURNServer() is nil despite NodeConfig.TurnServer")
	}
	return n, ts
}

// startRelayNode starts a DHT node in client relay mode (NodeConfig.TurnRelay
// pointed at relayAddr). The allocation is established INSIDE Start, so
// RelayedMode is already decided when this returns.
func startRelayNode(t *testing.T, relayAddr string) *Node {
	t.Helper()
	n, err := NewNode(NodeConfig{
		Keypair:    mustKeypair(t),
		ListenAddr: "127.0.0.1:0",
		Store:      NewEnvelopeStore(0, nil),
		TurnRelay:  relayAddr,
	})
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	if err := n.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	return n
}

// pingPeers pings from a to b's DHT address (the §6.2 bootstrap exchange
// that seeds both routing tables).
func pingPeers(t *testing.T, a, b *Node) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.Ping(ctx, peerFor(b)); err != nil {
		t.Fatalf("ping %s: %v", peerFor(b).Addr, err)
	}
}

// TestTurnRelayAdvertisesRelayedAddress: a relay-mode node (B) peered with
// the TURN-server node (A) advertises exactly its relayed address — the
// §6.2 dialable address a symmetric-NAT node could never offer otherwise —
// and A learns B AT that address (advertise stamp wins over the observed
// source, which for tunnelled traffic is also the relayed address). The
// allocation is synchronous in Start, but poll (≤5s) per the acceptance
// criteria anyway.
func TestTurnRelayAdvertisesRelayedAddress(t *testing.T) {
	a, ts := startTurnServerNode(t)
	defer a.Close()
	ta, err := ts.Addr()
	if err != nil {
		t.Fatalf("TURN Addr: %v", err)
	}

	b := startRelayNode(t, ta.String())
	defer b.Close()
	if err := b.AddPeer(a.PublicKey(), peerFor(a).Addr); err != nil {
		t.Fatal(err)
	}
	pingPeers(t, b, a)

	if !b.RelayedMode() {
		t.Fatal("RelayedMode() = false after a successful allocation at Start")
	}
	deadline := time.Now().Add(5 * time.Second)
	for b.advertised() == "" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	want := b.turnConn.RelayedAddr().String()
	if got := b.advertised(); got != want {
		t.Fatalf("advertised() = %q, want the relayed address %q", got, want)
	}
	if n := ts.Allocations(); n < 1 {
		t.Fatalf("TURN server reports %d allocations, want ≥1 (B's)", n)
	}
	// A must learn B at the RELAYED address (the advertise stamp), never at
	// B's original private socket.
	for time.Now().Before(deadline) {
		for _, c := range a.RoutingTable().AllContacts() {
			if bytes.Equal(c.NodeID, b.ID()) {
				if c.Addr != want {
					t.Fatalf("A learned B at %q, want the relayed %q", c.Addr, want)
				}
				return // learned, at the right address: done
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("A never learned B through the relay")
}

// TestTurnRelayPublishAndGetThroughRelay: a record published BY the
// relay-mode node B reaches A through the allocation (§6.4 PUT via the
// tunnel), and a third plain node C peered with A fetches it via
// IterativeGet. B also READS through the tunnel: a record seeded on A is
// fetched by B's IterativeGet. Together this is the A↔B data path proof.
func TestTurnRelayPublishAndGetThroughRelay(t *testing.T) {
	a, ts := startTurnServerNode(t)
	defer a.Close()
	ta, err := ts.Addr()
	if err != nil {
		t.Fatalf("TURN Addr: %v", err)
	}

	b := startRelayNode(t, ta.String())
	defer b.Close()
	if !b.RelayedMode() {
		t.Skip("allocation not established — internal/turn not integrated yet")
	}
	c, _ := startTestNode(t, nil)
	defer c.Close()

	aAddr := peerFor(a)
	if err := b.AddPeer(a.PublicKey(), aAddr.Addr); err != nil {
		t.Fatal(err)
	}
	if err := c.AddPeer(a.PublicKey(), aAddr.Addr); err != nil {
		t.Fatal(err)
	}
	pingPeers(t, b, a)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Publish from B (through the relay) → A's store must hold it.
	owner := mustKeypair(t)
	env, key := makeTLDRecord(t, owner, "viaturn")
	if err := b.Publish(ctx, env); err != nil {
		t.Fatalf("Publish through relay: %v", err)
	}
	if !a.store.Has(key, time.Now().Unix()) {
		t.Fatal("A does not hold the record published by B through the relay")
	}

	// C (plain node, peered with A only) fetches it iteratively.
	got, err := c.IterativeGet(ctx, key)
	if err != nil {
		t.Fatalf("IterativeGet from C: %v", err)
	}
	if got == nil {
		t.Fatal("IterativeGet from C returned nil")
	}
	gh, _ := got.RecordHash()
	eh, _ := env.RecordHash()
	if !bytes.Equal(gh, eh) {
		t.Error("C fetched a different envelope than B published")
	}

	// B's READ path through the tunnel: a record seeded on A, fetched by B.
	// (Distinct owner key: two same-sequence TLD records under one owner
	// share K_tld, and the second seed would lose the winner rule.)
	owner2 := mustKeypair(t)
	env2, key2 := makeTLDRecord(t, owner2, "tob")
	if acc, err := a.store.Put(key2, env2, time.Now().Unix(), true); err != nil || !acc {
		t.Fatalf("seed A store: accepted=%v err=%v", acc, err)
	}
	got2, err := b.IterativeGet(ctx, key2)
	if err != nil {
		t.Fatalf("IterativeGet from B through relay: %v", err)
	}
	if got2 == nil {
		t.Fatal("B could not read a record through the relay")
	}
}

// TestTurnRelayFallbackDeadServer: a TurnRelay pointing at a dead server
// must not brick the node — Start still succeeds (after the bounded 5s
// allocation attempt), the direct UDP socket survives, RelayedMode is
// false, nothing is advertised, and direct peer UDP works normally.
func TestTurnRelayFallbackDeadServer(t *testing.T) {
	peer, _ := startTestNode(t, nil)
	defer peer.Close()

	start := time.Now()
	n := startRelayNode(t, "127.0.0.1:1") // port 1: nothing listens on loopback
	defer n.Close()
	if elapsed := time.Since(start); elapsed > 6*time.Second {
		t.Fatalf("Start took %v with a dead relay; the allocation attempt must be bounded at 5s", elapsed)
	}
	if n.RelayedMode() {
		t.Fatal("RelayedMode() = true against a dead relay server")
	}
	if got := n.advertised(); got != "" {
		t.Fatalf("advertised() = %q, want empty (direct-UDP fallback)", got)
	}
	// The direct socket works: ping a peer and be learned by it.
	if err := n.AddPeer(peer.PublicKey(), peerFor(peer).Addr); err != nil {
		t.Fatal(err)
	}
	pingPeers(t, n, peer)
	if got := peer.RoutingTable().Size(); got < 1 {
		t.Fatalf("peer learned %d contacts after our ping, want ≥1 (direct UDP dead?)", got)
	}
}

// TestTurnServerCoexistsWithDHT: while the co-located TURN server serves an
// active allocation (B in relay mode), the DHT port keeps answering — a
// third node C pings A and completes an IterativeGet through A's DHT socket.
func TestTurnServerCoexistsWithDHT(t *testing.T) {
	a, ts := startTurnServerNode(t)
	defer a.Close()
	ta, err := ts.Addr()
	if err != nil {
		t.Fatalf("TURN Addr: %v", err)
	}

	// B holds an allocation on A's TURN server for the duration.
	b := startRelayNode(t, ta.String())
	defer b.Close()
	if err := b.AddPeer(a.PublicKey(), peerFor(a).Addr); err != nil {
		t.Fatal(err)
	}
	pingPeers(t, b, a)
	if !b.RelayedMode() || ts.Allocations() < 1 {
		t.Skip("allocation not established — internal/turn not integrated yet")
	}

	c, _ := startTestNode(t, nil)
	defer c.Close()
	if err := c.AddPeer(a.PublicKey(), peerFor(a).Addr); err != nil {
		t.Fatal(err)
	}
	// Ping through the DHT port while allocations are active.
	pingPeers(t, c, a)
	// And a full get: seed a record on A, fetch it from C.
	owner := mustKeypair(t)
	env, key := makeTLDRecord(t, owner, "whileturn")
	if acc, err := a.store.Put(key, env, time.Now().Unix(), true); err != nil || !acc {
		t.Fatalf("seed A store: accepted=%v err=%v", acc, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := c.IterativeGet(ctx, key)
	if err != nil || got == nil {
		t.Fatalf("IterativeGet while TURN allocations active: env=%v err=%v", got, err)
	}
}
