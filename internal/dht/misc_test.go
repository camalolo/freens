package dht

// misc_test.go collects the §6.2 advertised-address tests (NodeConfig.
// Advertise: peers learn the advertised addr instead of the observed UDP
// source; invalid values fall back) and the §8.3 get-by-hash audit-path test
// (a superseded envelope stays fetchable network-wide via its H_record).

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/laurent/freens/internal/crypto"
	"github.com/laurent/freens/internal/naming"
	"github.com/laurent/freens/internal/wire"
)

// freeUDPPort reserves an ephemeral loopback UDP port and releases it, so a
// test can pass a CONCRETE address (e.g. a distinct -advertise target) before
// the node that will bind it exists.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// startAdvertisedNode starts a node with the given advertised address.
func startAdvertisedNode(t *testing.T, advertise string) *Node {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	n, err := NewNode(NodeConfig{
		Keypair:    kp,
		ListenAddr: "127.0.0.1:0",
		Store:      NewEnvelopeStore(0, nil),
		Advertise:  advertise,
	})
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	if err := n.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	return n
}

// TestAdvertiseOverridesLearnedAddr (§6.2 line 422-423: "nodes advertise
// (ip, port, node_pubkey)"): A pings B while advertising a DISTINCT valid
// address; B's routing-table contact for A must carry the advertised address,
// not A's observed source. This is the NAT/port-forward case: the observed
// source would be a private address peers cannot dial back.
func TestAdvertiseOverridesLearnedAddr(t *testing.T) {
	listenPort := freeUDPPort(t)
	advertisePort := freeUDPPort(t) // distinct from the bound port
	if listenPort == advertisePort {
		t.Skip("OS handed out the same ephemeral port twice; retry")
	}
	advertise := fmt.Sprintf("127.0.0.1:%d", advertisePort)

	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewNode(NodeConfig{
		Keypair:    kp,
		ListenAddr: fmt.Sprintf("127.0.0.1:%d", listenPort),
		Store:      NewEnvelopeStore(0, nil),
		Advertise:  advertise,
	})
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	if err := a.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer a.Close()
	if a.advertise != advertise {
		t.Fatalf("valid Advertise was not honored: n.advertise=%q", a.advertise)
	}

	b, _ := startTestNode(t, nil)
	defer b.Close()
	bAddr, err := b.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.AddPeer(b.PublicKey(), bAddr.String()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := a.Ping(ctx, Peer{Addr: bAddr.String(), PublicKey: b.PublicKey()}); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	got := b.RoutingTable().Get(a.ID())
	if got == nil {
		t.Fatal("B did not learn A from the signed ping")
	}
	if got.Addr != advertise {
		t.Errorf("B's contact for A carries %q, want the advertised %q (observed source would be 127.0.0.1:%d)",
			got.Addr, advertise, listenPort)
	}
}

// TestAdvertiseInvalidFallsBackToObserved: an unparseable Advertise logs a
// warning at Start and the node keeps today's behavior — peers learn the
// observed source address.
func TestAdvertiseInvalidFallsBackToObserved(t *testing.T) {
	a := startAdvertisedNode(t, "not-a-valid-addr")
	defer a.Close()
	if a.advertise != "" {
		t.Fatalf("invalid Advertise was not dropped: n.advertise=%q", a.advertise)
	}
	aAddr, err := a.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}

	b, _ := startTestNode(t, nil)
	defer b.Close()
	bAddr, _ := b.LocalAddr()
	if err := a.AddPeer(b.PublicKey(), bAddr.String()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := a.Ping(ctx, Peer{Addr: bAddr.String(), PublicKey: b.PublicKey()}); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	got := b.RoutingTable().Get(a.ID())
	if got == nil {
		t.Fatal("B did not learn A from the signed ping")
	}
	if got.Addr != aAddr.String() {
		t.Errorf("B's contact for A carries %q, want the observed %q", got.Addr, aAddr.String())
	}
}

// TestAdvertiseGarbageFromPeerIgnored: a peer-stamped "advertise" argument
// that is not a literal host:port is ignored in favor of the observed source
// (learnPeer never performs DNS on the read loop, and never trusts an
// advertisement over the signature-derived identity).
func TestAdvertiseGarbageFromPeerIgnored(t *testing.T) {
	a, b := peerPair(t)
	defer a.Close()
	defer b.Close()
	aAddr, _ := a.LocalAddr()
	bAddr, _ := b.LocalAddr()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := a.sendQuery(ctx, bAddr, b.ID(), "ping", map[string]any{"advertise": "not an addr:portal"}); err != nil {
		t.Fatalf("sendQuery: %v", err)
	}
	// The response delivery is asynchronous; give the read loop a moment.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if c := b.RoutingTable().Get(a.ID()); c != nil {
			if c.Addr != aAddr.String() {
				t.Errorf("B's contact for A carries %q, want the observed %q (garbage advertise must be ignored)", c.Addr, aAddr.String())
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("B did not learn A from the signed ping")
}

// TestGetByHashHistoryFallback (§8.3 audit path): v1 is superseded by v2 in
// A's single-slot store, yet a peer's IterativeGet(H_record(v1)) still
// returns v1 — the hGet store-miss fallback into the superseded-envelope
// history is what makes transferred-TLD hand-off verification work
// network-wide.
func TestGetByHashHistoryFallback(t *testing.T) {
	a, b := peerPair(t)
	defer a.Close()
	defer b.Close()

	owner, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	tid, err := crypto.TldID(owner.Public())
	if err != nil {
		t.Fatal(err)
	}
	wn, err := naming.EncodeWireName(nil, "histfall", tid)
	if err != nil {
		t.Fatal(err)
	}
	now := uint64(time.Now().Unix())
	rec1, err := wire.NewRecord(wn, owner.Public(), 1, now, now+3600)
	if err != nil {
		t.Fatal(err)
	}
	env1, err := wire.SignRecord(rec1, owner)
	if err != nil {
		t.Fatal(err)
	}
	rec2, err := wire.NewRecord(wn, owner.Public(), 2, now, now+3600) // sequence 2 supersedes
	if err != nil {
		t.Fatal(err)
	}
	env2, err := wire.SignRecord(rec2, owner)
	if err != nil {
		t.Fatal(err)
	}
	key, err := KeyForWireName(wn)
	if err != nil {
		t.Fatal(err)
	}
	ts := time.Now().Unix()
	if ok, err := a.store.Put(key, env1, ts, true); err != nil || !ok {
		t.Fatalf("put v1: ok=%v err=%v", ok, err)
	}
	if ok, err := a.store.Put(key, env2, ts, true); err != nil || !ok {
		t.Fatalf("put v2 (supersede): ok=%v err=%v", ok, err)
	}
	h1, err := env1.RecordHash()
	if err != nil {
		t.Fatal(err)
	}
	if a.store.GetHistory(h1) == nil {
		t.Fatal("precondition: superseded v1 not retained in the audit history")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Fetch the SUPERSEDED envelope by its H_record across the network.
	got, err := b.IterativeGet(ctx, h1)
	if err != nil {
		t.Fatalf("IterativeGet(H(v1)): %v", err)
	}
	if got == nil {
		t.Fatal("IterativeGet(H(v1)) returned nil — the §8.3 audit path is broken")
	}
	gh, _ := got.RecordHash()
	if !bytes.Equal(gh, h1) {
		t.Errorf("audit fetch returned the wrong envelope (H_record mismatch)")
	}
	// The live winner at the record key is still v2 (the audit path must not
	// shadow the §6.4 winner).
	got2, err := b.IterativeGet(ctx, key)
	if err != nil {
		t.Fatalf("IterativeGet(key): %v", err)
	}
	if got2 == nil {
		t.Fatal("IterativeGet(key) returned nil")
	}
	h2, _ := env2.RecordHash()
	g2h, _ := got2.RecordHash()
	if !bytes.Equal(g2h, h2) {
		t.Error("live key fetch did not return the current winner v2")
	}
}

// TestUpdateAdvertise — the runtime §6.2 address update (UPnP renewal /
// STUN monitor path): a valid address replaces what outbound queries stamp,
// an invalid one is rejected without change, and empty returns to
// observed-source mode.
func TestUpdateAdvertise(t *testing.T) {
	n, err := NewNode(NodeConfig{Keypair: mustKeypair(t), ListenAddr: "127.0.0.1:0", Store: NewEnvelopeStore(0, nil)})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(); err != nil {
		t.Fatal(err)
	}
	defer n.Close()

	if got := n.advertised(); got != "" {
		t.Fatalf("fresh node advertises %q", got)
	}
	if err := n.UpdateAdvertise("127.0.0.1:15353"); err != nil {
		t.Fatalf("UpdateAdvertise: %v", err)
	}
	if got := n.advertised(); got != "127.0.0.1:15353" {
		t.Fatalf("advertised = %q", got)
	}
	if err := n.UpdateAdvertise("not an address"); err == nil {
		t.Fatal("invalid address accepted")
	}
	if got := n.advertised(); got != "127.0.0.1:15353" {
		t.Fatalf("rejected update changed the address to %q", got)
	}
	if err := n.UpdateAdvertise(""); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if got := n.advertised(); got != "" {
		t.Fatalf("empty address did not clear: %q", got)
	}
}

// TestIPv6LoopbackEndToEnd — the transport is family-agnostic ("udp" binds
// dual-stack; addresses ride *net.UDPAddr of either family), and this pins
// it: two nodes over [::1] ping, publish, and IterativeGet. Skipped on
// hosts without IPv6 loopback (some containers/CI).
func TestIPv6LoopbackEndToEnd(t *testing.T) {
	if !hasIPv6Loopback(t) {
		t.Skip("no IPv6 loopback on this host")
	}
	a, err := NewNode(NodeConfig{Keypair: mustKeypair(t), ListenAddr: "[::1]:0", Store: NewEnvelopeStore(0, nil)})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Start(); err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := NewNode(NodeConfig{Keypair: mustKeypair(t), ListenAddr: "[::1]:0", Store: NewEnvelopeStore(0, nil)})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Start(); err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	la, err := a.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	if la.IP.To4() != nil {
		t.Fatalf("bound %v, want IPv6", la)
	}
	if err := b.AddPeer(a.PublicKey(), la.String()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := b.Ping(ctx, Peer{Addr: la.String(), PublicKey: a.PublicKey()}); err != nil {
		t.Fatalf("ping over IPv6: %v", err)
	}
	owner := mustKeypair(t)
	env, key := makeTLDRecord(t, owner, "v6test")
	if acc, err := a.store.Put(key, env, time.Now().Unix(), true); err != nil || !acc {
		t.Fatalf("seed on a: %v %v", acc, err)
	}
	got, err := b.IterativeGet(ctx, key)
	if err != nil || got == nil {
		t.Fatalf("IterativeGet over IPv6: %v %v", got, err)
	}
	eh, _ := env.RecordHash()
	gh, _ := got.RecordHash()
	if !bytes.Equal(eh, gh) {
		t.Fatal("different envelope returned over IPv6")
	}
}

func hasIPv6Loopback(t *testing.T) bool {
	t.Helper()
	c, err := net.Dial("udp6", "[::1]:1")
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}
