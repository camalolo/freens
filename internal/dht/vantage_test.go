package dht

// vantage_test.go — the GLOBAL foreign-LAN dial filter (sendQuery and the
// TCP blob channel): an address that is private/loopback/link-local AND
// not covered by any local interface is refused INSTANTLY — a WAN node
// probing a LAN-heavy table sheds those candidates in microseconds
// instead of burning an RPC timeout per probe and listing the impossible
// dials as peer failures (user-reported 2026-09-19 on the friend's VPS).

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/crypto"
)

// startVantageNode is a node whose vantage is Pinned to a synthetic
// interface set (stand-in for the friend's VPS: public-only).
func startVantageNode(t *testing.T, nets []*net.IPNet) *Node {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	n, err := NewNode(NodeConfig{
		Keypair:    kp,
		ListenAddr: "127.0.0.1:0",
		Store:      NewEnvelopeStore(0, nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(); err != nil {
		t.Fatal(err)
	}
	// AFTER Start: Start() seeds localNets from the REAL interfaces (the
	// test box may genuinely sit on 192.168.1.0/24); the synthetic vantage
	// is the fixture's whole point.
	n.mu.Lock()
	n.localNets = nets
	n.mu.Unlock()
	t.Cleanup(func() { n.Close() })
	return n
}

func publicOnlyNets() []*net.IPNet {
	_, pub, _ := net.ParseCIDR("93.184.216.34/32")
	return []*net.IPNet{pub}
}

func TestSendQueryRefusesForeignLanInstantly(t *testing.T) {
	n := startVantageNode(t, publicOnlyNets())

	// A foreign LAN address: refused BEFORE any dial, instantly.
	start := time.Now()
	_, err := n.sendQuery(context.Background(), &net.UDPAddr{IP: net.ParseIP("192.168.1.32"), Port: 15353},
		make([]byte, 32), "ping", map[string]any{})
	if err == nil || !errors.Is(err, ErrUnreachableVantage) {
		t.Fatalf("foreign-LAN ping = %v, want ErrUnreachableVantage", err)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("refusal took %v — it must be instant, not a dial timeout", elapsed)
	}
	// Loopback IS local on every machine: not refused (the ping then
	// simply fails/answers normally against whatever listens there).
	if _, err := n.sendQuery(context.Background(), &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1},
		make([]byte, 32), "ping", map[string]any{}); errors.Is(err, ErrUnreachableVantage) {
		t.Fatal("loopback must never be vantage-refused")
	}
}

func TestSendQueryAllowsOwnLan(t *testing.T) {
	// A node ON the 192.168.1.0/24 LAN: its neighbor's address dials
	// normally (here: against a live test node bound on 127.0.0.1 via the
	// LAN subnet covering loopback — the point is no vantage refusal).
	_, lan, _ := net.ParseCIDR("192.168.1.16/24")
	n := startVantageNode(t, []*net.IPNet{lan})
	peer := startFlagTestNode(t, false)
	addr, err := peer.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	ua, err := net.ResolveUDPAddr("udp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := n.sendQuery(ctx, ua, peer.ID(), "ping", map[string]any{}); err != nil {
		t.Fatalf("own-viable ping failed: %v", err)
	}
}

func TestBlobTCPGetRefusesForeignLan(t *testing.T) {
	n := startVantageNode(t, publicOnlyNets())
	peer := Peer{Addr: "192.168.1.32:15353", PublicKey: make([]byte, 32)}
	_, _, err := n.BlobTCPGet(context.Background(), peer, make([]byte, 32), make([]byte, 32), 0, 16)
	if !errors.Is(err, ErrUnreachableVantage) {
		t.Fatalf("foreign-LAN blob TCP = %v, want ErrUnreachableVantage", err)
	}
}

func TestViableIPClassification(t *testing.T) {
	n := startVantageNode(t, publicOnlyNets())
	cases := []struct {
		ip   string
		want bool
	}{
		{"93.184.216.34", true}, // public
		{"2001:db8::1", true},   // public v6 (doc range parses as global here)
		{"192.168.1.32", false}, // foreign LAN
		{"10.1.2.3", false},     // foreign private
		{"172.16.0.9", false},   // foreign private
		{"127.0.0.1", true},     // loopback: local on every machine
		{"fe80::1", false},      // link-local, foreign
	}
	for _, c := range cases {
		if got := n.viableIP(net.ParseIP(c.ip)); got != c.want {
			t.Errorf("viableIP(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

// TestLearnContactDropsForeignLan: the learn-side vantage rule — a
// foreign-LAN address is never STORED (the user's directive: from a WAN
// node's point of view, other LANs' addresses should simply not exist).
func TestLearnContactDropsForeignLan(t *testing.T) {
	n := startVantageNode(t, publicOnlyNets())

	mk := func(addr string) *NodeContact {
		kp, err := crypto.Generate()
		if err != nil {
			t.Fatal(err)
		}
		id, err := crypto.NodeID(kp.Public())
		if err != nil {
			t.Fatal(err)
		}
		c, err := NewNodeContact(id, kp.Public(), addr, time.Now().Unix())
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	foreign := mk("192.168.1.32:15353") // foreign LAN: dropped entirely
	n.learnContact(foreign)
	if c := n.rt.Get(foreign.NodeID); c != nil {
		t.Fatal("foreign-LAN contact was stored")
	}
	public := mk("93.184.216.34:15353") // public: stored
	n.learnContact(public)
	if c := n.rt.Get(public.NodeID); c == nil {
		t.Fatal("public contact dropped")
	}
}
