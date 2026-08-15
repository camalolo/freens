package dht

// stun_loop_test.go — §6.2 STUN monitor integration: a real internal/stun
// server on loopback, a real Node with NodeConfig.Stun pointed at it, and
// the no-op paths (explicit Advertise wins; Stun unset; unresolvable
// server). All nodes bind ephemeral loopback ports, so nothing collides.

import (
	"net"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/stun"
)

// startSTUNNode builds and starts a Node with the given Stun/Advertise
// configuration and a fresh envelope store. The caller defers Close.
func startSTUNNode(t *testing.T, stunServer, advertise string) *Node {
	t.Helper()
	n, err := NewNode(NodeConfig{
		Keypair:    mustKeypair(t),
		ListenAddr: "127.0.0.1:0",
		Store:      NewEnvelopeStore(0, nil),
		Stun:       stunServer,
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

// TestStartSTUNDiscoversReflexiveAddress: with Stun set to a live server the
// monitor populates the advertisement within seconds. The discovered
// address is the discovery socket's source AS SEEN BY THE SERVER: on
// loopback its IP is the node's local IP (127.0.0.1) and its port is the
// throwaway discovery socket's ephemeral port, so the assertion checks the
// IP and a valid port rather than the node's DHT listen port.
func TestStartSTUNDiscoversReflexiveAddress(t *testing.T) {
	t.Parallel()
	srv, err := stun.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("stun.Listen: %v", err)
	}
	defer srv.Close()
	saddr, err := srv.Addr()
	if err != nil {
		t.Fatalf("stun Addr: %v", err)
	}

	n := startSTUNNode(t, saddr.String(), "")
	defer n.Close()
	local, err := n.LocalAddr()
	if err != nil {
		t.Fatalf("LocalAddr: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for n.advertised() == "" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	adv := n.advertised()
	if adv == "" {
		t.Fatal("STUN monitor did not advertise a reflexive address within 5s")
	}
	ra, err := net.ResolveUDPAddr("udp", adv)
	if err != nil {
		t.Fatalf("advertised %q is not a UDP address: %v", adv, err)
	}
	if !ra.IP.Equal(local.IP) {
		t.Fatalf("reflexive IP %v != node local IP %v (advertised %q)", ra.IP, local.IP, adv)
	}
	if ra.Port <= 0 || ra.Port > 65535 {
		t.Fatalf("reflexive port %d out of range (advertised %q)", ra.Port, adv)
	}
}

// TestStartSTUNExplicitAdvertiseWins: when both Advertise and Stun are set,
// startSTUN is a no-op — the explicit address stays and no discovery runs
// (a discovery would have overwritten it with a 127.0.0.1 reflexive address
// within the settle window).
func TestStartSTUNExplicitAdvertiseWins(t *testing.T) {
	t.Parallel()
	srv, err := stun.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("stun.Listen: %v", err)
	}
	defer srv.Close()
	saddr, err := srv.Addr()
	if err != nil {
		t.Fatalf("stun Addr: %v", err)
	}

	const explicit = "203.0.113.10:15353" // TEST-NET-3 literal: resolvable, never dialed
	n := startSTUNNode(t, saddr.String(), explicit)
	defer n.Close()
	time.Sleep(500 * time.Millisecond) // a misbehaving monitor would act well within this
	if got := n.advertised(); got != explicit {
		t.Fatalf("advertised() = %q, want the explicit %q (STUN must not override it)", got, explicit)
	}
}

// TestStartSTUNDisabledWithoutServer: Stun unset ⇒ no-op, nothing is ever
// advertised.
func TestStartSTUNDisabledWithoutServer(t *testing.T) {
	t.Parallel()
	n := startSTUNNode(t, "", "")
	defer n.Close()
	time.Sleep(300 * time.Millisecond)
	if got := n.advertised(); got != "" {
		t.Fatalf("advertised() = %q, want empty (no Stun configured)", got)
	}
}

// TestStartSTUNUnresolvableServer: an unresolvable Stun address disables the
// monitor with a warning (tested by outcome: the node starts fine and never
// advertises anything).
func TestStartSTUNUnresolvableServer(t *testing.T) {
	t.Parallel()
	n := startSTUNNode(t, "no-port-in-here", "") // SplitHostPort failure, no DNS needed
	defer n.Close()
	time.Sleep(300 * time.Millisecond)
	if got := n.advertised(); got != "" {
		t.Fatalf("advertised() = %q, want empty (STUN server unresolvable)", got)
	}
}
