package dht

// transient_test.go — the v0.19.7 §6.3 field-8 transient-sender flag
// (watch item #2, the NAT-mapping ghost fix):
//
//   - a transient node (CLI one-shot) is SERVED — its queries answer —
//     but the receiver never learns it as a routing-table contact;
//   - a normal (unflagged) peer is learned and confirmed exactly as
//     before (the flag changes nothing for real daemons);
//   - the flag rides on every outbound query of a Transient-configured
//     node and on no one else's.

import (
	"context"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/crypto"
)

func startFlagTestNode(t *testing.T, transient bool) *Node {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	n, err := NewNode(NodeConfig{
		Keypair:    kp,
		ListenAddr: "127.0.0.1:0",
		Store:      NewEnvelopeStore(0, nil),
		Transient:  transient,
	})
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	if err := n.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { n.Close() })
	return n
}

func peerOf(t *testing.T, n *Node) Peer {
	t.Helper()
	addr, err := n.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	return Peer{Addr: addr.String(), PublicKey: n.kp.Public()}
}

// TestTransientSenderNeverLearned is THE regression test for the ghost
// class: a one-shot's queries must be answerable without the receiver
// keeping the corpse. Before the flag, every CLI verb planted a confirmed
// ephemeral-port contact that ranked as a citizen for an hour.
func TestTransientSenderNeverLearned(t *testing.T) {
	a := startFlagTestNode(t, false) // the receiver: a real daemon
	tNode := startFlagTestNode(t, true)
	b := startFlagTestNode(t, false) // control: a normal peer

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// The transient node's ping is ANSWERED (served, not dropped)…
	if err := tNode.Ping(ctx, peerOf(t, a)); err != nil {
		t.Fatalf("transient ping: %v (the flag must not degrade service)", err)
	}
	// …but A must NOT hold a contact for it.
	if c := a.rt.Get(tNode.ID()); c != nil {
		t.Fatalf("transient sender WAS learned as a contact (%s) — the ghost class is back", c.Addr)
	}

	// Control: a normal peer's ping learns AND confirms it, as always.
	if err := b.Ping(ctx, peerOf(t, a)); err != nil {
		t.Fatalf("normal ping: %v", err)
	}
	c := a.rt.Get(b.ID())
	if c == nil {
		t.Fatal("normal peer was NOT learned — the flag broke the learn path")
	}
	if c.ConfirmedAt == 0 {
		t.Error("normal peer learned but not confirmed (ConfirmedAt unset)")
	}
}

// TestTransientConfigMarker: the config flag reaches the node and nobody
// else — the wire flag must be impossible to set by accident.
func TestTransientConfigMarker(t *testing.T) {
	tNode := startFlagTestNode(t, true)
	if !tNode.Transient() {
		t.Error("Transient() = false for a Transient-configured node")
	}
	normal := startFlagTestNode(t, false)
	if normal.Transient() {
		t.Error("Transient() = true for a default-configured node")
	}
}
