package dht

// witness_reserved_test.go — the §7.7 reserved-alias gate on the §6.3 witness
// RPC (naming/reserved.go): a node running with the default policy REFUSES to
// co-sign a claim whose alias is a delegated ICANN TLD or IANA special-use
// name, before any crypto work; NodeConfig.AllowReserved opts a node out so a
// deliberate operator can still host such a namespace locally. A refused
// witness is invisible to CollectWitnesses (it answers 305, the collector
// counts it as a short haul) — which is exactly the policy outcome: no
// quorum, no claim.

import (
	"context"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/crypto"
)

func startReservedTestNode(t *testing.T, allowReserved bool) *Node {
	t.Helper()
	a, _ := startTestNode(t, nil)
	if !allowReserved {
		return a
	}
	// startTestNode has no AllowReserved knob; rebuild via the exported
	// config path so the test exercises the same construction the daemon
	// uses.
	a.Close()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatalf("gen keypair: %v", err)
	}
	n, err := NewNode(NodeConfig{
		Keypair:       kp,
		ListenAddr:    "127.0.0.1:0",
		Store:         NewEnvelopeStore(0, nil),
		AllowReserved: true,
	})
	if err != nil {
		t.Fatalf("NewNode(AllowReserved): %v", err)
	}
	if err := n.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { n.Close() })
	return n
}

// TestWitnessRefusesReservedAlias: with the default policy, B answers the
// witness RPC for "com" with a refusal (305) — CollectWitnesses reports a
// short haul, and B's witness cooldown bookkeeping stays untouched (it never
// signed).
func TestWitnessRefusesReservedAlias(t *testing.T) {
	a, b := peerPair(t)
	defer a.Close()
	defer b.Close()

	const alias = "com" // the canonical squatted-TLD case
	id := newWitnessIdentity(t, uint64(time.Now().Unix()))
	nonce, powHash := id.mineWitnessPoW(t, alias)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	atts, err := a.CollectWitnesses(ctx, alias, id.tldID, id.claimantKP.Public(), id.ts, nonce, powHash, 0)
	if err != nil {
		t.Fatalf("CollectWitnesses: %v", err)
	}
	if len(atts) != 0 {
		t.Fatalf("got %d attestations for a reserved alias, want 0 (the §7.7 gate must refuse)", len(atts))
	}
	// localhost (special-use kind) is refused the same way.
	id2 := newWitnessIdentity(t, uint64(time.Now().Unix()))
	n2, ph2 := id2.mineWitnessPoW(t, "localhost")
	atts2, err := a.CollectWitnesses(ctx, "localhost", id2.tldID, id2.claimantKP.Public(), id2.ts, n2, ph2, 0)
	if err != nil {
		t.Fatalf("CollectWitnesses(localhost): %v", err)
	}
	if len(atts2) != 0 {
		t.Fatalf("got %d attestations for localhost, want 0", len(atts2))
	}
	// A normal alias still witnesses through the SAME pair — the refusal is
	// the alias policy, not a broken transport.
	id3 := newWitnessIdentity(t, uint64(time.Now().Unix()))
	n3, ph3 := id3.mineWitnessPoW(t, "witfoo")
	atts3, err := a.CollectWitnesses(ctx, "witfoo", id3.tldID, id3.claimantKP.Public(), id3.ts, n3, ph3, 0)
	if err != nil {
		t.Fatalf("CollectWitnesses(witfoo): %v", err)
	}
	if len(atts3) != 1 {
		t.Fatalf("got %d attestations for witfoo, want 1 (control)", len(atts3))
	}
}

// TestWitnessAllowReservedOverride: a node constructed with
// NodeConfig.AllowReserved co-signs the reserved-alias claim the default
// policy refuses — the deliberate local opt-out.
func TestWitnessAllowReservedOverride(t *testing.T) {
	a, _ := startTestNode(t, nil)
	defer a.Close()
	b := startReservedTestNode(t, true)

	aAddr, err := a.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	if err := b.AddPeer(a.PublicKey(), aAddr.String()); err != nil {
		t.Fatal(err)
	}
	bAddr, err := b.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.AddPeer(b.PublicKey(), bAddr.String()); err != nil {
		t.Fatal(err)
	}

	const alias = "com"
	id := newWitnessIdentity(t, uint64(time.Now().Unix()))
	nonce, powHash := id.mineWitnessPoW(t, alias)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	atts, err := a.CollectWitnesses(ctx, alias, id.tldID, id.claimantKP.Public(), id.ts, nonce, powHash, 0)
	if err != nil {
		t.Fatalf("CollectWitnesses: %v", err)
	}
	if len(atts) != 1 {
		t.Fatalf("got %d attestations with AllowReserved, want 1 (the override must witness)", len(atts))
	}
}
