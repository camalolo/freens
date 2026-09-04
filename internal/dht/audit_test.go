package dht

// audit_test.go — regressions for the bounded-state findings of the
// 2026-09-04 audit: the deadUntil penalty map and the witnessLast cooldown
// map used to grow by one permanent entry per probed corpse / per alias ever
// co-signed for the node's lifetime.

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestDeadPenaltySweepBoundsMap(t *testing.T) {
	n, _ := startTestNode(t, nil)
	defer n.Close()

	now := int64(1_000_000)
	for i := 0; i < deadPenaltySweepAt+50; i++ {
		id := make([]byte, 32)
		id[0] = byte(i)
		id[1] = byte(i >> 8)
		n.markDead(id, now)
	}
	n.penaltyMu.Lock()
	before := len(n.deadUntil)
	n.penaltyMu.Unlock()
	if before != deadPenaltySweepAt+50 {
		t.Fatalf("precondition: %d entries, want %d (nothing expired yet)", before, deadPenaltySweepAt+50)
	}

	// One insert at a later clock: every earlier entry is now past its
	// window, and the insert-time sweep must drop them.
	fresh := make([]byte, 32)
	fresh[0] = 0xff
	n.markDead(fresh, now+int64(deadPenaltyWindow/time.Second)+1)

	n.penaltyMu.Lock()
	after := len(n.deadUntil)
	n.penaltyMu.Unlock()
	if after != 1 {
		t.Fatalf("after sweep: %d entries, want 1 — the penalty map must stay bounded by live entries", after)
	}
	if !n.penalized(fresh, now+int64(deadPenaltyWindow/time.Second)+1) {
		t.Error("the fresh penalty entry was swept too")
	}
}

func TestWitnessLastPruneBoundsMap(t *testing.T) {
	a, b := peerPair(t)
	defer a.Close()
	defer b.Close()

	// Seed the cooldown map with a threshold of long-expired entries.
	b.witnessMu.Lock()
	for i := 0; i < witnessLastPruneAt; i++ {
		b.witnessLast[fmt.Sprintf("old-alias-%d", i)] = witnessSigned{
			prefixHash: []byte{byte(i), 1},
			claimant:   []byte{2},
			at:         1, // stone age
		}
	}
	b.witnessMu.Unlock()

	// One real witness round trip inserts a fresh entry and must trigger
	// the insert-time prune of the post-cooldown entries.
	const alias = "prunefoo"
	id := newWitnessIdentity(t, uint64(time.Now().Unix()))
	nonce, powHash := id.mineWitnessPoW(t, alias)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	atts, err := a.CollectWitnesses(ctx, alias, id.tldID, id.claimantKP.Public(), id.ts, nonce, powHash, 0)
	if err != nil {
		t.Fatalf("CollectWitnesses: %v", err)
	}
	if len(atts) != 1 {
		t.Fatalf("attestations = %d, want 1", len(atts))
	}

	b.witnessMu.Lock()
	got := len(b.witnessLast)
	_, oldLeft := b.witnessLast["old-alias-0"]
	_, freshLeft := b.witnessLast[alias]
	b.witnessMu.Unlock()
	if got >= witnessLastPruneAt {
		t.Fatalf("witnessLast still holds %d entries — the post-cooldown prune never ran", got)
	}
	if oldLeft {
		t.Error("a stone-age cooldown entry survived the prune")
	}
	if !freshLeft {
		t.Error("the fresh entry was pruned along with the expired ones")
	}
}
