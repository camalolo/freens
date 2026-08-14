package dht

// gossip_test.go exercises the Appendix A.4 difficulty machinery (spec lines
// 995-1008): the observed-ring median behind DHTLookup.NetworkDifficulty
// (odd/even samples, empty fallbacks), the POW_RETARGET_BLOCK retarget on
// accepted claims (with an injected clock on the witnessing node), and the
// gossip feed — difficulty values from witness responses landing in the
// collector's observed ring.

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/laurent/freens/internal/constants"
	"github.com/laurent/freens/internal/crypto"
)

// gossipStateNode builds an UNSTARTED node (no socket, no loops) whose
// difficultyState can be driven deterministically.
func gossipStateNode(t *testing.T) *Node {
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
		t.Fatalf("NewNode: %v", err)
	}
	return n
}

// TestNetworkDifficultyNilNodeAndEmptyRing: a node-less lookup (island
// resolver) reports POW_DIFFICULTY_INIT; a noded lookup with an empty
// observed ring reports the node's OWN current difficulty (24 at start).
func TestNetworkDifficultyNilNodeAndEmptyRing(t *testing.T) {
	island := NewDHTLookup(NewEnvelopeStore(0, nil), nil)
	if got := island.NetworkDifficulty(); got != constants.PoWDifficultyInit {
		t.Errorf("nil-node NetworkDifficulty = %d, want %d", got, constants.PoWDifficultyInit)
	}

	n := gossipStateNode(t)
	l := NewDHTLookup(n.store, n)
	if got := l.NetworkDifficulty(); got != constants.PoWDifficultyInit {
		t.Errorf("empty-ring NetworkDifficulty = %d, want own current %d", got, constants.PoWDifficultyInit)
	}
}

// TestNetworkDifficultyMedianOddEven: the observed ring's median is the
// element at index (n-1)/2 of the ascending-sorted samples — the exact middle
// for odd counts, the LOWER-middle for even counts (documented in
// difficultyState.medianObserved).
func TestNetworkDifficultyMedianOddEven(t *testing.T) {
	n := gossipStateNode(t)
	l := NewDHTLookup(n.store, n)
	for _, v := range []int{30, 24, 26} { // odd count: sorted [24 26 30] → 26
		n.diff.observe(v)
	}
	if got := l.NetworkDifficulty(); got != 26 {
		t.Errorf("odd-sample median = %d, want 26", got)
	}

	n2 := gossipStateNode(t)
	l2 := NewDHTLookup(n2.store, n2)
	for _, v := range []int{24, 30} { // even count: sorted [24 30] → lower-middle 24
		n2.diff.observe(v)
	}
	if got := l2.NetworkDifficulty(); got != 24 {
		t.Errorf("even-sample lower-median = %d, want 24", got)
	}
}

// TestObserveRejectsInvalidValues: outside [PoWDifficultyInit, 256] an
// advertised difficulty is not "historically valid" (A.4) and must not enter
// the ring.
func TestObserveRejectsInvalidValues(t *testing.T) {
	n := gossipStateNode(t)
	n.diff.observe(0)
	n.diff.observe(23)
	n.diff.observe(999)
	if _, ok := n.diff.medianObserved(); ok {
		t.Error("invalid difficulties polluted the observed ring")
	}
	n.diff.observe(24)
	if med, ok := n.diff.medianObserved(); !ok || med != 24 {
		t.Errorf("valid difficulty not observed: med=%d ok=%v", med, ok)
	}
}

// TestDifficultyRetargetAdvancesAfterBlock: 2015 accepted claims do not move
// D; the 2016th (POW_RETARGET_BLOCK) retargets by
// clamp(ceil(log2(actual/target)), -2, +2) over the block's wall-clock span.
// Slow block (4x target interval) ⇒ +2; then a fast block (span ~0) ⇒ -2,
// floored at POW_DIFFICULTY_INIT.
func TestDifficultyRetargetAdvancesAfterBlock(t *testing.T) {
	t0 := int64(1_700_000_000)
	slow := int64(4 * constants.PoWTargetInterval) // 2400 s vs 600 s target → log2(4)=+2

	// Drive the state machine directly (block-started-at-t0); the wire-level
	// variant (2016 real witness RPCs) is covered below.
	st := newDifficultyState(t0)
	for i := 0; i < constants.PoWRetargetBlock-1; i++ {
		st.recordAccepted(t0)
	}
	if got := st.currentDifficulty(); got != constants.PoWDifficultyInit {
		t.Fatalf("difficulty moved after %d acceptances, want unchanged %d", got, constants.PoWDifficultyInit)
	}
	st.recordAccepted(t0 + slow) // the 2016th completes the block
	if got := st.currentDifficulty(); got != constants.PoWDifficultyInit+2 {
		t.Fatalf("slow-block retarget = %d, want %d", got, constants.PoWDifficultyInit+2)
	}
	// Block restarted: another full block at a ~zero span retargets down by
	// the clamp, but never below POW_DIFFICULTY_INIT.
	for i := 0; i < constants.PoWRetargetBlock-1; i++ {
		st.recordAccepted(t0 + slow)
	}
	st.recordAccepted(t0 + slow + 1)
	if got := st.currentDifficulty(); got != constants.PoWDifficultyInit {
		t.Fatalf("fast-block retarget = %d, want floor %d", got, constants.PoWDifficultyInit)
	}
}

// TestWitnessRetargetOverTheWire: the same retarget driven by REAL witness
// RPCs — 2016 successful co-signs on the witnessing node (whose Now is
// injected) advance its gossiped difficulty after POW_RETARGET_BLOCK.
func TestWitnessRetargetOverTheWire(t *testing.T) {
	t0 := time.Now().Unix()
	var clock atomic.Int64
	clock.Store(t0)

	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewNode(NodeConfig{
		Keypair:    kp,
		ListenAddr: "127.0.0.1:0",
		Store:      NewEnvelopeStore(0, nil),
		Now:        func() int64 { return clock.Load() },
	})
	if err != nil {
		t.Fatalf("NewNode witness: %v", err)
	}
	if err := b.Start(); err != nil {
		t.Fatalf("Start witness: %v", err)
	}
	defer b.Close()
	a, _ := startTestNode(t, nil)
	defer a.Close()
	bAddr, err := b.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.AddPeer(b.PublicKey(), bAddr.String()); err != nil {
		t.Fatal(err)
	}

	// The claimant re-requests the SAME claim (same prefix hash — the §7.3
	// cooldown allows idempotent re-signing) 2016 times; each successful
	// co-sign counts as one accepted claim. The block's span is stretched to
	// 4x the target interval just before the block-completing witness.
	const alias = "retargetfoo"
	id := newWitnessIdentity(t, uint64(t0))
	slow := int64(4 * constants.PoWTargetInterval)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	for i := 0; i < constants.PoWRetargetBlock; i++ {
		if i == constants.PoWRetargetBlock-1 {
			clock.Store(t0 + slow) // complete the block with a 4x-slow span
		}
		atts, err := a.CollectWitnesses(ctx, alias, id.tldID, id.claimantKP.Public(), id.ts, 1)
		if err != nil {
			t.Fatalf("CollectWitnesses %d: %v", i, err)
		}
		if len(atts) != 1 {
			t.Fatalf("CollectWitnesses %d returned %d attestations, want 1", i, len(atts))
		}
	}
	if got := b.diff.currentDifficulty(); got != constants.PoWDifficultyInit+2 {
		t.Fatalf("witness difficulty after %d co-signs = %d, want %d (+2 per A.4 on a 4x-slow block)",
			constants.PoWRetargetBlock, got, constants.PoWDifficultyInit+2)
	}
}

// TestCollectWitnessesRecordsObservedDifficulty: each witness response's
// gossiped `difficulty` lands in the collector's observed ring, and
// NetworkDifficulty answers the ring's median (lower-middle for the even
// sample).
func TestCollectWitnessesRecordsObservedDifficulty(t *testing.T) {
	a, _ := startTestNode(t, nil) // claimant / collector
	b, _ := startTestNode(t, nil) // witness advertising 30
	c, _ := startTestNode(t, nil) // witness advertising 26
	defer a.Close()
	defer b.Close()
	defer c.Close()
	for _, w := range []*Node{b, c} {
		wAddr, err := w.LocalAddr()
		if err != nil {
			t.Fatal(err)
		}
		if err := a.AddPeer(w.PublicKey(), wAddr.String()); err != nil {
			t.Fatal(err)
		}
	}
	// Pin the witnesses' gossiped difficulties (their own retarget blocks
	// never complete within a test).
	b.diff.mu.Lock()
	b.diff.current = 30
	b.diff.mu.Unlock()
	c.diff.mu.Lock()
	c.diff.current = 26
	c.diff.mu.Unlock()

	const alias = "gossipfoo"
	id := newWitnessIdentity(t, uint64(time.Now().Unix()))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	atts, err := a.CollectWitnesses(ctx, alias, id.tldID, id.claimantKP.Public(), id.ts, 2)
	if err != nil {
		t.Fatalf("CollectWitnesses: %v", err)
	}
	if len(atts) != 2 {
		t.Fatalf("got %d attestations, want 2", len(atts))
	}
	ring := a.diff.observedSnapshot()
	if len(ring) != 2 {
		t.Fatalf("observed ring holds %d values, want 2", len(ring))
	}
	got := map[int]bool{}
	for _, v := range ring {
		got[v] = true
	}
	if !got[30] || !got[26] {
		t.Errorf("observed ring = %v, want the peers' advertised {26, 30}", ring)
	}
	l := NewDHTLookup(a.store, a)
	if med := l.NetworkDifficulty(); med != 26 {
		t.Errorf("NetworkDifficulty = %d, want lower-median 26 of {26, 30}", med)
	}
}
