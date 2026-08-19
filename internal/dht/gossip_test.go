package dht

// gossip_test.go exercises the Appendix A.4 difficulty machinery (spec lines
// 995-1008): the observed-ring median behind DHTLookup.NetworkDifficulty
// (odd/even samples, empty fallbacks), the POW_RETARGET_BLOCK retarget on
// accepted claims (with an injected clock on the witnessing node), and the
// gossip feed — difficulty values from witness responses landing in the
// collector's observed ring.

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
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

// TestDifficultyRetargetAdvancesAfterBlock: PoWRetargetBlock-1 accepted
// claims do not move D; the block-completing claim retargets by
// clamp(round(log2(target_block_span / actual_block_span)), -2, +2)
// (v0.8.0 corrected direction: FAST blocks raise D — the mass-squatting
// scenario gets MORE expensive — and slow blocks lower it, floored at
// POW_DIFFICULTY_INIT).
func TestDifficultyRetargetAdvancesAfterBlock(t *testing.T) {
	t0 := int64(1_700_000_000)
	fast := int64(1)                                                            // block span ~0 s vs the 256x600 s target ⇒ +2 (clamped)
	slow := int64(4 * constants.PoWRetargetBlock * constants.PoWTargetInterval) // 4x target span ⇒ -2

	// Drive the state machine directly (block-started-at-t0); the wire-level
	// variant (256 real witness RPCs) is covered below.
	st := newDifficultyState(t0)
	for i := 0; i < constants.PoWRetargetBlock-1; i++ {
		st.recordAccepted(t0)
	}
	if got := st.currentDifficulty(); got != constants.PoWDifficultyInit {
		t.Fatalf("difficulty moved after %d acceptances, want unchanged %d", got, constants.PoWDifficultyInit)
	}
	st.recordAccepted(t0 + fast) // the block-completing claim: instantaneous block
	if got := st.currentDifficulty(); got != constants.PoWDifficultyInit+2 {
		t.Fatalf("fast-block retarget = %d, want %d (+2: claims arriving too quickly raise the price)", got, constants.PoWDifficultyInit+2)
	}
	// Block restarted: a 4x-slow block lowers D by the clamp (26 -> 24,
	// the floor).
	for i := 0; i < constants.PoWRetargetBlock-1; i++ {
		st.recordAccepted(t0 + fast)
	}
	st.recordAccepted(t0 + fast + slow)
	if got := st.currentDifficulty(); got != constants.PoWDifficultyInit {
		t.Fatalf("slow-block retarget = %d, want floor %d", got, constants.PoWDifficultyInit)
	}
}

// TestWitnessRetargetOverTheWire: the same retarget driven by REAL witness
// RPCs — 256 first-time co-signs on the witnessing node (whose Now is
// injected) advance its gossiped difficulty after POW_RETARGET_BLOCK: the
// block completes with a ~zero span (a registration burst), which must
// RAISE D by the clamp (v0.8.0 direction).
func TestWitnessRetargetOverTheWire(t *testing.T) {
	t0 := time.Now().Unix()
	var clock atomic.Int64
	clock.Store(t0)

	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	// GetRateLimit: -1 — the witness RPC shares the §12 per-source bucket
	// with get (v0.7.0), and 2016 back-to-back co-signs from one test IP
	// would otherwise be throttled long before the block completes.
	b, err := NewNode(NodeConfig{
		Keypair:      kp,
		ListenAddr:   "127.0.0.1:0",
		Store:        NewEnvelopeStore(0, nil),
		Now:          func() int64 { return clock.Load() },
		GetRateLimit: -1,
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

	// Since v0.7.0 only the FIRST co-sign of an alias counts as an accepted
	// claim (re-signs of the same claim no longer inflate the count — a
	// re-sign flood must not drive the network difficulty up), so the block
	// is filled with POW_RETARGET_BLOCK DISTINCT aliases, each co-signed
	// once. All co-signs happen at t0: the block's span is ~zero (a
	// registration burst), which under the v0.8.0 direction must raise D.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()
	for i := 0; i < constants.PoWRetargetBlock; i++ {
		alias := fmt.Sprintf("retargetfoo%d", i)
		id := newWitnessIdentity(t, uint64(t0))
		nonce, powHash := id.mineWitnessPoW(t, alias)
		atts, err := a.CollectWitnesses(ctx, alias, id.tldID, id.claimantKP.Public(), id.ts, nonce, powHash, 1)
		if err != nil {
			t.Fatalf("CollectWitnesses %d: %v", i, err)
		}
		if len(atts) != 1 {
			t.Fatalf("CollectWitnesses %d returned %d attestations, want 1", i, len(atts))
		}
	}
	if got := b.diff.currentDifficulty(); got != constants.PoWDifficultyInit+2 {
		t.Fatalf("witness difficulty after %d co-signs = %d, want %d (+2 per A.4 on a burst block)",
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
	nonce, powHash := id.mineWitnessPoW(t, alias)
	atts, err := a.CollectWitnesses(ctx, alias, id.tldID, id.claimantKP.Public(), id.ts, nonce, powHash, 2)
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
