package dht

// claims_pool_test.go exercises the §7.4 storing-node side of verifier step 1
// (spec lines 602-604: "storing nodes keep the top 2 by ordering"): ClaimPool
// ordering/eviction by the (timestamp, pow_hash, tld_id) tuple, the hPut →
// pool write on the explicit-K_claim branch (via PublishClaim), the hGet
// `envelopes` wire extension (raw sendQuery inspection), the two-publisher
// contested-alias collection through a storing node's pool, and the
// DHTLookup.CollectClaims pool offer-back.

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/wire"
)

// poolOffered checks that env is pooled under key at position pos (0=best).
func poolOffered(t *testing.T, p *ClaimPool, key []byte, env *wire.SignedEnvelope, pos int) {
	t.Helper()
	top := p.Top2(key)
	if len(top) <= pos {
		t.Fatalf("pool holds %d envelopes for key, want > %d", len(top), pos)
	}
	want, err := env.RecordHash()
	if err != nil {
		t.Fatal(err)
	}
	got, err := top[pos].RecordHash()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("pool position %d holds a different envelope (H_record mismatch)", pos)
	}
}

// TestClaimPoolOfferOrdering: within one K_claim the pool keeps the BEST claim
// first per the §7.4 step-3 tuple — an earlier-timestamp claim offered LAST
// still becomes #1.
func TestClaimPoolOfferOrdering(t *testing.T) {
	p := NewClaimPool()
	const alias = "orderfoo"
	ts := uint64(time.Now().Unix())
	envEarly, kClaim := contestedClaimEnv(t, alias, ts) // better: earlier ts
	envLate, _ := contestedClaimEnv(t, alias, ts+3600)  // worse: later ts

	// Offer the worse one first: it must be stored...
	if !p.Offer(kClaim, envLate) {
		t.Fatal("first offer (late ts) was not stored")
	}
	// ...then the better one displaces it from the #1 slot.
	if !p.Offer(kClaim, envEarly) {
		t.Fatal("second offer (early ts) was not stored")
	}
	poolOffered(t, p, kClaim, envEarly, 0) // best-first: earlier ts is #1
	poolOffered(t, p, kClaim, envLate, 1)

	// A duplicate H_record is a no-op (returns false, contents unchanged).
	if p.Offer(kClaim, envEarly) {
		t.Error("re-offering the same envelope reported stored")
	}
	poolOffered(t, p, kClaim, envEarly, 0)
	if got := len(p.Top2(kClaim)); got != 2 {
		t.Errorf("pool size = %d after duplicate offer, want 2", got)
	}
}

// TestClaimPoolEvictsWorstBeyondTwo: with the pool full, a strictly better
// claim evicts the WORST member (the later-ts one), and a strictly worse
// newcomer is rejected outright.
func TestClaimPoolEvictsWorstBeyondTwo(t *testing.T) {
	p := NewClaimPool()
	const alias = "evictfoo"
	ts := uint64(time.Now().Unix())
	envBest, kClaim := contestedClaimEnv(t, alias, ts)
	envMid, _ := contestedClaimEnv(t, alias, ts+60)
	envWorst, _ := contestedClaimEnv(t, alias, ts+120)

	if !p.Offer(kClaim, envWorst) || !p.Offer(kClaim, envMid) {
		t.Fatal("filling the pool failed")
	}
	// envBest (earliest ts) belongs in the top 2: stored, evicting envWorst.
	if !p.Offer(kClaim, envBest) {
		t.Fatal("best claim was not stored into a full pool")
	}
	poolOffered(t, p, kClaim, envBest, 0)
	poolOffered(t, p, kClaim, envMid, 1)
	if got := len(p.Top2(kClaim)); got != 2 {
		t.Fatalf("pool size = %d, want 2 (capped)", got)
	}
	// A claim worse than both members is rejected without a change.
	envLoser, _ := contestedClaimEnv(t, alias, ts+6000)
	if p.Offer(kClaim, envLoser) {
		t.Error("worse-than-worst claim was stored into a full pool")
	}
	poolOffered(t, p, kClaim, envBest, 0)
	poolOffered(t, p, kClaim, envMid, 1)
}

// TestHPutViaPublishClaimLandsInPool: a claim envelope put at K_claim (the
// explicit-key branch of hPut, driven here by PublishClaim) lands in the
// STORING node's pool in addition to its single-slot store.
func TestHPutViaPublishClaimLandsInPool(t *testing.T) {
	a, b := peerPair(t)
	defer a.Close()
	defer b.Close()

	env, kClaim := contestedClaimEnv(t, "putpool", uint64(time.Now().Unix()))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.PublishClaim(ctx, env); err != nil {
		t.Fatalf("PublishClaim: %v", err)
	}
	poolOffered(t, b.claims, kClaim, env, 0)
	// The legacy single-slot write happened too (single-envelope compat).
	if got, _ := b.store.Get(kClaim, time.Now().Unix()); got == nil {
		t.Error("store winner slot was not written alongside the pool")
	}
}

// TestHGetEnvelopesOnStoreHit: when the store HITS on a K_claim that has pool
// entries, the response carries BOTH the legacy `envelope` (store winner) and
// the `envelopes` array (pool top-2, best first) — inspected through a raw
// sendQuery so the wire shape itself is pinned.
func TestHGetEnvelopesOnStoreHit(t *testing.T) {
	a, b := peerPair(t)
	defer a.Close()
	defer b.Close()

	const alias = "wirefoo"
	ts := uint64(time.Now().Unix())
	envBest, kClaim := contestedClaimEnv(t, alias, ts) // earlier ts → pool #1
	envSecond, _ := contestedClaimEnv(t, alias, ts+60)
	now := time.Now().Unix()
	// Store winner: envSecond (any winner works — the pool refines it).
	if ok, err := a.store.Put(kClaim, envSecond, now, true); err != nil || !ok {
		t.Fatalf("seed store: ok=%v err=%v", ok, err)
	}
	a.claims.Offer(kClaim, envBest)
	a.claims.Offer(kClaim, envSecond)

	aAddr, _ := a.LocalAddr()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err := b.sendQuery(ctx, aAddr, a.ID(), "get", map[string]any{"key": kClaim})
	if err != nil {
		t.Fatalf("sendQuery get: %v", err)
	}
	if resp.Y != wire.MsgTypeResponse {
		t.Fatalf("get answered with y=%v, want a response", resp.Y)
	}
	// Legacy field: the store winner, and no `nodes` on a hit.
	eb, ok := resp.A["envelope"].([]byte)
	if !ok || len(eb) == 0 {
		t.Fatal("response lacks the legacy `envelope` bstr")
	}
	if _, hasNodes := resp.A["nodes"]; hasNodes {
		t.Error("store hit must not carry `nodes`")
	}
	// Extension: `envelopes` is an array of bstr, best-first.
	arr, ok := resp.A["envelopes"].([]any)
	if !ok || len(arr) != 2 {
		t.Fatalf("response `envelopes` = %T len %d, want a 2-element bstr array", resp.A["envelopes"], len(arr))
	}
	first, ok := arr[0].([]byte)
	if !ok {
		t.Fatalf("envelopes[0] is %T, want a bstr", arr[0])
	}
	dec, err := wire.DecodeEnvelope(first)
	if err != nil {
		t.Fatalf("decode envelopes[0]: %v", err)
	}
	dh, _ := dec.RecordHash()
	wh, _ := envBest.RecordHash()
	if !bytes.Equal(dh, wh) {
		t.Error("envelopes[0] is not the best (earliest-ts) claim — best-first order violated")
	}
}

// TestHGetEnvelopesOnStoreMissWithNodes: on a store MISS at a K_claim with
// pool entries, the response carries `envelopes` IN ADDITION to `nodes`.
func TestHGetEnvelopesOnStoreMissWithNodes(t *testing.T) {
	a, b := peerPair(t)
	defer a.Close()
	defer b.Close()

	const alias = "wirebar"
	ts := uint64(time.Now().Unix())
	env1, kClaim := contestedClaimEnv(t, alias, ts)
	env2, _ := contestedClaimEnv(t, alias, ts+60)
	a.claims.Offer(kClaim, env1)
	a.claims.Offer(kClaim, env2)
	// Store stays EMPTY at kClaim (a pool-only storer).

	aAddr, _ := a.LocalAddr()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err := b.sendQuery(ctx, aAddr, a.ID(), "get", map[string]any{"key": kClaim})
	if err != nil {
		t.Fatalf("sendQuery get: %v", err)
	}
	if arr, ok := resp.A["envelopes"].([]any); !ok || len(arr) != 2 {
		t.Fatalf("store-miss response lacks the 2-envelope array: %T %v", resp.A["envelopes"], resp.A["envelopes"])
	}
	if _, hasNodes := resp.A["nodes"]; !hasNodes {
		t.Error("store miss must still carry `nodes` for the iterative walk")
	}
	if _, hasEnv := resp.A["envelope"]; hasEnv {
		t.Error("store miss must not carry the legacy `envelope`")
	}
}

// TestCollectClaimsTwoPublishersViaPoolPath: two nodes each PublishClaim a
// DIFFERENT claim for one alias to a shared storer; the storer's single slot
// keeps one §6.4 winner but its pool keeps BOTH (§7.4 top-2), so a third
// node's CollectClaims — served over the wire through `envelopes` — returns
// the full contested set of 2.
func TestCollectClaimsTwoPublishersViaPoolPath(t *testing.T) {
	c, _ := startTestNode(t, nil) // shared storer
	a, _ := startTestNode(t, nil) // publisher 1
	b, _ := startTestNode(t, nil) // publisher 2
	d, _ := startTestNode(t, nil) // collector
	defer a.Close()
	defer b.Close()
	defer c.Close()
	defer d.Close()
	cAddr, err := c.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []*Node{a, b, d} {
		if err := n.AddPeer(c.PublicKey(), cAddr.String()); err != nil {
			t.Fatal(err)
		}
	}

	const alias = "poolrace"
	ts := uint64(time.Now().Unix())
	env1, kClaim := contestedClaimEnv(t, alias, ts)
	env2, _ := contestedClaimEnv(t, alias, ts+1)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	if err := a.PublishClaim(ctx, env1); err != nil {
		t.Fatalf("A PublishClaim: %v", err)
	}
	if err := b.PublishClaim(ctx, env2); err != nil {
		t.Fatalf("B PublishClaim: %v", err)
	}

	// The storer's pool kept both competitors (its store slot kept one).
	if got := len(c.claims.Top2(kClaim)); got != 2 {
		t.Fatalf("storer pool holds %d claims, want 2", got)
	}

	// A third node merges the pool's top-2 over the wire.
	set, _, err := d.CollectClaims(ctx, alias)
	if err != nil {
		t.Fatalf("CollectClaims: %v", err)
	}
	if len(set) != 2 {
		t.Fatalf("CollectClaims returned %d envelopes, want 2 (the pool's contested pair)", len(set))
	}
	h1, _ := env1.RecordHash()
	h2, _ := env2.RecordHash()
	seen := map[string]bool{}
	for _, env := range set {
		h, _ := env.RecordHash()
		seen[string(h)] = true
	}
	if !seen[string(h1)] || !seen[string(h2)] {
		t.Errorf("collected set is missing a competitor: claim1=%v claim2=%v", seen[string(h1)], seen[string(h2)])
	}
}

// TestDHTLookupCollectClaimsOffersIntoPool: DHTLookup.CollectClaims (the
// ClaimSetResolver) offers every collected claim into the collecting node's
// pool (§7.4 "storing nodes keep the top 2 by ordering") — so the collector
// itself becomes a multi-claim storer and keeps serving the contested pair
// even after the original storers die.
func TestDHTLookupCollectClaimsOffersIntoPool(t *testing.T) {
	a, b, c := contestedTriangle(t)
	defer c.Close()

	const alias = "backpool"
	ts := uint64(time.Now().Unix())
	env1, kClaim := contestedClaimEnv(t, alias, ts)
	env2, _ := contestedClaimEnv(t, alias, ts+1)
	now := time.Now().Unix()
	if ok, err := a.store.Put(kClaim, env1, now, true); err != nil || !ok {
		t.Fatalf("seed A: ok=%v err=%v", ok, err)
	}
	if ok, err := b.store.Put(kClaim, env2, now, true); err != nil || !ok {
		t.Fatalf("seed B: ok=%v err=%v", ok, err)
	}

	lookup := NewDHTLookup(c.store, c)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	set, err := lookup.CollectClaims(ctx, alias, now)
	if err != nil {
		t.Fatalf("DHTLookup.CollectClaims: %v", err)
	}
	if len(set) != 2 {
		t.Fatalf("DHTLookup.CollectClaims returned %d envelopes, want 2", len(set))
	}
	// The collected set was offered into the collector's pool.
	if got := len(c.claims.Top2(kClaim)); got != 2 {
		t.Fatalf("collector pool holds %d claims after CollectClaims, want 2", got)
	}
	// The empty-slot single-store cache-back fired exactly once (slot was
	// empty) and did NOT displace anything (it was the pool that kept 2).
	if got, _ := c.store.Get(kClaim, now); got == nil {
		t.Fatal("empty-slot cache-back did not run")
	}

	// With the original storers gone, the collector still serves the pair —
	// out of its own pool (the single-slot store holds just one).
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	set2, err := lookup.CollectClaims(ctx, alias, now)
	if err != nil {
		t.Fatalf("CollectClaims (local pool only): %v", err)
	}
	if len(set2) != 2 {
		t.Fatalf("CollectClaims (local pool only) returned %d envelopes, want 2", len(set2))
	}
}
