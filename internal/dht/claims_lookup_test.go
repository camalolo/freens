package dht

// claims_lookup_test.go exercises the §7.4 verifier-side step-1 multi-claim
// collection (spec lines 600-604): Node.CollectClaims runs an iterative lookup
// on K_claim that MERGES the distinct claim envelopes offered by the closest
// reachable nodes (instead of returning the single §6.4 winner), includes the
// local store's copy, deduplicates by H_record, and drives
// DHTLookup.CollectClaims — the ClaimSetResolver the resolver's §7.4 ordering
// consumes.
//
// Topology: three loopback nodes; A holds claim1 (ts=T) and B holds claim2
// (ts=T+1) for the same alias under K_claim (both valid, mined at difficulty 8
// via claims.MineAliasClaim, witnesses assembled out of band — the
// claimedTLDRecord pattern of witness_test.go). C collects and must see BOTH.

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/claims"
	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/wire"
)

// contestedClaimEnv builds one side of a §7.4 claim race: a low-difficulty
// mined, W-witnessed AliasClaim for alias at the GIVEN claimant-asserted
// timestamp, embedded in the claimant's self-certifying TLD record (field 11),
// signed by the TLD key. Returns the envelope and K_claim. The record's own
// validity window straddles the real clock (these DHT-layer tests use
// startTestNode's wall time), while the claim ts is caller-chosen so two
// envelopes can be ordered (T vs T+1) per §7.4 step 3.
func contestedClaimEnv(t *testing.T, alias string, ts uint64) (*wire.SignedEnvelope, []byte) {
	t.Helper()
	claimant, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	tid, err := crypto.TldID(claimant.Public())
	if err != nil {
		t.Fatal(err)
	}
	claim, err := claims.MineAliasClaim(alias, claimant, ts, 8, 2_000_000, 16)
	if err != nil {
		t.Fatalf("MineAliasClaim: %v", err)
	}
	witnesses := make([]*claims.WitnessAttestation, 0, constants.W)
	for i := 0; i < constants.W; i++ {
		wkp, err := crypto.Generate()
		if err != nil {
			t.Fatal(err)
		}
		w, err := claims.NewWitnessAttestation(wkp, ts+uint64(i), alias, tid, claimant.Public())
		if err != nil {
			t.Fatalf("NewWitnessAttestation: %v", err)
		}
		witnesses = append(witnesses, w)
	}
	claim.Witnesses = witnesses
	cb, err := claim.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	now := uint64(time.Now().Unix())
	wn, err := naming.EncodeWireName(nil, alias, tid)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := wire.NewRecord(wn, claimant.Public(), 1, now-10, now+3600)
	if err != nil {
		t.Fatal(err)
	}
	rec.Claim = cb
	env, err := wire.SignRecord(rec, claimant)
	if err != nil {
		t.Fatal(err)
	}
	kClaim, err := KeyForClaim(alias)
	if err != nil {
		t.Fatal(err)
	}
	return env, kClaim
}

// contestedTriangle starts C, A, B and peers C with both A and B (A and B need
// not know each other — C's walk only needs its own routing table).
func contestedTriangle(t *testing.T) (a, b, c *Node) {
	t.Helper()
	a, _ = startTestNode(t, nil)
	b, _ = startTestNode(t, nil)
	c, _ = startTestNode(t, nil)
	aAddr, err := a.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	bAddr, err := b.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AddPeer(a.PublicKey(), aAddr.String()); err != nil {
		t.Fatal(err)
	}
	if err := c.AddPeer(b.PublicKey(), bAddr.String()); err != nil {
		t.Fatal(err)
	}
	return a, b, c
}

// TestCollectClaimsMergesCompetingClaims — THE §7.4 step-1 test: A holds
// claim1 (ts=T), B holds claim2 (ts=T+1) for the same alias under K_claim
// (split state: each node's §6.4 store kept a different winner). C's
// CollectClaims must return BOTH distinct envelopes — the merged set a
// verifier needs for the §7.4 step-3 ordering — not the single winner an
// IterativeGet would settle for.
func TestCollectClaimsMergesCompetingClaims(t *testing.T) {
	a, b, c := contestedTriangle(t)
	defer a.Close()
	defer b.Close()
	defer c.Close()

	const alias = "contestme"
	ts := uint64(time.Now().Unix())
	env1, kClaim := contestedClaimEnv(t, alias, ts) // earlier ts
	env2, _ := contestedClaimEnv(t, alias, ts+1)    // later ts
	now := time.Now().Unix()
	if ok, err := a.store.Put(kClaim, env1, now, true); err != nil || !ok {
		t.Fatalf("seed A at K_claim: ok=%v err=%v", ok, err)
	}
	if ok, err := b.store.Put(kClaim, env2, now, true); err != nil || !ok {
		t.Fatalf("seed B at K_claim: ok=%v err=%v", ok, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	set, err := c.CollectClaims(ctx, alias)
	if err != nil {
		t.Fatalf("CollectClaims: %v", err)
	}
	if len(set) != 2 {
		t.Fatalf("CollectClaims returned %d envelopes, want 2 (both competing claims)", len(set))
	}
	h1, _ := env1.RecordHash()
	h2, _ := env2.RecordHash()
	seen := map[string]bool{}
	for _, env := range set {
		h, err := env.RecordHash()
		if err != nil {
			t.Fatalf("RecordHash: %v", err)
		}
		seen[string(h)] = true
	}
	if !seen[string(h1)] || !seen[string(h2)] {
		t.Errorf("collected set is missing a competitor: has claim1=%v claim2=%v", seen[string(h1)], seen[string(h2)])
	}
}

// TestCollectClaimsIncludesLocalCopyAndDedupes: the collecting node's own
// store copy joins the merge (§7.4 "all competing claims nodes offer" — this
// node is one of the nodes), and an H_record-identical copy offered by both
// the local store and a peer counts once.
func TestCollectClaimsIncludesLocalCopyAndDedupes(t *testing.T) {
	a, b, c := contestedTriangle(t)
	defer a.Close()
	defer b.Close()
	defer c.Close()

	const alias = "localfoo"
	ts := uint64(time.Now().Unix())
	env1, kClaim := contestedClaimEnv(t, alias, ts)
	env2, _ := contestedClaimEnv(t, alias, ts+1)
	now := time.Now().Unix()
	// A and C hold the SAME envelope (dedupe must collapse them); B holds the
	// competitor.
	for _, n := range []*Node{a, c} {
		if ok, err := n.store.Put(kClaim, env1, now, true); err != nil || !ok {
			t.Fatalf("seed node at K_claim: ok=%v err=%v", ok, err)
		}
	}
	if ok, err := b.store.Put(kClaim, env2, now, true); err != nil || !ok {
		t.Fatalf("seed B at K_claim: ok=%v err=%v", ok, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	set, err := c.CollectClaims(ctx, alias)
	if err != nil {
		t.Fatalf("CollectClaims: %v", err)
	}
	if len(set) != 2 {
		t.Fatalf("CollectClaims returned %d envelopes, want 2 (local copy deduped against A's identical offer, plus B's competitor)", len(set))
	}
	h1, _ := env1.RecordHash()
	h2, _ := env2.RecordHash()
	for _, env := range set {
		h, _ := env.RecordHash()
		if !bytes.Equal(h, h1) && !bytes.Equal(h, h2) {
			t.Errorf("unexpected envelope in collected set (H_record mismatch)")
		}
	}

	// C alone with its local copy (peers gone) still sees the one-claim set:
	// the local store's offer survives the death of every other node.
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	set2, err := c.CollectClaims(ctx, alias)
	if err != nil {
		t.Fatalf("CollectClaims (local only): %v", err)
	}
	if len(set2) != 1 {
		t.Fatalf("CollectClaims (local only) returned %d envelopes, want 1", len(set2))
	}
	if h, _ := set2[0].RecordHash(); !bytes.Equal(h, h1) {
		t.Error("local-only collection returned the wrong envelope")
	}
}

// TestCollectClaimsUnknownAlias: with no claim anywhere on the network (and
// nothing local), the set is empty — (nil/empty, nil), not an error — so the
// resolver treats it as "no claim on the network".
func TestCollectClaimsUnknownAlias(t *testing.T) {
	a, b, c := contestedTriangle(t)
	defer a.Close()
	defer b.Close()
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	set, err := c.CollectClaims(ctx, "no-such-claim-anywhere")
	if err != nil {
		t.Fatalf("CollectClaims(unknown): %v", err)
	}
	if len(set) != 0 {
		t.Fatalf("CollectClaims(unknown) returned %d envelopes, want 0", len(set))
	}
}

// TestDHTLookupCollectClaimsLocalFirst: DHTLookup.CollectClaims (the
// ClaimSetResolver) merges the local K_claim envelope with the
// network-collected set — on a total network miss the local copy is still
// returned. The collected competitors are deliberately NOT cached back into
// the single-slot store: a cache-back Put at equal sequence resolves by the
// H_record tie-break and would DISPLACE a storer's own offer, collapsing the
// network-wide set (§7.4 "storing nodes keep the top 2"; verified live on a
// two-node split). See DHTLookup.CollectClaims' doc comment.
func TestDHTLookupCollectClaimsLocalFirst(t *testing.T) {
	a, b, c := contestedTriangle(t)
	defer a.Close()
	defer b.Close()
	defer c.Close()

	const alias = "lookupfoo"
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

	// Regression (live-verified bug): a collector must not write the merged
	// set into its own single-slot store — otherwise the H_record tie-break
	// displaces a storer's own offer and the split collapses network-wide.
	if _, err := a.store.Get(kClaim, now); err != nil {
		t.Fatal(err)
	}
	h1, _ := env1.RecordHash()
	if got, _ := a.store.Get(kClaim, now); got == nil {
		t.Fatal("A's own K_claim offer vanished after a third party collected")
	} else {
		gh, _ := got.RecordHash()
		if !bytes.Equal(gh, h1) {
			t.Error("A's K_claim offer was displaced by collection — the contested set collapsed")
		}
	}

	// Node-less DHTLookup degrades to the local store only (still a valid
	// ClaimSetResolver for an island).
	island := NewDHTLookup(c.store, nil)
	set2, err := island.CollectClaims(ctx, alias, now)
	if err != nil {
		t.Fatalf("island CollectClaims: %v", err)
	}
	if len(set2) != 1 {
		t.Fatalf("island CollectClaims returned %d envelopes, want 1 (local store only)", len(set2))
	}
}

// TestStorageKeysClaimDualHoming pins the -load seeding rule: a claim-bearing
// TLD envelope lives at BOTH K_tld and K_claim (§7.4/C.1), so StorageKeys must
// return both — otherwise a daemon restart loses K_claim and every alias
// registered before the restart stops resolving (the PersistTo files are keyed
// by storage key, but the seeder derives keys from the record NAME).
func TestStorageKeysClaimDualHoming(t *testing.T) {
	env, kClaim := contestedClaimEnv(t, "dualhome", uint64(time.Now().Unix()))
	keys, err := StorageKeys(env)
	if err != nil {
		t.Fatalf("StorageKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("claim-bearing envelope must home at 2 keys, got %d", len(keys))
	}
	found := map[string]bool{}
	for _, k := range keys {
		found[string(k)] = true
	}
	if !found[string(kClaim)] {
		t.Error("K_claim missing from StorageKeys for a claim-bearing envelope")
	}
	// The name-derived key (K_tld for a TLD root) must also be present.
	nameKey, err := KeyForWireName(env.Record.Name)
	if err != nil {
		t.Fatal(err)
	}
	if !found[string(nameKey)] {
		t.Error("K_tld missing from StorageKeys for a TLD-root envelope")
	}
}

// TestStorageKeysPlainSingleHoming: a non-claim envelope homes at exactly its
// name-derived key.
func TestStorageKeysPlainSingleHoming(t *testing.T) {
	kp, _ := crypto.Generate()
	tid, err := crypto.TldID(kp.Public())
	if err != nil {
		t.Fatal(err)
	}
	wn, err := naming.EncodeWireName([]string{"www"}, "plainfoo", tid)
	if err != nil {
		t.Fatal(err)
	}
	now := uint64(time.Now().Unix())
	rec, err := wire.NewRecord(wn, kp.Public(), 1, now, now+3600)
	if err != nil {
		t.Fatal(err)
	}
	env, err := wire.SignRecord(rec, kp)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := StorageKeys(env)
	if err != nil {
		t.Fatalf("StorageKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("plain envelope must home at 1 key, got %d", len(keys))
	}
}
