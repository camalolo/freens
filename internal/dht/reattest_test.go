package dht

// reattest_test.go — the §8.3 re-attestation machinery (v2 renewal
// amendment): the witness RPC's re-attest mode (eligibility: identity held
// here, holding period met, no live conflict), the pool's identity firstSeen
// tracking across renewal generations and restarts, the persist/reload
// round trip, and the collect-path merge into DHTLookup.ReAttestSets.

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/claims"
	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
)

// poolLiveClaim offers a LIVE claim envelope for alias into p with a
// caller-chosen firstSeen stamp (the §7.3 holding-period anchor), returning
// the claim and its identity prefix hash.
func poolLiveClaim(t *testing.T, p *ClaimPool, alias string, now, firstSeen int64) (*claims.AliasClaim, []byte) {
	t.Helper()
	env, claim, _ := tombstoneFixture(t, alias, uint64(now-3600), now-3600, now+80000, true, false)
	kClaim, err := KeyForClaim(alias)
	if err != nil {
		t.Fatal(err)
	}
	if !p.OfferSeen(kClaim, env, now, firstSeen) {
		t.Fatal("fixture: live claim not pooled")
	}
	ph, err := claim.PrefixHash()
	if err != nil {
		t.Fatal(err)
	}
	return claim, ph
}

func mustKeyClaim(t *testing.T, alias string) []byte {
	t.Helper()
	k, err := KeyForClaim(alias)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestPoolIdentityFirstSeen: the stamp is set at first sight of the identity
// and SURVIVES generational replacement (renewals re-carrier the same claim
// in a new envelope) — the holding period must not re-arm per renewal.
func TestPoolIdentityFirstSeen(t *testing.T) {
	now := time.Now().Unix()
	alias := "firstseenfoo"
	p := NewClaimPool()

	claim, ph := poolLiveClaim(t, p, alias, now, now-2*int64(constants.ReAttestHold))
	phHex := hex.EncodeToString(ph)
	kClaim, _ := KeyForClaim(alias)

	fs, ok := p.IdentityFirstSeen(kClaim, phHex)
	if !ok || fs != now-2*int64(constants.ReAttestHold) {
		t.Fatalf("firstSeen = %d, %v; want the caller stamp", fs, ok)
	}

	// A renewal generation: same identity, different envelope. The stamp
	// must NOT move.
	renewed, _, _ := tombstoneFixture(t, alias, claim.Timestamp, now-10, now+86000, true, false)
	p.OfferSeen(kClaim, renewed, now+10, 0)
	fs2, _ := p.IdentityFirstSeen(kClaim, phHex)
	if fs2 != now-2*int64(constants.ReAttestHold) {
		t.Fatalf("firstSeen moved on renewal: %d — the stamp is per claim identity, not per envelope", fs2)
	}

	// Holding period reads from the ORIGINAL stamp: held 2×ReAttestHold is
	// eligible; a freshly-pooled identity is not.
	if !p.ReAttestEligible(kClaim, phHex, now) {
		t.Error("identity held two hold-windows: want eligible")
	}
	_, youngPh := poolLiveClaim(t, p, "firstseenyoung", now, now)
	if p.ReAttestEligible(mustKeyClaim(t, "firstseenyoung"), hex.EncodeToString(youngPh), now) {
		t.Error("freshly-pooled identity eligible — the holding period never engaged")
	}
}

// TestPoolReAttestPersistRoundTrip: stored evidence and the holding stamp
// survive a persist/reload cycle, stay bounded per identity, and re-verify
// on load (a hand-edited meta file must not manufacture evidence).
func TestPoolReAttestPersistRoundTrip(t *testing.T) {
	now := time.Now().Unix()
	alias := "reattmeta"
	dir := t.TempDir()
	p := NewClaimPool()
	kClaim := mustKeyClaim(t, alias)

	_, ph := poolLiveClaim(t, p, alias, now, now-90000)
	phHex := hex.EncodeToString(ph)

	// Stuff the store past the per-identity bound: only the newest
	// reAttestMaxSets survive.
	for i := 0; i < reAttestMaxSets+4; i++ {
		kp, err := crypto.Generate()
		if err != nil {
			t.Fatal(err)
		}
		att, err := claims.NewWitnessAttestation(kp, uint64(now-int64(i)), ph)
		if err != nil {
			t.Fatal(err)
		}
		p.StoreReAttests(kClaim, phHex, []*claims.WitnessAttestation{att})
	}
	if got := len(p.ReAttestsOf(kClaim, phHex)); got != reAttestMaxSets {
		t.Fatalf("stored = %d, want the bound %d", got, reAttestMaxSets)
	}

	if _, err := p.PersistClaimPoolTo(dir, now); err != nil {
		t.Fatalf("persist: %v", err)
	}

	p2 := NewClaimPool()
	if _, err := p2.RetainClaimPool(dir, now); err != nil {
		t.Fatalf("retain: %v", err)
	}
	if !p2.ReAttestEligible(kClaim, phHex, now) {
		t.Error("holding period did not survive the restart")
	}
	got := p2.ReAttestsOf(kClaim, phHex)
	if len(got) != reAttestMaxSets {
		t.Fatalf("re-attests after reload = %d, want %d", len(got), reAttestMaxSets)
	}
	for _, a := range got {
		if !a.Verify(ph) {
			t.Error("reloaded attestation failed signature verification")
		}
	}
}

// TestWitnessReAttestEligibility (wire level): the full §8.3 matrix on a
// real two-node harness —
//   - a witness holding the identity past the holding period re-attests
//     (NOW-dated attestation, stored in its pool);
//   - a witness whose holding period is not met refuses;
//   - a witness NOT holding the identity refuses;
//   - a witness holding a live CONFLICTING identity refuses (a disputed
//     alias gets re-attested for NEITHER side).
func TestWitnessReAttestEligibility(t *testing.T) {
	now := time.Now().Unix()
	alias := "reattfoo"

	w, _ := startTestNode(t, nil)
	defer w.Close()
	a, _ := startTestNode(t, nil)
	defer a.Close()
	wAddr, err := w.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.AddPeer(w.PublicKey(), wAddr.String()); err != nil {
		t.Fatal(err)
	}

	// Happy path: pooled longer than the holding period.
	claim, ph := poolLiveClaim(t, w.claims, alias, now, now-int64(constants.ReAttestHold)-60)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	atts, err := a.CollectReAttests(ctx, alias, claim, constants.WitnessSet)
	if err != nil {
		t.Fatalf("CollectReAttests: %v", err)
	}
	if len(atts) != 1 {
		t.Fatalf("re-attest haul = %d, want 1", len(atts))
	}
	if !atts[0].Verify(ph) {
		t.Error("re-attestation does not verify against the claim identity")
	}
	if int64(atts[0].TS) < now-60 {
		t.Errorf("re-attestation dated %d, want ~now (%d)", atts[0].TS, now)
	}
	if got := w.claims.ReAttestsOf(mustKeyClaim(t, alias), hex.EncodeToString(ph)); len(got) != 1 {
		t.Fatalf("witness pool kept %d re-attests, want 1", len(got))
	}

	// Holding period not met: refused.
	alias2 := "reattyoung"
	youngClaim, _ := poolLiveClaim(t, w.claims, alias2, now, now)
	atts, err = a.CollectReAttests(ctx, alias2, youngClaim, constants.WitnessSet)
	if err != nil || len(atts) != 0 {
		t.Fatalf("young-holding re-attest: atts=%d err=%v, want 0/nil", len(atts), err)
	}

	// Identity not held here: refused (a fully-valid claim the witness
	// simply does not pool).
	_, ghostClaim, _ := tombstoneFixture(t, "reattghost", uint64(now-3600), now-3600, now+80000, true, false)
	atts, err = a.CollectReAttests(ctx, "reattghost", ghostClaim, constants.WitnessSet)
	if err != nil || len(atts) != 0 {
		t.Fatalf("not-held re-attest: atts=%d err=%v, want 0/nil", len(atts), err)
	}

	// Live conflicting identity: the alias is disputed — NEITHER side is
	// re-attested (exclusivity on the re-attest channel).
	alias3 := "reattconflict"
	conflictClaim, _ := poolLiveClaim(t, w.claims, alias3, now, now-int64(constants.ReAttestHold)-60)
	other, _, _ := tombstoneFixture(t, alias3, uint64(now-10), now-10, now+86000, true, false)
	if !w.claims.Offer(mustKeyClaim(t, alias3), other) {
		t.Fatal("fixture: conflicting claim not pooled")
	}
	atts, err = a.CollectReAttests(ctx, alias3, conflictClaim, constants.WitnessSet)
	if err != nil || len(atts) != 0 {
		t.Fatalf("disputed alias re-attest: atts=%d err=%v, want 0/nil", len(atts), err)
	}
}

// TestHGetServesReAttestsAndCollectMerges: the full evidence path — the
// re-attesting witness serves its stored set at hGet; a collector's walk
// merges it into its own pool, and DHTLookup.ReAttestSets surfaces it for
// the resolver.
func TestHGetServesReAttestsAndCollectMerges(t *testing.T) {
	now := time.Now().Unix()
	alias := "reattget"

	w, _ := startTestNode(t, nil)
	defer w.Close()
	c, _ := startTestNode(t, nil)
	defer c.Close()
	wAddr, err := w.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AddPeer(w.PublicKey(), wAddr.String()); err != nil {
		t.Fatal(err)
	}

	claim, ph := poolLiveClaim(t, w.claims, alias, now, now-int64(constants.ReAttestHold)-60)
	phHex := hex.EncodeToString(ph)

	// The witness re-attests its holding (the same RPC the owner's renewal
	// drives — driven through c, the node with reach) and keeps the
	// attestation in its own pool.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if atts, err := c.CollectReAttests(ctx, alias, claim, constants.WitnessSet); err != nil || len(atts) == 0 {
		t.Fatalf("re-attest through the reachable node: %d atts, err=%v", len(atts), err)
	}

	// A third node collects through the witness: envelopes AND re-attests
	// arrive; ReAttestSets surfaces the evidence for the resolver.
	lookup := NewDHTLookup(c.store, c)
	envs, _, err := lookup.CollectClaimsWithWitnesses(ctx, alias, now)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(envs) == 0 {
		t.Fatal("collect gathered no envelopes from the holding witness")
	}
	sets, err := lookup.ReAttestSets(ctx, alias, now)
	if err != nil {
		t.Fatalf("ReAttestSets: %v", err)
	}
	atts := sets[phHex]
	if len(atts) != 1 {
		t.Fatalf("ReAttestSets[%s] = %d attestations, want 1", phHex, len(atts))
	}
	if !atts[0].Verify(ph) {
		t.Error("merged re-attestation does not verify")
	}
	// And freshness filtering (the resolver's job) accepts it: quorum of 1
	// with a nil set (sparse view) — HasFreshQuorum semantics.
	if !claims.HasFreshQuorum(atts, ph, now, int64(constants.ReAttestFresh), nil, 1) {
		t.Error("fresh quorum of 1 not recognized")
	}
}
