package resolver

// backdate_test.go — the v0.7.0 backdating regression (the §7.4 alias-theft
// hole, found by the external security review): the §7.4 step-3 order is
// (timestamp, pow_hash, tld_id) ASCENDING on the CLAIMANT-asserted
// timestamp, so a claim re-mined with an artificially old timestamp
// out-orders every honest claim — UNLESS the witness layer refuses to
// corroborate it. Three defenses, tested end-to-end through the real
// resolveClaimSet path (the same one the daemon's resolver runs):
//
//  1. the corroboration band: modern-dated attestations (fabricated or
//     honestly gathered for a fresh claim — the transplant variant) do not
//     count toward a backdated claim's quorum;
//  2. WITNESS_SET membership WITHIN THE CONTEST WINDOW (v0.14.1 horizon):
//     a fully self-consistent fabricated quorum (own keys, in-band
//     backdated clocks) fails while the claim is young — the window where
//     it could displace a LIVE registration — when the collecting walk can
//     name the converged witness set. Past CONTEST_WINDOW the claim is
//     FINAL per §7.5(b) and membership is no longer re-litigated: the
//     pre-v0.14.1 behavior let routing-table churn kill every mature name
//     whose registration-time witnesses had moved on or departed (found
//     live fleet-wide 2026-09-01: the seed NXDOMAINed every name it had
//     itself witnessed);
//  3. the honest path keeps working: a fresh claim, in-band attestations
//     from the named set, resolves NOERROR — and so does a MATURE claim
//     whose witnesses have churned out of the verifier's view (the
//     v0.14.1 availability regression).
//
// The residuals are asserted LAST and documented: (a) a sparse view (nil
// set) cannot name a witness set — the protocol's Sybil bound (§12);
// (b) a MATURE self-consistent fabricated quorum now passes because
// membership has a horizon. Both are the priced-by-grinding §12 bound, not
// bugs; re-tightening either must update the changelog and this file
// together.

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/camalolo/freens/internal/claims"
	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/wire"
)

// bdWorld assembles one claimed world: claimant keypair, mined claim at
// claimTS with n witness attestations dated attTS (all sharing the same
// clock, in or out of band by construction), TLD-root carrier record.
func bdWorld(t *testing.T, alias string, claimTS, attTS uint64, n int) (*claims.AliasClaim, *wire.SignedEnvelope, *crypto.Keypair) {
	t.Helper()
	withFastPoW(t)
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	claim, err := claims.MineAliasClaim(alias, kp, claimTS, 8, 2_000_000, 16)
	if err != nil {
		t.Fatalf("MineAliasClaim: %v", err)
	}
	ph, err := claim.PrefixHash()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		wkp, err := crypto.Generate()
		if err != nil {
			t.Fatal(err)
		}
		att, err := claims.NewWitnessAttestation(wkp, attTS+uint64(i), ph)
		if err != nil {
			t.Fatalf("NewWitnessAttestation: %v", err)
		}
		claim.Witnesses = append(claim.Witnesses, att)
	}
	// The CARRIER record is fresh regardless of the claim's backdating:
	// an attacker publishes today; only the CLAIM identity (field 11)
	// carries the old timestamp. Expires comfortably past fixedNow so the
	// IsBasicValid window cannot mask the assertions.
	wn, err := naming.EncodeWireName(nil, alias, claim.TldID)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := wire.NewRecord(wn, kp.Public(), 1, uint64(fixedNow)-3600, uint64(fixedNow)+30*86400)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := claim.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	rec.Claim = cb
	env, err := wire.SignRecord(rec, kp)
	if err != nil {
		t.Fatal(err)
	}
	return claim, env, kp
}

// bdSetSource is a ClaimSetWithWitnesses fake: fixed envelopes + a fixed
// witness set (nil = sparse view).
type bdSetSource struct {
	envs  []*wire.SignedEnvelope
	set   map[string]bool
	inner RecordLookup // the chain walk after alias resolution (unused here)
}

func (s *bdSetSource) CollectClaimsWithWitnesses(_ context.Context, _ string, _ int64) ([]*wire.SignedEnvelope, map[string]bool, error) {
	return s.envs, s.set, nil
}

// CollectClaims satisfies the base ClaimSetResolver too (resolveClaimSet's
// interface preference order must find the with-witnesses form, and tests
// that assert "nil" need the nil to come from the FILTER, not from a failed
// type assertion).
func (s *bdSetSource) CollectClaims(ctx context.Context, alias string, now int64) ([]*wire.SignedEnvelope, error) {
	envs, _, err := s.CollectClaimsWithWitnesses(ctx, alias, now)
	return envs, err
}

func (s *bdSetSource) Lookup(ctx context.Context, wireName []byte, now int64) (*wire.SignedEnvelope, error) {
	if s.inner == nil {
		return nil, nil
	}
	return s.inner.Lookup(ctx, wireName, now)
}

// bdResolve drives the §7 alias-claim layer (resolveAliasClaim) against a
// bdSetSource: the answer is the winning tld_id (nil = no valid claim) and
// the §7.5 contest flag. The chain walk that follows in production is not
// under test here.
func bdResolve(t *testing.T, src *bdSetSource, alias string) (tldID []byte, contested bool) {
	t.Helper()
	cfg, err := ParseConfig("[tld-routes]\n* = freens\n")
	if err != nil {
		t.Fatal(err)
	}
	r := New(cfg, src, nil)
	r.Now = func() int64 { return fixedNow }
	got, contested, _ := r.resolveAliasClaim(context.Background(), alias, fixedNow)
	return got, contested
}

// TestBackdatedModernDatedQuorumRejected: the ORIGINAL PoC shape — 45-day
// backdated claim, five fabricated witnesses dated NOW. Before v0.7.0 this
// passed the full resolver filter and won the ordering (alias theft at zero
// network presence). The corroboration band must drop every attestation.
func TestBackdatedModernDatedQuorumRejected(t *testing.T) {
	const alias = "bank"
	_, malloryEnv, _ := bdWorld(t, alias, uint64(fixedNow)-45*86400, uint64(fixedNow), constants.W)
	src := &bdSetSource{envs: []*wire.SignedEnvelope{malloryEnv}, set: nil}
	if got, _ := bdResolve(t, src, alias); got != nil {
		t.Fatal("VULNERABLE: backdated claim with modern-dated fabricated quorum resolved (corroboration band failed)")
	}
}

// TestBackdatedSelfConsistentQuorumRejectedByWitnessSet: the hardest variant
// — the attacker fabricates witnesses whose clocks are BACKDATED to match
// the claim (in-band), so only WITNESS_SET membership can refuse them. The
// claim is TWO HOURS old: inside CONTEST_WINDOW, so membership is enforced
// (and this is the case that matters — a young backdated claim displacing a
// live registration).
func TestBackdatedSelfConsistentQuorumRejectedByWitnessSet(t *testing.T) {
	const alias = "bank2"
	claimTS := uint64(fixedNow - 2*3600)
	_, malloryEnv, _ := bdWorld(t, alias, claimTS, claimTS, constants.W)

	// The converged witness set names 8 honest node IDs (hex form — the
	// claims.HasQuorum key format).
	set := make(map[string]bool, constants.WitnessSet)
	for i := 0; i < constants.WitnessSet; i++ {
		hkp, err := crypto.Generate()
		if err != nil {
			t.Fatal(err)
		}
		nid, err := crypto.NodeID(hkp.Public())
		if err != nil {
			t.Fatal(err)
		}
		set[hex.EncodeToString(nid)] = true
	}
	src := &bdSetSource{envs: []*wire.SignedEnvelope{malloryEnv}, set: set}
	if got, _ := bdResolve(t, src, alias); got != nil {
		t.Fatal("VULNERABLE: self-consistent fabricated quorum resolved against a named witness set (in-window claim)")
	}
}

// TestMatureClaimSurvivesChurnedWitnessSet: the v0.14.1 availability fix as
// a regression — an HONEST claim registered 15 days ago (attestations
// in-band at mining time, all verified signatures) must still resolve when
// the verifier's CURRENT witness set has churned away from the
// registration-time one (nodes departed, newer nodes shifted the keyspace
// boundary). Pre-horizon, this was fleet-wide NXDOMAIN for every mature
// name (the seed refused the very names it had witnessed).
func TestMatureClaimSurvivesChurnedWitnessSet(t *testing.T) {
	const alias = "mature"
	claimTS := uint64(fixedNow - 15*86400)
	claim, env, _ := bdWorld(t, alias, claimTS, claimTS, constants.W)

	// The converged set names a completely different keyspace neighborhood
	// (none of the claim's witnesses are members anymore).
	set := make(map[string]bool, constants.WitnessSet)
	for i := 0; i < constants.WitnessSet; i++ {
		hkp, err := crypto.Generate()
		if err != nil {
			t.Fatal(err)
		}
		nid, err := crypto.NodeID(hkp.Public())
		if err != nil {
			t.Fatal(err)
		}
		set[hex.EncodeToString(nid)] = true
	}
	src := &bdSetSource{envs: []*wire.SignedEnvelope{env}, set: set}
	got, contested := bdResolve(t, src, alias)
	if got == nil {
		t.Fatal("mature honest claim died to witness churn (the v0.14.0 fleet failure)")
	}
	if string(got) != string(claim.TldID) {
		t.Fatal("resolved tld_id does not match the honest claimant")
	}
	if contested {
		t.Error("a 15-day-old winning claim is past CONTEST_WINDOW: must be final, not contested")
	}
}

// TestBackdatedMatureFabricatedQuorumResidual: the MIRROR residual — the
// same horizon that saves mature honest claims also waves through a MATURE
// SELF-CONSISTENT fabricated quorum against a named set. This is the
// accepted price (documented, §12-priced): membership's anti-fabrication
// value is concentrated inside the contest window, where the previous test
// asserts it still bites. If a later change re-tightens mature-claim
// membership, this test and TestMatureClaimSurvivesChurnedWitnessSet must
// be reworked together — one gate cannot both open and close.
func TestBackdatedMatureFabricatedQuorumResidual(t *testing.T) {
	const alias = "bank4"
	claimTS := uint64(fixedNow - 200*86400)
	_, malloryEnv, _ := bdWorld(t, alias, claimTS, claimTS, constants.W)
	set := make(map[string]bool, constants.WitnessSet)
	for i := 0; i < constants.WitnessSet; i++ {
		hkp, err := crypto.Generate()
		if err != nil {
			t.Fatal(err)
		}
		nid, err := crypto.NodeID(hkp.Public())
		if err != nil {
			t.Fatal(err)
		}
		set[hex.EncodeToString(nid)] = true
	}
	src := &bdSetSource{envs: []*wire.SignedEnvelope{malloryEnv}, set: set}
	got, contested := bdResolve(t, src, alias)
	if got == nil {
		t.Fatal("horizon changed: a mature fabricated quorum is rejected again — rework this residual AND TestMatureClaimSurvivesChurnedWitnessSet together (one gate cannot both open and close)")
	}
	if contested {
		t.Error("a 200-day-old winning claim is past CONTEST_WINDOW: must be final, not contested")
	}
}

// TestHonestFreshClaimStillResolves: the honest flow — fresh claim, in-band
// attestations from the named witness set — keeps resolving (regression
// guard for the two defenses above).
func TestHonestFreshClaimStillResolves(t *testing.T) {
	const alias = "honest"
	now := uint64(fixedNow)
	claim, env, _ := bdWorld(t, alias, now, now, constants.W)
	set := make(map[string]bool, constants.WitnessSet)
	for _, w := range claim.Witnesses {
		set[hex.EncodeToString(w.NodeID)] = true
	}
	src := &bdSetSource{envs: []*wire.SignedEnvelope{env}, set: set}
	got, contested := bdResolve(t, src, alias)
	if got == nil {
		t.Fatal("honest fresh claim stopped resolving (over-tight filter)")
	}
	if string(got) != string(claim.TldID) {
		t.Fatal("resolved tld_id does not match the honest claimant")
	}
	if !contested {
		t.Error("a just-registered claim must be flagged contested (§7.5 window)")
	}
}

// TestBackdatedSparseViewResidualDocumentsSybilBound: with a SPARSE view
// (nil witness set — e.g. the 3-box beta fleet) a fully self-consistent
// fabricated quorum on a backdated claim still resolves, AS FINAL (the ts
// is older than CONTEST_WINDOW). This is the documented residual: defenses
// 1+2 raise the attack cost from zero to forging a Sybil quorum that
// survives §7.5 scrutiny; closing it fully requires a network large enough
// to always name the WITNESS_SET. The assertion is a TRIPWIRE: if a later
// hardening makes the nil-set path reject this, the test fails loudly and
// the changelog residual note must be updated together.
func TestBackdatedSparseViewResidualDocumentsSybilBound(t *testing.T) {
	const alias = "bank3"
	claimTS := uint64(fixedNow - 100*86400)
	claim, env, _ := bdWorld(t, alias, claimTS, claimTS, constants.W)
	src := &bdSetSource{envs: []*wire.SignedEnvelope{env}, set: nil}
	got, contested := bdResolve(t, src, alias)
	if got == nil {
		t.Fatal("nil-set residual changed: the sparse-view path now rejects self-consistent fabricated quorums — update this tripwire AND the v0.7.0 changelog residual note together")
	}
	if string(got) != string(claim.TldID) {
		t.Fatal("sparse-view resolution returned a foreign tld_id")
	}
	if contested {
		t.Error("a 100-day-old winning claim is past CONTEST_WINDOW: must be final, not contested")
	}
}
