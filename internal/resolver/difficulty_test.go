// difficulty_test.go — the Appendix A.4 verifier-side difficulty floor (spec
// lines 995-1008): "Nodes gossip the current D in witness responses; clients
// use the median of the GET_CLOSEST nodes' advertised values ... claims are
// individually verified against any historically valid D >= POW_DIFFICULTY_INIT
// recorded with the claim (pow_bits SHOULD be recorded in nonce's first
// byte)". A source implementing DifficultyOracle floors the §7.4 step-2 PoW
// check at its gossiped median; a source without it keeps the exact legacy
// claims.InferDifficulty behavior.
//
// The fake oracles here report PROTOCOL-scale gossip values exactly as
// dht.DHTLookup.NetworkDifficulty does (anchored at
// constants.PoWDifficultyInit = 24), while the claims are mined in the test
// scale (withFastPoW lowers claims.PoWDifficultyInit to 8). The resolver
// translates the floor into the verifier's baseline, so the production
// matrix runs verbatim: gossip 24 ≡ floor 8, gossip 26 ≡ floor 10 — a
// difficulty-8 claim is rejected once the network retargets 24 → 26 and a
// re-mined difficulty-10 claim is accepted, without paying for real 24/26-bit
// mining. TestEffectivePoWDifficulty additionally pins the pure helper at the
// production constants directly.
package resolver

import (
	"testing"

	"github.com/camalolo/freens/internal/claims"
	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/wire"
	"github.com/miekg/dns"
)

// fakeOracle is a RecordLookup + ClaimResolver + DifficultyOracle: the §9.2
// step-3a single-claim source with a fixed gossiped network difficulty.
type fakeOracle struct {
	fakeClaimLookup
	diff int
}

func (o *fakeOracle) NetworkDifficulty() int { return o.diff }

// fakeSetOracle is the ClaimSetResolver flavor of the same, so the §7.4
// set path's per-claim filter is covered too.
type fakeSetOracle struct {
	fakeClaimSetLookup
	diff int
}

func (o *fakeSetOracle) NetworkDifficulty() int { return o.diff }

// buildClaimWorldAt is buildClaimedWorldOnce with the mining difficulty as a
// parameter: a mined + W-witnessed claim embedded in a self-certifying TLD
// record, plus the www A record. difficulty must be >= claims.PoWDifficultyInit
// so the A.4 inference (nonce[0]) picks it up.
func buildClaimWorldAt(t *testing.T, alias string, difficulty int) (tldEnv, wwwEnv *wire.SignedEnvelope) {
	t.Helper()
	return buildClaimWorldBelow(t, alias, difficulty, 1<<30)
}

// buildClaimWorldBelow is buildClaimWorldAt with a strict PoW ceiling: mining
// retries until the claim's hash meets `difficulty` bits but NOT `ceiling`
// bits. Mining stops at the FIRST hash clearing `difficulty`, and such a hash
// clears two more bits ~25% of the time — without the ceiling, a "rejected at
// floor difficulty+2" assertion would be flaky (the below-floor claim would
// luck through the stricter check). Each draw costs ~2^difficulty hashes, so
// the expected ~1.3 attempts are instant.
func buildClaimWorldBelow(t *testing.T, alias string, difficulty, ceiling int) (tldEnv, wwwEnv *wire.SignedEnvelope) {
	t.Helper()
	withFastPoW(t)

	claimant, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	tldID, err := crypto.TldID(claimant.Public())
	if err != nil {
		t.Fatal(err)
	}
	const claimTS = uint64(fixedNow - 50)

	var claim *claims.AliasClaim
	for attempt := 0; ; attempt++ {
		claim, err = claims.MineAliasClaim(alias, claimant, claimTS, difficulty, 2_000_000, 16)
		if err != nil {
			t.Fatalf("MineAliasClaim(difficulty %d): %v", difficulty, err)
		}
		if !crypto.MeetsDifficulty(claim.PowHash, ceiling) {
			break // strictly below the ceiling: a check at `ceiling` must fail
		}
		if attempt >= 500 {
			t.Fatalf("fixture: could not mine below %d bits at difficulty %d in 500 attempts", ceiling, difficulty)
		}
	}
	ph, err := claim.PrefixHash()
	if err != nil {
		t.Fatal(err)
	}
	witnesses := make([]*claims.WitnessAttestation, 0, constants.W)
	for i := 0; i < constants.W; i++ {
		wkp, err := crypto.Generate()
		if err != nil {
			t.Fatal(err)
		}
		att, err := claims.NewWitnessAttestation(wkp, claimTS+uint64(i), ph)
		if err != nil {
			t.Fatalf("NewWitnessAttestation: %v", err)
		}
		witnesses = append(witnesses, att)
	}
	claim.Witnesses = witnesses
	if !claims.VerifyFull(claim, difficulty, nil, constants.W) {
		t.Fatalf("fixture: claim does not pass VerifyFull at difficulty %d", difficulty)
	}

	tldWire, err := naming.EncodeWireName(nil, alias, tldID)
	if err != nil {
		t.Fatal(err)
	}
	tldRec, err := wire.NewRecord(tldWire, claimant.Public(), 1, uint64(fixedNow-100), uint64(fixedNow+3600))
	if err != nil {
		t.Fatal(err)
	}
	cb, err := claim.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	tldRec.Claim = cb
	tldEnv, err = wire.SignRecord(tldRec, claimant)
	if err != nil {
		t.Fatal(err)
	}

	wwwWire, err := naming.EncodeWireName([]string{"www"}, alias, tldID)
	if err != nil {
		t.Fatal(err)
	}
	wwwRec, err := wire.NewRecord(wwwWire, claimant.Public(), 1, uint64(fixedNow-100), uint64(fixedNow+3600))
	if err != nil {
		t.Fatal(err)
	}
	aRR, err := wire.A([]byte{203, 0, 113, 77}, 600)
	if err != nil {
		t.Fatal(err)
	}
	wwwRec.RRset = []*wire.RR{aRR}
	wwwEnv, err = wire.SignRecord(wwwRec, claimant)
	if err != nil {
		t.Fatal(err)
	}
	return tldEnv, wwwEnv
}

// TestDifficultyOracleFloorLetsEqualDifficultyPass: a claim mined at the
// oracle's exact floor verifies (the A.4 happy path — the network floor
// equals the difficulty recorded in nonce[0]). Gossip 24 is floor 8 in the
// test scale.
func TestDifficultyOracleFloorLetsEqualDifficultyPass(t *testing.T) {
	tldEnv, wwwEnv := buildClaimWorldAt(t, "footld", 8)
	lookup := &fakeOracle{fakeClaimLookup: *newFakeClaimLookup(), diff: 24}
	lookup.putClaim("footld", tldEnv)
	lookup.put(wwwEnv)

	rrs, rcode, err := resolveFootld(t, lookup)
	if err != nil {
		t.Fatalf("ResolveQuestion: unexpected err: %v", err)
	}
	if rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR(%d): gossip 24 must accept a difficulty-8 claim", rcode, dns.RcodeSuccess)
	}
	if len(rrs) != 1 {
		t.Fatalf("len(rrs) = %d, want 1", len(rrs))
	}
}

// TestDifficultyOracleFloorRejectsThenRemineAccepts is the required floor
// matrix: a claim mined at the floor REJECTS once the network retargets two
// bits higher (24 → 26; the nonce-recorded difficulty no longer meets the
// gossiped median), and re-mining at the new floor is accepted.
func TestDifficultyOracleFloorRejectsThenRemineAccepts(t *testing.T) {
	// Claim mined at 8 with its hash strictly below 10 bits, gossip 26
	// (floor 10 in the test scale) → effective 10 → PoW fails → NXDOMAIN.
	loTld, loWww := buildClaimWorldBelow(t, "footld", 8, 10)
	lookup := &fakeOracle{fakeClaimLookup: *newFakeClaimLookup(), diff: 26}
	lookup.putClaim("footld", loTld)
	lookup.put(loWww)

	rrs, rcode, err := resolveFootld(t, lookup)
	if err != nil {
		t.Fatalf("ResolveQuestion: unexpected err: %v", err)
	}
	if rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %d, want NXDOMAIN(%d): gossip 26 must reject a difficulty-8 claim", rcode, dns.RcodeNameError)
	}
	if len(rrs) != 0 {
		t.Errorf("len(rrs) = %d, want 0", len(rrs))
	}

	// Re-mine at 10 with the network still at 26 → accepted.
	hiTld, hiWww := buildClaimWorldAt(t, "footld", 10)
	lookup2 := &fakeOracle{fakeClaimLookup: *newFakeClaimLookup(), diff: 26}
	lookup2.putClaim("footld", hiTld)
	lookup2.put(hiWww)

	rrs2, rcode2, err := resolveFootld(t, lookup2)
	if err != nil {
		t.Fatalf("ResolveQuestion (re-mined): unexpected err: %v", err)
	}
	if rcode2 != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR(%d): gossip 26 must accept a difficulty-10 claim", rcode2, dns.RcodeSuccess)
	}
	if len(rrs2) != 1 {
		t.Fatalf("len(rrs) = %d, want 1", len(rrs2))
	}
}

// TestDifficultyOracleFloorBelowRecordedDifficulty: the floor can only RAISE
// the check. A claim that recorded a HIGHER difficulty than the oracle's
// floor is verified at its own recorded difficulty (A.4: "any historically
// valid D >= POW_DIFFICULTY_INIT recorded with the claim"), never downgraded
// to the floor.
func TestDifficultyOracleFloorBelowRecordedDifficulty(t *testing.T) {
	tldEnv, wwwEnv := buildClaimWorldAt(t, "footld", 10)
	lookup := &fakeOracle{fakeClaimLookup: *newFakeClaimLookup(), diff: 24} // floor 8
	lookup.putClaim("footld", tldEnv)
	lookup.put(wwwEnv)

	rrs, rcode, err := resolveFootld(t, lookup)
	if err != nil {
		t.Fatalf("ResolveQuestion: unexpected err: %v", err)
	}
	if rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR(%d): a difficulty-10 claim passes gossip 24", rcode, dns.RcodeSuccess)
	}
	if len(rrs) != 1 {
		t.Fatalf("len(rrs) = %d, want 1", len(rrs))
	}
}

// TestDifficultyNoOracleKeepsLegacyBehavior: a claim source WITHOUT
// DifficultyOracle keeps the exact legacy verification — the difficulty is
// inferred from nonce[0] alone (Appendix A.4's recorded pow_bits), with no
// network floor. A difficulty-8 claim resolves as before.
func TestDifficultyNoOracleKeepsLegacyBehavior(t *testing.T) {
	tldEnv, wwwEnv := buildClaimWorldAt(t, "footld", 8)
	lookup := newFakeClaimLookup() // Lookup + LookupClaim only — no oracle
	lookup.putClaim("footld", tldEnv)
	lookup.put(wwwEnv)

	rrs, rcode, err := resolveFootld(t, lookup)
	if err != nil {
		t.Fatalf("ResolveQuestion: unexpected err: %v", err)
	}
	if rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR(%d): legacy path must keep accepting", rcode, dns.RcodeSuccess)
	}
	if len(rrs) != 1 {
		t.Fatalf("len(rrs) = %d, want 1", len(rrs))
	}
}

// TestDifficultySetPathFloorRejectsBelowFloor: the §7.4 SET path
// (ClaimSetResolver + resolveClaimSet) shares verifyClaimEnvelope, so the
// floor applies there identically — a below-floor claim drops out of the
// filter and the alias misses.
func TestDifficultySetPathFloorRejectsBelowFloor(t *testing.T) {
	tldEnv, wwwEnv := buildClaimWorldBelow(t, "footld", 8, 10)
	lookup := &fakeSetOracle{
		fakeClaimSetLookup: fakeClaimSetLookup{fakeClaimLookup: *newFakeClaimLookup()},
		diff:               26, // floor 10 in the test scale
	}
	lookup.putClaim("footld", tldEnv)
	lookup.put(wwwEnv)
	lookup.set = []*wire.SignedEnvelope{tldEnv} // the §7.4 collected set

	rrs, rcode, err := resolveFootld(t, lookup)
	if err != nil {
		t.Fatalf("ResolveQuestion: unexpected err: %v", err)
	}
	if rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %d, want NXDOMAIN(%d): set path gossip 26 must reject a difficulty-8 claim", rcode, dns.RcodeNameError)
	}
	if len(rrs) != 0 {
		t.Errorf("len(rrs) = %d, want 0", len(rrs))
	}
}

// TestEffectivePoWDifficulty pins the pure helper at the PRODUCTION
// constants (claims.PoWDifficultyInit == constants.PoWDifficultyInit == 24,
// so the oracle-floor translation is the identity) — the 24/26 matrix of
// A.4 without paying for real 24/26-bit mining: only the computed difficulty
// is asserted, not a mined hash.
func TestEffectivePoWDifficulty(t *testing.T) {
	if int(claims.PoWDifficultyInit.Load()) != constants.PoWDifficultyInit {
		t.Skipf("claims.PoWDifficultyInit = %d (test downshift active); production matrix needs the default", claims.PoWDifficultyInit.Load())
	}
	claimAt := func(nonceByte int) *claims.AliasClaim {
		return &claims.AliasClaim{Nonce: []byte{byte(nonceByte), 1, 2, 3}}
	}
	floor := func(d int) DifficultyOracle { return fakeOracleValue{d} }

	cases := []struct {
		name   string
		claim  *claims.AliasClaim
		oracle DifficultyOracle
		want   int
	}{
		{"no oracle is the sentinel", claimAt(24), nil, claims.InferDifficulty},
		{"mined at 24, floor 24 → 24", claimAt(24), floor(24), 24},
		{"mined at 24, floor 26 → 26 (the retarget rejection)", claimAt(24), floor(26), 26},
		{"mined at 26, floor 24 → 26 (floor only raises)", claimAt(26), floor(24), 26},
		{"mined at 30, floor 26 → 30", claimAt(30), floor(26), 30},
		{"nonce[0] below init infers the init", claimAt(3), floor(24), 24},
		{"oracle below init is clamped to init", claimAt(24), floor(9), 24},
		{"empty nonce infers the init", &claims.AliasClaim{}, floor(24), 24},
		{"nil claim infers the init", nil, floor(24), 24},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := effectivePoWDifficulty(tc.claim, tc.oracle)
			if got != tc.want {
				t.Errorf("effectivePoWDifficulty(claim %v, oracle %v) = %d, want %d",
					tc.claim, tc.oracle, got, tc.want)
			}
		})
	}
}

// fakeOracleValue is a minimal DifficultyOracle for the pure-helper test.
type fakeOracleValue struct{ d int }

func (f fakeOracleValue) NetworkDifficulty() int { return f.d }
