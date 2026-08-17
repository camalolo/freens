package claims

// band_test.go — v0.7.0 corroboration-band and fabricated-quorum regressions
// for the §7.4 backdating hole. The ordering tuple is
// (timestamp, pow_hash, tld_id) on the CLAIMANT-asserted timestamp, so a
// claim re-mined with an old timestamp out-orders every honest claim unless
// the witness layer refuses to corroborate it. Three defenses are under
// test, in the order an attacker meets them:
//
//  1. v2 attestation binding (TestBandTransplantRejected): attestations
//     gathered for one claim identity do not Verify against a re-mined
//     backdated claim.
//  2. the corroboration band (TestCorroborationBandEdges): a VALID v2
//     attestation whose own timestamp is inconsistent with the claim's
//     asserted timestamp does not count toward the quorum — so modern-dated
//     attestations cannot corroborate an old-dated claim, and vice versa.
//  3. witness-set membership (TestWitnessSetMembershipDropsFabricatedKeys):
//     a self-consistent fabricated quorum (attacker-owned keys, in-band
//     timestamps) still fails HasQuorum when the verifier can name the true
//     WITNESS_SET.

import (
	"encoding/hex"
	"testing"

	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
)

// bandClaim mines a claim at difficulty 8 with n in-band fabricated v2
// attestations (witness TS = claim.TS + i, i < n — all inside the band).
func bandClaim(t *testing.T, alias string, ts uint64, n int) *AliasClaim {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	c, err := MineAliasClaim(alias, kp, ts, 8, 2_000_000, 16)
	if err != nil {
		t.Fatalf("MineAliasClaim: %v", err)
	}
	ph, err := c.PrefixHash()
	if err != nil {
		t.Fatalf("PrefixHash: %v", err)
	}
	for i := 0; i < n; i++ {
		wkp, err := crypto.Generate()
		if err != nil {
			t.Fatal(err)
		}
		w, err := NewWitnessAttestation(wkp, ts+uint64(i), ph)
		if err != nil {
			t.Fatalf("NewWitnessAttestation: %v", err)
		}
		c.Witnesses = append(c.Witnesses, w)
	}
	return c
}

// TestBandTransplantRejected: attestations obtained for a FRESH claim (the
// honest witness flow) must not verify against the SAME alias re-mined with
// a backdated timestamp — the v2 prefix-hash binding.
func TestBandTransplantRejected(t *testing.T) {
	now := uint64(1_700_000_000)
	fresh := bandClaim(t, "bank", now, 0)
	phFresh, _ := fresh.PrefixHash()

	wkp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	att, err := NewWitnessAttestation(wkp, now, phFresh) // honest, dated now
	if err != nil {
		t.Fatal(err)
	}

	// Attacker re-mines "bank" for the same claimant key with ts - 45 days.
	backdated := bandClaim(t, "bank", now-45*86400, 0)
	backdated.ClaimantPK = fresh.ClaimantPK // same key: only the ts differs
	backdated.TldID = fresh.TldID
	phOld, _ := backdated.PrefixHash()

	if phFresh == nil || phOld == nil || string(phFresh) == string(phOld) {
		t.Fatal("fixture: prefix hashes should differ across claim timestamps")
	}
	if att.Verify(phOld) {
		t.Fatal("VULNERABLE: fresh attestation verifies against a backdated re-mined claim (transplant)")
	}
	// Control: it still verifies against the claim it was issued for.
	if !att.Verify(phFresh) {
		t.Fatal("fixture: attestation no longer verifies against its own claim")
	}
}

// TestCorroborationBandEdges: HasQuorum counts only in-band attestations.
// Band = [claim.ts - SKEW_TOLERANCE, claim.ts + WITNESS_COOLDOWN + SKEW_TOLERANCE].
func TestCorroborationBandEdges(t *testing.T) {
	const ts = uint64(1_700_000_000)
	ph, err := (&AliasClaim{Alias: "bank", TldID: make([]byte, 32), Timestamp: ts, ClaimantPK: make([]byte, 32)}).PrefixHash()
	if err != nil {
		t.Fatal(err)
	}
	mk := func(wts uint64) *WitnessAttestation {
		wkp, gerr := crypto.Generate()
		if gerr != nil {
			t.Fatal(gerr)
		}
		w, werr := NewWitnessAttestation(wkp, wts, ph)
		if werr != nil {
			t.Fatal(werr)
		}
		return w
	}
	claim := func(ws ...*WitnessAttestation) *AliasClaim {
		return &AliasClaim{Alias: "bank", TldID: make([]byte, 32), Timestamp: ts,
			ClaimantPK: make([]byte, 32), Witnesses: ws}
	}

	lo := int64(ts) - int64(constants.SkewTolerance)
	hi := int64(ts) + int64(constants.WitnessCooldown) + int64(constants.SkewTolerance)

	cases := []struct {
		name string
		wts  uint64
		want bool
	}{
		{"exactly at lower edge (claim.ts - skew)", uint64(lo), true},
		{"one second below lower edge", uint64(lo - 1), false},
		{"witnessed at mining time", ts, true},
		{"cooldown-aged retry", uint64(ts + constants.WitnessCooldown), true},
		{"exactly at upper edge", uint64(hi), true},
		{"one second above upper edge", uint64(hi + 1), false},
		{"modern-dated on an old claim (45 days late)", ts + 45*86400, false},
	}
	for _, tc := range cases {
		c := claim(mk(tc.wts))
		if got := c.HasQuorum(nil, 1); got != tc.want {
			t.Errorf("%s: w.TS=%d HasQuorum(nil,1) = %v, want %v", tc.name, tc.wts, got, tc.want)
		}
	}
}

// TestWitnessSetMembershipDropsFabricatedKeys: a fully self-consistent
// fabricated quorum (v2 attestations, in-band timestamps — everything the
// attacker controls is "valid") fails the quorum when the verifier names the
// WITNESS_SET, because none of the fabricated node IDs is in the set.
func TestWitnessSetMembershipDropsFabricatedKeys(t *testing.T) {
	const ts = uint64(1_700_000_000)
	fabricated := bandClaim(t, "bank", ts-45*86400, constants.W) // backdated + 5 fake witnesses

	// Unenforced (nil set — sparse view / legacy source): still passes; the
	// band alone cannot know the KEYS are fabricated (their dates are
	// consistent with the backdated claim).
	if !fabricated.HasQuorum(nil, constants.W) {
		t.Fatal("fixture: fabricated in-band quorum should pass without a witness set")
	}

	// The verifier's converged witness set: 8 honest node IDs the fabricated
	// keys are not part of (hex-encoded — HasQuorum's key form).
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
	if fabricated.HasQuorum(set, constants.W) {
		t.Fatal("VULNERABLE: fabricated quorum counts under a named witness set")
	}

	// Control: an HONEST quorum passes when the set is named FROM its own
	// witnesses (a converged view that includes them).
	honest := bandClaim(t, "bank2", ts, constants.W)
	hSet := make(map[string]bool, constants.W)
	for _, w := range honest.Witnesses {
		hSet[hex.EncodeToString(w.NodeID)] = true
	}
	if !honest.HasQuorum(hSet, constants.W) {
		t.Fatal("control: honest quorum should pass its own witness set")
	}
	if !honest.HasQuorum(nil, constants.W) {
		t.Fatal("control: honest quorum should pass without a witness set")
	}
}
