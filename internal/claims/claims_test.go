package claims

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/fxamacker/cbor/v2"
)

// withDifficulty lowers PoWDifficultyInit for the duration of fn, restoring it
// afterwards. Required because mining at the production difficulty (24) is far
// too slow for tests; we mine at 8 and lower the inference floor to match.
func withDifficulty(t *testing.T, d int, fn func()) {
	t.Helper()
	prev := PoWDifficultyInit
	PoWDifficultyInit = d
	t.Cleanup(func() { PoWDifficultyInit = prev })
	fn()
}

// mineTestClaim mines a claim at difficulty 8 (fast) for the given alias/ts.
func mineTestClaim(t *testing.T, alias string, ts uint64) *AliasClaim {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	c, err := MineAliasClaim(alias, kp, ts, 8, 2_000_000, 16)
	if err != nil {
		t.Fatalf("MineAliasClaim: %v", err)
	}
	return c
}

// makeWitnesses builds n distinct valid witness attestations for c, each
// dated inside the corroboration band around c.Timestamp (an offset of i
// seconds keeps every fixture honest under the v0.7.0 band).
func makeWitnesses(t *testing.T, c *AliasClaim, n int) []*WitnessAttestation {
	t.Helper()
	prefixHash, err := c.PrefixHash()
	if err != nil {
		t.Fatalf("PrefixHash: %v", err)
	}
	out := make([]*WitnessAttestation, 0, n)
	for i := 0; i < n; i++ {
		kp, err := crypto.Generate()
		if err != nil {
			t.Fatalf("witness Generate: %v", err)
		}
		w, err := NewWitnessAttestation(kp, c.Timestamp+uint64(i), prefixHash)
		if err != nil {
			t.Fatalf("NewWitnessAttestation: %v", err)
		}
		out = append(out, w)
	}
	return out
}

// ---------------------------------------------------------------------------
// WitnessAttestation
// ---------------------------------------------------------------------------

func TestWitnessAttestation(t *testing.T) {
	nodeKP, err := crypto.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	claimantKP, err := crypto.Generate()
	if err != nil {
		t.Fatalf("Generate claimant: %v", err)
	}
	tldID, err := crypto.TldID(claimantKP.Public())
	if err != nil {
		t.Fatalf("TldID: %v", err)
	}
	claimantPK := claimantKP.Public()
	const claimTS = uint64(1_700_000_000)
	const ts = uint64(1_700_000_000) // the witness's own clock

	// prefixFor hashes the claim identity the way a witness would.
	prefixFor := func(alias string, tld, pk []byte, cts uint64) []byte {
		h, err := (&AliasClaim{Alias: alias, TldID: tld, Timestamp: cts, ClaimantPK: pk}).PrefixHash()
		if err != nil {
			t.Fatalf("PrefixHash: %v", err)
		}
		return h
	}
	ph := prefixFor("foo", tldID, claimantPK, claimTS)

	w, err := NewWitnessAttestation(nodeKP, ts, ph)
	if err != nil {
		t.Fatalf("NewWitnessAttestation: %v", err)
	}

	// (a) node_id binds to node_pk, sig verifies → true.
	if !w.Verify(ph) {
		t.Fatal("freshly-built attestation fails Verify")
	}

	// Tamper TS → false.
	good := w.TS
	w.TS = good + 1
	if w.Verify(ph) {
		t.Fatal("Verify should fail after TS tamper")
	}
	w.TS = good

	// Tamper alias context (a different claim identity) → false.
	if w.Verify(prefixFor("bar", tldID, claimantPK, claimTS)) {
		t.Fatal("Verify should fail with wrong alias context")
	}

	// Tamper tld_id context → false.
	badTld := make([]byte, len(tldID))
	copy(badTld, tldID)
	badTld[0] ^= 0xff
	if w.Verify(prefixFor("foo", badTld, claimantPK, claimTS)) {
		t.Fatal("Verify should fail with wrong tld_id context")
	}

	// Tamper claimant_pk context → false.
	badPK := make([]byte, len(claimantPK))
	copy(badPK, claimantPK)
	badPK[0] ^= 0xff
	if w.Verify(prefixFor("foo", tldID, badPK, claimTS)) {
		t.Fatal("Verify should fail with wrong claimant_pk context")
	}

	// v0.7.0 transplant regression: a claim re-mined with a DIFFERENT
	// (e.g. backdated) timestamp has a different prefix hash, so the
	// attestation must not verify against it — this is the binding that
	// kills the backdating attack (v1 bound the identity fields but left
	// the timestamp replayable across re-mined claims of the same alias).
	if w.Verify(prefixFor("foo", tldID, claimantPK, claimTS-45*86400)) {
		t.Fatal("Verify should fail against a backdated re-mined claim (transplant)")
	}

	// CanonicalBytes round-trips via DecodeWitnessAttestation.
	cb, err := w.CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	w2, err := DecodeWitnessAttestation(cb)
	if err != nil {
		t.Fatalf("DecodeWitnessAttestation: %v", err)
	}
	if !bytes.Equal(cb, must(w2.CanonicalBytes())) {
		t.Fatal("CanonicalBytes not byte-stable across decode")
	}
	if !w2.Verify(ph) {
		t.Fatal("decoded attestation fails Verify")
	}

	// node_id must equal SHA-256(node_pk).
	nid, _ := crypto.NodeID(nodeKP.Public())
	if !bytes.Equal(nid, w.NodeID) {
		t.Fatal("NodeID != SHA-256(NodePK)")
	}

	// Forged node_id (unbound) → false.
	forged := &WitnessAttestation{
		NodeID: bytes.Repeat([]byte{0xaa}, constants.NodeIDLen),
		NodePK: w.NodePK,
		TS:     ts,
		Sig:    w.Sig,
	}
	if forged.Verify(ph) {
		t.Fatal("unbound node_id should fail Verify")
	}
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

// ---------------------------------------------------------------------------
// MineAliasClaim
// ---------------------------------------------------------------------------

func TestMineAliasClaim(t *testing.T) {
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	const ts = uint64(1_700_000_000)
	c, err := MineAliasClaim("foo", kp, ts, 8, 2_000_000, 16)
	if err != nil {
		t.Fatalf("MineAliasClaim: %v", err)
	}

	// Alias normalized & stored.
	if c.Alias != "foo" {
		t.Errorf("Alias = %q, want %q", c.Alias, "foo")
	}
	// TldID == SHA-256(ClaimantPK).
	wantTld, _ := crypto.TldID(kp.Public())
	if !bytes.Equal(c.TldID, wantTld) {
		t.Error("TldID != SHA-256(ClaimantPK)")
	}
	// Nonce[0] conventionally == difficulty (crypto.MinePoW fixes it).
	if len(c.Nonce) == 0 || c.Nonce[0] != 8 {
		t.Errorf("Nonce[0] = %v, want 8", c.Nonce)
	}
	// Claimant consistency.
	if !c.VerifyClaimantConsistency() {
		t.Error("VerifyClaimantConsistency false on mined claim")
	}
	// PoW valid at explicit difficulty 8.
	if !c.VerifyPoW(8) {
		t.Error("VerifyPoW(8) false on mined claim")
	}
	// crypto.PoWHash(Prefix, Nonce) == PowHash.
	prefix, err := c.Prefix()
	if err != nil {
		t.Fatalf("Prefix: %v", err)
	}
	if got := crypto.PoWHash(prefix, c.Nonce); !bytes.Equal(got, c.PowHash) {
		t.Error("crypto.PoWHash(Prefix,Nonce) != PowHash")
	}
	// Prefix == canonical CBOR of {1:alias,2:tldID,3:ts,5:claimantPK} (field 4 SKIPPED).
	em, _ := cbor.CoreDetEncOptions().EncMode()
	wantPrefix, _ := em.Marshal(map[int]any{1: "foo", 2: c.TldID, 3: ts, 5: c.ClaimantPK})
	if !bytes.Equal(prefix, wantPrefix) {
		t.Errorf("Prefix mismatch: got %x, want %x (field 4 should be skipped)", prefix, wantPrefix)
	}
	// Field 4 (nonce) must NOT appear in the prefix. UNCONDITIONAL check:
	// always decode the prefix as a CBOR map and assert it contains EXACTLY
	// keys {1,2,3,5} and does NOT contain key 4. This locks the Appendix C.1
	// interpretation (PoW prefix excludes the nonce) regardless of whether the
	// byte 0x04 happens to occur inside a value.
	var pmap map[int]cbor.RawMessage
	if err := cbor.Unmarshal(prefix, &pmap); err != nil {
		t.Fatalf("prefix not a CBOR map: %v", err)
	}
	if _, ok := pmap[4]; ok {
		t.Fatal("prefix must not contain field 4 (nonce)")
	}
	if len(pmap) != 4 {
		t.Fatalf("prefix should have exactly 4 keys {1,2,3,5}, got %d: %v", len(pmap), pmap)
	}
	for _, k := range []int{1, 2, 3, 5} {
		if _, ok := pmap[k]; !ok {
			t.Fatalf("prefix missing key %d", k)
		}
	}

	// CanonicalBytes round-trips via DecodeAliasClaim, byte-stable.
	cb, err := c.CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	c2, err := DecodeAliasClaim(cb)
	if err != nil {
		t.Fatalf("DecodeAliasClaim: %v", err)
	}
	cb2, err := c2.CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalBytes(2): %v", err)
	}
	if !bytes.Equal(cb, cb2) {
		t.Errorf("CanonicalBytes not byte-stable across decode:\n %x\n %x", cb, cb2)
	}
	// Decoded claim still verifies.
	if !c2.VerifyClaimantConsistency() {
		t.Error("decoded claim fails VerifyClaimantConsistency")
	}
	if !c2.VerifyPoW(8) {
		t.Error("decoded claim fails VerifyPoW(8)")
	}
}

// TestNilWitnessesEncodesAsEmptyArray locks the canonicalEM robustness fix
// (NilContainerAsEmpty): an AliasClaim with Witnesses == nil must encode field 7
// as a CBOR empty array `[]`, NOT as null. Matches the Python reference, which
// always emits `[]`. Without the NilContainerAsEmpty override the default
// NilContainerAsNull would emit CBOR null for a nil slice.
func TestNilWitnessesEncodesAsEmptyArray(t *testing.T) {
	// Build a fully-valid claim via mining, then force Witnesses to nil.
	c := mineTestClaim(t, "foo", 1_700_000_000)
	c.Witnesses = nil

	cb, err := c.CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}

	// Decode as a generic int→any map and inspect field 7 (witnesses).
	var m map[int]any
	if err := cbor.Unmarshal(cb, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	got, ok := m[7]
	if !ok {
		t.Fatal("field 7 (witnesses) absent from canonical bytes")
	}
	arr, ok := got.([]any)
	if !ok {
		t.Fatalf("field 7 decoded as %T (%v), want []any — nil Witnesses must emit `[]` not `null`", got, got)
	}
	if len(arr) != 0 {
		t.Fatalf("field 7 len = %d, want 0 (nil Witnesses must encode as empty array)", len(arr))
	}

	// Round-trip byte-stability: decode → re-encode is byte-identical.
	c2, err := DecodeAliasClaim(cb)
	if err != nil {
		t.Fatalf("DecodeAliasClaim: %v", err)
	}
	cb2, err := c2.CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalBytes(2): %v", err)
	}
	if !bytes.Equal(cb, cb2) {
		t.Errorf("CanonicalBytes not byte-stable across decode:\n %x\n %x", cb, cb2)
	}
	// Decoded claim still has an (logically) empty witness set.
	if n := len(c2.ValidWitnesses()); n != 0 {
		t.Errorf("decoded nil-witness claim has %d valid witnesses, want 0", n)
	}
}

// ---------------------------------------------------------------------------
// VerifyPoW inference (lowered PoWDifficultyInit)
// ---------------------------------------------------------------------------

func TestVerifyPoWInference(t *testing.T) {
	c := mineTestClaim(t, "foo", 1_700_000_000) // mined at difficulty 8

	// With the production floor (24), inference picks 24 (Nonce[0]=8 < 24) and
	// the hash (8 leading-zero bits) fails.
	withDifficulty(t, constants.PoWDifficultyInit, func() {
		if c.VerifyPoW(InferDifficulty) {
			t.Fatal("VerifyPoW(inferred) should fail at production difficulty 24 for an 8-bit claim")
		}
	})

	// Lower the floor to 8: Nonce[0]=8 >= 8 → inferred difficulty 8 → passes.
	withDifficulty(t, 8, func() {
		if !c.VerifyPoW(InferDifficulty) {
			t.Fatal("VerifyPoW(inferred) should pass with PoWDifficultyInit=8")
		}
	})

	// Sanity: explicit 8 always passes regardless of the floor.
	if !c.VerifyPoW(8) {
		t.Fatal("VerifyPoW(8) should always pass for an 8-bit claim")
	}
}

// ---------------------------------------------------------------------------
// SelectWinner / OrderClaims
// ---------------------------------------------------------------------------

func TestSelectWinnerOrderClaims(t *testing.T) {
	withDifficulty(t, 8, func() {
		c1 := mineTestClaim(t, "foo", 2000)
		c2 := mineTestClaim(t, "foo", 1000)

		// c2 (ts=1000) is earlier → wins.
		if got := SelectWinner([]*AliasClaim{c1, c2}); got != c2 {
			t.Errorf("SelectWinner([c1,c2]) = %p, want c2 (ts=1000)", got)
		}
		// OrderClaims ascending → [c2, c1].
		got := OrderClaims([]*AliasClaim{c1, c2})
		if len(got) != 2 || got[0] != c2 || got[1] != c1 {
			t.Errorf("OrderClaims = %v, want [c2,c1]", orderPtrs(got))
		}

		// Empty → nil.
		if got := SelectWinner(nil); got != nil {
			t.Errorf("SelectWinner(nil) = %p, want nil", got)
		}
		if got := SelectWinner([]*AliasClaim{}); got != nil {
			t.Errorf("SelectWinner([]) = %p, want nil", got)
		}

		// Deterministic regardless of input order.
		wA := SelectWinner([]*AliasClaim{c2, c1})
		wB := SelectWinner([]*AliasClaim{c1, c2})
		if wA != wB {
			t.Error("SelectWinner not deterministic across input orderings")
		}

		// Structurally-invalid claim (TldID != SHA-256(ClaimantPK)) is filtered.
		bad := *c1                                    // shallow copy
		bad.TldID = make([]byte, constants.SHA256Len) // all zeros, never matches
		if got := SelectWinner([]*AliasClaim{&bad}); got != nil {
			t.Errorf("SelectWinner([bad]) = %p, want nil (claimant inconsistent)", got)
		}
		if surv := OrderClaims([]*AliasClaim{&bad}); len(surv) != 0 {
			t.Errorf("OrderClaims([bad]) = %d survivors, want 0", len(surv))
		}

		// Invalid-only input → SelectWinner nil, OrderClaims empty.
		if got := SelectWinner([]*AliasClaim{&bad, &bad}); got != nil {
			t.Error("SelectWinner should be nil for all-invalid input")
		}
	})
}

func orderPtrs(cs []*AliasClaim) []uint64 {
	out := make([]uint64, len(cs))
	for i, c := range cs {
		out[i] = c.Timestamp
	}
	return out
}

// OrderKey tie-break on pow_hash then tld_id (with equal timestamps, impossible
// for distinct claimants but exercised by fabricating two claims sharing a
// timestamp).
func TestOrderKeyTieBreak(t *testing.T) {
	withDifficulty(t, 8, func() {
		const ts = uint64(1234)
		a := mineTestClaim(t, "foo", ts)
		b := mineTestClaim(t, "foo", ts)
		if a.PowHash == nil || b.PowHash == nil {
			t.Fatal("nil pow_hash")
		}
		// Distinct claimants → distinct tld_id; pow_hash very likely distinct.
		wantFirst := a
		if lessOrderKey(b, a) {
			wantFirst = b
		}
		if got := SelectWinner([]*AliasClaim{a, b}); got != wantFirst {
			t.Error("SelectWinner tie-break disagrees with lessOrderKey")
		}
		got := OrderClaims([]*AliasClaim{a, b})
		if len(got) != 2 || got[0] != wantFirst {
			t.Error("OrderClaims tie-break disagrees with lessOrderKey")
		}
		// Total order: exactly one of lessOrderKey(a,b)/lessOrderKey(b,a) holds.
		lab := lessOrderKey(a, b)
		lba := lessOrderKey(b, a)
		if lab == lba {
			t.Error("tie-break not antisymmetric for distinct claimants")
		}
	})
}

// ---------------------------------------------------------------------------
// Quorum
// ---------------------------------------------------------------------------

func TestQuorum(t *testing.T) {
	W := constants.W // 5
	c := mineTestClaim(t, "foo", 1_700_000_000)

	// W+2 = 7 valid witnesses.
	c.Witnesses = makeWitnesses(t, c, W+2)
	if !c.HasQuorum(nil, W) {
		t.Error("HasQuorum(nil, W) should be true with W+2 valid witnesses")
	}
	if c.HasQuorum(nil, W+3) {
		t.Error("HasQuorum(nil, W+3) should be false with only W+2 valid")
	}

	// Exactly W valid → quorum W met, W+1 not.
	c2 := mineTestClaim(t, "foo", 1_700_000_001)
	c2.Witnesses = makeWitnesses(t, c2, W)
	if !c2.HasQuorum(nil, W) {
		t.Error("HasQuorum(nil, W) should be true with exactly W valid")
	}
	if c2.HasQuorum(nil, W+1) {
		t.Error("HasQuorum(nil, W+1) should be false with exactly W valid")
	}

	// W-1 valid → quorum W not met.
	c3 := mineTestClaim(t, "foo", 1_700_000_002)
	c3.Witnesses = makeWitnesses(t, c3, W-1)
	if c3.HasQuorum(nil, W) {
		t.Error("HasQuorum(nil, W) should be false with only W-1 valid")
	}

	// Tampered witness is excluded: W valid + 1 tampered → still W valid.
	c4 := mineTestClaim(t, "foo", 1_700_000_003)
	valid := makeWitnesses(t, c4, W)
	tampered := *valid[0]
	tampered.Sig = append([]byte(nil), valid[0].Sig...) // deep-copy: don't mutate original
	tampered.Sig[0] ^= 0xff                             // break signature
	c4.Witnesses = append(append([]*WitnessAttestation{}, valid...), &tampered)
	if n := len(c4.ValidWitnesses()); n != W {
		t.Errorf("ValidWitnesses = %d, want %d (tampered should be excluded)", n, W)
	}
	if !c4.HasQuorum(nil, W) {
		t.Error("HasQuorum(nil, W) should be true: tampered witness excluded, W remain")
	}
	if c4.HasQuorum(nil, W+1) {
		t.Error("HasQuorum(nil, W+1) should be false after excluding tampered")
	}

	// witnessSetIDs restriction: only 3 of the W valid node ids in the set.
	c5 := mineTestClaim(t, "foo", 1_700_000_004)
	c5.Witnesses = makeWitnesses(t, c5, W)
	restricted := make(map[string]bool, 3)
	for i := 0; i < 3; i++ {
		restricted[hex.EncodeToString(c5.Witnesses[i].NodeID)] = true
	}
	if c5.HasQuorum(restricted, W) {
		t.Error("HasQuorum(restricted-to-3, W) should be false")
	}
	if !c5.HasQuorum(restricted, 3) {
		t.Error("HasQuorum(restricted-to-3, 3) should be true")
	}
	// Full set restriction → met.
	full := make(map[string]bool, W)
	for _, w := range c5.Witnesses {
		full[hex.EncodeToString(w.NodeID)] = true
	}
	if !c5.HasQuorum(full, W) {
		t.Error("HasQuorum(full-set, W) should be true")
	}

	// Dedup by NodeID keeping first: duplicate the same node_id twice.
	c6 := mineTestClaim(t, "foo", 1_700_000_005)
	ws := makeWitnesses(t, c6, W)
	c6.Witnesses = append(append([]*WitnessAttestation{}, ws...), ws[0]) // dup
	if n := len(c6.ValidWitnesses()); n != W {
		t.Errorf("ValidWitnesses should dedup NodeID: got %d, want %d", n, W)
	}
}

// ---------------------------------------------------------------------------
// VerifyFull
// ---------------------------------------------------------------------------

func TestVerifyFull(t *testing.T) {
	withDifficulty(t, 8, func() {
		W := constants.W

		// Claim with W witnesses → full validity.
		good := mineTestClaim(t, "foo", 1_700_000_000)
		good.Witnesses = makeWitnesses(t, good, W)
		if !VerifyFull(good, InferDifficulty, nil, W) {
			t.Error("VerifyFull should be true with W witnesses (inferred difficulty)")
		}
		// Explicit difficulty also works.
		if !VerifyFull(good, 8, nil, W) {
			t.Error("VerifyFull should be true with explicit difficulty 8")
		}

		// Claim with W-1 witnesses → false.
		short := mineTestClaim(t, "foo", 1_700_000_001)
		short.Witnesses = makeWitnesses(t, short, W-1)
		if VerifyFull(short, InferDifficulty, nil, W) {
			t.Error("VerifyFull should be false with W-1 witnesses")
		}

		// Inconsistent claimant → false even with quorum.
		bad := *good
		bad.TldID = make([]byte, constants.SHA256Len)
		if VerifyFull(&bad, InferDifficulty, nil, W) {
			t.Error("VerifyFull should be false for inconsistent claimant")
		}

		// Tampered PoW → false even with quorum.
		badpow := *good
		badpow.PowHash = bytes.Repeat([]byte{0xff}, constants.SHA256Len)
		if VerifyFull(&badpow, InferDifficulty, nil, W) {
			t.Error("VerifyFull should be false for tampered PoW")
		}
	})
}

// ---------------------------------------------------------------------------
// Decode validation
// ---------------------------------------------------------------------------

func TestDecodeValidation(t *testing.T) {
	// Wrong-length fields are rejected by DecodeAliasClaim.
	c := mineTestClaim(t, "foo", 1_700_000_000)
	cb, err := c.CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}

	// Decode a generic map, mutate, re-encode, expect validation failure.
	var m map[int]cbor.RawMessage
	if err := cbor.Unmarshal(cb, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	em, _ := cbor.CoreDetEncOptions().EncMode()

	// Shorten tld_id (field 2) to 31 bytes.
	var tld []byte
	if err := cbor.Unmarshal(m[2], &tld); err != nil {
		t.Fatalf("tld unmarshal: %v", err)
	}
	short, _ := em.Marshal(tld[:len(tld)-1])
	m[2] = short
	bad, _ := em.Marshal(m)
	if _, err := DecodeAliasClaim(bad); err == nil {
		t.Error("DecodeAliasClaim should reject short tld_id")
	}

	// Invalid alias rejected.
	var badAlias map[int]any
	if err := cbor.Unmarshal(cb, &badAlias); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	badAlias[1] = "UPPER_NOT_ALLOWED" // fails LDH check
	badAliasBytes, _ := em.Marshal(badAlias)
	if _, err := DecodeAliasClaim(badAliasBytes); err == nil {
		t.Error("DecodeAliasClaim should reject invalid alias")
	}
}

func ExampleSelectWinner() {
	// This example documents the deterministic-winner property: for any set of
	// competing claims, all honest clients compute the same winner from claim
	// contents alone (§7.4 step 3). (Mining is omitted; see TestSelectWinner.)
	fmt.Println("SelectWinner picks the smallest (timestamp, pow_hash, tld_id)")
	// Output: SelectWinner picks the smallest (timestamp, pow_hash, tld_id)
}
