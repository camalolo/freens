// Package integration contains the Go analog of the Python reference
// end-to-end test (archive/python-v0.1/tests/test_integration.py): a full
// create → claim → delegate → publish → resolve lifecycle exercised against
// the in-process dht.EnvelopeStore, plus deterministic collision resolution and
// spec golden-vector checks.
//
// Mining uses difficulty 8 throughout (PoW difficulty is a retargetable network
// parameter, Appendix A.4); claims.PoWDifficultyInit is lowered to 8 for the
// duration of each test so the default difficulty-inference path inside
// VerifyPoW / VerifyFull / SelectWinner is exercised end-to-end exactly as it
// would be on difficulty-24 claims in production.
package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"testing"

	"github.com/camalolo/freens/internal/claims"
	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/dht"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/resolver"
	"github.com/camalolo/freens/internal/wire"
	"github.com/fxamacker/cbor/v2"
	"github.com/miekg/dns"
)

// withFastPoW lowers claims.PoWDifficultyInit to 8 for the test (restored on
// cleanup) so difficulty-8 claims are spec-valid via the inference path.
func withFastPoW(t *testing.T) {
	t.Helper()
	saved := claims.PoWDifficultyInit
	claims.PoWDifficultyInit = 8
	t.Cleanup(func() { claims.PoWDifficultyInit = saved })
}

// storeLookup used to be defined locally here; it now lives once in
// internal/dht as dht.StoreLookup (NewStoreLookup adapts an *EnvelopeStore to
// resolver.RecordLookup with the canonical TLD-root → K_tld / else K_name
// routing). The TestEndToEndFlow resolver below passes dht.NewStoreLookup(store)
// directly.

// TestEndToEndFlow is the Go port of test_integration.test_full_flow: a complete
// create → claim → delegate → publish → resolve lifecycle, an authority-chain
// forgery rejection, and a sequence-bump winner replacement.
func TestEndToEndFlow(t *testing.T) {
	withFastPoW(t)
	const now int64 = 2_000_000
	store := dht.NewEnvelopeStore(0, func() int64 { return now })

	// 1. Alice creates a self-certifying TLD keypair; tld_id = SHA-256(pk).
	alice, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	aliceTID, err := crypto.TldID(alice.Public())
	if err != nil {
		t.Fatal(err)
	}

	// 2. Mine the "foo" alias claim at difficulty 8 (nonce_size=16 fixes
	//    nonce[0]=8 per Appendix A.4).
	claim, err := claims.MineAliasClaim("foo", alice, uint64(now), 8, 2_000_000, 16)
	if err != nil {
		t.Fatalf("MineAliasClaim: %v", err)
	}
	// Self-certifying TLD: tld_id == SHA-256(claimant_pk).
	if !claim.VerifyClaimantConsistency() {
		t.Fatal("VerifyClaimantConsistency: want true")
	}
	// PoW recomputes at the difficulty we mined (8 leading-zero bits).
	if !claim.VerifyPoW(8) {
		t.Fatal("VerifyPoW(8): want true")
	}
	// Inference path: with PoWDifficultyInit=8 and nonce[0]=8.
	if !claim.VerifyPoW(claims.InferDifficulty) {
		t.Fatal("VerifyPoW(InferDifficulty): want true")
	}

	// 3. Build W witnesses (distinct node keypairs) co-signing the claim.
	witnesses := make([]*claims.WitnessAttestation, 0, constants.W)
	for i := 0; i < constants.W; i++ {
		nkp, err := crypto.Generate()
		if err != nil {
			t.Fatal(err)
		}
		w, err := claims.NewWitnessAttestation(nkp, uint64(now)+uint64(i), "foo", aliceTID, alice.Public())
		if err != nil {
			t.Fatal(err)
		}
		witnesses = append(witnesses, w)
	}
	claim.Witnesses = witnesses
	// §7.3 anti-Sybil restriction: only the WITNESS_SET (the constants.W
	// closest node IDs to K_claim) may count toward quorum. HasQuorum keys
	// that set by hex(NodeID); build the same map here from the W in-set
	// witnesses we just assembled.
	witnessSet := make(map[string]bool, len(witnesses))
	for _, w := range witnesses {
		witnessSet[hex.EncodeToString(w.NodeID)] = true
	}
	// Full §7.4 validity: claimant binds, PoW valid via inference, and W
	// distinct in-set witness signatures all verify.
	if !claims.VerifyFull(claim, claims.InferDifficulty, witnessSet, constants.W) {
		t.Fatal("VerifyFull with in-set witnesses: want true")
	}

	// R8 NEGATIVE sub-checks: an out-of-set witness must NOT count, and
	// losing a single in-set witness must drop below quorum.
	// (a) Add a fresh valid attestation that is NOT in witnessSet: the
	//     in-set count is still W, so HasQuorum(set, W) holds but
	//     HasQuorum(set, W+1) cannot (the extra witness is filtered out).
	extraKP, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	extraW, err := claims.NewWitnessAttestation(extraKP, uint64(now)+999, "foo", aliceTID, alice.Public())
	if err != nil {
		t.Fatal(err)
	}
	if witnessSet[hex.EncodeToString(extraW.NodeID)] {
		t.Fatal("fixture: extra witness unexpectedly collides with in-set NodeID ( astronomically unlikely)")
	}
	claim.Witnesses = append(claim.Witnesses, extraW)
	if !claim.HasQuorum(witnessSet, constants.W) {
		t.Error("HasQuorum(set, W) = false with W in-set witnesses present; want true")
	}
	if claim.HasQuorum(witnessSet, constants.W+1) {
		t.Error("HasQuorum(set, W+1) = true; want false — out-of-set witness must NOT count toward quorum (§7.3)")
	}
	// (b) Remove one in-set witness from the eligible set: with only W-1
	//     counted witnesses, quorum (W) cannot be reached, so VerifyFull
	//     fails even though the claim carries W+1 valid signatures.
	var dropped string
	for k := range witnessSet {
		dropped = k
		break
	}
	restricted := make(map[string]bool, len(witnessSet)-1)
	for k := range witnessSet {
		if k != dropped {
			restricted[k] = true
		}
	}
	if claims.VerifyFull(claim, claims.InferDifficulty, restricted, constants.W) {
		t.Error("VerifyFull with one in-set witness removed: want false (below quorum)")
	}

	// 4. Publish the TLD record (claim embedded in field 11) at K_tld.
	tldName, err := naming.EncodeWireName(nil, "foo", aliceTID)
	if err != nil {
		t.Fatal(err)
	}
	tldRec, err := wire.NewRecord(tldName, alice.Public(), 1, uint64(now), uint64(now+constants.RecordDefaultTTL))
	if err != nil {
		t.Fatal(err)
	}
	cb, err := claim.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	tldRec.Claim = cb // embedded verbatim as the value of map key 11
	tldEnv, err := wire.SignRecord(tldRec, alice)
	if err != nil {
		t.Fatal(err)
	}
	if !tldEnv.VerifySignature() {
		t.Fatal("tld env signature invalid")
	}
	// Self-certifying root: signer == owner == the TLD key.
	if !bytes.Equal(tldEnv.Signer, tldEnv.Record.Owner) {
		t.Fatal("TLD record must be self-signed (signer == owner)")
	}
	kTld, err := naming.DHTKeyTld(aliceTID)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := store.Put(kTld, tldEnv, now, true); err != nil || !ok {
		t.Fatalf("put K_tld: ok=%v err=%v", ok, err)
	}

	// Delegate alice.foo to a fresh sub-key (Delegation field names the
	// authorized signer of the alice.foo subtree).
	aliceSub, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	aliceName, err := naming.EncodeWireName([]string{"alice"}, "foo", aliceTID)
	if err != nil {
		t.Fatal(err)
	}
	aliceRec, err := wire.NewRecord(aliceName, aliceSub.Public(), 1, uint64(now), uint64(now+constants.RecordDefaultTTL))
	if err != nil {
		t.Fatal(err)
	}
	aliceRec.Delegation = aliceSub.Public()
	aliceEnv, err := wire.SignRecord(aliceRec, alice) // signed by the TLD key
	if err != nil {
		t.Fatal(err)
	}
	kAlice := naming.DHTKeyName(aliceName)
	if ok, err := store.Put(kAlice, aliceEnv, now, true); err != nil || !ok {
		t.Fatalf("put K_alice: ok=%v err=%v", ok, err)
	}

	// Publish www.alice.foo with A=203.0.113.42, signed by the delegated key.
	wwwName, err := naming.EncodeWireName([]string{"www", "alice"}, "foo", aliceTID)
	if err != nil {
		t.Fatal(err)
	}
	wwwRec, err := wire.NewRecord(wwwName, aliceSub.Public(), 1, uint64(now), uint64(now+constants.RecordDefaultTTL))
	if err != nil {
		t.Fatal(err)
	}
	aRR, err := wire.A([]byte{203, 0, 113, 42}, 300)
	if err != nil {
		t.Fatal(err)
	}
	wwwRec.RRset = []*wire.RR{aRR}
	wwwEnv, err := wire.SignRecord(wwwRec, aliceSub)
	if err != nil {
		t.Fatal(err)
	}
	kWWW := naming.DHTKeyName(wwwName)
	if ok, err := store.Put(kWWW, wwwEnv, now, true); err != nil || !ok {
		t.Fatalf("put K_www: ok=%v err=%v", ok, err)
	}

	// 5. Fetch the chain [TLD, alice, www] and verify it.
	fetchedTld, err := store.Get(kTld, now)
	if err != nil || fetchedTld == nil {
		t.Fatalf("get K_tld: env=%v err=%v", fetchedTld, err)
	}
	fetchedAlice, err := store.Get(kAlice, now)
	if err != nil || fetchedAlice == nil {
		t.Fatalf("get K_alice: env=%v err=%v", fetchedAlice, err)
	}
	fetchedWWW, err := store.Get(kWWW, now)
	if err != nil || fetchedWWW == nil {
		t.Fatalf("get K_www: env=%v err=%v", fetchedWWW, err)
	}
	chain := []*wire.SignedEnvelope{fetchedTld, fetchedAlice, fetchedWWW}
	if !wire.VerifyAuthorityChain(chain) {
		t.Fatal("VerifyAuthorityChain([tld, alice, www]): want true")
	}
	if !wire.IsBasicValid(fetchedWWW, uint64(now)) {
		t.Fatal("IsBasicValid(www): want true")
	}
	// Read the A record out of the resolved rrset.
	var gotA, gotTTL = fetchA(fetchedWWW)
	if !bytes.Equal(gotA, []byte{203, 0, 113, 42}) {
		t.Errorf("A rdata = %v, want 203.0.113.42", gotA)
	}
	if gotTTL != 300 {
		t.Errorf("A ttl = %d, want 300", gotTTL)
	}

	// 6. Resolver: alias "foo" is freens-routed and pinned to Alice's tld_id.
	lookup := dht.NewStoreLookup(store)
	cfg := &resolver.Config{
		ListenUDP: "127.0.0.1:0",
		ListenTCP: "127.0.0.1:0",
		TLDRoutes: map[string]resolver.Route{"foo": resolver.RouteFREENS, "*": resolver.RouteDNSFirst},
		AliasPins: map[string][]byte{"foo": append([]byte(nil), aliceTID...)},
	}
	res := resolver.New(cfg, lookup, nil)
	res.Now = func() int64 { return now }

	q := dns.Question{Name: "www.alice.foo.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	rrs, rcode, _, err := res.ResolveQuestion(context.Background(), q)
	if err != nil {
		t.Fatalf("ResolveQuestion: %v", err)
	}
	if rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR(%d)", rcode, dns.RcodeSuccess)
	}
	if len(rrs) != 1 {
		t.Fatalf("len(rrs) = %d, want 1", len(rrs))
	}
	aOut, ok := rrs[0].(*dns.A)
	if !ok {
		t.Fatalf("rrs[0] = %T, want *dns.A", rrs[0])
	}
	if !aOut.A.Equal(net.IPv4(203, 0, 113, 42)) {
		t.Errorf("resolver A = %s, want 203.0.113.42", aOut.A)
	}

	// 7. A record signed by an UNAUTHORIZED key is rejected by the chain even
	//    though it is alone structurally + signature valid.
	evilKP, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	evilRec, err := wire.NewRecord(wwwName, aliceSub.Public(), 2, uint64(now), uint64(now+constants.RecordDefaultTTL))
	if err != nil {
		t.Fatal(err)
	}
	evilARR, err := wire.A([]byte{6, 6, 6, 6}, 300)
	if err != nil {
		t.Fatal(err)
	}
	evilRec.RRset = []*wire.RR{evilARR}
	evilEnv, err := wire.SignRecord(evilRec, evilKP) // signed by evil, not alice_sub
	if err != nil {
		t.Fatal(err)
	}
	if !wire.IsBasicValid(evilEnv, uint64(now)) {
		t.Fatal("evil env should be IsBasicValid alone (structure + sig are fine)")
	}
	if wire.VerifyAuthorityChain([]*wire.SignedEnvelope{fetchedTld, fetchedAlice, evilEnv}) {
		t.Fatal("chain with unauthorized signer must NOT verify")
	}

	// 8. Sequence update: publish www seq 2 with a new IP; the store winner is
	//    seq 2 (§6.4 step 3: higher sequence strictly wins).
	wwwRec2, err := wire.NewRecord(wwwName, aliceSub.Public(), 2, uint64(now), uint64(now+constants.RecordDefaultTTL))
	if err != nil {
		t.Fatal(err)
	}
	newA, err := wire.A([]byte{198, 51, 100, 7}, 300)
	if err != nil {
		t.Fatal(err)
	}
	wwwRec2.RRset = []*wire.RR{newA}
	wwwEnv2, err := wire.SignRecord(wwwRec2, aliceSub)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := store.Put(kWWW, wwwEnv2, now, true); err != nil || !ok {
		t.Fatalf("put seq2: ok=%v err=%v", ok, err)
	}
	final, err := store.Get(kWWW, now)
	if err != nil || final == nil {
		t.Fatalf("get final: env=%v err=%v", final, err)
	}
	if final.Record.Sequence != 2 {
		t.Errorf("final sequence = %d, want 2", final.Record.Sequence)
	}
	gotA2, _ := fetchA(final)
	if !bytes.Equal(gotA2, []byte{198, 51, 100, 7}) {
		t.Errorf("final A = %v, want 198.51.100.7", gotA2)
	}
}

// fetchA returns the rdata and ttl of the first A RR in env, or (nil,0) if none.
func fetchA(env *wire.SignedEnvelope) ([]byte, uint64) {
	for _, rr := range env.Record.RRset {
		if rr.Type == wire.RRTypeA {
			return rr.Rdata, rr.TTL
		}
	}
	return nil, 0
}

// TestCollisionResolution is the Go port of test_integration.test_collision_resolution:
// two parties claim "foo"; the §7.4 total order (timestamp, pow_hash, tld_id)
// picks the earlier-timestamp claim deterministically regardless of input order.
func TestCollisionResolution(t *testing.T) {
	withFastPoW(t)
	const now uint64 = 1_000_000
	alice, err := crypto.FromSeed(bytes.Repeat([]byte{0xa1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	bob, err := crypto.FromSeed(bytes.Repeat([]byte{0xb0}, 32))
	if err != nil {
		t.Fatal(err)
	}
	// Bob's asserted timestamp (now+50) is earlier than Alice's (now+100).
	cA, err := claims.MineAliasClaim("foo", alice, now+100, 8, 2_000_000, 16)
	if err != nil {
		t.Fatal(err)
	}
	cB, err := claims.MineAliasClaim("foo", bob, now+50, 8, 2_000_000, 16)
	if err != nil {
		t.Fatal(err)
	}
	// Both are valid at the difficulty they were mined.
	if !cA.VerifyPoW(8) {
		t.Fatal("Alice claim PoW(8) invalid")
	}
	if !cB.VerifyPoW(8) {
		t.Fatal("Bob claim PoW(8) invalid")
	}
	// Inference path succeeds (nonce[0]=8 >= lowered PoWDifficultyInit=8).
	if !cA.VerifyPoW(claims.InferDifficulty) {
		t.Fatal("Alice claim PoW(inferred) invalid")
	}

	// SelectWinner applies the §7.4 total order and deterministically picks
	// Bob (earlier asserted timestamp), independent of input order.
	w1 := claims.SelectWinner([]*claims.AliasClaim{cA, cB})
	w2 := claims.SelectWinner([]*claims.AliasClaim{cB, cA})
	if w1 == nil || w2 == nil {
		t.Fatal("SelectWinner returned nil")
	}
	if !bytes.Equal(w1.ClaimantPK, bob.Public()) {
		t.Errorf("SelectWinner[Alice,Bob] picked Alice; want Bob (earlier ts)")
	}
	if !bytes.Equal(w1.ClaimantPK, w2.ClaimantPK) {
		t.Errorf("SelectWinner is not input-order independent")
	}
	if w1.Timestamp != now+50 {
		t.Errorf("winner ts = %d, want %d", w1.Timestamp, now+50)
	}
}

// TestGoldenVectorsMatchSpec locks the byte-stable encodings against the spec's
// worked examples: the §3.3 wire_name layout, the §4.1 record CBOR map, and the
// §3.3 K_claim / K_name storage-key formulas. These match the Python reference
// since both are spec-derived.
func TestGoldenVectorsMatchSpec(t *testing.T) {
	// 1. wire_name(["www","alice"], "foo", bytes(0..31)) == 0x01 05 "alice"
	//    0x01 03 "www" 0x00 <tld_id> (spec line 192).
	tldID := make([]byte, 32)
	for i := 0; i < 32; i++ {
		tldID[i] = byte(i)
	}
	gotWire, err := naming.EncodeWireName([]string{"www", "alice"}, "foo", tldID)
	if err != nil {
		t.Fatal(err)
	}
	wantPrefix := []byte{0x01, 5, 'a', 'l', 'i', 'c', 'e', 0x01, 3, 'w', 'w', 'w', 0x00}
	wantWire := append(append([]byte{}, wantPrefix...), tldID...)
	if !bytes.Equal(gotWire, wantWire) {
		t.Errorf("EncodeWireName mismatch:\n got %x\nwant %x", gotWire, wantWire)
	}

	// 2. A minimal wire Record marshals identically to the hand-built
	//    map[int]any{1:1, 2:name, 3:owner, 4:1, 5:0, 6:1, 7:[]any{}} under
	//    cbor.CoreDetEncOptions(). This locks the §4.1 CBOR encoding. (The
	//    struct is built directly so arbitrary 1-byte name/owner fields can be
	//    used; NewRecord would (correctly) reject them — this test is about the
	//    encoder, not the validity rules.)
	name := []byte("n")
	owner := []byte("o")
	rec := &wire.Record{
		Version:  constants.ProtoVersion,
		Name:     name,
		Owner:    owner,
		Sequence: 1,
		Created:  0,
		Expires:  1,
		RRset:    []*wire.RR{},
	}
	gotCBOR, err := rec.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	em, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	wantCBOR, err := em.Marshal(map[int]any{
		1: 1,
		2: name,
		3: owner,
		4: 1,
		5: 0,
		6: 1,
		7: []any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotCBOR, wantCBOR) {
		t.Errorf("minimal Record CBOR mismatch:\n got %x\nwant %x", gotCBOR, wantCBOR)
	}

	// 3. K_claim = SHA-256(0x03 || "claim:" || alias); K_name = SHA-256(0x02 || wire).
	gotClaim, err := naming.DHTKeyClaim("foo")
	if err != nil {
		t.Fatal(err)
	}
	hc := sha256.New()
	hc.Write([]byte{0x03})
	hc.Write([]byte("claim:foo"))
	if wantClaim := hc.Sum(nil); !bytes.Equal(gotClaim, wantClaim) {
		t.Errorf("DHTKeyClaim(foo) mismatch:\n got %x\nwant %x", gotClaim, wantClaim)
	}
	gotName := naming.DHTKeyName(gotWire)
	hn := sha256.New()
	hn.Write([]byte{0x02})
	hn.Write(gotWire)
	if wantName := hn.Sum(nil); !bytes.Equal(gotName, wantName) {
		t.Errorf("DHTKeyName mismatch:\n got %x\nwant %x", gotName, wantName)
	}
}
