package wire

// transfer_test.go pins VerifyAuthorityChainWithTransfers — the §8.3
// (specifications.md lines 666-688) transfer-aware §3.4 authority-chain
// verifier: a chain[0] whose signer != owner must walk prev_hash links
// (fetched via a callback) back to a self-certifying TLD root, each hop
// signed by the PREVIOUS owner with sequence = prev + 1 and the same name,
// and historical predecessors are NOT required to be inside their validity
// window (audit history, not live records).

import (
	"errors"
	"testing"

	"github.com/laurent/freens/internal/crypto"
)

// transferHop builds the §8.3 successor envelope over prev: same wire_name,
// owner = newOwnerKP, prev_hash = H_record(prev), sequence = prev + 1, signed
// by signerKP. In a real transfer signerKP is prev's owner (the CURRENT
// owner at hand-off time); tests pass other keys to pin the failure modes.
func transferHop(t *testing.T, prev *SignedEnvelope, signerKP, newOwnerKP *crypto.Keypair, created, expires uint64) *SignedEnvelope {
	t.Helper()
	ph, err := prev.RecordHash()
	if err != nil {
		t.Fatalf("RecordHash: %v", err)
	}
	rec := mustRecord(t, prev.Record.Name, newOwnerKP.Public(), prev.Record.Sequence+1, created, expires)
	rec.PrevHash = ph
	return mustSign(t, rec, signerKP)
}

// fetchMap adapts a set of envelopes into a fetchPredecessor callback keyed
// by H_record; calls counts invocations (the self-certifying paths must never
// fetch).
func fetchMap(calls *int, envs ...*SignedEnvelope) func([]byte) (*SignedEnvelope, error) {
	m := make(map[string]*SignedEnvelope, len(envs))
	for _, e := range envs {
		h, err := e.RecordHash()
		if err != nil {
			continue
		}
		m[string(h)] = e
	}
	return func(prevHash []byte) (*SignedEnvelope, error) {
		if calls != nil {
			*calls++
		}
		return m[string(prevHash)], nil
	}
}

// TestTransferVerifierSelfCertifiedRootStillPasses: when chain[0].Signer ==
// chain[0].Record.Owner the behaviour is identical to
// VerifyAuthorityChain — including multi-hop delegation chains — and the
// fetch callback is NEVER invoked.
func TestTransferVerifierSelfCertifiedRootStillPasses(t *testing.T) {
	tldKP := mustKeypair(t)
	tldID := mustTldID(t, tldKP.Public())

	calls := 0
	fetch := fetchMap(&calls)

	tldEnv := makeTldEnv(t, tldKP, "foo", nil)
	if !VerifyAuthorityChainWithTransfers([]*SignedEnvelope{tldEnv}, fetch) {
		t.Error("self-certifying 1-hop TLD chain should verify")
	}

	aliceKP := mustKeypair(t)
	tldDel := makeTldEnv(t, tldKP, "foo", aliceKP.Public())
	aliceEnv := makeNameEnv(t, aliceKP, aliceKP, []string{"alice"}, "foo", tldID, nil)
	if !VerifyAuthorityChainWithTransfers([]*SignedEnvelope{tldDel, aliceEnv}, fetch) {
		t.Error("self-certifying 2-hop delegation chain should verify")
	}

	// Failure cases stay failures (root not self-certifying, no transfer
	// evidence available).
	forged := *tldEnv
	forged.Signer = mustKeypair(t).Public()
	if VerifyAuthorityChainWithTransfers([]*SignedEnvelope{&forged}, fetch) {
		t.Error("forged-signer root without a fetchable predecessor should fail")
	}
	if calls != 0 {
		t.Errorf("fetch called %d times on self-certifying paths, want 0 (forged case aside)", calls)
	}
}

// TestTransferVerifierOneHop: a single §8.3 transfer of a whole TLD — the
// root signed by the PREVIOUS owner (A), owner re-pointed to B, prev_hash =
// H_record(original root), sequence = prev + 1 — verifies against the real
// fetched predecessor. The plain VerifyAuthorityChain rejects it (signer !=
// owner), pinning the delta between the two verifiers.
func TestTransferVerifierOneHop(t *testing.T) {
	aKP, bKP := mustKeypair(t), mustKeypair(t)
	root := makeTldEnv(t, aKP, "foo", nil) // seq 1, owner+signer A
	xfer := transferHop(t, root, aKP, bKP, 2500, 4000)

	chain := []*SignedEnvelope{xfer}
	if !VerifyAuthorityChainWithTransfers(chain, fetchMap(nil, root)) {
		t.Error("1-hop transfer chain should verify with the real predecessor")
	}
	if VerifyAuthorityChain(chain) {
		t.Error("plain VerifyAuthorityChain must reject a transferred root (signer != owner)")
	}

	// The transferred root still authorizes children signed by the NEW owner.
	child := makeNameEnv(t, bKP, bKP, []string{"alice"}, "foo", mustTldID(t, aKP.Public()), nil)
	if !VerifyAuthorityChainWithTransfers([]*SignedEnvelope{xfer, child}, fetchMap(nil, root)) {
		t.Error("transferred root should authorize a child signed by the new owner")
	}
}

// TestTransferVerifierThreeHop: A -> B -> C -> D over the same TLD name;
// every hop is signed by the then-current owner and chains by prev_hash.
func TestTransferVerifierThreeHop(t *testing.T) {
	aKP, bKP, cKP, dKP := mustKeypair(t), mustKeypair(t), mustKeypair(t), mustKeypair(t)
	root := makeTldEnv(t, aKP, "foo", nil)           // seq 1, A
	t1 := transferHop(t, root, aKP, bKP, 2500, 4000) // seq 2, A->B
	t2 := transferHop(t, t1, bKP, cKP, 2501, 4000)   // seq 3, B->C
	t3 := transferHop(t, t2, cKP, dKP, 2502, 4000)   // seq 4, C->D
	fetch := fetchMap(nil, root, t1, t2)
	if !VerifyAuthorityChainWithTransfers([]*SignedEnvelope{t3}, fetch) {
		t.Error("3-hop transfer chain should verify")
	}
	// A missing intermediate predecessor (t2 absent) makes it unverifiable.
	if VerifyAuthorityChainWithTransfers([]*SignedEnvelope{t3}, fetchMap(nil, root, t1)) {
		t.Error("3-hop chain without the t2 predecessor must fail")
	}
}

// TestTransferVerifierWrongSigner: a transfer envelope signed by a key that
// is NOT the previous owner (signature itself valid) must fail — §8.3: "the
// network accepts the new record because the previous owner ... signed it".
func TestTransferVerifierWrongSigner(t *testing.T) {
	aKP, bKP, eveKP := mustKeypair(t), mustKeypair(t), mustKeypair(t)
	root := makeTldEnv(t, aKP, "foo", nil)
	// Signed by eve (not A): signature verifies, authorization does not.
	byEve := transferHop(t, root, eveKP, bKP, 2500, 4000)
	if !byEve.VerifySignature() {
		t.Fatal("precondition: eve's signature must itself be valid")
	}
	if VerifyAuthorityChainWithTransfers([]*SignedEnvelope{byEve}, fetchMap(nil, root)) {
		t.Error("transfer signed by a non-owner third party must fail")
	}
}

// TestTransferVerifierBrokenPrevHash: a properly-signed transfer whose
// prev_hash names nothing makes the chain unverifiable. (The corrupted
// envelopes are built and SIGNED with the bad prev_hash — mutating a signed
// record would fail on the signature instead, which is a different rule.)
func TestTransferVerifierBrokenPrevHash(t *testing.T) {
	aKP, bKP := mustKeypair(t), mustKeypair(t)
	root := makeTldEnv(t, aKP, "foo", nil)

	// Well-formed-but-wrong 32-byte prev_hash.
	garbage := make([]byte, 32)
	for i := range garbage {
		garbage[i] = 0xEE
	}
	wrongHash := mustRecord(t, root.Record.Name, bKP.Public(), root.Record.Sequence+1, 2500, 4000)
	wrongHash.PrevHash = garbage
	wrongEnv := mustSign(t, wrongHash, aKP)
	if !wrongEnv.VerifySignature() {
		t.Fatal("precondition: the envelope's own signature must be valid")
	}
	if VerifyAuthorityChainWithTransfers([]*SignedEnvelope{wrongEnv}, fetchMap(nil, root)) {
		t.Error("transfer with a broken prev_hash must fail")
	}

	// A nil prev_hash on a transferred (signer != owner) root fails too.
	noPrev := mustRecord(t, root.Record.Name, bKP.Public(), root.Record.Sequence+1, 2500, 4000)
	noPrevEnv := mustSign(t, noPrev, aKP)
	if VerifyAuthorityChainWithTransfers([]*SignedEnvelope{noPrevEnv}, fetchMap(nil, root)) {
		t.Error("transferred root without prev_hash must fail")
	}
}

// TestTransferVerifierSequenceJump: prev_hash correct but sequence = prev+2
// (VerifyChainLink's strictly-increasing check alone would pass) must fail
// the §8.3 "sequence = prev + 1" rule.
func TestTransferVerifierSequenceJump(t *testing.T) {
	aKP, bKP := mustKeypair(t), mustKeypair(t)
	root := makeTldEnv(t, aKP, "foo", nil) // seq 1
	ph, err := root.RecordHash()
	if err != nil {
		t.Fatal(err)
	}
	jump := mustRecord(t, root.Record.Name, bKP.Public(), 3, 2500, 4000) // seq 3 = prev + 2
	jump.PrevHash = ph
	jumpEnv := mustSign(t, jump, aKP)
	if !VerifyChainLink(jumpEnv, root) {
		t.Fatal("precondition: VerifyChainLink (strictly increasing) should pass on a +2 jump")
	}
	if VerifyAuthorityChainWithTransfers([]*SignedEnvelope{jumpEnv}, fetchMap(nil, root)) {
		t.Error("sequence jump (prev+2) must fail the §8.3 exact-increment rule")
	}
}

// TestTransferVerifierFetchNil: (nil, nil) from the fetcher — predecessor
// unavailable — is unverifiable; a fetch error likewise fails.
func TestTransferVerifierFetchNil(t *testing.T) {
	aKP, bKP := mustKeypair(t), mustKeypair(t)
	root := makeTldEnv(t, aKP, "foo", nil)
	xfer := transferHop(t, root, aKP, bKP, 2500, 4000)

	nilFetch := func([]byte) (*SignedEnvelope, error) { return nil, nil }
	if VerifyAuthorityChainWithTransfers([]*SignedEnvelope{xfer}, nilFetch) {
		t.Error("(nil, nil) fetch must make the chain unverifiable")
	}
	errFetch := func([]byte) (*SignedEnvelope, error) { return nil, errors.New("boom") }
	if VerifyAuthorityChainWithTransfers([]*SignedEnvelope{xfer}, errFetch) {
		t.Error("a fetch error must make the chain unverifiable")
	}
}

// TestTransferVerifierDepthCap: exactly transferMaxDepth hand-offs verify;
// one more exceeds the walk budget and fails.
func TestTransferVerifierDepthCap(t *testing.T) {
	aKP := mustKeypair(t)
	root := makeTldEnv(t, aKP, "foo", nil)
	owners := make([]*crypto.Keypair, transferMaxDepth+1)
	for i := range owners {
		owners[i] = mustKeypair(t)
	}
	hops := make([]*SignedEnvelope, 0, transferMaxDepth+1)
	cur := root
	for i := 0; i < transferMaxDepth+1; i++ {
		var signer *crypto.Keypair
		if i == 0 {
			signer = aKP
		} else {
			signer = owners[i-1]
		}
		cur = transferHop(t, cur, signer, owners[i], 2500, 4000)
		hops = append(hops, cur)
	}
	// hops[transferMaxDepth-1] is exactly transferMaxDepth links from root.
	if !VerifyAuthorityChainWithTransfers([]*SignedEnvelope{hops[transferMaxDepth-1]}, fetchMap(nil, append([]*SignedEnvelope{root}, hops...)...)) {
		t.Errorf("chain of exactly %d transfers should verify", transferMaxDepth)
	}
	// One more hop: over budget.
	if VerifyAuthorityChainWithTransfers([]*SignedEnvelope{hops[transferMaxDepth]}, fetchMap(nil, append([]*SignedEnvelope{root}, hops...)...)) {
		t.Errorf("chain of %d transfers must fail the depth cap", transferMaxDepth+1)
	}
}

// TestTransferVerifierPredecessorNeedNotBeLive: §8.3's prev_hash chain is an
// AUDIT trail; predecessors are historical evidence, not live records, so an
// expired predecessor (created 1000, expires 2000 — long dead at any modern
// "now") still verifies a live tip (created 2500, expires 4000). The
// verifier consults no clock; liveness of chain[0] is the caller's
// IsBasicValid job.
func TestTransferVerifierPredecessorNeedNotBeLive(t *testing.T) {
	aKP, bKP := mustKeypair(t), mustKeypair(t)
	root := makeTldEnv(t, aKP, "foo", nil) // created 1000, expires 2000: dead
	if !(root.Record.Created == 1000 && root.Record.Expires == 2000) {
		t.Fatal("precondition: makeTldEnv must build a long-expired root (1000..2000)")
	}
	xfer := transferHop(t, root, aKP, bKP, 2500, 4000) // live tip
	if !VerifyAuthorityChainWithTransfers([]*SignedEnvelope{xfer}, fetchMap(nil, root)) {
		t.Error("an expired predecessor must still verify the transfer chain (§8.3 audit history)")
	}
}

// TestTransferVerifierMatchesPlainVerifier: on signer==owner chains the two
// verifiers must agree on every classic §3.4 case; the ONLY divergence is a
// signer!=owner root WITH transfer evidence.
func TestTransferVerifierMatchesPlainVerifier(t *testing.T) {
	tldKP := mustKeypair(t)
	tldID := mustTldID(t, tldKP.Public())
	aliceKP, eveKP := mustKeypair(t), mustKeypair(t)

	tldEnv := makeTldEnv(t, tldKP, "foo", nil)
	tldDel := makeTldEnv(t, tldKP, "foo", aliceKP.Public())
	aliceEnv := makeNameEnv(t, aliceKP, aliceKP, []string{"alice"}, "foo", tldID, nil)
	aliceByEve := makeNameEnv(t, aliceKP, eveKP, []string{"alice"}, "foo", tldID, nil)
	otherTldID := mustTldID(t, mustKeypair(t).Public())
	wrongTldChild := makeNameEnv(t, aliceKP, aliceKP, []string{"alice"}, "foo", otherTldID, nil)

	// Build a genuinely oversized chain of valid envelopes (len > MaxLabels+1).
	tooLong := make([]*SignedEnvelope, 0)
	for i := 0; i < 10; i++ {
		tooLong = append(tooLong, tldEnv)
	}

	cases := []struct {
		name  string
		chain []*SignedEnvelope
		want  bool
	}{
		{"1-hop TLD", []*SignedEnvelope{tldEnv}, true},
		{"2-hop delegation", []*SignedEnvelope{tldDel, aliceEnv}, true},
		{"unauthorized child", []*SignedEnvelope{tldDel, aliceByEve}, false},
		{"cross-TLD child", []*SignedEnvelope{tldDel, wrongTldChild}, false},
		{"empty chain", nil, false},
		{"oversized chain", tooLong, false},
	}

	for _, tc := range cases {
		if got := VerifyAuthorityChainWithTransfers(tc.chain, fetchMap(nil)); got != tc.want {
			t.Errorf("%s: WithTransfers = %v, want %v", tc.name, got, tc.want)
		}
		if got := VerifyAuthorityChain(tc.chain); got != tc.want {
			t.Errorf("%s: plain VerifyAuthorityChain = %v, want %v (verifiers must agree on signer==owner chains)", tc.name, got, tc.want)
		}
	}
}
