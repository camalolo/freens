package wire

// recovery_walk_test.go pins VerifyAuthorityChainWithHandoffs — the §8.4
// (specifications.md lines 689-707) recovery-aware §8.3/§3.4 authority-chain
// verifier. A recovery hand-off record has owner = signer = the NEW key
// (unlike §8.3 where the OLD owner signs) and prev_hash = H_record(previous
// envelope), and is accepted iff per-hop evidence satisfies
// VerifyRecovery(prev.Record.Recovery, ev, H(prev), now): quorum over the
// predecessor's §5.4 policy plus the §8.4 timelock (now >= NotBefore) against
// the caller's clock. Pure §8.3 transfer chains and plain self-certifying
// chains must keep verifying unchanged (backward compatibility).

import (
	"bytes"
	"testing"

	"github.com/laurent/freens/internal/constants"
	"github.com/laurent/freens/internal/crypto"
)

// recoveryWalkKeys builds the 2-of-3 §5.4 policy kit used by most tests:
// the policy plus its three recovery keypairs.
func recoveryWalkKeys(t *testing.T) (*RecoveryPolicyWire, []*crypto.Keypair) {
	t.Helper()
	var keys []*crypto.Keypair
	for _, seed := range []byte{0x61, 0x62, 0x63} {
		kp, err := crypto.FromSeed(bytes.Repeat([]byte{seed}, constants.Ed25519PrivateKeyLen))
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, kp)
	}
	pks := make([][]byte, len(keys))
	for i, kp := range keys {
		pks[i] = kp.Public()
	}
	policy, err := NewRecoveryPolicyWire(2, pks, 3600)
	if err != nil {
		t.Fatal(err)
	}
	return policy, keys
}

// makeRecoveryRoot builds the original self-certifying TLD record for alias
// carrying the §5.4 policy (field 10).
func makeRecoveryRoot(t *testing.T, kp *crypto.Keypair, alias string, policy *RecoveryPolicyWire) *SignedEnvelope {
	t.Helper()
	tldID := mustTldID(t, kp.Public())
	name := mustWireName(t, nil, alias, tldID)
	rec := mustRecord(t, name, kp.Public(), 1, 1000, 2000)
	rec.Recovery = policy
	return mustSign(t, rec, kp)
}

// makeRecoveryHop builds the §8.4 successor R2 over prev: same wire_name,
// owner = signer = newKP (the new primary signs its own record), sequence =
// prev+1, prev_hash = H_record(prev), optionally a rotated policy.
func makeRecoveryHop(t *testing.T, prev *SignedEnvelope, newKP *crypto.Keypair, policy *RecoveryPolicyWire, created, expires uint64) *SignedEnvelope {
	t.Helper()
	ph, err := prev.RecordHash()
	if err != nil {
		t.Fatalf("RecordHash: %v", err)
	}
	rec := mustRecord(t, prev.Record.Name, newKP.Public(), prev.Record.Sequence+1, created, expires)
	rec.PrevHash = ph
	rec.Recovery = policy
	return mustSign(t, rec, newKP)
}

// hopEvidence builds the §8.4 declaration evidence for a recovery hop
// prev -> cur signed by the given quorum of recovery keys: signatures over
// RecoverySigningMessage(H(prev), cur.Owner, notBefore).
func hopEvidence(t *testing.T, prev, cur *SignedEnvelope, signers []*crypto.Keypair, notBefore uint64) *RecoveryEvidence {
	t.Helper()
	hPrev, err := prev.RecordHash()
	if err != nil {
		t.Fatalf("RecordHash: %v", err)
	}
	return &RecoveryEvidence{
		NewOwnerPK: cur.Record.Owner,
		Signatures: signRecovery(t, signers, hPrev, cur.Record.Owner, notBefore),
		NotBefore:  notBefore,
	}
}

// evidenceFetcher adapts (envelope -> evidence) pairs into a fetchEvidence
// callback keyed by H_record of the RECOVERY record (the evidence table key).
func evidenceFetcher(pairs map[*SignedEnvelope]*RecoveryEvidence) func([]byte) (*RecoveryEvidence, error) {
	m := make(map[string]*RecoveryEvidence, len(pairs))
	for env, ev := range pairs {
		h, err := env.RecordHash()
		if err != nil {
			continue
		}
		m[string(h)] = ev
	}
	return func(recordHash []byte) (*RecoveryEvidence, error) {
		return m[string(recordHash)], nil
	}
}

// TestHandoffWalkerRecoveryAcceptedAfterTimelock: R1 root (K1, 2-of-3 policy)
// -> R2 recovery (owner = signer = K2). With now >= NotBefore the chain
// verifies through the evidence; with now < NotBefore (§8.4 step 2/3: the
// timelock has not elapsed — the current primary may still cancel) it is
// rejected. The plain verifier and the pure-transfer verifier both reject R2
// (signer == owner but tld_id != H(K2)), pinning the delta.
func TestHandoffWalkerRecoveryAcceptedAfterTimelock(t *testing.T) {
	policy, _ := recoveryWalkKeys(t)
	policy, keys := recoveryWalkKeys(t)
	k1, k2 := mustKeypair(t), mustKeypair(t)
	r1 := makeRecoveryRoot(t, k1, "foo", policy)
	r2 := makeRecoveryHop(t, r1, k2, policy, 2500, 4000)
	notBefore := uint64(3_000)
	ev := hopEvidence(t, r1, r2, keys[:2], notBefore)

	fetch := fetchMap(nil, r1)
	fetchEv := evidenceFetcher(map[*SignedEnvelope]*RecoveryEvidence{r2: ev})
	chain := []*SignedEnvelope{r2}

	if !VerifyAuthorityChainWithHandoffs(chain, fetch, fetchEv, notBefore) {
		t.Error("recovery chain should verify once the timelock has elapsed (now == NotBefore)")
	}
	if !VerifyAuthorityChainWithHandoffs(chain, fetch, fetchEv, notBefore+1) {
		t.Error("recovery chain should verify after the timelock")
	}
	if VerifyAuthorityChainWithHandoffs(chain, fetch, fetchEv, notBefore-1) {
		t.Error("recovery chain must be rejected BEFORE the timelock elapses (§8.4 cancellation window)")
	}

	// The old verifiers cannot prove a recovery root at all.
	if VerifyAuthorityChain(chain) {
		t.Error("plain VerifyAuthorityChain must reject a recovery root (not self-certifying for K2)")
	}
	if VerifyAuthorityChainWithTransfers(chain, fetch) {
		t.Error("transfer walker must reject a recovery root (stops at signer==owner, not self-certifying)")
	}

	// The recovered root still authorizes children signed by the NEW owner.
	child := makeNameEnv(t, k2, k2, []string{"alice"}, "foo", mustTldID(t, k1.Public()), nil)
	if !VerifyAuthorityChainWithHandoffs([]*SignedEnvelope{r2, child}, fetch, fetchEv, notBefore) {
		t.Error("recovered root should authorize a child signed by the new owner")
	}
}

// TestHandoffWalkerRecoveryQuorumMissing: 1-of-2 signatures does not satisfy
// the threshold.
func TestHandoffWalkerRecoveryQuorumMissing(t *testing.T) {
	policy, keys := recoveryWalkKeys(t)
	k1, k2 := mustKeypair(t), mustKeypair(t)
	r1 := makeRecoveryRoot(t, k1, "foo", policy)
	r2 := makeRecoveryHop(t, r1, k2, policy, 2500, 4000)
	ev := hopEvidence(t, r1, r2, keys[:1], 1000) // 1 of the required 2

	if VerifyAuthorityChainWithHandoffs([]*SignedEnvelope{r2}, fetchMap(nil, r1),
		evidenceFetcher(map[*SignedEnvelope]*RecoveryEvidence{r2: ev}), 5000) {
		t.Error("below-threshold quorum must fail the recovery hop")
	}
}

// TestHandoffWalkerRecoveryWrongPolicy: evidence signed by keys that are NOT
// in the predecessor's §5.4 policy contributes nothing (a rogue witness set
// cannot manufacture a hand-off).
func TestHandoffWalkerRecoveryWrongPolicy(t *testing.T) {
	policy, _ := recoveryWalkKeys(t)
	// A DISJOINT witness set (recoveryWalkKeys is deterministic, so mint
	// foreign keys from different seeds).
	var foreign []*crypto.Keypair
	for _, seed := range []byte{0x71, 0x72} {
		kp, err := crypto.FromSeed(bytes.Repeat([]byte{seed}, constants.Ed25519PrivateKeyLen))
		if err != nil {
			t.Fatal(err)
		}
		foreign = append(foreign, kp)
	}
	k1, k2 := mustKeypair(t), mustKeypair(t)
	r1 := makeRecoveryRoot(t, k1, "foo", policy)
	r2 := makeRecoveryHop(t, r1, k2, policy, 2500, 4000)
	ev := hopEvidence(t, r1, r2, foreign[:2], 1000)

	if VerifyAuthorityChainWithHandoffs([]*SignedEnvelope{r2}, fetchMap(nil, r1),
		evidenceFetcher(map[*SignedEnvelope]*RecoveryEvidence{r2: ev}), 5000) {
		t.Error("evidence from keys outside the policy must fail the recovery hop")
	}
}

// TestHandoffWalkerRecoveryEvidenceUnavailable: a nil evidence fetch (or a
// nil fetcher) makes the recovery hop — and hence the chain — unverifiable.
func TestHandoffWalkerRecoveryEvidenceUnavailable(t *testing.T) {
	policy, _ := recoveryWalkKeys(t)
	k1, k2 := mustKeypair(t), mustKeypair(t)
	r1 := makeRecoveryRoot(t, k1, "foo", policy)
	r2 := makeRecoveryHop(t, r1, k2, policy, 2500, 4000)

	nilFetch := func([]byte) (*RecoveryEvidence, error) { return nil, nil }
	if VerifyAuthorityChainWithHandoffs([]*SignedEnvelope{r2}, fetchMap(nil, r1), nilFetch, 5000) {
		t.Error("(nil, nil) evidence fetch must make the recovery chain unverifiable")
	}
	if VerifyAuthorityChainWithHandoffs([]*SignedEnvelope{r2}, fetchMap(nil, r1), nil, 5000) {
		t.Error("nil fetchEvidence must make the recovery chain unverifiable")
	}
}

// TestHandoffWalkerMixedTransferThenRecovery: R1 (K1, policy P) -> R2 §8.3
// transfer (owner K2, signer K1) carrying policy P' -> R3 §8.4 recovery
// (owner = signer = K3) with quorum evidence over P'. Both hops dispatch
// correctly in one walk.
func TestHandoffWalkerMixedTransferThenRecovery(t *testing.T) {
	policy, _ := recoveryWalkKeys(t)
	policy2, keys2 := recoveryWalkKeys(t)
	k1, k2, k3 := mustKeypair(t), mustKeypair(t), mustKeypair(t)

	r1 := makeRecoveryRoot(t, k1, "foo", policy)
	r2 := transferHop(t, r1, k1, k2, 2500, 4000) // §8.3: previous owner K1 signs
	r2.Record.Recovery = policy2
	r2 = mustSign(t, r2.Record, k1)                   // re-sign with the policy embedded
	r3 := makeRecoveryHop(t, r2, k3, nil, 2600, 4000) // §8.4: K3 signs, policy rotated
	ev := hopEvidence(t, r2, r3, keys2[:2], 1000)

	fetch := fetchMap(nil, r1, r2)
	fetchEv := evidenceFetcher(map[*SignedEnvelope]*RecoveryEvidence{r3: ev})
	if !VerifyAuthorityChainWithHandoffs([]*SignedEnvelope{r3}, fetch, fetchEv, 5000) {
		t.Error("mixed transfer-then-recovery chain should verify")
	}
	// Without the evidence the recovery hop (and only it) fails.
	if VerifyAuthorityChainWithHandoffs([]*SignedEnvelope{r3}, fetch, nil, 5000) {
		t.Error("mixed chain without recovery evidence must fail")
	}
}

// TestHandoffWalkerSequenceJump: prev_hash correct but sequence = prev+2 must
// fail the exact-increment rule (§8.2/§8.3 "sequence = prev + 1").
func TestHandoffWalkerSequenceJump(t *testing.T) {
	policy, _ := recoveryWalkKeys(t)
	k1, k2 := mustKeypair(t), mustKeypair(t)
	r1 := makeRecoveryRoot(t, k1, "foo", policy) // seq 1
	ph, err := r1.RecordHash()
	if err != nil {
		t.Fatal(err)
	}
	jump := mustRecord(t, r1.Record.Name, k2.Public(), 3, 2500, 4000) // seq 3 = prev + 2
	jump.PrevHash = ph
	jumpEnv := mustSign(t, jump, k2)
	if !jumpEnv.VerifySignature() {
		t.Fatal("precondition: the envelope's own signature must be valid")
	}
	if VerifyAuthorityChainWithHandoffs([]*SignedEnvelope{jumpEnv}, fetchMap(nil, r1),
		evidenceFetcher(nil), 5000) {
		t.Error("sequence jump (prev+2) must fail the exact-increment rule")
	}
}

// TestHandoffWalkerPrevHashTampering: a well-signed recovery record whose
// prev_hash names nothing is unverifiable.
func TestHandoffWalkerPrevHashTampering(t *testing.T) {
	policy, _ := recoveryWalkKeys(t)
	k1, k2 := mustKeypair(t), mustKeypair(t)
	r1 := makeRecoveryRoot(t, k1, "foo", policy)

	garbage := make([]byte, constants.SHA256Len)
	for i := range garbage {
		garbage[i] = 0xEE
	}
	bad := mustRecord(t, r1.Record.Name, k2.Public(), r1.Record.Sequence+1, 2500, 4000)
	bad.PrevHash = garbage
	badEnv := mustSign(t, bad, k2)
	if !badEnv.VerifySignature() {
		t.Fatal("precondition: the envelope's own signature must be valid")
	}
	if VerifyAuthorityChainWithHandoffs([]*SignedEnvelope{badEnv}, fetchMap(nil, r1),
		evidenceFetcher(nil), 5000) {
		t.Error("recovery record with a broken prev_hash must fail")
	}
}

// TestHandoffWalkerDepthCap: exactly transferMaxDepth hand-off hops verify;
// one more exceeds the walk budget.
func TestHandoffWalkerDepthCap(t *testing.T) {
	k1 := mustKeypair(t)
	owners := make([]*crypto.Keypair, transferMaxDepth+1)
	for i := range owners {
		owners[i] = mustKeypair(t)
	}
	root := makeTldEnv(t, k1, "foo", nil)
	// Alternate §8.3 transfer hops: every hop signed by the then-current
	// owner (the shared walk shape; the cap is structural, not per-type).
	hops := make([]*SignedEnvelope, 0, transferMaxDepth+1)
	cur := root
	for i := 0; i < transferMaxDepth+1; i++ {
		signer := k1
		if i > 0 {
			signer = owners[i-1]
		}
		cur = transferHop(t, cur, signer, owners[i], 2500, 4000)
		hops = append(hops, cur)
	}
	fetch := fetchMap(nil, append([]*SignedEnvelope{root}, hops...)...)
	if !VerifyAuthorityChainWithHandoffs([]*SignedEnvelope{hops[transferMaxDepth-1]}, fetch, nil, 5000) {
		t.Errorf("chain of exactly %d hand-offs should verify", transferMaxDepth)
	}
	if VerifyAuthorityChainWithHandoffs([]*SignedEnvelope{hops[transferMaxDepth]}, fetch, nil, 5000) {
		t.Errorf("chain of %d hand-offs must fail the depth cap", transferMaxDepth+1)
	}
}

// TestHandoffWalkerTransferBackwardCompat: a pure §8.3 transfer chain still
// verifies via the new function — with a non-nil evidence fetcher present —
// and plain self-certifying chains (with children) verify byte-identically
// without ever fetching.
func TestHandoffWalkerTransferBackwardCompat(t *testing.T) {
	aKP, bKP := mustKeypair(t), mustKeypair(t)
	root := makeTldEnv(t, aKP, "foo", nil)
	xfer := transferHop(t, root, aKP, bKP, 2500, 4000)
	evCalls := 0
	fetchEv := func([]byte) (*RecoveryEvidence, error) {
		evCalls++
		return nil, nil
	}

	if !VerifyAuthorityChainWithHandoffs([]*SignedEnvelope{xfer}, fetchMap(nil, root), fetchEv, 5000) {
		t.Error("pure transfer chain must still verify via the handoffs walker")
	}
	if evCalls != 0 {
		t.Errorf("evidence fetched %d times on a pure transfer chain, want 0", evCalls)
	}

	// Plain chains: identical acceptance to VerifyAuthorityChain, no fetches.
	tldKP := mustKeypair(t)
	tldID := mustTldID(t, tldKP.Public())
	aliceKP := mustKeypair(t)
	tldDel := makeTldEnv(t, tldKP, "foo", aliceKP.Public())
	aliceEnv := makeNameEnv(t, aliceKP, aliceKP, []string{"alice"}, "foo", tldID, nil)
	calls := 0
	fetch := fetchMap(&calls)
	if !VerifyAuthorityChainWithHandoffs([]*SignedEnvelope{tldDel, aliceEnv}, fetch, fetchEv, 5000) {
		t.Error("plain 2-hop delegation chain must verify via the handoffs walker")
	}
	forged := *tldDel
	forged.Signer = mustKeypair(t).Public()
	if VerifyAuthorityChainWithHandoffs([]*SignedEnvelope{&forged, aliceEnv}, fetch, fetchEv, 5000) {
		t.Error("unauthorized child must still fail")
	}
	if calls != 0 {
		t.Errorf("fetchPredecessor called %d times on plain chains, want 0", calls)
	}
}
