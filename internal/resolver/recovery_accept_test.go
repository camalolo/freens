// recovery_accept_test.go — §8.4 recovery acceptance on the resolver side
// (spec lines 689-707). A recovery hand-off TLD root has owner = signer =
// the NEW key K2 ("the new primary key owns the name") and prev_hash =
// H_record(R1), but the name still carries the ORIGINAL tld_id, so the plain
// §3.4 self-certification rejects it. The resolver accepts such a root iff
// its record source implements HistoryResolver (the R1 predecessor) AND
// RecoveryEvidenceResolver (the threshold declaration), the quorum verifies,
// and the resolver's clock is past the declaration's execute_not_before
// ("After the timelock elapses with no cancellation, the recovery record
// takes effect"). Pre-timelock, or without an evidence source, the name
// NXDOMAINs exactly as before.
package resolver

import (
	"context"
	"encoding/hex"
	"net"
	"sync"
	"testing"

	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/wire"
	"github.com/miekg/dns"
)

// recoveredWorld is the §8.4 fixture for alias "foo":
//
//   - R1: the original self-certifying TLD record (owner = signer = K1,
//     tld_id = SHA-256(K1)) carrying a 2-of-3 §5.4 recovery policy;
//   - R2: the §8.4 recovery hand-off record (owner = signer = K2 — the NEW
//     primary signs, unlike §8.3 — sequence 2 = prev + 1, prev_hash =
//     H_record(R1), policy rotated);
//   - www2: the www.foo record signed by K2 after the hand-off (authorized
//     by R2 via parent.Owner == child.Signer);
//   - evidence: the 2-of-3 declaration over (H(R1), K2, notBefore).
type recoveredWorld struct {
	k1, k2   *crypto.Keypair
	recKeys  []*crypto.Keypair // the §5.4 recovery witness set
	tldID    []byte
	r1, r2   *wire.SignedEnvelope
	www2     *wire.SignedEnvelope
	wwwIPv4  net.IP
	notAfter uint64 // execute_not_before carried by the evidence
}

// newRecoveredWorld builds the fixture with the declaration's timelock
// expiring at fixedNow+notAfterOffset (negative = already elapsed).
func newRecoveredWorld(t *testing.T, notAfterOffset int64) *recoveredWorld {
	t.Helper()
	w := &recoveredWorld{wwwIPv4: net.IPv4(198, 51, 100, 9), notAfter: uint64(fixedNow + notAfterOffset)}

	k1, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	k2, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	w.k1, w.k2 = k1, k2
	for i := 0; i < 3; i++ {
		kp, err := crypto.Generate()
		if err != nil {
			t.Fatal(err)
		}
		w.recKeys = append(w.recKeys, kp)
	}
	pks := make([][]byte, len(w.recKeys))
	for i, kp := range w.recKeys {
		pks[i] = kp.Public()
	}
	policy, err := wire.NewRecoveryPolicyWire(2, pks, 3600)
	if err != nil {
		t.Fatal(err)
	}
	tldID, err := crypto.TldID(k1.Public())
	if err != nil {
		t.Fatal(err)
	}
	w.tldID = tldID
	tldWire, err := naming.EncodeWireName(nil, "foo", tldID)
	if err != nil {
		t.Fatal(err)
	}

	// R1: self-certifying root with the §5.4 policy (field 10).
	r1Rec, err := wire.NewRecord(tldWire, k1.Public(), 1, uint64(fixedNow-100), uint64(fixedNow+3600))
	if err != nil {
		t.Fatal(err)
	}
	r1Rec.Recovery = policy
	w.r1, err = wire.SignRecord(r1Rec, k1)
	if err != nil {
		t.Fatal(err)
	}
	h1, err := w.r1.RecordHash()
	if err != nil {
		t.Fatal(err)
	}

	// R2: the §8.4 recovery record — owner K2, K2 SIGNS (the primary K1 is
	// lost; §8.4 step 1: "published like any record (sequence +1, `recovery`
	// fields updated)" — the policy SHOULD rotate).
	rotated, err := wire.NewRecoveryPolicyWire(1, [][]byte{k2.Public()}, 3600)
	if err != nil {
		t.Fatal(err)
	}
	r2Rec, err := wire.NewRecord(tldWire, k2.Public(), 2, uint64(fixedNow-50), uint64(fixedNow+3600))
	if err != nil {
		t.Fatal(err)
	}
	r2Rec.PrevHash = h1
	r2Rec.Recovery = rotated
	w.r2, err = wire.SignRecord(r2Rec, k2)
	if err != nil {
		t.Fatal(err)
	}

	// www2: the child signed by the new primary after the hand-off.
	wwwWire, err := naming.EncodeWireName([]string{"www"}, "foo", tldID)
	if err != nil {
		t.Fatal(err)
	}
	wwwRec, err := wire.NewRecord(wwwWire, k2.Public(), 2, uint64(fixedNow-50), uint64(fixedNow+3600))
	if err != nil {
		t.Fatal(err)
	}
	aRR, err := wire.A(w.wwwIPv4.To4(), 600)
	if err != nil {
		t.Fatal(err)
	}
	wwwRec.RRset = []*wire.RR{aRR}
	w.www2, err = wire.SignRecord(wwwRec, k2)
	if err != nil {
		t.Fatal(err)
	}

	// Fixture sanity: every envelope is individually valid, but the
	// recovered chain FAILS the plain §3.4 verifier (the root carries the
	// ORIGINAL tld_id ≠ SHA-256(K2), so signer == owner still does not
	// self-certify) — the exact gap the evidence path closes.
	for _, env := range []*wire.SignedEnvelope{w.r1, w.r2, w.www2} {
		if !wire.IsBasicValid(env, uint64(fixedNow)) {
			t.Fatal("fixture: envelope not IsBasicValid")
		}
	}
	if wire.VerifyAuthorityChain([]*wire.SignedEnvelope{w.r2, w.www2}) {
		t.Fatal("fixture: plain VerifyAuthorityChain must reject a §8.4 recovered root")
	}
	if !wire.VerifyAuthorityChain([]*wire.SignedEnvelope{w.r1}) {
		t.Fatal("fixture: R1 must verify as a self-certifying root")
	}
	return w
}

// evidence builds the 2-of-3 §8.4 declaration for w: signatures over
// RecoverySigningMessage(H(R1), K2, notBefore).
func (w *recoveredWorld) evidence(t *testing.T, signers int) *wire.RecoveryEvidence {
	t.Helper()
	h1, err := w.r1.RecordHash()
	if err != nil {
		t.Fatal(err)
	}
	msg, err := wire.RecoverySigningMessage(h1, w.k2.Public(), w.notAfter)
	if err != nil {
		t.Fatal(err)
	}
	sigs := make([][]byte, 0, signers)
	for _, kp := range w.recKeys[:signers] {
		sigs = append(sigs, kp.Sign(msg))
	}
	return &wire.RecoveryEvidence{NewOwnerPK: w.k2.Public(), Signatures: sigs, NotBefore: w.notAfter}
}

// fakeEvidenceSource is a fakeLookup implementing BOTH HistoryResolver (the
// predecessors) and RecoveryEvidenceResolver (the §8.4 declarations), keyed
// by H_record. fail drops every evidence fetch to (nil, nil).
type fakeEvidenceSource struct {
	fakeHistory
	mu       sync.Mutex
	evidence map[string]*wire.RecoveryEvidence
	fail     bool
}

func newFakeEvidenceSource() *fakeEvidenceSource {
	return &fakeEvidenceSource{
		fakeHistory: *newFakeHistory(),
		evidence:    map[string]*wire.RecoveryEvidence{},
	}
}

func (f *fakeEvidenceSource) putEvidence(t *testing.T, env *wire.SignedEnvelope, ev *wire.RecoveryEvidence) {
	t.Helper()
	h, err := env.RecordHash()
	if err != nil {
		t.Fatalf("fixture: H_record: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.evidence[hex.EncodeToString(h)] = ev
}

func (f *fakeEvidenceSource) RecoveryEvidence(_ context.Context, recordHash []byte) (*wire.RecoveryEvidence, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return nil, nil
	}
	return f.evidence[hex.EncodeToString(recordHash)], nil
}

// resolveWwwFooRecovered mirrors transfer_accept_test.go's resolveWwwFoo.
func resolveWwwFooRecovered(t *testing.T, tldID []byte, lookup RecordLookup) ([]dns.RR, int, bool, error) {
	t.Helper()
	r := newResolver(transferConfig(t, tldID), lookup, nil)
	q := dns.Question{Name: "www.foo.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	return r.ResolveQuestion(context.Background(), q)
}

// TestRecoveredTLDAcceptedAfterTimelock is THE §8.4 acceptance test: the TLD
// record served at K_tld is the recovery record R2 (owner = signer = K2,
// prev_hash-linked), www is signed by the new primary K2, the source can
// produce R1 by hash AND the 2-of-3 declaration for R2, and the resolver's
// clock is past execute_not_before — so www.foo resolves, aa=true.
func TestRecoveredTLDAcceptedAfterTimelock(t *testing.T) {
	w := newRecoveredWorld(t, -60) // timelock elapsed a minute ago
	src := newFakeEvidenceSource()
	src.put(w.r2) // K_tld now serves the recovery record (R1 was superseded)
	src.put(w.www2)
	src.putByHash(t, w.r1)                     // the retained predecessor
	src.putEvidence(t, w.r2, w.evidence(t, 2)) // the §8.4 declaration

	rrs, rcode, aa, err := resolveWwwFooRecovered(t, w.tldID, src)
	if err != nil {
		t.Fatalf("ResolveQuestion: unexpected err: %v", err)
	}
	if rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR(%d)", rcode, dns.RcodeSuccess)
	}
	if len(rrs) != 1 {
		t.Fatalf("len(rrs) = %d, want 1", len(rrs))
	}
	a, ok := rrs[0].(*dns.A)
	if !ok {
		t.Fatalf("rrs[0] is %T, want *dns.A", rrs[0])
	}
	if !a.A.Equal(w.wwwIPv4) {
		t.Errorf("A.A = %s, want %s", a.A, w.wwwIPv4)
	}
	if !aa {
		t.Error("freens-routed recovered answer must be authoritative (aa=true)")
	}
}

// TestRecoveredTLDRejectedBeforeTimelock: during the §8.4 timelock ("the
// current primary key MAY cancel by publishing a higher-sequence normal
// record") the recovery has NOT taken effect — the resolver's clock is before
// execute_not_before, so the recovered root is unprovable → NXDOMAIN (still
// authoritative for the freens namespace).
func TestRecoveredTLDRejectedBeforeTimelock(t *testing.T) {
	w := newRecoveredWorld(t, 3600) // timelock elapses in an hour
	src := newFakeEvidenceSource()
	src.put(w.r2)
	src.put(w.www2)
	src.putByHash(t, w.r1)
	src.putEvidence(t, w.r2, w.evidence(t, 2))

	rrs, rcode, aa, err := resolveWwwFooRecovered(t, w.tldID, src)
	if err != nil {
		t.Fatalf("ResolveQuestion: unexpected err: %v", err)
	}
	if rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %d, want NXDOMAIN(%d) before execute_not_before", rcode, dns.RcodeNameError)
	}
	if len(rrs) != 0 {
		t.Errorf("len(rrs) = %d, want 0", len(rrs))
	}
	if !aa {
		t.Error("a freens-route NXDOMAIN is still authoritative (aa=true)")
	}
}

// TestRecoveredTLDRejectedWithoutEvidenceSource: a source that can fetch
// predecessors (HistoryResolver) but NOT §8.4 evidence cannot prove the
// recovery hop — the behavior stays exactly today's reject (NXDOMAIN).
func TestRecoveredTLDRejectedWithoutEvidenceSource(t *testing.T) {
	w := newRecoveredWorld(t, -60) // timelock long elapsed; still unprovable
	h := newFakeHistory()          // HistoryResolver only — no RecoveryEvidence
	h.put(w.r2)
	h.put(w.www2)
	h.putByHash(t, w.r1)

	rrs, rcode, _, err := resolveWwwFooRecovered(t, w.tldID, h)
	if err != nil {
		t.Fatalf("ResolveQuestion: unexpected err: %v", err)
	}
	if rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %d, want NXDOMAIN(%d) without an evidence source", rcode, dns.RcodeNameError)
	}
	if len(rrs) != 0 {
		t.Errorf("len(rrs) = %d, want 0", len(rrs))
	}
}

// TestRecoveredTLDRejectedWhenEvidenceMissing: the evidence source exists but
// cannot produce the declaration (nil fetch) — or the declaration lacks the
// quorum — so the recovery hop is unprovable → NXDOMAIN.
func TestRecoveredTLDRejectedWhenEvidenceMissing(t *testing.T) {
	w := newRecoveredWorld(t, -60)

	// Evidence unobtainable.
	src := newFakeEvidenceSource()
	src.put(w.r2)
	src.put(w.www2)
	src.putByHash(t, w.r1)
	src.fail = true
	if _, rcode, _, err := resolveWwwFooRecovered(t, w.tldID, src); err != nil ||
		rcode != dns.RcodeNameError {
		t.Fatalf("nil evidence fetch: rcode=%d err=%v, want NXDOMAIN", rcode, err)
	}

	// Evidence obtainable but below threshold (1 of the required 2).
	src.fail = false
	src.putEvidence(t, w.r2, w.evidence(t, 1))
	if _, rcode, _, err := resolveWwwFooRecovered(t, w.tldID, src); err != nil ||
		rcode != dns.RcodeNameError {
		t.Fatalf("below-threshold quorum: rcode=%d err=%v, want NXDOMAIN", rcode, err)
	}
}

// TestPlainWorldUnchangedWithEvidenceSource is the regression guard: a source
// implementing BOTH optional hand-off sources must not alter the ordinary
// self-certifying path (chain[0] without prev_hash keeps the plain
// VerifyAuthorityChain route — zero behavior change).
func TestPlainWorldUnchangedWithEvidenceSource(t *testing.T) {
	w := newFreensWorld(t)
	src := newFakeEvidenceSource() // HistoryResolver + RecoveryEvidenceResolver
	src.put(w.tldEnv)
	src.put(w.wwwEnv)

	rrs, rcode, aa, err := resolveWwwFoo(t, w.tldID, src)
	if err != nil {
		t.Fatalf("ResolveQuestion: unexpected err: %v", err)
	}
	if rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR(%d) for the plain world", rcode, dns.RcodeSuccess)
	}
	if len(rrs) != 1 || !rrs[0].(*dns.A).A.Equal(w.wwwIPv4) {
		t.Errorf("rrs = %v, want one A %s", rrs, w.wwwIPv4)
	}
	if !aa {
		t.Error("freens-routed answer must be authoritative (aa=true)")
	}
}
