// transfer_accept_test.go — §8.3 whole-TLD transfer acceptance on the
// resolver side (spec lines 666-687). A transferred TLD root has
// owner = the NEW owner key but is SIGNED by the PREVIOUS owner
// ("The network accepts the new record because the previous owner — whose
// key the current authority chain names — signed it") and carries
// prev_hash = H_record(previous signed envelope), so the plain §3.4
// chain[0] rule (signer == owner, self-certifying) rejects it. The resolver
// accepts such a root iff its record source implements HistoryResolver and
// the prev_hash walk re-establishes self-certification through the retained
// predecessor history ("prev_hash links the transfer into an auditable chain
// so third parties can verify the hand-off history offline").
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

// transferredWorld is the §8.3 fixture for alias "footld":
//
//   - v1: the original self-certifying TLD record (owner = signer = K1,
//     tld_id = SHA-256(K1));
//   - v2: the whole-TLD transfer record (owner = K2, signer = K1 — the
//     previous owner, sequence 2 = prev + 1, prev_hash = H_record(v1),
//     delegation = K2 "subtree authority follows");
//   - www2: the www.footld record re-signed by K2 after the hand-off (authorized
//     by v2 via parent.Owner == child.Signer, and by Delegation = K2).
type transferredWorld struct {
	k1, k2  *crypto.Keypair
	tldID   []byte
	v1, v2  *wire.SignedEnvelope
	www2    *wire.SignedEnvelope
	wwwIPv4 net.IP
}

func newTransferredWorld(t *testing.T, alias string) *transferredWorld {
	t.Helper()
	w := &transferredWorld{wwwIPv4: net.IPv4(198, 51, 100, 7)}

	k1, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	k2, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	w.k1, w.k2 = k1, k2
	tldID, err := crypto.TldID(k1.Public())
	if err != nil {
		t.Fatal(err)
	}
	w.tldID = tldID

	// v1: self-certifying root, exactly like freensWorld's TLD record.
	tldWire, err := naming.EncodeWireName(nil, alias, tldID)
	if err != nil {
		t.Fatal(err)
	}
	v1Rec, err := wire.NewRecord(tldWire, k1.Public(), 1, uint64(fixedNow-100), uint64(fixedNow+3600))
	if err != nil {
		t.Fatal(err)
	}
	w.v1, err = wire.SignRecord(v1Rec, k1)
	if err != nil {
		t.Fatal(err)
	}
	h1, err := w.v1.RecordHash() // H_record, §4.2 (the prev_hash input)
	if err != nil {
		t.Fatal(err)
	}

	// v2: the §8.3 transfer record — owner K2, PREVIOUS owner K1 signs.
	v2Rec, err := wire.NewRecord(tldWire, k2.Public(), 2, uint64(fixedNow-50), uint64(fixedNow+3600))
	if err != nil {
		t.Fatal(err)
	}
	v2Rec.Delegation = k2.Public() // "subtree authority follows"
	v2Rec.PrevHash = h1
	w.v2, err = wire.SignRecord(v2Rec, k1)
	if err != nil {
		t.Fatal(err)
	}

	// www2: the child re-signed by the new owner after the hand-off.
	wwwWire, err := naming.EncodeWireName([]string{"www"}, alias, tldID)
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

	// Fixture sanity: every envelope is individually valid...
	for _, env := range []*wire.SignedEnvelope{w.v1, w.v2, w.www2} {
		if !wire.IsBasicValid(env, uint64(fixedNow)) {
			t.Fatal("fixture: envelope not IsBasicValid")
		}
	}
	// ...but the transferred chain FAILS the plain §3.4 verifier (chain[0]
	// signer K1 != owner K2) — the exact gap the HistoryResolver path closes.
	if wire.VerifyAuthorityChain([]*wire.SignedEnvelope{w.v2, w.www2}) {
		t.Fatal("fixture: plain VerifyAuthorityChain must reject a §8.3 transferred root")
	}
	// The pre-transfer root alone still verifies (self-certifying).
	if !wire.VerifyAuthorityChain([]*wire.SignedEnvelope{w.v1}) {
		t.Fatal("fixture: v1 must verify as a self-certifying root")
	}
	return w
}

// transferConfig routes "footld" into freens and PINS it to the world's tld_id,
// so the tests exercise the pure §3b chain walk (no §7 claim machinery).
func transferConfig(t *testing.T, tldID []byte) *Config {
	t.Helper()
	cfg, err := ParseConfig("[tld-routes]\n* = dns-first\n")
	if err != nil {
		t.Fatal(err)
	}
	cfg.TLDRoutes["footld"] = RouteFREENS
	cfg.AliasPins = map[string][]byte{"footld": append([]byte(nil), tldID...)}
	return cfg
}

// resolveWwwFootld runs www.footld. A through a resolver over lookup, pinning
// "footld" to tldID (the pure §3b chain walk — no §7 claim machinery).
func resolveWwwFootld(t *testing.T, tldID []byte, lookup RecordLookup) ([]dns.RR, int, bool, error) {
	t.Helper()
	r := newResolver(transferConfig(t, tldID), lookup, nil)
	q := dns.Question{Name: "www.footld.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	return r.ResolveQuestion(context.Background(), q)
}

// fakeHistory is a fakeLookup that ALSO implements HistoryResolver: the
// superseded envelopes a §8.3 walk fetches by H_record. Setting fail makes
// LookupByHash report "predecessor unobtainable" (nil, nil) for every hash.
type fakeHistory struct {
	fakeLookup
	mu     sync.Mutex
	byHash map[string]*wire.SignedEnvelope
	fail   bool
}

func newFakeHistory() *fakeHistory {
	return &fakeHistory{fakeLookup: *newFakeLookup(), byHash: map[string]*wire.SignedEnvelope{}}
}

func (f *fakeHistory) putByHash(t *testing.T, env *wire.SignedEnvelope) {
	t.Helper()
	h, err := env.RecordHash()
	if err != nil {
		t.Fatalf("fixture: H_record: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.byHash[hex.EncodeToString(h)] = env
}

func (f *fakeHistory) LookupByHash(_ context.Context, h []byte) (*wire.SignedEnvelope, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return nil, nil
	}
	return f.byHash[hex.EncodeToString(h)], nil
}

// TestTransferredTLDAcceptedWithHistory is THE §8.3 acceptance test: the TLD
// record served at K_tld is the transfer record v2 (owner K2, signer K1,
// prev_hash-linked), the www child is signed by the new owner K2, and the
// source can produce v1 by hash — so the transfer walk re-establishes
// self-certification and www.footld resolves, aa=true.
func TestTransferredTLDAcceptedWithHistory(t *testing.T) {
	w := newTransferredWorld(t, "footld")
	h := newFakeHistory()
	h.put(w.v2) // K_tld now serves the transfer record (v1 was superseded)
	h.put(w.www2)
	h.putByHash(t, w.v1) // the retained predecessor: the audit history

	cfg := transferConfig(t, w.tldID)
	r := newResolver(cfg, h, nil)
	q := dns.Question{Name: "www.footld.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	rrs, rcode, aa, err := r.ResolveQuestion(context.Background(), q)
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
		t.Error("freens-routed transferred answer must be authoritative (aa=true)")
	}
}

// TestTransferredTLDRejectedWithoutHistorySource: a source that cannot fetch
// predecessors (no HistoryResolver) cannot prove the hand-off, so the
// transferred root stays rejected — today's pre-§8.3 behavior (NXDOMAIN,
// still authoritative for the freens namespace).
func TestTransferredTLDRejectedWithoutHistorySource(t *testing.T) {
	w := newTransferredWorld(t, "footld")
	lookup := newFakeLookup() // Lookup only — no LookupByHash
	lookup.put(w.v2)
	lookup.put(w.www2)

	cfg := transferConfig(t, w.tldID)
	r := newResolver(cfg, lookup, nil)
	q := dns.Question{Name: "www.footld.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	rrs, rcode, aa, err := r.ResolveQuestion(context.Background(), q)
	if err != nil {
		t.Fatalf("ResolveQuestion: unexpected err: %v", err)
	}
	if rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %d, want NXDOMAIN(%d) without a history source", rcode, dns.RcodeNameError)
	}
	if len(rrs) != 0 {
		t.Errorf("len(rrs) = %d, want 0", len(rrs))
	}
	if !aa {
		t.Error("a freens-route NXDOMAIN is still authoritative (aa=true)")
	}
}

// TestTransferredTLDRejectedWhenPredecessorMissing: the history source exists
// but cannot produce the predecessor (nil fetch) — the hand-off is
// unverifiable → NXDOMAIN.
func TestTransferredTLDRejectedWhenPredecessorMissing(t *testing.T) {
	w := newTransferredWorld(t, "footld")
	h := newFakeHistory()
	h.put(w.v2)
	h.put(w.www2)
	h.fail = true // LookupByHash: (nil, nil) for everything

	cfg := transferConfig(t, w.tldID)
	r := newResolver(cfg, h, nil)
	q := dns.Question{Name: "www.footld.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	rrs, rcode, _, err := r.ResolveQuestion(context.Background(), q)
	if err != nil {
		t.Fatalf("ResolveQuestion: unexpected err: %v", err)
	}
	if rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %d, want NXDOMAIN(%d) when the predecessor is unobtainable", rcode, dns.RcodeNameError)
	}
	if len(rrs) != 0 {
		t.Errorf("len(rrs) = %d, want 0", len(rrs))
	}
}

// TestTransferredTLDRejectedWhenPredecessorForeign: the history serves a
// v1 slot occupied by a THIRD-KEY record at the same name, and the transfer
// record points its prev_hash at it. Every signature is valid and the hash
// linkage is internally consistent, but the chain bottoms out at a "root"
// that is not self-certifying for the tld_id (SHA-256(K3) != tld_id) → the
// hand-off proves nothing → NXDOMAIN.
func TestTransferredTLDRejectedWhenPredecessorForeign(t *testing.T) {
	w := newTransferredWorld(t, "footld")

	// The foreign "v1": same name (zero labels, the real tld_id embedded),
	// owned and signed by an unrelated third key — valid envelope, wrong
	// authority.
	k3, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	v1Wire := append([]byte(nil), w.v1.Record.Name...)
	v1Foreign, err := wire.NewRecord(v1Wire, k3.Public(), 1, uint64(fixedNow-100), uint64(fixedNow+3600))
	if err != nil {
		t.Fatal(err)
	}
	v1ForeignEnv, err := wire.SignRecord(v1Foreign, k3)
	if err != nil {
		t.Fatal(err)
	}
	if !wire.IsBasicValid(v1ForeignEnv, uint64(fixedNow)) {
		t.Fatal("fixture: foreign predecessor must still be IsBasicValid")
	}
	hForeign, err := v1ForeignEnv.RecordHash()
	if err != nil {
		t.Fatal(err)
	}

	// v2f: the transfer record pointing at the foreign predecessor. K3 (the
	// record the fake history holds as "current" at that hop) signs it, so
	// the per-hop owner/signer linkage is satisfied and only the terminal
	// self-certification can (and must) reject the walk.
	v2fRec, err := wire.NewRecord(append([]byte(nil), w.v2.Record.Name...), w.k2.Public(), 2, uint64(fixedNow-50), uint64(fixedNow+3600))
	if err != nil {
		t.Fatal(err)
	}
	v2fRec.Delegation = w.k2.Public()
	v2fRec.PrevHash = hForeign
	v2f, err := wire.SignRecord(v2fRec, k3)
	if err != nil {
		t.Fatal(err)
	}
	if !wire.IsBasicValid(v2f, uint64(fixedNow)) {
		t.Fatal("fixture: foreign-linked transfer record must be IsBasicValid")
	}

	h := newFakeHistory()
	h.put(v2f)
	h.put(w.www2)
	h.putByHash(t, v1ForeignEnv) // obtainable by hash — and still rejected

	cfg := transferConfig(t, w.tldID)
	r := newResolver(cfg, h, nil)
	q := dns.Question{Name: "www.footld.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	rrs, rcode, _, err := r.ResolveQuestion(context.Background(), q)
	if err != nil {
		t.Fatalf("ResolveQuestion: unexpected err: %v", err)
	}
	if rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %d, want NXDOMAIN(%d) for a third-key predecessor", rcode, dns.RcodeNameError)
	}
	if len(rrs) != 0 {
		t.Errorf("len(rrs) = %d, want 0", len(rrs))
	}
}

// TestTransferredTLDTamperedPrevHashRejected: the transfer record carries a
// prev_hash that matches NO obtainable predecessor (first byte flipped), so
// even with the true v1 in history the walk cannot link v2 to it → NXDOMAIN.
func TestTransferredTLDTamperedPrevHashRejected(t *testing.T) {
	w := newTransferredWorld(t, "footld")

	// v2t: identical transfer record except a corrupted prev_hash, correctly
	// re-signed by K1 (the envelope itself stays fully valid).
	badPrev := append([]byte(nil), w.v2.Record.PrevHash...)
	badPrev[0] ^= 0xff
	rec := *w.v2.Record // shallow copy: only PrevHash differs
	rec.PrevHash = badPrev
	v2t, err := wire.SignRecord(&rec, w.k1)
	if err != nil {
		t.Fatal(err)
	}
	if !wire.IsBasicValid(v2t, uint64(fixedNow)) {
		t.Fatal("fixture: tampered transfer record must be IsBasicValid")
	}

	h := newFakeHistory()
	h.put(v2t)
	h.put(w.www2)
	h.putByHash(t, w.v1) // the true predecessor IS available by its own hash

	cfg := transferConfig(t, w.tldID)
	r := newResolver(cfg, h, nil)
	q := dns.Question{Name: "www.footld.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	rrs, rcode, _, err := r.ResolveQuestion(context.Background(), q)
	if err != nil {
		t.Fatalf("ResolveQuestion: unexpected err: %v", err)
	}
	if rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %d, want NXDOMAIN(%d) for a tampered prev_hash", rcode, dns.RcodeNameError)
	}
	if len(rrs) != 0 {
		t.Errorf("len(rrs) = %d, want 0", len(rrs))
	}
}

// TestUntransferredTLDStillResolves is the regression guard: a source that
// DOES implement HistoryResolver must not alter the ordinary self-certifying
// path — chain[0].Signer == chain[0].Record.Owner keeps using plain
// VerifyAuthorityChain (zero behavior change).
func TestUntransferredTLDStillResolves(t *testing.T) {
	w := newFreensWorld(t)
	h := newFakeHistory() // implements HistoryResolver; must not matter
	h.put(w.tldEnv)
	h.put(w.wwwEnv)

	rrs, rcode, aa, err := resolveWwwFootld(t, w.tldID, h)
	if err != nil {
		t.Fatalf("ResolveQuestion: unexpected err: %v", err)
	}
	if rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR(%d) for the un-transferred world", rcode, dns.RcodeSuccess)
	}
	if len(rrs) != 1 || !rrs[0].(*dns.A).A.Equal(w.wwwIPv4) {
		t.Errorf("rrs = %v, want one A %s", rrs, w.wwwIPv4)
	}
	if !aa {
		t.Error("freens-routed answer must be authoritative (aa=true)")
	}
}
