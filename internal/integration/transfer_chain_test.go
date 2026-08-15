// transfer_chain_test.go — the §8.3 whole-TLD transfer, end to end over real
// loopback DHT nodes (spec lines 666-687). Node A registers the "xfera"
// alias, R resolves www.xfera from the network, then A TRANSFERS the TLD to a
// fresh key (v2: owner = K2, signer = K1 — "The network accepts the new
// record because the previous owner — whose key the current authority chain
// names — signed it", prev_hash = H_record(v1), sequence = prev + 1,
// delegation = K2) and re-signs www with K2. R must then resolve through the
// transfer walk, fetching the superseded v1 by hash ("prev_hash links the
// transfer into an auditable chain so third parties can verify the hand-off
// history offline") — and a node that NEVER saw v1 must fetch it from A's
// history over the network. A tampered prev_hash must NXDOMAIN.
package integration

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/claims"
	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/dht"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/resolver"
	"github.com/camalolo/freens/internal/wire"
	"github.com/miekg/dns"
)

// xferClock is a mutable shared wall clock: the DHT stores, nodes, and
// resolvers all read it, and the test ADVANCES it past the DHTLookup cache
// freshness windows (the records carry 10 s RRs, so +60 s stales every
// cached hop) to force re-fetches after the transfer — the fixture analogue
// of waiting out the TTL.
type xferClock struct {
	mu sync.Mutex
	v  int64
}

func (c *xferClock) Now() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.v
}

func (c *xferClock) Advance(d int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.v += d
}

// xferNode is one loopback DHT node with the background loops disabled
// (nothing here depends on refresh/republish), same shape as claimTestNode.
type xferNode struct {
	node  *dht.Node
	store *dht.EnvelopeStore
	kp    *crypto.Keypair
}

func startXferNode(t *testing.T, clk *xferClock) *xferNode {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	store := dht.NewEnvelopeStore(0, clk.Now)
	node, err := dht.NewNode(dht.NodeConfig{
		Keypair:               kp,
		ListenAddr:            "127.0.0.1:0",
		Store:                 store,
		Logger:                testLogger(),
		Now:                   clk.Now,
		BucketRefreshInterval: -1,
		RepublishInterval:     -1,
	})
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	if err := node.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = node.Close() })
	return &xferNode{node: node, store: store, kp: kp}
}

// peerXferNodes cross-seeds two nodes' routing tables (both directions).
func peerXferNodes(t *testing.T, a, b *xferNode) {
	t.Helper()
	aAddr, err := a.node.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	bAddr, err := b.node.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.node.AddPeer(b.node.PublicKey(), bAddr.String()); err != nil {
		t.Fatal(err)
	}
	if err := b.node.AddPeer(a.node.PublicKey(), aAddr.String()); err != nil {
		t.Fatal(err)
	}
}

// xferResolver builds a resolver over lookup routing alias → freens with NO
// pins (the §7 claim layer must carry the alias alone) and the shared clock.
func xferResolver(clk *xferClock, lookup *dht.DHTLookup, alias string) *resolver.Resolver {
	cfg := &resolver.Config{
		ListenUDP: "127.0.0.1:0",
		ListenTCP: "127.0.0.1:0",
		TLDRoutes: map[string]resolver.Route{alias: resolver.RouteFREENS, "*": resolver.RouteDNSFirst},
		AliasPins: map[string][]byte{}, // nothing pinned
	}
	res := resolver.New(cfg, lookup, nil)
	res.Now = clk.Now
	return res
}

// xferWorld is the alias "xfera" through a whole-TLD transfer:
//
//   - v1: self-certifying TLD record (owner = signer = K1) carrying the mined
//   - W-witnessed claim, and www1 signed by K1 — the §7.4/C.1 registration;
//   - v2: the §8.3 transfer record (owner K2, PREVIOUS owner K1 signs,
//     sequence 2, prev_hash = H_record(v1), delegation = K2 — "For a
//     whole-TLD transfer, the same operation on the TLD record transfers the
//     alias and all undelegated names at once"), still carrying the claim;
//   - www2: www re-signed by K2 (authorized by v2's Owner and Delegation).
//
// All RRs carry TTL 10 so a +60 s clock advance stales every DHTLookup cache
// entry (cache freshness = min RR TTL).
type xferWorld struct {
	k1, k2      *crypto.Keypair
	tldID       []byte
	alias       string
	tldWire     []byte
	wwwWire     []byte
	claimBytes  []byte
	v1, v2      *wire.SignedEnvelope
	www1, www2  *wire.SignedEnvelope
	kTld, kName []byte
}

var (
	xferIP1 = []byte{203, 0, 113, 42} // pre-transfer answer
	xferIP2 = []byte{203, 0, 113, 99} // post-transfer answer
)

// buildXferWorld registers the v1 world LOCALLY on A (the -load pattern: the
// peering node must fetch everything over the network) and returns it.
func buildXferWorld(t *testing.T, a *xferNode, alias string, now int64) *xferWorld {
	t.Helper()
	w := &xferWorld{alias: alias}

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

	// §7.3 mine (difficulty 8, fast) + W witnesses, A's own key included —
	// the out-of-band stand-in for the §7.4 step-3 witness RPC round.
	claim, err := claims.MineAliasClaim(alias, k1, uint64(now), 8, 2_000_000, 16)
	if err != nil {
		t.Fatalf("MineAliasClaim: %v", err)
	}
	witnessKPs := []*crypto.Keypair{a.kp}
	for len(witnessKPs) < constants.W {
		wkp, err := crypto.Generate()
		if err != nil {
			t.Fatal(err)
		}
		witnessKPs = append(witnessKPs, wkp)
	}
	atts := make([]*claims.WitnessAttestation, 0, len(witnessKPs))
	for i, wkp := range witnessKPs {
		att, err := claims.NewWitnessAttestation(wkp, uint64(now)+uint64(i), alias, tldID, k1.Public())
		if err != nil {
			t.Fatalf("NewWitnessAttestation: %v", err)
		}
		atts = append(atts, att)
	}
	claim.Witnesses = atts
	cb, err := claim.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	w.claimBytes = cb

	w.tldWire, err = naming.EncodeWireName(nil, alias, tldID)
	if err != nil {
		t.Fatal(err)
	}
	w.wwwWire, err = naming.EncodeWireName([]string{"www"}, alias, tldID)
	if err != nil {
		t.Fatal(err)
	}

	// v1: the TLD record with the claim embedded, plus a TTL-10 TXT so the
	// DHTLookup cache freshness of K_tld/K_claim is 10 s.
	v1Rec, err := wire.NewRecord(w.tldWire, k1.Public(), 1, uint64(now), uint64(now+constants.RecordDefaultTTL))
	if err != nil {
		t.Fatal(err)
	}
	v1Rec.Claim = cb
	txt, err := wire.TXT("freens-tld-v1", 10)
	if err != nil {
		t.Fatal(err)
	}
	v1Rec.RRset = []*wire.RR{txt}
	w.v1, err = wire.SignRecord(v1Rec, k1)
	if err != nil {
		t.Fatal(err)
	}

	// www1: signed by the (sole) current authority K1.
	www1Rec, err := wire.NewRecord(w.wwwWire, k1.Public(), 1, uint64(now), uint64(now+constants.RecordDefaultTTL))
	if err != nil {
		t.Fatal(err)
	}
	a1, err := wire.A(xferIP1, 10)
	if err != nil {
		t.Fatal(err)
	}
	www1Rec.RRset = []*wire.RR{a1}
	w.www1, err = wire.SignRecord(www1Rec, k1)
	if err != nil {
		t.Fatal(err)
	}

	// Sanity: the pre-transfer world fully verifies per §3.4.
	if !wire.VerifyAuthorityChain([]*wire.SignedEnvelope{w.v1, w.www1}) {
		t.Fatal("fixture: v1 world must verify before the transfer")
	}

	kTld, err := dht.KeyForWireName(w.tldWire)
	if err != nil {
		t.Fatal(err)
	}
	kClaim, err := dht.KeyForClaim(alias)
	if err != nil {
		t.Fatal(err)
	}
	w.kTld, w.kName = kTld, naming.DHTKeyName(w.wwwWire)
	for _, put := range []struct {
		key []byte
		env *wire.SignedEnvelope
	}{
		{kTld, w.v1}, {kClaim, w.v1}, {w.kName, w.www1},
	} {
		if ok, err := a.store.Put(put.key, put.env, now, true); err != nil || !ok {
			t.Fatalf("local put: ok=%v err=%v", ok, err)
		}
	}
	return w
}

// transferXferWorld performs the §8.3 whole-TLD transfer on A at `now`: it
// mints v2 + www2 (mintTransfer) and propagates them (publishTransfer).
func transferXferWorld(t *testing.T, a *xferNode, w *xferWorld, now int64) {
	t.Helper()
	mintTransfer(t, a, w, now)
	publishTransfer(t, a, w)
}

// mintTransfer creates the §8.3 v2 transfer record (owner K2, PREVIOUS owner
// K1 signs, sequence 2, prev_hash = H_record(v1), delegation = K2 — "For a
// whole-TLD transfer, the same operation on the TLD record transfers the
// alias and all undelegated names at once", still carrying the claim) and the
// K2-signed www2, then supersedes v1/www1 in A's LOCAL store: the superseded
// envelopes move into A's §8.3 audit history keyed by their H_record — the
// LookupByHash source, local and to the network's get-by-hash.
func mintTransfer(t *testing.T, a *xferNode, w *xferWorld, now int64) {
	t.Helper()

	h1, err := w.v1.RecordHash() // H_record(v1), §4.2
	if err != nil {
		t.Fatal(err)
	}

	v2Rec, err := wire.NewRecord(w.tldWire, w.k2.Public(), 2, uint64(now), uint64(now+constants.RecordDefaultTTL))
	if err != nil {
		t.Fatal(err)
	}
	v2Rec.Delegation = w.k2.Public() // "subtree authority follows"
	v2Rec.PrevHash = h1              // the auditable hand-off link
	v2Rec.Claim = w.claimBytes       // the alias follows the TLD (§8.3)
	txt, err := wire.TXT("freens-tld-v2", 10)
	if err != nil {
		t.Fatal(err)
	}
	v2Rec.RRset = []*wire.RR{txt}
	w.v2, err = wire.SignRecord(v2Rec, w.k1) // the PREVIOUS owner signs
	if err != nil {
		t.Fatal(err)
	}

	www2Rec, err := wire.NewRecord(w.wwwWire, w.k2.Public(), 2, uint64(now), uint64(now+constants.RecordDefaultTTL))
	if err != nil {
		t.Fatal(err)
	}
	a2, err := wire.A(xferIP2, 10)
	if err != nil {
		t.Fatal(err)
	}
	www2Rec.RRset = []*wire.RR{a2}
	w.www2, err = wire.SignRecord(www2Rec, w.k2) // the NEW owner signs
	if err != nil {
		t.Fatal(err)
	}

	// Sanity: the transferred world FAILS the plain §3.4 verifier but every
	// envelope is individually valid — exactly the resolver-side §8.3 gap.
	if wire.VerifyAuthorityChain([]*wire.SignedEnvelope{w.v2, w.www2}) {
		t.Fatal("fixture: plain VerifyAuthorityChain must reject the transferred root")
	}
	for _, env := range []*wire.SignedEnvelope{w.v2, w.www2} {
		if !wire.IsBasicValid(env, uint64(now)) {
			t.Fatal("fixture: post-transfer envelope not IsBasicValid")
		}
	}

	// Local supersede on A at all three key spaces (K_tld, K_claim, K_name).
	kClaim, err := dht.KeyForClaim(w.alias)
	if err != nil {
		t.Fatal(err)
	}
	for _, put := range []struct {
		key []byte
		env *wire.SignedEnvelope
	}{
		{w.kTld, w.v2}, {kClaim, w.v2}, {w.kName, w.www2},
	} {
		if ok, err := a.store.Put(put.key, put.env, now, true); err != nil || !ok {
			t.Fatalf("local supersede put: ok=%v err=%v", ok, err)
		}
	}
}

// publishTransfer propagates the transferred world to A's peers (§6.4 PUT:
// v2 at K_tld AND K_claim, www2 at K_name), pushing R's store onto v2 as well.
func publishTransfer(t *testing.T, a *xferNode, w *xferWorld) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := a.node.Publish(ctx, w.v2); err != nil {
		t.Fatalf("Publish(v2): %v", err)
	}
	if err := a.node.PublishClaim(ctx, w.v2); err != nil {
		t.Fatalf("PublishClaim(v2): %v", err)
	}
	if err := a.node.Publish(ctx, w.www2); err != nil {
		t.Fatalf("Publish(www2): %v", err)
	}
}

// resolveWwwXfera asks www.<alias>. A and checks the whole answer shape.
func resolveWwwXfera(t *testing.T, ctx context.Context, res *resolver.Resolver, alias string, wantIP []byte, where string) {
	t.Helper()
	q := dns.Question{Name: "www." + alias + ".", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	rrs, rcode, aa, err := res.ResolveQuestion(ctx, q)
	if err != nil {
		t.Fatalf("ResolveQuestion (%s): %v", where, err)
	}
	if rcode != dns.RcodeSuccess {
		t.Fatalf("(%s) rcode = %d, want NOERROR(%d)", where, rcode, dns.RcodeSuccess)
	}
	if len(rrs) != 1 {
		t.Fatalf("(%s) len(rrs) = %d, want 1", where, len(rrs))
	}
	a, ok := rrs[0].(*dns.A)
	if !ok {
		t.Fatalf("(%s) rrs[0] = %T, want *dns.A", where, rrs[0])
	}
	if !a.A.Equal(wantIP) {
		t.Errorf("(%s) A.A = %s, want %s", where, a.A, wantIP)
	}
	if !aa {
		t.Errorf("(%s) freens-routed answer must be authoritative (aa=true)", where)
	}
}

// TestTransferredTLDChainResolution is THE §8.3 cross-node transfer test:
//
//  1. R (resolver side, peered to A) resolves www.xfera from the network in
//     the v1 world — warming every cache R has (claim, K_tld, K_name).
//  2. A transfers the TLD to K2 and re-signs www; the clock advances past
//     every cache-freshness window. R re-resolves with the SAME resolver and
//     lookup: chain[0] is now the transfer record, and the walk must fetch
//     the superseded v1 by hash (R's own retained history or A's).
//  3. A fresh node C, peered ONLY to A, never saw v1 at all — its
//     LookupByHash must fetch v1 from A's history over the network.
func TestTransferredTLDChainResolution(t *testing.T) {
	withFastPoW(t)
	clk := &xferClock{v: 2_000_000}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	const alias = "xfera"
	a := startXferNode(t, clk)
	r := startXferNode(t, clk)
	peerXferNodes(t, a, r)

	w := buildXferWorld(t, a, alias, clk.Now())

	// --- 1: the v1 world, fetched over the network ----------------------
	rLookup := dht.NewDHTLookup(r.store, r.node)
	res := xferResolver(clk, rLookup, alias)
	resolveWwwXfera(t, ctx, res, alias, xferIP1, "R pre-transfer")

	// --- 2: A transfers; R walks the hand-off ---------------------------
	transferXferWorld(t, a, w, clk.Now())
	clk.Advance(60) // > the 10 s RR-TTL cache-freshness of every hop
	resolveWwwXfera(t, ctx, res, alias, xferIP2, "R post-transfer")

	// --- 3: fresh node C never saw v1 ------------------------------------
	c := startXferNode(t, clk)
	peerXferNodes(t, c, a) // C's ONLY peer is A: the history fetch must cross the wire
	cLookup := dht.NewDHTLookup(c.store, c.node)
	cRes := xferResolver(clk, cLookup, alias)
	resolveWwwXfera(t, ctx, cRes, alias, xferIP2, "C fresh node")
}

// TestTransferredTLDTamperedPrevHashNXDOMAIN: a fresh node T holds a transfer
// record whose prev_hash points at an OBTAINABLE but WRONG envelope (H_record
// of the superseded www1, fetchable from A's §8.3 history). The hand-off
// links nothing that re-establishes self-certification (the predecessor is a
// one-label name, never the TLD root), so the resolver must NXDOMAIN the name
// even though every signature involved is valid. T is seeded directly (with
// no incumbent the store's §6.4 winner rule cannot catch the tamper) — the
// RESOLVER's §8.3 walk must.
func TestTransferredTLDTamperedPrevHashNXDOMAIN(t *testing.T) {
	withFastPoW(t)
	clk := &xferClock{v: 2_000_000}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	const alias = "xfera2"
	a := startXferNode(t, clk)
	w := buildXferWorld(t, a, alias, clk.Now())
	mintTransfer(t, a, w, clk.Now()) // A: v2 live; v1/www1 retained in history

	// The tampered root: a fully valid §8.3-shaped record (K2 owner, K1
	// signs, seq 2, delegation K2, claim intact) whose prev_hash is
	// H_record(www1) — a real envelope in A's history, but not the TLD
	// predecessor.
	now := clk.Now()
	hWWW1, err := w.www1.RecordHash()
	if err != nil {
		t.Fatal(err)
	}
	badRec, err := wire.NewRecord(w.tldWire, w.k2.Public(), 2, uint64(now), uint64(now+constants.RecordDefaultTTL))
	if err != nil {
		t.Fatal(err)
	}
	badRec.Delegation = w.k2.Public()
	badRec.PrevHash = hWWW1
	badRec.Claim = w.claimBytes
	badEnv, err := wire.SignRecord(badRec, w.k1)
	if err != nil {
		t.Fatal(err)
	}
	if !wire.IsBasicValid(badEnv, uint64(now)) {
		t.Fatal("fixture: tampered transfer record must be IsBasicValid")
	}

	// T: fresh node peered ONLY to A (the claim and the predecessor fetch
	// must cross the wire), holding the tampered root and the matching www2.
	tam := startXferNode(t, clk)
	peerXferNodes(t, tam, a)
	if ok, err := tam.store.Put(w.kTld, badEnv, now, true); err != nil || !ok {
		t.Fatalf("seed tampered root: ok=%v err=%v", ok, err)
	}
	if ok, err := tam.store.Put(w.kName, w.www2, now, true); err != nil || !ok {
		t.Fatalf("seed www2: ok=%v err=%v", ok, err)
	}

	res := xferResolver(clk, dht.NewDHTLookup(tam.store, tam.node), alias)
	q := dns.Question{Name: "www." + alias + ".", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	rrs, rcode, aa, err := res.ResolveQuestion(ctx, q)
	if err != nil {
		t.Fatalf("ResolveQuestion: %v", err)
	}
	if rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %d, want NXDOMAIN(%d) for a tampered prev_hash", rcode, dns.RcodeNameError)
	}
	if len(rrs) != 0 {
		t.Errorf("len(rrs) = %d, want 0", len(rrs))
	}
	if !aa {
		t.Error("a freens-route NXDOMAIN is still authoritative (aa=true)")
	}
}
