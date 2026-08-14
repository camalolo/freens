// Package integration — claim_resolution_test.go is the §7 + §9.2 step-3a
// end-to-end: a claim published on node A (K_tld + K_claim + K_name) resolves
// from node B over the network with NO local pin, B's cache serves a second
// resolution after A disappears, and a broken-witness claim NXDOMAINs.
package integration

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/laurent/freens/internal/claims"
	"github.com/laurent/freens/internal/constants"
	"github.com/laurent/freens/internal/crypto"
	"github.com/laurent/freens/internal/dht"
	"github.com/laurent/freens/internal/naming"
	"github.com/laurent/freens/internal/resolver"
	"github.com/laurent/freens/internal/wire"
	"github.com/miekg/dns"
)

// testLogger discards node log output so the DHT info lines (e.g. witnessing)
// do not clutter test output.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// claimTestNode starts one loopback DHT node with a fixed clock and the
// background loops disabled (nothing here depends on refresh/republish).
type claimTestNode struct {
	node  *dht.Node
	store *dht.EnvelopeStore
	kp    *crypto.Keypair
}

func startClaimNode(t *testing.T, now int64) *claimTestNode {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	store := dht.NewEnvelopeStore(0, func() int64 { return now })
	node, err := dht.NewNode(dht.NodeConfig{
		Keypair:               kp,
		ListenAddr:            "127.0.0.1:0",
		Store:                 store,
		Logger:                testLogger(),
		Now:                   func() int64 { return now },
		BucketRefreshInterval: -1,
		RepublishInterval:     -1,
	})
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	if err := node.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	return &claimTestNode{node: node, store: store, kp: kp}
}

// peerClaimNodes cross-seeds two nodes' routing tables (both directions, as
// -peers would).
func peerClaimNodes(t *testing.T, a, b *claimTestNode) {
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

// publishClaimWorld performs the §7.4/C.1 registration on node n for alias:
// mine a low-difficulty claim (witnesses assembled out of band, including n's
// own node keypair — simulating the §7.4 step-3 witness RPC round), embed it
// in the TLD record, and store the envelope at K_tld AND K_claim plus a www
// A record at K_name — LOCALLY ONLY (the -load pattern). Peering nodes must
// therefore fetch everything over the network (IterativeGet), which is the
// point of these tests; the on-the-wire Publish/PublishClaim path is covered
// by internal/dht (TestPublishStoresOnPeer / TestPublishClaimStoresAtKClaimOnPeer).
type claimWorld struct {
	tldEnv *wire.SignedEnvelope
	wwwEnv *wire.SignedEnvelope
	kClaim []byte
	kTld   []byte
	kName  []byte
}

func publishClaimWorld(t *testing.T, n *claimTestNode, alias string, now int64, breakWitness bool) *claimWorld {
	t.Helper()

	// 1-2. Self-certifying TLD keypair; mine the PoW (difficulty 8, fast).
	claimant, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	tldID, err := crypto.TldID(claimant.Public())
	if err != nil {
		t.Fatal(err)
	}
	claim, err := claims.MineAliasClaim(alias, claimant, uint64(now), 8, 2_000_000, 16)
	if err != nil {
		t.Fatalf("MineAliasClaim: %v", err)
	}

	// 3-4. Witness attestations (§7.3 quorum W = 5): the publishing node's own
	// keypair stands in for a gathered witness, plus W-1 fresh ones.
	witnessKPs := []*crypto.Keypair{n.kp}
	for len(witnessKPs) < constants.W {
		wkp, err := crypto.Generate()
		if err != nil {
			t.Fatal(err)
		}
		witnessKPs = append(witnessKPs, wkp)
	}
	atts := make([]*claims.WitnessAttestation, 0, len(witnessKPs))
	for i, wkp := range witnessKPs {
		w, err := claims.NewWitnessAttestation(wkp, uint64(now)+uint64(i), alias, tldID, claimant.Public())
		if err != nil {
			t.Fatalf("NewWitnessAttestation: %v", err)
		}
		atts = append(atts, w)
	}
	if breakWitness {
		atts[0].Sig[0] ^= 0xff // broken witness signature → quorum fails
	}
	claim.Witnesses = atts

	// 5. TLD record with the claim embedded (field 11), signed by SK_tld.
	tldWire, err := naming.EncodeWireName(nil, alias, tldID)
	if err != nil {
		t.Fatal(err)
	}
	tldRec, err := wire.NewRecord(tldWire, claimant.Public(), 1, uint64(now), uint64(now+constants.RecordDefaultTTL))
	if err != nil {
		t.Fatal(err)
	}
	cb, err := claim.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	tldRec.Claim = cb
	tldEnv, err := wire.SignRecord(tldRec, claimant)
	if err != nil {
		t.Fatal(err)
	}

	// www.<alias> A record, direct-signed by the TLD key.
	wwwWire, err := naming.EncodeWireName([]string{"www"}, alias, tldID)
	if err != nil {
		t.Fatal(err)
	}
	wwwRec, err := wire.NewRecord(wwwWire, claimant.Public(), 1, uint64(now), uint64(now+constants.RecordDefaultTTL))
	if err != nil {
		t.Fatal(err)
	}
	aRR, err := wire.A([]byte{203, 0, 113, 42}, 300)
	if err != nil {
		t.Fatal(err)
	}
	wwwRec.RRset = []*wire.RR{aRR}
	wwwEnv, err := wire.SignRecord(wwwRec, claimant)
	if err != nil {
		t.Fatal(err)
	}

	// Publish: locally (as -load would) AND to the peers (§6.4 PUT), at all
	// three key spaces (§7.4 step 5 / C.1 step 4: K_tld AND K_claim).
	kClaim, err := dht.KeyForClaim(alias)
	if err != nil {
		t.Fatal(err)
	}
	kTld, err := dht.KeyForWireName(tldWire)
	if err != nil {
		t.Fatal(err)
	}
	kName := naming.DHTKeyName(wwwWire)
	for _, put := range []struct {
		key []byte
		env *wire.SignedEnvelope
	}{
		{kTld, tldEnv}, {kClaim, tldEnv}, {kName, wwwEnv},
	} {
		if ok, err := n.store.Put(put.key, put.env, now, true); err != nil || !ok {
			t.Fatalf("local put: ok=%v err=%v", ok, err)
		}
	}
	return &claimWorld{tldEnv: tldEnv, wwwEnv: wwwEnv, kClaim: kClaim, kTld: kTld, kName: kName}
}

// TestNetworkClaimResolution is THE cross-node §7 resolution test. Node A
// holds a fully registered alias; node B has NOTHING pinned and must fetch
// the claim from the network to resolve. Then A is killed and B's cache
// serves the same answer.
func TestNetworkClaimResolution(t *testing.T) {
	withFastPoW(t)
	const now int64 = 2_000_000
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	a := startClaimNode(t, now)
	b := startClaimNode(t, now)
	defer b.node.Close()
	peerClaimNodes(t, a, b)

	const alias = "netfoo"
	world := publishClaimWorld(t, a, alias, now, false /* intact witnesses */)

	// B's resolver: freens route for the alias, NO pins — the §7 claim layer
	// must carry the alias alone (dht.DHTLookup also implements
	// resolver.ClaimResolver; the resolver picks that up by type assertion).
	lookup := dht.NewDHTLookup(b.store, b.node)
	cfg := &resolver.Config{
		ListenUDP: "127.0.0.1:0",
		ListenTCP: "127.0.0.1:0",
		TLDRoutes: map[string]resolver.Route{alias: resolver.RouteFREENS, "*": resolver.RouteDNSFirst},
		AliasPins: map[string][]byte{}, // nothing pinned
	}
	res := resolver.New(cfg, lookup, nil)
	res.Now = func() int64 { return now }

	// Precondition: B holds none of the three keys yet.
	for i, k := range [][]byte{world.kClaim, world.kTld, world.kName} {
		if b.store.Has(k, now) {
			t.Fatalf("precondition: B already holds key %d", i)
		}
	}

	// --- 1st resolution: over the network -----------------------------
	q := dns.Question{Name: "www." + alias + ".", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	rrs, rcode, aa, err := res.ResolveQuestion(ctx, q)
	if err != nil {
		t.Fatalf("ResolveQuestion (network): %v", err)
	}
	if rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR(%d)", rcode, dns.RcodeSuccess)
	}
	if len(rrs) != 1 {
		t.Fatalf("len(rrs) = %d, want 1", len(rrs))
	}
	aRR, ok := rrs[0].(*dns.A)
	if !ok {
		t.Fatalf("rrs[0] = %T, want *dns.A", rrs[0])
	}
	if !aRR.A.Equal(net.IPv4(203, 0, 113, 42)) {
		t.Errorf("resolver A = %s, want 203.0.113.42", aRR.A)
	}
	if !aa {
		t.Error("freens-routed answer must be authoritative (aa=true)")
	}

	// --- the claim envelope is now cached in B's store ----------------
	if !b.store.Has(world.kClaim, now) {
		t.Fatal("claim envelope was not cached in B's local store (LookupClaim cache step)")
	}
	if !b.store.Has(world.kTld, now) || !b.store.Has(world.kName, now) {
		t.Fatal("chain envelopes missing from B's local store")
	}

	// --- 2nd resolution: served from B's cache, A gone ----------------
	if err := a.node.Close(); err != nil {
		t.Fatalf("close A: %v", err)
	}
	rrs2, rcode2, _, err := res.ResolveQuestion(ctx, q)
	if err != nil {
		t.Fatalf("ResolveQuestion (cached): %v", err)
	}
	if rcode2 != dns.RcodeSuccess || len(rrs2) != 1 {
		t.Fatalf("cached resolution: rcode=%d len=%d, want NOERROR/1", rcode2, len(rrs2))
	}
	a2, ok := rrs2[0].(*dns.A)
	if !ok || !a2.A.Equal(net.IPv4(203, 0, 113, 42)) {
		t.Fatalf("cached resolution returned %v, want 203.0.113.42", rrs2)
	}
}

// TestNetworkClaimBrokenWitnessNXDOMAIN: a claim whose witness signature is
// broken publishes just fine (the DHT stores signed envelopes, §6.4 — it does
// not adjudicate claims, §6.5), but the resolver's §7.4 verification rejects
// it → the freens branch misses → NXDOMAIN.
func TestNetworkClaimBrokenWitnessNXDOMAIN(t *testing.T) {
	withFastPoW(t)
	const now int64 = 2_000_000
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	a := startClaimNode(t, now)
	b := startClaimNode(t, now)
	defer a.node.Close()
	defer b.node.Close()
	peerClaimNodes(t, a, b)

	const alias = "brokenfoo"
	publishClaimWorld(t, a, alias, now, true /* break a witness signature */)

	lookup := dht.NewDHTLookup(b.store, b.node)
	cfg := &resolver.Config{
		ListenUDP: "127.0.0.1:0",
		ListenTCP: "127.0.0.1:0",
		TLDRoutes: map[string]resolver.Route{alias: resolver.RouteFREENS, "*": resolver.RouteDNSFirst},
		AliasPins: map[string][]byte{},
	}
	res := resolver.New(cfg, lookup, nil)
	res.Now = func() int64 { return now }

	q := dns.Question{Name: "www." + alias + ".", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	rrs, rcode, aa, err := res.ResolveQuestion(ctx, q)
	if err != nil {
		t.Fatalf("ResolveQuestion: %v", err)
	}
	if rcode != dns.RcodeNameError {
		t.Errorf("rcode = %d, want NXDOMAIN(%d) for a broken-witness claim", rcode, dns.RcodeNameError)
	}
	if len(rrs) != 0 {
		t.Errorf("len(rrs) = %d, want 0", len(rrs))
	}
	if !aa {
		t.Error("a freens-route NXDOMAIN is still authoritative (aa=true)")
	}
}
