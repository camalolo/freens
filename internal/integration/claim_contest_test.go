// Package integration — claim_contest_test.go is the §7.4/§7.5 contested-alias
// end-to-end: two peered nodes each hold a DIFFERENT fully-valid claim for the
// same alias under K_claim (simulated split state — each node's §6.4 store
// winner is a different claimant), plus their own K_tld and K_name records. A
// third node's resolver must resolve www.<alias> to the §7.4 deterministic
// winner's A record — the earliest claimant timestamp — from BOTH assignments
// of the two claims to the two storing nodes (deterministic convergence: the
// answer is a function of claim contents, not of which node holds what).
package integration

import (
	"context"
	"net"
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

// contestWorld is one claimant's complete §7.4/C.1 registration output: the
// claim-carrying TLD envelope (K_tld and K_claim) and the www A record
// (K_name), mined at low difficulty with W out-of-band witnesses.
type contestWorld struct {
	tldEnv  *wire.SignedEnvelope
	wwwEnv  *wire.SignedEnvelope
	kClaim  []byte
	kTld    []byte
	kName   []byte
	wwwIPv4 net.IP
}

// buildContestWorld registers alias for a fresh claimant whose claim asserts
// claimTS. It is publishClaimWorld split in two (build + place) so the two
// competing worlds can be assigned to storing nodes in either order.
func buildContestWorld(t *testing.T, alias string, now, claimTS int64, ip net.IP) *contestWorld {
	t.Helper()

	// §7.4 steps 1-2: self-certifying TLD keypair; mine the PoW (difficulty 8).
	claimant, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	tldID, err := crypto.TldID(claimant.Public())
	if err != nil {
		t.Fatal(err)
	}
	claim, err := claims.MineAliasClaim(alias, claimant, uint64(claimTS), 8, 2_000_000, 16)
	if err != nil {
		t.Fatalf("MineAliasClaim: %v", err)
	}

	// Steps 3-4: W distinct witness attestations (§7.3 quorum), gathered out
	// of band as publishClaimWorld does.
	ph, err := claim.PrefixHash()
	if err != nil {
		t.Fatalf("PrefixHash: %v", err)
	}
	atts := make([]*claims.WitnessAttestation, 0, constants.W)
	for i := 0; i < constants.W; i++ {
		wkp, err := crypto.Generate()
		if err != nil {
			t.Fatal(err)
		}
		w, err := claims.NewWitnessAttestation(wkp, uint64(claimTS)+uint64(i), ph)
		if err != nil {
			t.Fatalf("NewWitnessAttestation: %v", err)
		}
		atts = append(atts, w)
	}
	claim.Witnesses = atts

	// Step 5: TLD record with the claim embedded (field 11), signed by SK_tld.
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
	aRR, err := wire.A(ip.To4(), 300)
	if err != nil {
		t.Fatal(err)
	}
	wwwRec.RRset = []*wire.RR{aRR}
	wwwEnv, err := wire.SignRecord(wwwRec, claimant)
	if err != nil {
		t.Fatal(err)
	}

	kClaim, err := dht.KeyForClaim(alias)
	if err != nil {
		t.Fatal(err)
	}
	kTld, err := dht.KeyForWireName(tldWire)
	if err != nil {
		t.Fatal(err)
	}
	return &contestWorld{
		tldEnv: tldEnv, wwwEnv: wwwEnv,
		kClaim: kClaim, kTld: kTld, kName: naming.DHTKeyName(wwwWire),
		wwwIPv4: ip,
	}
}

// hold seeds one node's store with a world's three envelopes (the -load
// pattern: local puts only, so the peering nodes must fetch over the network).
func hold(t *testing.T, n *claimTestNode, w *contestWorld, now int64) {
	t.Helper()
	for _, put := range []struct {
		key []byte
		env *wire.SignedEnvelope
	}{
		{w.kTld, w.tldEnv}, {w.kClaim, w.tldEnv}, {w.kName, w.wwwEnv},
	} {
		if ok, err := n.store.Put(put.key, put.env, now, true); err != nil || !ok {
			t.Fatalf("local put: ok=%v err=%v", ok, err)
		}
	}
}

// TestClaimContestDeterministicConvergence — THE cross-node §7.4 test. Nodes
// A and B are peered and each holds a DIFFERENT valid claim for "contest"
// under the SAME K_claim (split state). Node C (peered with both) resolves
// www.contest through dht.DHTLookup — a ClaimSetResolver, so the resolver
// COLLECTS both claims, applies the §7.4 ordering, and answers with the
// earliest-timestamp claimant's A record. The two subtests swap which claim
// lives on which storing node: the answer must not change (convergence
// without consensus, spec lines 613-615).
func TestClaimContestDeterministicConvergence(t *testing.T) {
	withFastPoW(t)
	const now int64 = 2_000_000
	const alias = "contest"

	for _, tc := range []struct {
		name    string
		swapped bool
	}{
		{name: "early claim on A, late claim on B"},
		{name: "swapped: late claim on A, early claim on B", swapped: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			// Two claimants race within SKEW_TOLERANCE (§7.5): ts and ts+1.
			early := buildContestWorld(t, alias, now, now-50, net.IPv4(203, 0, 113, 10))
			late := buildContestWorld(t, alias, now, now-49, net.IPv4(203, 0, 113, 20))

			a := startClaimNode(t, now)
			b := startClaimNode(t, now)
			c := startClaimNode(t, now)
			defer a.node.Close()
			defer b.node.Close()
			defer c.node.Close()
			peerClaimNodes(t, a, b)
			peerClaimNodes(t, a, c)
			peerClaimNodes(t, b, c)

			onA, onB := early, late
			if tc.swapped {
				onA, onB = late, early
			}
			hold(t, a, onA, now)
			hold(t, b, onB, now)

			// C's resolver: freens route for the alias, nothing pinned.
			// dht.DHTLookup is both ClaimResolver and ClaimSetResolver, so
			// the resolver takes the §7.4 set path automatically.
			lookup := dht.NewDHTLookup(c.store, c.node)
			cfg := &resolver.Config{
				ListenUDP: "127.0.0.1:0",
				ListenTCP: "127.0.0.1:0",
				TLDRoutes: map[string]resolver.Route{alias: resolver.RouteFREENS, "*": resolver.RouteDNSFirst},
				AliasPins: map[string][]byte{},
			}
			res := resolver.New(cfg, lookup, nil)
			res.Now = func() int64 { return now }

			// Precondition: C holds nothing of either world.
			for i, k := range [][]byte{early.kClaim, early.kTld, early.kName, late.kClaim, late.kTld, late.kName} {
				if c.store.Has(k, now) {
					t.Fatalf("precondition: C already holds key %d", i)
				}
			}

			q := dns.Question{Name: "www." + alias + ".", Qtype: dns.TypeA, Qclass: dns.ClassINET}
			rrs, rcode, aa, err := res.ResolveQuestion(ctx, q)
			if err != nil {
				t.Fatalf("ResolveQuestion: %v", err)
			}
			if rcode != dns.RcodeSuccess || len(rrs) != 1 {
				t.Fatalf("rcode=%d len=%d, want NOERROR/1", rcode, len(rrs))
			}
			aRR, ok := rrs[0].(*dns.A)
			if !ok {
				t.Fatalf("rrs[0] = %T, want *dns.A", rrs[0])
			}
			if !aa {
				t.Error("freens-routed answer must be authoritative (aa=true)")
			}
			// Deterministic convergence: the earliest-timestamp claimant wins
			// regardless of which physical node held which claim.
			if !aRR.A.Equal(early.wwwIPv4) {
				t.Errorf("resolver A = %s, want the §7.4 winner's %s (earliest ts)", aRR.A, early.wwwIPv4)
			}
			if aRR.A.Equal(late.wwwIPv4) {
				t.Error("resolver answered with the later-timestamp claimant's record")
			}

			// §7.5 + §10.4: the winner is CONTEST_WINDOW-young, so the answer
			// TTL is capped at 60 s even though the www record says 300.
			if aRR.Header().Ttl > 60 {
				t.Errorf("contested winner TTL = %d, want <= 60 (§10.4 contested caching)", aRR.Header().Ttl)
			}
		})
	}
}
