package resolver

// claims_window_test.go — the §8.4 ALIAS_REUSE_DELAY reuse window (v0.8.0):
// a dead-but-offered claim envelope is a tombstone; while
//
//	expires <= now < expires + ALIAS_REUSE_DELAY
//
// and no live claim's carrier OVERLAPS the dead lease (created before the
// death — an unbroken renewal chain), the resolver must select no winner
// (NXDOMAIN). The window is content-verified: a quorum-less fabrication
// (what a rogue node could pool at zero witness cost) must NOT lock an
// alias, and the lock must lift when the window closes or when a live
// overlapping carrier exists.

import (
	"net"
	"testing"

	"github.com/camalolo/freens/internal/claims"
	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/wire"
	"github.com/miekg/dns"
)

// windowedWorld is claimedWorld with a CALLER-chosen carrier validity window
// and an optional quorum sabotage: the tombstone fixture needs carriers that
// died at a controlled time (the stock builders always straddle the test
// clock), and the rogue-fabrication fixture needs a PoW-valid claim with NO
// witness quorum. The www record shares the window (only the re-claimer's is
// ever actually resolved).
func windowedWorld(t *testing.T, alias string, claimTS uint64, ip net.IP, created, expires int64, quorum bool) *claimedWorld {
	t.Helper()
	withFastPoW(t)
	w := &claimedWorld{wwwIPv4: ip}
	tldKP, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	w.tldKP = tldKP
	tldID, err := crypto.TldID(tldKP.Public())
	if err != nil {
		t.Fatal(err)
	}
	w.tldID = tldID
	claim, err := claims.MineAliasClaim(alias, tldKP, claimTS, 8, 2_000_000, 16)
	if err != nil {
		t.Fatalf("MineAliasClaim: %v", err)
	}
	if quorum {
		ph, err := claim.PrefixHash()
		if err != nil {
			t.Fatal(err)
		}
		witnesses := make([]*claims.WitnessAttestation, 0, constants.W)
		for i := 0; i < constants.W; i++ {
			wkp, err := crypto.Generate()
			if err != nil {
				t.Fatal(err)
			}
			att, err := claims.NewWitnessAttestation(wkp, claimTS+uint64(i), ph)
			if err != nil {
				t.Fatal(err)
			}
			witnesses = append(witnesses, att)
		}
		claim.Witnesses = witnesses
	}
	cb, err := claim.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	w.claim = claim

	tldWire, err := naming.EncodeWireName(nil, alias, tldID)
	if err != nil {
		t.Fatal(err)
	}
	tldRec, err := wire.NewRecord(tldWire, tldKP.Public(), 1, uint64(created), uint64(expires))
	if err != nil {
		t.Fatal(err)
	}
	tldRec.Claim = cb
	w.tldEnv, err = wire.SignRecord(tldRec, tldKP)
	if err != nil {
		t.Fatal(err)
	}

	wwwWire, err := naming.EncodeWireName([]string{"www"}, alias, tldID)
	if err != nil {
		t.Fatal(err)
	}
	wwwRec, err := wire.NewRecord(wwwWire, tldKP.Public(), 1, uint64(fixedNow-100), uint64(fixedNow+3600))
	if err != nil {
		t.Fatal(err)
	}
	wwwRec.RRset = []*wire.RR{{Type: wire.RRTypeA, TTL: 300, Rdata: ip.To4()}}
	w.wwwEnv, err = wire.SignRecord(wwwRec, tldKP)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// TestResolveQuestionReuseWindowLocksAlias: a fully-verified tombstone (died
// at fixedNow-50, window open for 30 d) plus a FRESH re-claimer whose carrier
// was created at/after the death ⇒ NXDOMAIN for the whole window.
func TestResolveQuestionReuseWindowLocksAlias(t *testing.T) {
	tomb := windowedWorld(t, "foo", uint64(fixedNow-1000), net.IPv4(203, 0, 113, 50),
		fixedNow-200, fixedNow-50, true) // dead 50 s ago: window open
	fresh := windowedWorld(t, "foo", uint64(fixedNow-10), net.IPv4(203, 0, 113, 51),
		fixedNow-30, fixedNow+3600, true) // created AFTER the death

	lookup := newFakeClaimSetLookup("foo", []*wire.SignedEnvelope{tomb.tldEnv, fresh.tldEnv}, tomb, fresh)
	rrs, rcode, err := resolveFoo(t, lookup)
	if err != nil {
		t.Fatalf("ResolveQuestion: %v", err)
	}
	if rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %d, want NXDOMAIN (alias inside its §8.4 reuse window)", rcode)
	}
	if len(rrs) != 0 {
		t.Fatalf("len(rrs) = %d, want 0 inside the window", len(rrs))
	}
}

// TestResolveQuestionReuseWindowAllowsOverlappingRenewal: the same tombstone,
// but the surviving claim's carrier was created BEFORE the death (an
// unbroken renewal chain / live competitor) ⇒ the alias resolves normally.
func TestResolveQuestionReuseWindowAllowsOverlappingRenewal(t *testing.T) {
	tomb := windowedWorld(t, "foo", uint64(fixedNow-1000), net.IPv4(203, 0, 113, 52),
		fixedNow-200, fixedNow-50, true)
	overlapping := windowedWorld(t, "foo", uint64(fixedNow-10), net.IPv4(203, 0, 113, 53),
		fixedNow-100, fixedNow+3600, true) // created BEFORE the death

	lookup := newFakeClaimSetLookup("foo", []*wire.SignedEnvelope{tomb.tldEnv, overlapping.tldEnv}, tomb, overlapping)
	rrs, rcode, err := resolveFoo(t, lookup)
	if err != nil {
		t.Fatalf("ResolveQuestion: %v", err)
	}
	if rcode != dns.RcodeSuccess || len(rrs) != 1 {
		t.Fatalf("rcode=%d len=%d, want NOERROR/1 (live carrier overlaps the dead lease)", rcode, len(rrs))
	}
	if a := rrs[0].(*dns.A); !a.A.Equal(overlapping.wwwIPv4) {
		t.Errorf("A.A = %s, want the overlapping carrier's %s", a.A, overlapping.wwwIPv4)
	}
}

// TestResolveQuestionReuseWindowSameIdentityResurrection (v0.9.1, the
// 2026-08-22 fleet deadlock): a verified tombstone whose OWN claim identity
// comes back on a live carrier created AFTER the death resolves normally —
// the claimant re-asserting its lapsed lease is ownership continuity (only
// the claimant key can sign the carrier; the PoW and attestations are the
// ones the alias was registered with). v0.8.0 refused this and locked every
// alias whose auto-renewal arrived one tick late.
func TestResolveQuestionReuseWindowSameIdentityResurrection(t *testing.T) {
	tomb := windowedWorld(t, "foo", uint64(fixedNow-1000), net.IPv4(203, 0, 113, 60),
		fixedNow-200, fixedNow-50, true) // dead 50 s ago: window open

	// Re-wrap the TOMBSTONE'S OWN claim (same identity, same witnesses) in
	// a fresh carrier created AFTER the death — the daemon auto-renew
	// shape (renewal.RenewEnvelope embeds prev.Record.Claim verbatim).
	cb, err := tomb.claim.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	freshRec, err := wire.NewRecord(tomb.tldEnv.Record.Name, tomb.tldKP.Public(),
		tomb.tldEnv.Record.Sequence+1, uint64(fixedNow-30), uint64(fixedNow+86400))
	if err != nil {
		t.Fatal(err)
	}
	freshRec.Claim = cb
	freshTldEnv, err := wire.SignRecord(freshRec, tomb.tldKP)
	if err != nil {
		t.Fatal(err)
	}
	// The www record under the same (resurrected) identity must resolve.
	wwwWire, err := naming.EncodeWireName([]string{"www"}, "foo", tomb.tldID)
	if err != nil {
		t.Fatal(err)
	}
	wwwRec, err := wire.NewRecord(wwwWire, tomb.tldKP.Public(), 1, uint64(fixedNow-100), uint64(fixedNow+3600))
	if err != nil {
		t.Fatal(err)
	}
	wwwRec.RRset = []*wire.RR{{Type: wire.RRTypeA, TTL: 300, Rdata: net.IPv4(203, 0, 113, 61).To4()}}
	freshWWWEnv, err := wire.SignRecord(wwwRec, tomb.tldKP)
	if err != nil {
		t.Fatal(err)
	}
	tomb.wwwEnv = freshWWWEnv // the lookup serves the fresh www record
	tomb.tldEnv = freshTldEnv

	lookup := newFakeClaimSetLookup("foo", []*wire.SignedEnvelope{freshTldEnv}, tomb)
	rrs, rcode, rerr := resolveFoo(t, lookup)
	if rerr != nil {
		t.Fatalf("ResolveQuestion: %v", rerr)
	}
	if rcode != dns.RcodeSuccess || len(rrs) != 1 {
		t.Fatalf("rcode=%d len=%d, want NOERROR/1 (same-identity resurrection is ownership continuity)", rcode, len(rrs))
	}
	if a := rrs[0].(*dns.A); !a.A.Equal(net.IPv4(203, 0, 113, 61)) {
		t.Errorf("A.A = %s, want the resurrected carrier's record", a.A)
	}
}

// TestResolveQuestionReuseWindowCloses: past expires + ALIAS_REUSE_DELAY the
// tombstone is inert — a fresh claim resolves.
func TestResolveQuestionReuseWindowCloses(t *testing.T) {
	delay := int64(constants.AliasReuseDelay)
	tomb := windowedWorld(t, "foo", uint64(fixedNow-1000-delay), net.IPv4(203, 0, 113, 54),
		fixedNow-200-delay, fixedNow-50-delay, true) // dead > 30 d ago: window closed
	fresh := windowedWorld(t, "foo", uint64(fixedNow-10), net.IPv4(203, 0, 113, 55),
		fixedNow-30, fixedNow+3600, true)

	lookup := newFakeClaimSetLookup("foo", []*wire.SignedEnvelope{tomb.tldEnv, fresh.tldEnv}, tomb, fresh)
	rrs, rcode, err := resolveFoo(t, lookup)
	if err != nil {
		t.Fatalf("ResolveQuestion: %v", err)
	}
	if rcode != dns.RcodeSuccess || len(rrs) != 1 {
		t.Fatalf("rcode=%d len=%d, want NOERROR/1 (window closed)", rcode, len(rrs))
	}
	if a := rrs[0].(*dns.A); !a.A.Equal(fresh.wwwIPv4) {
		t.Errorf("A.A = %s, want the fresh claimant's %s", a.A, fresh.wwwIPv4)
	}
}

// TestResolveQuestionRogueFabricationDoesNotLock: a dead carrier WITHOUT the
// witness quorum (everything a rogue node can manufacture at zero witness
// cost — PoW-valid, claimant-bound, but no attestations) is NOT a tombstone:
// the alias resolves. Locking must cost a real, once-verified registration.
func TestResolveQuestionRogueFabricationDoesNotLock(t *testing.T) {
	fake := windowedWorld(t, "foo", uint64(fixedNow-1000), net.IPv4(203, 0, 113, 56),
		fixedNow-200, fixedNow-50, false) // no quorum: the rogue's "tombstone"
	fresh := windowedWorld(t, "foo", uint64(fixedNow-10), net.IPv4(203, 0, 113, 57),
		fixedNow-30, fixedNow+3600, true)

	lookup := newFakeClaimSetLookup("foo", []*wire.SignedEnvelope{fake.tldEnv, fresh.tldEnv}, fake, fresh)
	rrs, rcode, err := resolveFoo(t, lookup)
	if err != nil {
		t.Fatalf("ResolveQuestion: %v", err)
	}
	if rcode != dns.RcodeSuccess || len(rrs) != 1 {
		t.Fatalf("rcode=%d len=%d, want NOERROR/1 (a quorum-less fabrication cannot lock an alias)", rcode, len(rrs))
	}
	if a := rrs[0].(*dns.A); !a.A.Equal(fresh.wwwIPv4) {
		t.Errorf("A.A = %s, want the fresh claimant's %s", a.A, fresh.wwwIPv4)
	}
}

// TestResolveQuestionTombstoneAloneIsNXDOMAIN: only the dead claim is offered
// (the classic abandoned-alias state mid-window): no live survivor at all ⇒
// NXDOMAIN — the §7.4 path would say the same (dead carrier fails
// verifyClaimEnvelope), locked or not; this pins that the tombstone branch
// adds no failure mode of its own.
func TestResolveQuestionTombstoneAloneIsNXDOMAIN(t *testing.T) {
	tomb := windowedWorld(t, "foo", uint64(fixedNow-1000), net.IPv4(203, 0, 113, 58),
		fixedNow-200, fixedNow-50, true)
	lookup := newFakeClaimSetLookup("foo", []*wire.SignedEnvelope{tomb.tldEnv}, tomb)
	_, rcode, err := resolveFoo(t, lookup)
	if err != nil {
		t.Fatalf("ResolveQuestion: %v", err)
	}
	if rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %d, want NXDOMAIN", rcode)
	}
}
