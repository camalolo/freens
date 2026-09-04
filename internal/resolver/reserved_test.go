package resolver

// reserved_test.go — the §7.7 resolution-side gate (naming/reserved.go +
// resolver.go freensResolve): an alias equal to a delegated ICANN TLD or
// IANA special-use name is treated as claim-less — NXDOMAIN, claim source
// never able to answer — EVEN when the network holds a perfectly valid,
// fully-witnessed claim for it. That is the point: five malicious witnesses
// must not be able to make this node resolve a freens ".com". Escape hatches,
// in precedence order: [alias-pins] (checked BEFORE the gate — operator
// policy wins) and [options] allow-reserved / the daemon -allow-reserved
// flag (the whole-policy opt-out).

import (
	"context"
	"testing"

	"github.com/camalolo/freens/internal/crypto"
	"github.com/miekg/dns"
)

// reservedClaimConfig routes "com" into freens (the squatter's dream config)
// with no pins and no allow-reserved.
func reservedClaimConfig() *Config {
	cfg, err := ParseConfig("[tld-routes]\n* = dns-first\n")
	if err != nil {
		panic(err)
	}
	cfg.TLDRoutes["com"] = RouteFREENS
	return cfg
}

// TestResolveQuestionReservedAliasClaimRefused: a fully valid claim world for
// "com" (PoW, W witnesses, matching chain, valid signature — the same fixture
// the §7.4 checklist tests pass with for ordinary aliases) resolves to
// NXDOMAIN under the default policy. With cfg.AllowReserved the SAME world
// resolves — proving the miss is the gate, not the fixture.
func TestResolveQuestionReservedAliasClaimRefused(t *testing.T) {
	w := newClaimedWorld(t, "com")
	lookup := newFakeClaimLookup()
	lookup.putClaim("com", w.tldEnv)
	lookup.put(w.wwwEnv)

	r := newResolver(reservedClaimConfig(), lookup, nil)
	q := dns.Question{Name: "www.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	rrs, rcode, aa, err := r.ResolveQuestion(context.Background(), q)
	if err != nil {
		t.Fatalf("ResolveQuestion: unexpected err: %v", err)
	}
	if rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %d, want NXDOMAIN(%d): the §7.7 gate must refuse a freens .com even with a rogue-witnessed claim", rcode, dns.RcodeNameError)
	}
	if len(rrs) != 0 {
		t.Fatalf("len(rrs) = %d, want 0", len(rrs))
	}
	if !aa {
		t.Error("aa = false; the gated NXDOMAIN comes from the freens branch, which is authoritative for its own misses")
	}

	// The override accepts the identical world.
	allowCfg := reservedClaimConfig()
	allowCfg.AllowReserved = true
	r2 := newResolver(allowCfg, lookup, nil)
	rrs2, rcode2, _, err := r2.ResolveQuestion(context.Background(), q)
	if err != nil {
		t.Fatalf("ResolveQuestion(allow): %v", err)
	}
	if rcode2 != dns.RcodeSuccess || len(rrs2) != 1 {
		t.Fatalf("allow-reserved rcode = %d len = %d, want NOERROR with 1 RR (the override must resolve)", rcode2, len(rrs2))
	}
}

// TestResolveQuestionReservedAliasPinWins: [alias-pins] are resolved BEFORE
// the gate — an explicit local pin is operator policy, immune to claims by
// design, and must not be broken by the reserved-alias refusal.
func TestResolveQuestionReservedAliasPinWins(t *testing.T) {
	w := newClaimedWorld(t, "com")
	lookup := newFakeClaimLookup()
	lookup.putClaim("com", w.tldEnv)
	lookup.put(w.wwwEnv)

	tid, err := crypto.TldID(w.tldKP.Public())
	if err != nil {
		t.Fatal(err)
	}
	cfg := reservedClaimConfig()
	cfg.AliasPins["com"] = tid
	r := newResolver(cfg, lookup, nil)
	q := dns.Question{Name: "www.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	rrs, rcode, _, err := r.ResolveQuestion(context.Background(), q)
	if err != nil {
		t.Fatalf("ResolveQuestion: %v", err)
	}
	if rcode != dns.RcodeSuccess || len(rrs) != 1 {
		t.Fatalf("rcode = %d len = %d, want NOERROR with 1 RR (a pin must win over the §7.7 gate)", rcode, len(rrs))
	}
}

// TestParseConfigAllowReserved: the [options] key parses, defaults off, and
// a bad boolean is a config error.
func TestParseConfigAllowReserved(t *testing.T) {
	def, err := ParseConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if def.AllowReserved {
		t.Error("default AllowReserved = true, want false")
	}
	cfg, err := ParseConfig("[options]\nallow-reserved = true\n")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.AllowReserved {
		t.Error("allow-reserved = true did not parse")
	}
	if _, err := ParseConfig("[options]\nallow-reserved = maybe\n"); err == nil {
		t.Error("non-boolean allow-reserved accepted")
	}
}
