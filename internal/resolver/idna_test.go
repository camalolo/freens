package resolver

// IDNA integration tests (spec §3.2 "plus IDNA2008 U-labels" MAY, spec lines
// 155-162): prove that naming.EnableIDNA() changes what the daemon's query
// path accepts, and equally what it does NOT change.
//
// What the -idna flag / [options] "idna = true" enables, code-verified:
//
//   - ServeDNS → ResolveQuestion → naming.DecomposeName(q.Name) routes ONLY
//     the alias (TLD-adjacent) component through ValidateAlias, which applies
//     the IDNA normalizer to non-ASCII input. So a client that puts raw UTF-8
//     U-label bytes in the alias position (legal: DNS labels are opaque wire
//     bytes; dig passes typed UTF-8 through verbatim) resolves iff IDNA is on.
//   - Intermediate subdomain labels go through ValidateLabel, which never
//     normalizes: strict ASCII LDH regardless of the flag.
//   - Already-punycoded names ("xn--…" A-labels — what real stub resolvers
//     and browsers send) are plain ASCII LDH and resolve identically with the
//     flag off: IDNA is only needed for raw U-label lookups.

import (
	"context"
	"encoding/base32"
	"fmt"
	"net"
	"testing"

	"github.com/laurent/freens/internal/crypto"
	"github.com/laurent/freens/internal/naming"
	"github.com/laurent/freens/internal/wire"
	"github.com/miekg/dns"
)

// idnaFixedNow mirrors resolver_test.go's fixedNow (kept local so this file
// stays self-contained against concurrent edits to resolver_test.go).
const idnaFixedNow int64 = 1_700_000_000

// idnaTestLookup is a self-contained RecordLookup keyed on the raw wire_name.
type idnaTestLookup struct {
	records map[string]*wire.SignedEnvelope
}

func (l *idnaTestLookup) Lookup(_ context.Context, wireName []byte, _ int64) (*wire.SignedEnvelope, error) {
	return l.records[string(wireName)], nil
}

// idnaTestWorld builds a self-certifying TLD whose alias is "xn--bcher-kva"
// (the IDNA2008 A-label of the U-label "bücher") carrying an A RR at the
// TLD root, plus a §9.3 config that routes the alias to freens and pins it to
// the tld_id (pin-first per §9.3, so no claim machinery is needed).
type idnaTestWorld struct {
	cfg    *Config
	lookup *idnaTestLookup
	res    *Resolver
}

func newIDNATestWorld(t *testing.T) *idnaTestWorld {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	tldID, err := crypto.TldID(kp.Public())
	if err != nil {
		t.Fatal(err)
	}
	wn, err := naming.EncodeWireName(nil, "xn--bcher-kva", tldID)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := wire.NewRecord(wn, kp.Public(), 1, uint64(idnaFixedNow-100), uint64(idnaFixedNow+3600))
	if err != nil {
		t.Fatal(err)
	}
	aRR, err := wire.A([]byte{192, 0, 2, 10}, 600)
	if err != nil {
		t.Fatal(err)
	}
	rec.RRset = []*wire.RR{aRR}
	env, err := wire.SignRecord(rec, kp)
	if err != nil {
		t.Fatal(err)
	}
	if !wire.IsBasicValid(env, uint64(idnaFixedNow)) {
		t.Fatal("fixture: TLD env not IsBasicValid")
	}

	cfgText := fmt.Sprintf(`[tld-routes]
xn--bcher-kva = freens
[alias-pins]
xn--bcher-kva = %s
`, base32.StdEncoding.EncodeToString(tldID))
	cfg, err := ParseConfig(cfgText)
	if err != nil {
		t.Fatal(err)
	}
	lookup := &idnaTestLookup{records: map[string]*wire.SignedEnvelope{string(wn): env}}
	res := New(cfg, lookup, nil)
	res.Now = func() int64 { return idnaFixedNow }
	return &idnaTestWorld{cfg: cfg, lookup: lookup, res: res}
}

// withIDNA runs f with the naming package-global IDNA normalizer enabled,
// restoring the previous (default nil = strict ASCII LDH) state afterwards.
// Resolver tests run sequentially (no t.Parallel), so the global is safe to
// flip for the duration of one test.
func withIDNA(t *testing.T, f func()) {
	t.Helper()
	saved := naming.IDNANormalizer
	naming.EnableIDNA()
	defer func() { naming.IDNANormalizer = saved }()
	f()
}

// TestIDNADisabledByDefault rejects a raw U-label alias: DecomposeName errors
// and §9.2 step 1 answers non-authoritative NXDOMAIN. The punycoded A-label
// form resolves fine without the flag — this is what real stub resolvers
// (which send xn-- ASCII) experience, flag or no flag.
func TestIDNADisabledByDefault(t *testing.T) {
	w := newIDNATestWorld(t)
	if naming.IDNANormalizer != nil {
		t.Fatal("precondition: IDNANormalizer should be nil by default")
	}

	rrs, rcode, aa, err := w.res.ResolveQuestion(context.Background(),
		dns.Question{Name: "xn--bcher-kva.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	if err != nil {
		t.Fatalf("A-label query: unexpected error: %v", err)
	}
	if rcode != dns.RcodeSuccess || !aa || len(rrs) != 1 {
		t.Fatalf("A-label query: rcode=%d aa=%v rrs=%v, want NOERROR/aa=1 RR", rcode, aa, rrs)
	}
	if got := rrs[0].(*dns.A).A.String(); got != "192.0.2.10" {
		t.Fatalf("A-label query: answer = %s, want 192.0.2.10", got)
	}

	rrs, rcode, aa, err = w.res.ResolveQuestion(context.Background(),
		dns.Question{Name: "bücher.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	if err != nil {
		t.Fatalf("U-label query: unexpected error: %v", err)
	}
	// §9.2 step 1: unparseable name → NXDOMAIN, and the answer did not come
	// from the freens namespace, so it must NOT carry the AA bit.
	if rcode != dns.RcodeNameError || aa {
		t.Fatalf("U-label query with IDNA off: rcode=%d aa=%v rrs=%v, want NXDOMAIN/aa=false", rcode, aa, rrs)
	}
}

// TestIDNAEnabledAcceptsULabelAlias is the proof that -idna changes live
// query handling: the SAME raw UTF-8 U-label question that failed above now
// normalizes to the A-label ("bücher" → "xn--bcher-kva" per §3.2 UTS #46),
// matches the route + pin, and answers authoritatively from the envelope.
func TestIDNAEnabledAcceptsULabelAlias(t *testing.T) {
	w := newIDNATestWorld(t)
	withIDNA(t, func() {
		// Unit level: the alias normalizes to the punycode A-label.
		norm, err := naming.ValidateAlias("bücher")
		if err != nil {
			t.Fatalf("ValidateAlias(bücher): %v", err)
		}
		if norm != "xn--bcher-kva" {
			t.Fatalf("ValidateAlias(bücher) = %q, want xn--bcher-kva", norm)
		}

		// Query level: the raw U-label resolves end-to-end.
		rrs, rcode, aa, err := w.res.ResolveQuestion(context.Background(),
			dns.Question{Name: "bücher.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
		if err != nil {
			t.Fatalf("U-label query: unexpected error: %v", err)
		}
		if rcode != dns.RcodeSuccess || !aa {
			t.Fatalf("U-label query with IDNA on: rcode=%d aa=%v, want NOERROR/aa=true", rcode, aa)
		}
		if len(rrs) != 1 {
			t.Fatalf("U-label query: got %d RRs, want 1", len(rrs))
		}
		a, ok := rrs[0].(*dns.A)
		if !ok {
			t.Fatalf("U-label query: RR type %T, want *dns.A", rrs[0])
		}
		if !a.A.Equal(net.IPv4(192, 0, 2, 10)) {
			t.Fatalf("U-label query: answer = %s, want 192.0.2.10", a.A)
		}
		if a.Hdr.Name != "bücher." {
			t.Fatalf("U-label query: owner name = %q, want the queried name verbatim", a.Hdr.Name)
		}
	})

	// The global was restored: the U-label fails again afterwards.
	_, rcode, aa, err := w.res.ResolveQuestion(context.Background(),
		dns.Question{Name: "bücher.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	if err != nil {
		t.Fatal(err)
	}
	if rcode != dns.RcodeNameError || aa {
		t.Fatalf("U-label query after restore: rcode=%d aa=%v, want NXDOMAIN/aa=false", rcode, aa)
	}
}

// TestIDNADoesNotNormalizeSubdomainLabels proves the flag's precise scope:
// only the alias (TLD) component normalizes. A non-ASCII intermediate label
// fails ValidateLabel (strict ASCII LDH) even with IDNA on, so DecomposeName
// still errors → non-authoritative NXDOMAIN.
func TestIDNADoesNotNormalizeSubdomainLabels(t *testing.T) {
	w := newIDNATestWorld(t)
	withIDNA(t, func() {
		_, rcode, aa, err := w.res.ResolveQuestion(context.Background(),
			dns.Question{Name: "bücher.xn--bcher-kva.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
		if err != nil {
			t.Fatal(err)
		}
		if rcode != dns.RcodeNameError || aa {
			t.Fatalf("non-ASCII label with IDNA on: rcode=%d aa=%v, want NXDOMAIN/aa=false (unparseable)", rcode, aa)
		}
	})
}

// TestParseConfigOptionsIDNA covers the [options] idna boolean (§3.2 opt-in),
// including configparser-style spellings and error handling.
func TestParseConfigOptionsIDNA(t *testing.T) {
	cases := []struct {
		text string
		want bool
	}{
		{"", false},                          // default: strict ASCII LDH
		{"[options]\nidna = false", false},   // explicit off
		{"[options]\nidna = true", true},     // canonical on
		{"[options]\nidna = yes", true},      // configparser spelling
		{"[options]\nidna = ON", true},       // case-insensitive
		{"[options]\nverbose = true", false}, // unknown key ignored (forward-compat)
	}
	for _, c := range cases {
		cfg, err := ParseConfig(c.text)
		if err != nil {
			t.Fatalf("ParseConfig(%q): %v", c.text, err)
		}
		if cfg.EnableIDNA != c.want {
			t.Errorf("ParseConfig(%q).EnableIDNA = %v, want %v", c.text, cfg.EnableIDNA, c.want)
		}
	}
	if _, err := ParseConfig("[options]\nidna = maybe"); err == nil {
		t.Error("ParseConfig(idna = maybe): want error, got nil")
	}
}
