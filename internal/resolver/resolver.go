package resolver

// This file implements the §9.2 resolution algorithm: given a DNS question,
// consult the freens namespace (with authority-chain verification) and/or
// conventional upstream DNS, applying the §9.3 routing policy.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/laurent/freens/internal/constants"
	"github.com/laurent/freens/internal/naming"
	"github.com/laurent/freens/internal/wire"
	"github.com/miekg/dns"
)

// RecordLookup returns the winning SignedEnvelope for a freens wire_name, or
// (nil, nil) if no record is available at that name (so the resolver falls back
// per the routing policy). A non-nil error signals a transient lookup failure
// (the resolver maps it to SERVFAIL).
//
// This interface lets the resolver be tested without a live DHT: tests supply a
// fake that returns pre-built, properly signed envelopes.
type RecordLookup interface {
	Lookup(ctx context.Context, wireName []byte, now int64) (*wire.SignedEnvelope, error)
}

// Upstream forwards a DNS message to conventional recursive resolvers and
// returns the response. Implementations may do UDP/TCP fallback, DoH, etc.
type Upstream interface {
	Forward(ctx context.Context, q *dns.Msg) (*dns.Msg, error)
}

// Resolver answers DNS questions from the freens namespace, applying the §9.3
// routing policy. It is safe for concurrent use (no mutable state per query).
type Resolver struct {
	Cfg      *Config
	Freens   RecordLookup // nil ⇒ freens branch always misses
	Upstream Upstream     // nil ⇒ DNS branch refused
	Now      func() int64 // wall-clock seconds; defaults to time.Now().Unix()
}

// New builds a Resolver with a default clock. Cfg, Freens, and Upstream may be
// nil (the resolver degrades gracefully: freens misses, DNS refused).
func New(cfg *Config, freens RecordLookup, upstream Upstream) *Resolver {
	return &Resolver{Cfg: cfg, Freens: freens, Upstream: upstream}
}

func (r *Resolver) now() int64 {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now().Unix()
}

// ResolveQuestion answers a single DNS question, fully implementing §9.2
// steps 2-5 with the §9.3 routing policy. Returns:
//
//   - rrs:   the answer resource records (possibly empty for NODATA),
//   - rcode: a dns.RCODE_* constant (NOERROR / NXDOMAIN / REFUSED / SERVFAIL),
//   - aa:    whether the FINAL answer was produced by freensResolve — i.e. is
//     authoritative for the freens namespace (RFC 1035 §4.1.1). false iff the
//     answer ultimately came from forwardDNS (or the route was DENY/forwarded
//     after a freens miss). freens is authoritative even for its own
//     NXDOMAIN/NODATA within the FREENS and DNSFirst-fallthrough paths.
//   - err:   a non-nil value only on SERVFAIL-class failures.
//
// It does NOT synthesize a full dns.Msg; the caller (ServeDNS or a test) wraps
// the result. The algorithm:
//
//  1. Split q.Name into (labels, alias) via naming.DecomposeName. On error →
//     NXDOMAIN (non-authoritative — we cannot even parse the name).
//  2. route = RouteFor(r.Cfg, alias).
//  3. FREENS:  freensResolve(); aa=true (freens owns the namespace, even for
//     its own NXDOMAIN/NODATA).
//     DNS:     forward via Upstream; no upstream → REFUSED. aa=false.
//     FREENSFirst: freensResolve(); on NXDOMAIN ∨ NODATA fall through to DNS
//     and aa=false; otherwise aa=true (see the in-branch comment for the spec
//     reconciliation of §9.2 step 5 vs §9.3 line 784).
//     DNSFirst:    forward via DNS; on NXDOMAIN fall through to freens and
//     aa=true; otherwise aa=false.
//     DENY:    REFUSED; aa=false.
func (r *Resolver) ResolveQuestion(ctx context.Context, q dns.Question) (rrs []dns.RR, rcode int, aa bool, err error) {
	now := r.now()

	labels, alias, derr := naming.DecomposeName(q.Name)
	if derr != nil {
		// §9.2 step 1: an unparseable name has no answer.
		return nil, dns.RcodeNameError, false, nil
	}
	route := RouteFor(r.Cfg, alias)

	switch route {
	case RouteDENY:
		// §9.3: refuse (REFUSED) for known-bad or policy-blocked TLDs. The
		// answer is synthesized by local policy, not by an authoritative data
		// source, so AA=false.
		return nil, dns.RcodeRefused, false, nil

	case RouteFREENS:
		// §9.2 step 3: freens only. freens is the authoritative source for
		// the freens namespace, so AA=true even on its own NXDOMAIN/NODATA.
		rrs, rcode, err := r.freensResolve(ctx, labels, alias, q, now)
		return rrs, rcode, true, err

	case RouteDNS:
		// §9.2 step 4: forward verbatim; no upstream configured → REFUSED.
		// A DNS-forwarded answer is never authoritative for this server.
		rrs, rcode, err := r.forwardDNS(ctx, q)
		return rrs, rcode, false, err

	case RouteFREENSFirst:
		// §9.2 step 5 / §9.3: freens first; on a miss fall through to DNS.
		//
		// Spec reconciliation (R1): the prose is self-contradictory — §9.2
		// step 5 says fall through "on NXDOMAIN", while §9.3 line 784 says
		// "on miss". A "miss" includes both NXDOMAIN (name absent) and NODATA
		// (name present, type absent: NOERROR with empty answer). We follow
		// §9.3's broader "miss" interpretation: a freens NXDOMAIN ∨ NODATA
		// falls through to conventional DNS, which is the less-surprising
		// behavior for a stub resolver (a stale-NODATA fallthrough would
		// otherwise shadow a live DNS answer). On fallthrough the FINAL
		// answer is DNS-sourced → AA=false; otherwise freens is authoritative
		// for the namespace → AA=true.
		rrs, rcode, err := r.freensResolve(ctx, labels, alias, q, now)
		if rcode == dns.RcodeNameError || (rcode == dns.RcodeSuccess && len(rrs) == 0) {
			// NXDOMAIN or NODATA miss → try conventional DNS. The final
			// answer is upstream-sourced → AA=false.
			dnsRRs, dnsRcode, dnsErr := r.forwardDNS(ctx, q)
			return dnsRRs, dnsRcode, false, dnsErr
		}
		return rrs, rcode, true, err

	case RouteDNSFirst:
		// §9.3: ask DNS first; on NXDOMAIN fall through to freens. A DNS hit
		// (NOERROR, even with empty answer) is upstream-sourced → AA=false.
		// Only an upstream NXDOMAIN hands the question to the authoritative
		// freens namespace → AA=true.
		rrs, rcode, err := r.forwardDNS(ctx, q)
		if rcode == dns.RcodeNameError {
			// NXDOMAIN upstream → try the freens namespace, which is the
			// authoritative source for the freens TLD.
			fRRs, fRcode, fErr := r.freensResolve(ctx, labels, alias, q, now)
			return fRRs, fRcode, true, fErr
		}
		return rrs, rcode, false, err
	}

	// Unknown route token (config was validated, so this is unreachable).
	return nil, dns.RcodeRefused, false, fmt.Errorf("resolver: unknown route %q", route)
}

// freensResolve implements the §9.2 step 3 "freens route": resolve the alias to
// a tld_id, walk the authority chain from the TLD record down to the requested
// name, verify it, and answer from the terminal record's RRset.
//
// Returns:
//   - (rrs, NOERROR, nil)            on a successful answer,
//   - (nil, NOERROR, nil)            when the name exists but the type is absent (NODATA),
//   - (nil, NXDOMAIN, nil)           when the name / chain is absent or invalid,
//   - (nil, SERVFAIL, err)           on a transient lookup error.
func (r *Resolver) freensResolve(ctx context.Context, labels []string, alias string, q dns.Question, now int64) ([]dns.RR, int, error) {
	if r.Freens == nil {
		// No freens source wired: the freens branch misses.
		return nil, dns.RcodeNameError, nil
	}

	// Step 3a: alias → tld_id. Pin first (local policy, bypasses the claim
	// race). Without a pin and without a claim source this in-process
	// implementation cannot resolve the alias → NXDOMAIN for the freens branch.
	tldID := ResolvePin(r.Cfg, alias)
	if len(tldID) == 0 {
		return nil, dns.RcodeNameError, nil
	}

	// Step 3b: walk the authority chain TLD → ... → requested name. Each hop's
	// wire_name is built from a growing suffix of the display-order labels
	// (TLD-adjacent labels first, matching EncodeWireName's internal reversal).
	chain := make([]*wire.SignedEnvelope, 0, len(labels)+1)
	for k := 0; k <= len(labels); k++ {
		// For labels=[l0,l1,...,ln] (display order, most-specific first) the
		// hop-k prefix is labels[n-k:] (suffix growing from the TLD side):
		//   k=0 → []              (TLD record)
		//   k=1 → [ln]            (one label adjacent to the TLD)
		//   ...
		//   k=n → [l0,l1,...,ln]  (the requested name)
		prefix := labels[len(labels)-k:]
		wn, err := naming.EncodeWireName(prefix, alias, tldID)
		if err != nil {
			return nil, dns.RcodeNameError, nil
		}
		env, err := r.Freens.Lookup(ctx, wn, now)
		if err != nil {
			return nil, dns.RcodeServerFailure, err
		}
		if env == nil {
			// Missing hop: chain broken → name does not exist in freens.
			return nil, dns.RcodeNameError, nil
		}
		// R2: per-hop temporal validity. VerifyAuthorityChain checks each
		// hop's signature and parent/child binding but does NOT check that
		// every hop is still INSIDE its [Created, Expires) validity window —
		// an expired intermediate delegation record would otherwise pass and
		// could delegate authority past its intended lifetime. Reject any hop
		// that fails IsBasicValid at `now` by treating the name as
		// unresolvable (NXDOMAIN). The terminal hop is re-checked below
		// (redundantly but cheaply) along with the full chain.
		if !wire.IsBasicValid(env, uint64(now)) {
			return nil, dns.RcodeNameError, nil
		}
		chain = append(chain, env)
	}

	// Step 3c: verify the terminal envelope (basic validity) and the full
	// authority chain (§3.4).
	terminal := chain[len(chain)-1]
	if !wire.IsBasicValid(terminal, uint64(now)) {
		return nil, dns.RcodeNameError, nil
	}
	if !wire.VerifyAuthorityChain(chain) {
		return nil, dns.RcodeNameError, nil
	}

	// Step 3d: read the answer RRset for the requested type and map freens RRs
	// to dns.RRs. TTL = min(rr.TTL, expires-now) capped by ResponseTTLCap.
	expires := int64(terminal.Record.Expires)
	out := make([]dns.RR, 0, len(terminal.Record.RRset))
	for _, rr := range terminal.Record.RRset {
		if rr.Type != uint64(q.Qtype) {
			continue
		}
		mapped := freensRRToDNS(q.Name, rr, expires, now)
		if mapped != nil {
			out = append(out, mapped)
		}
	}
	if len(out) == 0 {
		// Name exists, type absent → NODATA (NOERROR with empty answer).
		return nil, dns.RcodeSuccess, nil
	}
	return out, dns.RcodeSuccess, nil
}

// forwardDNS implements §9.2 step 4: forward the question verbatim to the
// configured upstream recursive resolvers. No upstream → REFUSED. A transient
// forwarder error → SERVFAIL. Otherwise the upstream's answer RRs and rcode are
// returned as-is.
func (r *Resolver) forwardDNS(ctx context.Context, q dns.Question) ([]dns.RR, int, error) {
	if r.Upstream == nil {
		return nil, dns.RcodeRefused, nil
	}
	m := new(dns.Msg)
	m.SetQuestion(q.Name, q.Qtype)
	m.RecursionDesired = true
	resp, err := r.Upstream.Forward(ctx, m)
	if err != nil {
		return nil, dns.RcodeServerFailure, fmt.Errorf("resolver: upstream forward: %w", err)
	}
	if resp == nil {
		return nil, dns.RcodeServerFailure, errors.New("resolver: upstream returned no response")
	}
	return resp.Answer, resp.Rcode, nil
}

// freensRRToDNS maps a freens wire.RR to a dns.RR for the given owner name. TTL
// is computed per §9.2: min(rr.TTL, expires-now) capped by
// constants.ResponseTTLCap, clamped to a non-negative uint32. Unsupported RR
// types return nil (the caller skips them).
func freensRRToDNS(name string, rr *wire.RR, expires, now int64) dns.RR {
	ttl := int64(rr.TTL)
	if rem := expires - now; rem < ttl {
		ttl = rem
	}
	if ttl > constants.ResponseTTLCap {
		ttl = constants.ResponseTTLCap
	}
	if ttl < 0 {
		ttl = 0
	}
	hdr := dns.RR_Header{Name: name, Class: dns.ClassINET, Ttl: uint32(ttl)}
	switch rr.Type {
	case wire.RRTypeA:
		if len(rr.Rdata) != 4 {
			return nil
		}
		ip := net.IP(rr.Rdata).To4()
		if ip == nil {
			return nil
		}
		hdr.Rrtype = dns.TypeA
		return &dns.A{Hdr: hdr, A: ip}
	case wire.RRTypeAAAA:
		if len(rr.Rdata) != 16 {
			return nil
		}
		hdr.Rrtype = dns.TypeAAAA
		return &dns.AAAA{Hdr: hdr, AAAA: net.IP(rr.Rdata)}
	case wire.RRTypeTXT:
		hdr.Rrtype = dns.TypeTXT
		return &dns.TXT{Hdr: hdr, Txt: []string{string(rr.Rdata)}}
	default:
		// Other types (CNAME/MX/NS/SRV/...) are left to a future iteration;
		// the caller drops nil mappings.
		return nil
	}
}
