package resolver

// This file implements the §9.2 resolution algorithm: given a DNS question,
// consult the freens namespace (with authority-chain verification) and/or
// conventional upstream DNS, applying the §9.3 routing policy.

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/camalolo/freens/internal/claims"
	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/dht"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/wire"
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

// ClaimResolver is the OPTIONAL network alias-claim source for §9.2 step 3a
// (§7.4 verifier side, §3.2 alias layer): it returns the SignedEnvelope stored
// at K_claim = SHA-256(0x03 || "claim:" || alias) — the TLD-record envelope
// whose field 11 carries the AliasClaim — or (nil, nil) if the reachable
// network has no claim for the alias.
//
// A RecordLookup MAY also implement ClaimResolver; the resolver discovers that
// with a type assertion, so no configuration knob exists or is needed: claim
// resolution is automatic exactly when the wired record source is
// claim-capable (e.g. dht.DHTLookup), and a plain store-only lookup keeps the
// pin-only behavior. The returned envelope is UNTRUSTED input; the resolver
// runs the full §7 verification checklist on it (see resolveAliasClaim).
type ClaimResolver interface {
	LookupClaim(ctx context.Context, alias string, now int64) (*wire.SignedEnvelope, error)
}

// ClaimSetResolver is the OPTIONAL §7.4 verifier-side claim-SET source: it
// returns EVERY distinct claim envelope the source can offer for alias — the
// local K_claim copy merged with the set collected across the network (spec
// lines 602-604: "get(K_claim); collect all competing claims nodes offer
// (storing nodes keep the top 2 by ordering; clients SHOULD probe GET_CLOSEST
// nodes and merge)"). It exists because different storing nodes may
// temporarily hold different §6.4 winners for the same K_claim, so a single
// envelope (ClaimResolver) cannot feed the §7.4 step-3 ordering; only the
// merged set can. dht.DHTLookup satisfies it structurally.
//
// A RecordLookup MAY implement ClaimSetResolver (it then usually also
// implements ClaimResolver); the resolver prefers the set path via a type
// assertion and falls back to the single-claim ClaimResolver path for older
// sources, so wiring is still automatic and backward compatible. The returned
// envelopes are UNTRUSTED input: each one individually passes the full §7
// checklist (see verifyClaimEnvelope) before it may join the §7.4 ordering.
type ClaimSetResolver interface {
	CollectClaims(ctx context.Context, alias string, now int64) ([]*wire.SignedEnvelope, error)
}

// ClaimSetWithWitnesses is the OPTIONAL v0.7.0 extension of ClaimSetResolver:
// the same collected claim set, PLUS the converged WITNESS SET of the very
// walk that collected it — the hex(NodeID) set of the WitnessSet = 8 closest
// REACHED nodes to K_claim (§7.3), or nil when the source's reachable view is
// too sparse to honestly name a set (small fleets, partitions, young tables).
//
// When non-nil, the resolver restricts the §7.3 quorum to witnesses among
// that set (claims.VerifyFull): five keys minted out of thin air — however
// valid their signatures and however consistent their timestamps — are not
// among the network's actual witness nodes, so a fabricated quorum stops
// counting. This closes the backdating hole's last open path (a self-dated
// fabricated quorum on a re-mined old claim; see the v0.7.0 changelog).
//
// A nil set means "membership unenforced", NEVER "reject everything": the
// source is trusted to decide when its view can name the set. dht.DHTLookup
// satisfies this interface structurally (CollectClaimsWithWitnesses).
type ClaimSetWithWitnesses interface {
	CollectClaimsWithWitnesses(ctx context.Context, alias string, now int64) ([]*wire.SignedEnvelope, map[string]bool, error)
}

// HistoryResolver is the OPTIONAL §8.3 transfer-history source: it returns the
// SignedEnvelope whose H_record (SHA-256 of the canonical envelope CBOR, §4.2)
// is h — from this node's retained history or any peer's — or (nil, nil) if no
// such envelope is obtainable. §8.3 (lines 681-684): "prev_hash links the
// transfer into an auditable chain so third parties can verify the hand-off
// history offline"; storing nodes retain superseded envelopes for exactly
// that audit, so the predecessor of a whole-TLD hand-off stays fetchable by
// hash (locally or across the network) long after it lost its K_tld slot.
//
// A RecordLookup MAY implement HistoryResolver; the resolver discovers that
// with a type assertion when the walked chain[0] is a §8.3 hand-off (signer !=
// owner with a non-nil prev_hash). Trust model: a resolver can verify a
// hand-off IFF the predecessor is obtainable — without this source a
// transferred TLD root is unprovable and the name NXDOMAINs (the pre-§8.3
// behavior). The returned envelope is UNTRUSTED input: the transfer walk
// re-checks its signature, self-certification, and prev_hash linkage.
type HistoryResolver interface {
	LookupByHash(ctx context.Context, h []byte) (*wire.SignedEnvelope, error)
}

// RecoveryEvidenceResolver is the OPTIONAL §8.4 evidence source: it returns
// the RecoveryEvidence retained for recordHash — the H_record of the recovery
// hand-off record the evidence accompanies (the new primary's R2, NOT the
// recovered predecessor) — from this node's evidence table or any peer's, or
// (nil, nil) if no such evidence is obtainable. §8.4 (lines 691-701): the
// threshold-of-keys recovery declaration lives OUTSIDE the record (the §4.1
// schema carries only the §5.4 POLICY, field 10), so proving a recovery hop
// requires fetching the declaration as a separate hash-addressed object —
// dht.DHTLookup implements this over its evidence table (local first, then an
// iterative get asking peers; storing nodes retain the evidence published
// with the record, exactly like the §8.3 audit history).
//
// A RecordLookup MAY implement RecoveryEvidenceResolver (it then usually also
// implements HistoryResolver — a recovery hop needs BOTH the predecessor
// envelope and the evidence); the resolver discovers it with a type assertion
// when the walked chain[0] asserts a hand-off. Trust model: without this
// source a §8.4 recovery root is unprovable and the name NXDOMAINs — the
// timelock (now >= evidence.NotBefore) and the quorum are (re-)checked by the
// wire walker on every query, so the returned evidence is UNTRUSTED input
// like everything else the source hands over.
type RecoveryEvidenceResolver interface {
	RecoveryEvidence(ctx context.Context, recordHash []byte) (*wire.RecoveryEvidence, error)
}

// DifficultyOracle is the OPTIONAL Appendix A.4 gossip-difficulty source: the
// claim-PoW floor this node learned from the network. A.4 (lines 1004-1006):
// "Nodes gossip the current D in witness responses; clients use the median of
// the GET_CLOSEST nodes' advertised values" — dht.DHTLookup implements this
// over its recently observed gossip values (median, floored at
// POW_DIFFICULTY_INIT, nil-node safe).
//
// A RecordLookup MAY implement DifficultyOracle; the resolver takes the floor
// into account when verifying claim PoW (see effectivePoWDifficulty): a claim
// minted at a difficulty below the network's current floor stops verifying
// once the network has retargeted upward. A source without it keeps the exact
// legacy claims.InferDifficulty behavior (no floor).
type DifficultyOracle interface {
	NetworkDifficulty() int
}

// Upstream forwards a DNS message to conventional recursive resolvers and
// returns the response. Implementations may do UDP/TCP fallback, DoH, etc.
type Upstream interface {
	Forward(ctx context.Context, q *dns.Msg) (*dns.Msg, error)
}

// contestedClaimTTLCap implements the §10.4 contested-alias caching rule (spec
// lines 849-857, esp. line 853): "Alias claim winners cached per 7.5
// (contested: 60 s; uncontested: 6 h)". Per §7.5 (lines 625-633) a winning
// claim is NOT final while it is younger than CONTEST_WINDOW (48 h) — an
// earlier-ordered valid claim may still appear inside that window and displace
// it ("clients MUST NOT treat either as final until ... the deterministic
// order picks a winner and no earlier-ordered valid claim appears within
// CONTEST_WINDOW"). §7.5 also permits resolvers to answer with the current
// deterministic winner in the meantime, so the contested state is expressed as
// a TTL cap, not a refusal: answers resolved through a contested winner carry
// TTL <= 60 s, which bounds the ResponseCache entry (putFreens derives its
// expiry from the minimum answer RR TTL, §10.4 line 851) and any downstream
// cache alike. Uncontested winners need no extra cap: their 6 h allowance
// exceeds constants.ResponseTTLCap (1 h), which already bounds every answer.
const contestedClaimTTLCap = 60 // seconds

// Resolver answers DNS questions from the freens namespace, applying the §9.3
// routing policy. It is safe for concurrent use (no mutable state per query).
type Resolver struct {
	Cfg      *Config
	Freens   RecordLookup // nil ⇒ freens branch always misses
	Upstream Upstream     // nil ⇒ DNS branch refused
	Now      func() int64 // wall-clock seconds; defaults to time.Now().Unix()
	// Cache optionally caches freens-sourced ResolveQuestion outcomes per
	// §10.4 (positive: min RR TTL; negative: NegTTL). It is consulted ONLY
	// on the DNS server path (ServeDNS); direct ResolveQuestion callers
	// always hit the namespace. nil disables caching.
	Cache *ResponseCache

	// Single-flight state (v0.7.1): concurrent identical questions share one
	// resolution — see resolveShared. Lazily initialized under flightMu so
	// zero-value/embedded Resolvers keep working.
	flightMu sync.Mutex
	flights  map[cacheKey]*resFlight

	// Serve-stale-while-revalidate bookkeeping (§10.4 amended): the unix
	// second of the last background refresh KICK per cache key. Throttles
	// goroutine spawns while an entry keeps being served stale (e.g. the
	// namespace is unreachable and every refresh errors) — one attempt per
	// refreshKickEvery per name, never blocking the answering path.
	refreshes map[cacheKey]int64

	// Logger, when set, reports background-refresh state TRANSITIONS only
	// (fail-start / recover — never every failure, an outage would spam):
	// "answering from cache but blind" is the one operator-visible gap the
	// stale-serving design has, and it should be loud exactly once.
	Logger *slog.Logger

	refreshFailing map[cacheKey]bool

	// MaxConcurrentResolutions bounds simultaneously in-flight DISTINCT
	// resolutions (v0.9.2 overload cap). Single-flight collapses identical
	// questions, but a distinct-name query flood — every miss caching its
	// own cache-bypassing walk — would otherwise open unbounded concurrent
	// DHT walks (the dht.Node additionally caps walks itself; this bounds
	// the resolver's own chain-verification and upstream-forward work and
	// applies even with non-DHT sources). A leader that cannot acquire a
	// slot answers SERVFAIL immediately (never NXDOMAIN — an overloaded
	// resolver must not negative-cache names); followers of an already
	// running flight always share it, whatever this value. Zero ⇒ 64.
	// Negative ⇒ unlimited.
	MaxConcurrentResolutions int

	// resSem is the resolution-count semaphore, lazily initialized under
	// flightMu (never reassigned afterwards, so release paths may read it
	// without the lock). nil ⇒ unlimited.
	resSem chan struct{}

	// TLSSync is the OPTIONAL §9.5.4 trust-sync sink (nil ⇒ disabled). It is
	// notified — asynchronously, never blocking the answer — whenever a
	// VERIFIED winning apex record carries a TLSCA RR (OnOwnerCA), and when
	// an alias is definitely dead (OnAliasDead: no surviving claim, a
	// tombstoned/expired/missing apex record). Only the SCREENED path
	// notifies (§4.4 validity + §7.4 claim screening): trust sync must never
	// learn a CA binding the DNS path would not answer from. Transient
	// errors (SERVFAIL/degraded) notify nothing.
	TLSSync TLSTrustSync
}

// TLSTrustSync is the §9.5.4 visitor-side sink implemented by the daemon's
// trust-sync engine (internal/trustsync): cross-certify verified owner CAs
// into the local trust stores; purge what died. tldID nil in OnAliasDead
// means "the alias has no claim left" (purge regardless of identity).
type TLSTrustSync interface {
	OnOwnerCA(alias string, tldID []byte, caDER []byte, recordExpires int64)
	OnAliasDead(alias string, tldID []byte)
}

// errResolverBusy is resolveShared's overload refusal: maps to SERVFAIL,
// which ServeDNS never caches, so an honest client transparently retries.
var errResolverBusy = errors.New("resolver: too many concurrent resolutions")

// resFlight is one in-flight (or just-completed) shared resolution.
type resFlight struct {
	done  chan struct{} // closed when rrs/rcode/aa/err are set
	rrs   []dns.RR
	rcode int
	aa    bool
	err   error
}

// refreshKickEvery is the minimum spacing between background refresh kicks
// for one cache key (serve-stale revalidation, §10.4 amended): during an
// outage every stale serve would otherwise spawn a walk attempt; one try
// per interval keeps the revalidation effort bounded while the answering
// path never blocks on it.
const refreshKickEvery = 5

// refreshTimeout bounds ONE background revalidation walk (the answering
// path already returned; this only decides when the goroutine gives up).
const refreshTimeout = 60 * time.Second

// kickRefresh revalidates a stale cache entry in the background: the
// caller has already ANSWERED the query from the stale copy, so this is
// best-effort by construction. resolveShared provides the single-flight
// (concurrent identical refreshes join the leader's walk), the resolution
// semaphore (bounded like any other walk), and the re-cache — whose fresh
// outcome, positive OR negative, replaces the stale entry.
func (r *Resolver) kickRefresh(q dns.Question, ck cacheKey) {
	nowFn := r.Now
	if nowFn == nil {
		nowFn = func() int64 { return time.Now().Unix() }
	}
	now := nowFn()
	r.flightMu.Lock()
	if r.refreshes == nil {
		r.refreshes = make(map[cacheKey]int64)
	}
	if r.refreshFailing == nil {
		r.refreshFailing = make(map[cacheKey]bool)
	}
	if last, seen := r.refreshes[ck]; seen && now-last < refreshKickEvery {
		r.flightMu.Unlock()
		return
	}
	r.refreshes[ck] = now
	r.flightMu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), refreshTimeout)
		defer cancel()
		_, rcode, _, err := r.resolveShared(ctx, q, ck)
		failed := err != nil || rcode == dns.RcodeServerFailure
		r.flightMu.Lock()
		was := r.refreshFailing[ck]
		switch {
		case failed && !was:
			r.refreshFailing[ck] = true
			if r.Logger != nil {
				reason := "unreachable"
				if err != nil {
					reason = err.Error()
				}
				r.Logger.Warn("namespace refresh failed — names not re-verifiable are answered from cache (stale) until it recovers",
					"name", strings.TrimSuffix(q.Name, "."), "err", reason)
			}
		case !failed && was:
			delete(r.refreshFailing, ck)
			if r.Logger != nil {
				r.Logger.Info("namespace refresh recovered", "name", strings.TrimSuffix(q.Name, "."))
			}
		}
		r.flightMu.Unlock()
	}()
}

// New builds a Resolver with a default clock. Cfg, Freens, and Upstream may be
// nil (the resolver degrades gracefully: freens misses, DNS refused).
func New(cfg *Config, freens RecordLookup, upstream Upstream) *Resolver {
	return &Resolver{Cfg: cfg, Freens: freens, Upstream: upstream}
}

// resolveShared runs ResolveQuestion with per-question single-flight:
// concurrent queries with the same (qname, qtype, qclass) — the cache-expiry
// stampede, a fan-out of N client goroutines at once — share ONE resolution
// and its outcome instead of each running its own DHT claim walk + chain
// walk (N simultaneous walks also trip peers' §12 read throttle and
// self-inflict ErrThrottled SERVFAILs, field-observed as bursty failures at
// 60 s TTL boundaries). The leader stores the outcome in Cache (when wired)
// before waking the followers; followers return the shared result verbatim
// (identical question ⇒ identical namespace answer at the same instant).
//
// Overload cap (v0.9.2): the LEADER additionally needs a resolution slot
// (MaxConcurrentResolutions, default 64). A distinct-question flood beyond
// the cap gets an immediate SERVFAIL-class error instead of unbounded
// concurrent resolutions; followers never consume slots — joining an
// in-flight resolution is free by design.
func (r *Resolver) resolveShared(ctx context.Context, q dns.Question, ck cacheKey) ([]dns.RR, int, bool, error) {
	r.flightMu.Lock()
	if f, ok := r.flights[ck]; ok {
		r.flightMu.Unlock()
		<-f.done
		return f.rrs, f.rcode, f.aa, f.err
	}
	// Leader path: lazily build the semaphore, then acquire a slot
	// non-blocking (an overloaded resolver REFUSES; it never queues, which
	// would pile one goroutine per waiting query onto the flood).
	if r.resSem == nil && r.MaxConcurrentResolutions >= 0 {
		n := r.MaxConcurrentResolutions
		if n == 0 {
			n = 64
		}
		r.resSem = make(chan struct{}, n)
	}
	if r.resSem != nil {
		select {
		case r.resSem <- struct{}{}:
		default:
			r.flightMu.Unlock()
			return nil, dns.RcodeServerFailure, false, errResolverBusy
		}
	}
	f := &resFlight{done: make(chan struct{})}
	if r.flights == nil {
		r.flights = make(map[cacheKey]*resFlight)
	}
	r.flights[ck] = f
	r.flightMu.Unlock()

	defer func() {
		if r.resSem != nil {
			<-r.resSem
		}
	}()

	f.rrs, f.rcode, f.aa, f.err = r.ResolveQuestion(ctx, q)
	if r.Cache != nil {
		r.Cache.putFreens(ck, f.rrs, f.rcode, f.aa)
	}

	r.flightMu.Lock()
	delete(r.flights, ck)
	r.flightMu.Unlock()
	close(f.done)
	return f.rrs, f.rcode, f.aa, f.err
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

	// Undo miekg/dns's RFC 4343 presentation escaping so a raw-UTF-8 U-label
	// alias sent on the wire (opaque octets) reaches naming as its original
	// bytes, where the §3.2 IDNA normalization (when enabled) applies. The
	// echoed answer owner names still use q.Name verbatim.
	parseName := unescapeName(q.Name)
	labels, alias, derr := naming.DecomposeName(parseName)
	if derr != nil {
		// §9.2 step 1: an unparseable name has no answer.
		return nil, dns.RcodeNameError, false, nil
	}

	// §9.2 suffix rescue ([options] suffix-rescue, Windows single-label
	// support): for a name whose LAST label resolves to an upstream
	// NXDOMAIN, the name is almost certainly a freens name the OS resolver
	// dressed up with a DNS suffix ("desktop.freens" for a user typing
	// "desktop"; Windows never sends the bare single-label query). Give it
	// ONE chance: the same name with the suffix label stripped, resolved
	// through the freens namespace only. Eligible: unknown aliases (the
	// "*" dns-first crowd) AND the community namespace itself — an
	// explicit freens-first route whose freens resolution missed may
	// borrow the bare name, which is what makes the ".freens" connection
	// suffix work. Custom/pinned routes other than freens-first are
	// sacrosanct (a private namespace must not silently alias its names
	// to bare freens ones). Real domains answer upstream before the
	// rescue can run; a rescue miss returns the original NXDOMAIN. The
	// stripped identity feeds the lookup; the QUESTION (and therefore the
	// echoed owner names in the answer) stays the original one — a stub
	// client would discard answers owned by a different name. aa=true on
	// a hit — the answer is freens-sourced (freensResolve).
	if r.Cfg != nil && r.Cfg.SuffixRescue && len(labels) >= 1 {
		route := RouteFor(r.Cfg, alias)
		_, explicit := r.Cfg.TLDRoutes[alias]
		if !explicit || route == RouteFREENSFirst {
			rrs, rcode, aa, err = r.resolveRouted(ctx, q, labels, alias, now)
			if err == nil && rcode == dns.RcodeNameError {
				strippedLabels, strippedAlias, serr := naming.DecomposeName(dns.Fqdn(strings.Join(labels, ".")))
				if serr == nil {
					sRRs, sRcode, sErr := r.freensResolve(ctx, strippedLabels, strippedAlias, q, now)
					if sErr == nil && sRcode == dns.RcodeSuccess && len(sRRs) > 0 {
						return sRRs, dns.RcodeSuccess, true, nil
					}
				}
			}
			return rrs, rcode, aa, err
		}
	}

	return r.resolveRouted(ctx, q, labels, alias, now)
}

// resolveRouted is ResolveQuestion's routing switch (§9.2 steps 3-5), split
// out so the suffix-rescue wrapper can consult the normal route first and
// only intercede on its NXDOMAIN.
func (r *Resolver) resolveRouted(ctx context.Context, q dns.Question, labels []string, alias string, now int64) ([]dns.RR, int, bool, error) {
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
// name, verify it, and answer from the terminal record's RRset. A revoked
// envelope at any hop (§8.5) makes the name unresolvable.
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

	// Step 3a: alias → tld_id. Pin first (§9.3 [alias-pins]: local policy,
	// bypasses the claim race — a pin ALWAYS wins). Without a pin, consult the
	// network alias-claim layer (§7): a ClaimSetResolver yields the merged set
	// of competing claims on which resolveAliasClaim applies the full §7.4
	// ordering (contested aliases resolve to the deterministic winner while
	// the §7.5/§10.4 contest state is reported back for the TTL cap); a
	// ClaimResolver-only source keeps the legacy single-claim behavior. On no
	// source, no claim, or any verification failure the freens branch misses →
	// NXDOMAIN.
	tldID := ResolvePin(r.Cfg, alias)
	contested := false
	degraded := false
	if len(tldID) == 0 {
		// §7.7 reserved-alias gate (naming/reserved.go): a delegated ICANN
		// TLD or IANA special-use alias is treated as claim-less — NXDOMAIN,
		// no claim walk, AA per the caller's route wrapping — EVEN IF the
		// network holds a (rogue-witnessed) claim. This is the resolution
		// half of "a first-time user must never land on a spoofed site under
		// a real-TLD-shaped freens name": the witness gate keeps OUR nodes
		// from co-signing such claims, and this gate refuses to ACCEPT one
		// even if five malicious nodes did. [alias-pins] resolved above are
		// deliberately exempt (an explicit local pin is operator policy,
		// never something a remote claimant can plant); [options]
		// allow-reserved / the daemon -allow-reserved flag opts out.
		if naming.IsReservedTLD(alias) && (r.Cfg == nil || !r.Cfg.AllowReserved) {
			r.notifyAliasDead(alias, nil) // purge any trust-sync state for it
			return nil, dns.RcodeNameError, nil
		}
		tldID, contested, degraded = r.resolveAliasClaim(ctx, alias, now)
		if degraded {
			// Issue #1: the claim layer could not be interrogated (probe
			// failures, nothing local). SERVFAIL — which putFreens never
			// caches — so the next query retries instead of a 60 s
			// negative-cached NXDOMAIN for an alias whose claim holders
			// may be alive.
			return nil, dns.RcodeServerFailure, nil
		}
		if len(tldID) == 0 {
			r.notifyAliasDead(alias, nil) // no claim left: purge any trust-sync state
			return nil, dns.RcodeNameError, nil
		}
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
			// Missing hop: chain broken → name does not exist in freens. A
			// missing APEX (k == 0) is a dead alias for §9.5.4 purposes.
			if k == 0 {
				r.notifyAliasDead(alias, tldID)
			}
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
			if k == 0 {
				r.notifyAliasDead(alias, tldID) // expired/invalid apex: dead
			}
			return nil, dns.RcodeNameError, nil
		}
		// §8.5 (lines 708-713): a revoked envelope (revoke = true) marks its
		// name deliberately dead. Revocation at ANY hop — the terminal record
		// OR an intermediate delegation — breaks the authority walk, so the
		// queried name is unresolvable → NXDOMAIN. (The holder may un-revoke
		// via a newer sequence; until then the chain through this hop is
		// dead.)
		if env.IsRevoked() {
			if k == 0 {
				r.notifyAliasDead(alias, tldID) // §8.5 tombstone on the apex
			}
			return nil, dns.RcodeNameError, nil
		}
		chain = append(chain, env)
	}

	// Step 3c: verify the terminal envelope (basic validity) and the full
	// authority chain (§3.4, with §8.3 transferred TLD roots).
	terminal := chain[len(chain)-1]
	if !wire.IsBasicValid(terminal, uint64(now)) {
		return nil, dns.RcodeNameError, nil
	}
	if !r.verifyAuthorityChain(ctx, chain) {
		return nil, dns.RcodeNameError, nil
	}

	// §9.5.4: the verified winning apex may carry the owner-CA binding —
	// hand it to trust sync (asynchronously; never in the answer path). The
	// bytes are copied: the sink runs concurrently with the shared flight.
	if r.TLSSync != nil {
		for _, rr := range chain[0].Record.RRset {
			if rr != nil && rr.Type == wire.RRTypeTLSCA {
				caDER := append([]byte(nil), rr.Rdata...)
				tld := append([]byte(nil), tldID...)
				expires := int64(chain[0].Record.Expires)
				go r.TLSSync.OnOwnerCA(alias, tld, caDER, expires)
				break
			}
		}
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
	// §10.4 line 853 (via §7.5): an answer whose alias resolution went through
	// a CONTEST_WINDOW-young winning claim is not final — cap its TTL at
	// contestedClaimTTLCap so neither this resolver's ResponseCache
	// (putFreens expires with the minimum RR TTL) nor a downstream cache holds
	// it past the contest. Only lowered, never raised; pin-resolved names
	// (contested == false) and final winners keep their §9.2 TTL.
	if contested {
		for _, rr := range out {
			if rr.Header().Ttl > contestedClaimTTLCap {
				rr.Header().Ttl = contestedClaimTTLCap
			}
		}
	}
	return out, dns.RcodeSuccess, nil
}

// notifyAliasDead forwards a definite alias death to §9.5.4 trust sync.
// Asynchronous and nil-safe; never called on transient failures (the
// SERVFAIL/degraded paths return before reaching a notify point).
func (r *Resolver) notifyAliasDead(alias string, tldID []byte) {
	if r.TLSSync == nil {
		return
	}
	tld := append([]byte(nil), tldID...)
	go r.TLSSync.OnAliasDead(alias, tld)
}

// verifyAuthorityChain verifies the walked chain per §3.4, additionally
// accepting a §8.3 whole-TLD transfer OR a §8.4 recovery hand-off as
// chain[0] when — and only when — the record source can produce the
// superseded predecessors by hash (HistoryResolver), and, for recoveries,
// the §8.4 quorum evidence (RecoveryEvidenceResolver).
//
// §8.3 (lines 666-687) defines the transfer record as: owner = the NEW owner
// key, delegation = the same new key ("subtree authority follows"),
// prev_hash = H_record(previous signed envelope), sequence = prev + 1, and
// "signature: by ... (current owner key)" — i.e. signed by the PREVIOUS
// owner, "because the previous owner — whose key the current authority chain
// names — signed it" (line 681). "For a whole-TLD transfer, the same
// operation on the TLD record transfers the alias and all undelegated names
// at once" (lines 686-687).
//
// §8.4 (lines 689-707) defines the recovery hand-off dually: the primary key
// is lost, a threshold of the §5.4 recovery keys signs a declaration handing
// the name to a new primary, and the resulting record is "published like any
// record (sequence +1, `recovery` fields updated)" — but signed by the NEW
// owner (only K2 can sign after K1 was lost), with the PROOF living outside
// the record as RecoveryEvidence. "After the timelock elapses with no
// cancellation, the recovery record takes effect and the new primary key
// owns the name" (lines 700-701): the timelock (now >= NotBefore) and the
// cancellation race (step 2: the current primary cancels by publishing a
// higher-sequence record — which the §6.4 winner rule arbitrates before any
// of this is consulted) are therefore decided per query, at resolve time.
//
// Dispatch note (§8.4 vs the plain rules): a recovery hand-off record has
// Signer == Owner, so it would take the plain-verifier branch below — and
// FAIL it: the name still carries the ORIGINAL tld_id (crypto.TldID(K2) !=
// tld_id), so the root is not self-certifying for its new owner. ANY
// chain[0] with a non-empty prev_hash is therefore routed through the
// hand-off/transfers walker, which decides per hop whether it links via a
// §8.3 transfer (signer == predecessor owner) or a §8.4 recovery (signer ==
// owner != predecessor owner, quorum evidence + caller-clock timelock).
// signer==owner roots with NO prev_hash keep the byte-identical plain path.
//
// Concretely (zero behavior change outside the hand-off cases):
//
//   - chain[0].Record.PrevHash empty (or no record): wire.VerifyAuthorityChain
//     exactly as before — ordinary self-certifying roots, and a signer !=
//     owner record without prev_hash is NOT a hand-off and still rejects.
//   - prev_hash non-nil (a §8.3 transfer or a §8.4 recovery root):
//     if r.Freens implements HistoryResolver, the predecessors are fetched
//     via LookupByHash (this node's retained history or any peer's — storing
//     nodes retain superseded envelopes for audit per §8.3) and verification
//     goes through wire.VerifyAuthorityChainWithHandoffs when the source ALSO
//     implements RecoveryEvidenceResolver (the evidence fetcher is wired
//     through, and the resolver's own clock drives the §8.4 timelock gate),
//     else through wire.VerifyAuthorityChainWithTransfers exactly as today
//     (a recovery root then still rejects: its hops need evidence a
//     transfer-only walker cannot check). On false the caller NXDOMAINs as
//     usual. If the source implements NEITHER, the hand-off is unprovable
//     from this vantage point, so today's behavior stands: reject.
func (r *Resolver) verifyAuthorityChain(ctx context.Context, chain []*wire.SignedEnvelope) bool {
	root := chain[0]
	if root.Record == nil || len(root.Record.PrevHash) == 0 {
		// Ordinary (or malformed) root: the §3.4 rules alone apply —
		// identical to the pre-§8.3 resolver for every input.
		return wire.VerifyAuthorityChain(chain)
	}
	hr, ok := r.Freens.(HistoryResolver)
	if !ok {
		// A hand-off with no way to fetch predecessors: keep today's
		// reject (the plain chain rules fail signer != owner roots, and a
		// recovery root fails the self-certification).
		return wire.VerifyAuthorityChain(chain)
	}
	fetchPredecessor := func(prevHash []byte) (*wire.SignedEnvelope, error) {
		return hr.LookupByHash(ctx, prevHash)
	}
	if er, ok := r.Freens.(RecoveryEvidenceResolver); ok {
		fetchEvidence := func(recordHash []byte) (*wire.RecoveryEvidence, error) {
			return er.RecoveryEvidence(ctx, recordHash)
		}
		// §8.4: the caller's (resolver's) clock drives the timelock gate —
		// pre-timelock recoveries NXDOMAIN here even though the DHT stored
		// them (the §8.4 step-2 cancellation window).
		return wire.VerifyAuthorityChainWithHandoffs(chain, fetchPredecessor, fetchEvidence, uint64(r.now()))
	}
	return wire.VerifyAuthorityChainWithTransfers(chain, fetchPredecessor)
}

// resolveAliasClaim implements the network side of §9.2 step 3a (alias →
// tld_id without a local pin). Source discovery is by capability, newest
// first, so wiring stays automatic and backward compatible:
//
//   - ClaimSetResolver (§7.4 verifier side): collect the merged SET of
//     competing claim envelopes, filter each through the §7 checklist
//     (verifyClaimEnvelope), order the survivors per §7.4 step 3, and select
//     the deterministic winner (resolveClaimSet). Returns the winner's
//     tld_id and whether the winner is still inside the §7.5 CONTEST_WINDOW
//     (drives the §10.4 contested TTL cap in freensResolve).
//   - ClaimResolver only (legacy): the single K_claim envelope, verified by
//     the same checklist. §7.4 set semantics cannot be assessed from one
//     envelope, so the legacy path keeps its historical behavior (no contest
//     flag); sources wanting full §7.4 semantics implement ClaimSetResolver.
//
// It returns (nil, false, false) (freens branch miss → NXDOMAIN) on ANY
// failure — an unresolvable alias and an unprovable one are
// indistinguishable to the caller by design — EXCEPT the degraded-miss
// signal (issue #1): when the claim collection could not interrogate the
// network (probe failures, nothing local), degraded is true and the caller
// answers SERVFAIL (retryable, never negative-cached) instead of NXDOMAIN.
func (r *Resolver) resolveAliasClaim(ctx context.Context, alias string, now int64) (tldID []byte, contested, degraded bool) {
	if csr, ok := r.Freens.(ClaimSetResolver); ok {
		return r.resolveClaimSet(ctx, csr, alias, now)
	}
	cr, ok := r.Freens.(ClaimResolver)
	if !ok {
		return nil, false, false // record source is not claim-capable: pins only
	}
	env, err := cr.LookupClaim(ctx, alias, now)
	if errors.Is(err, dht.ErrDegradedMiss) || errors.Is(err, dht.ErrWalkBusy) {
		return nil, false, true
	}
	if err != nil || env == nil || env.Record == nil {
		return nil, false, false // transient error is a miss here — the freens branch NXDOMAINs
	}
	oracle, _ := r.Freens.(DifficultyOracle)
	claim := verifyClaimEnvelope(env, alias, now, oracle, nil) // legacy path: no converged set
	if claim == nil {
		return nil, false, false
	}
	return claim.TldID, false, false
}

// resolveClaimSet implements §7.4 verifier steps 1-4 (spec lines 600-617) on
// the claim set a ClaimSetResolver collected:
//
//  1. Collect (done by the source): "get(K_claim); collect all competing
//     claims nodes offer".
//  2. Filter: each envelope individually passes the §7 checklist
//     (verifyClaimEnvelope: structural validity, alias match, claimant
//     binding, PoW, and ≥ W = 5 distinct CORROBORATING witnesses via
//     claims.VerifyFull — v2 attestations bound to the claim identity and
//     dated inside the corroboration band; when the source also implements
//     ClaimSetWithWitnesses (v0.7.0) the witnesses are additionally
//     restricted to the converged WITNESS_SET of the same walk, closing the
//     fabricated-quorum hole. The Appendix A.4 difficulty inference is
//     floored at the source's gossiped network difficulty when it implements
//     DifficultyOracle; see effectivePoWDifficulty).
//  3. Order the surviving claims ascending by the §7.4 step-3 lexicographic
//     tuple (timestamp, pow_hash, tld_id) via claims.OrderClaims — "earliest
//     asserted time wins; ties broken by lower PoW hash (a public lottery),
//     then by lower TLD ID. This total order is computable by any client from
//     claim contents alone — convergence without consensus."
//  4. Select the winner via claims.SelectWinner (the minimum OrderKey over
//     the ordered survivors — SelectWinner does NOT itself encode the §7.5
//     contest window; it is the pure §7.4 step-3 minimum). The winner's
//     tld_id "is the resolution of the alias".
//
// The second return value is the §7.5/§10.4 contest state: the winner is
// CONTESTED while now - winner.timestamp < CONTEST_WINDOW (48 h), because
// §7.5 says clients "MUST NOT treat either as final until ... the
// deterministic order picks a winner and no earlier-ordered valid claim
// appears within CONTEST_WINDOW (48 h)" — a younger winner can still be
// displaced by a later-appearing earlier-ordered claim. (The live-race case
// of §7.5 — two claims within SKEW_TOLERANCE = 60 s — is subsumed: such a
// winner is necessarily younger than the window. Conversely an old winner
// whose runner-up is near-in-time has already survived the window with no
// earlier-ordered claim appearing, hence final per §7.5(b).) §7.5 lets a
// resolver "resolve contested aliases to the current deterministic winner
// while flagging the name as contested in diagnostics"; the flag surfaces
// here as the contested return value, consumed by freensResolve as the §10.4
// 60 s TTL cap (a diagnostics channel does not exist in this resolver).
func (r *Resolver) resolveClaimSet(ctx context.Context, csr ClaimSetResolver, alias string, now int64) (tldID []byte, contested, degraded bool) {
	var witnessSet map[string]bool // nil = membership unenforced (sparse view / legacy source)
	var envs []*wire.SignedEnvelope
	var err error
	// v0.7.0: prefer the walk-consistent witness set when the source can
	// name it; the §7.3 quorum is then restricted to the WITNESS_SET.
	if cww, ok := csr.(ClaimSetWithWitnesses); ok {
		envs, witnessSet, err = cww.CollectClaimsWithWitnesses(ctx, alias, now)
	} else {
		envs, err = csr.CollectClaims(ctx, alias, now)
	}
	if errors.Is(err, dht.ErrDegradedMiss) || errors.Is(err, dht.ErrWalkBusy) {
		return nil, false, true // issue #1 / overload: retryable, not NXDOMAIN
	}
	if err != nil || len(envs) == 0 {
		return nil, false, false // transient error / no claim anywhere: a miss
	}
	survivors := make([]*claims.AliasClaim, 0, len(envs))
	oracle, _ := r.Freens.(DifficultyOracle)
	// §8.4 reuse window (v0.8.0; exemption refined v0.9.1): dead-but-offered
	// claim envelopes act as tombstones. While one is inside
	// ALIAS_REUSE_DELAY past its expiry and no surviving claim is continuity
	// with the dead lease, the alias is cooling off: the resolver selects no
	// winner (NXDOMAIN). Continuity is EITHER of:
	//
	//   - a surviving carrier created BEFORE the tombstone's expires (the
	//     v0.8.0 unbroken-renewal-chain rule), OR
	//   - a surviving carrier of the TOMBSTONE'S OWN claim identity
	//     (v0.9.1): the claimant re-asserting its lapsed lease — only the
	//     claimant key can sign such a carrier, and it embeds the exact
	//     claim (same PoW, same attestations) that registered the alias.
	//     Without this, any owner whose renewal arrived late (daemon
	//     downtime, publish failures) locked the alias for the full 30-day
	//     window — found live fleet-wide 2026-08-22.
	//
	// Everything is re-verified locally from signatures (see
	// verifyClaimContents).
	var maxDeadExpires int64
	var maxDeadPH []byte // strongest tombstone's claim identity
	type liveClaim struct {
		claim   *claims.AliasClaim
		created int64
		ph      []byte
	}
	liveClaims := make([]liveClaim, 0, len(envs))
	for _, env := range envs {
		if claim := verifyClaimEnvelope(env, alias, now, oracle, witnessSet); claim != nil {
			ph, pherr := claim.PrefixHash()
			if pherr != nil {
				continue // unhashable identity: cannot prove continuity
			}
			liveClaims = append(liveClaims, liveClaim{claim, int64(env.Record.Created), ph})
			continue
		}
		// Tombstone candidate: same full content screen minus liveness
		// (no oracle floor and no WITNESS_SET membership — the claim was
		// mined and witnessed days ago; A.4's "any historically valid D"
		// and set churn both argue for the relaxed check), plus dead and
		// inside the window. Revoked carriers (§8.5, deliberate death)
		// are not tombstones. The §4.4 checks IsBasicValid would have
		// done on the live path are applied here explicitly EXCEPT the
		// time window (structure, signature, sequence).
		if env != nil && env.Record != nil && !env.IsRevoked() &&
			env.Record.Version == constants.ProtoVersion &&
			env.Record.Sequence >= 1 &&
			env.Record.Validate() == nil &&
			env.VerifySignature() &&
			uint64(now) >= env.Record.Expires &&
			int64(env.Record.Expires)+int64(constants.AliasReuseDelay) > now &&
			verifyClaimContents(env, alias, now, nil, nil) != nil {
			if int64(env.Record.Expires) > maxDeadExpires {
				maxDeadExpires = int64(env.Record.Expires)
				if deadClaim, derr := claims.DecodeAliasClaim(env.Record.Claim); derr == nil {
					if ph, pherr := deadClaim.PrefixHash(); pherr == nil {
						maxDeadPH = ph
					} else {
						maxDeadPH = nil
					}
				} else {
					maxDeadPH = nil
				}
			}
		}
	}
	if len(liveClaims) == 0 {
		return nil, false, false // every competing claim failed the §7.4 step-2 filter
	}
	if maxDeadExpires > 0 {
		continuity := false
		for _, lc := range liveClaims {
			if lc.created < maxDeadExpires ||
				(len(maxDeadPH) > 0 && bytes.Equal(lc.ph, maxDeadPH)) {
				continuity = true
				break
			}
		}
		if !continuity {
			// §8.4: the alias is inside its reuse window and no surviving
			// claim is continuity with the dead lease (every survivor is a
			// fresh re-claim post-dating the death) — no winner until the
			// window closes.
			return nil, false, false
		}
	}
	for _, lc := range liveClaims {
		survivors = append(survivors, lc.claim)
	}
	winner := claims.SelectWinner(claims.OrderClaims(survivors))
	if winner == nil {
		return nil, false, false // unreachable (survivors passed the same filter)
	}
	return winner.TldID, now-int64(winner.Timestamp) < int64(constants.ContestWindow), false
}

// verifyClaimEnvelope applies the per-claim §7.4 step-2 filter ("Filter:
// structurally valid, PoW valid, witness quorum valid", spec line 605) plus
// the record-side bindings, to ONE claim envelope. It returns the decoded
// AliasClaim on success or nil on any failure (the caller drops the claim —
// for the set path a failing claim loses the race by not surviving the
// filter; for the legacy single-claim path nil means "no claim"):
//
//  1. Envelope: wire.IsBasicValid at `now` — §4.4 structural validity, the
//     record signature over the canonical CBOR (which covers the embedded
//     claim as ordinary content, §4.2), and the created <= now < expires
//     window. A forged or stale carrier record is rejected here.
//  2. Claim decode: claims.DecodeAliasClaim on Record.Claim (raw canonical
//     CBOR of field 11) — a decode error is treated as "no claim".
//  3. Alias match: claim.Alias == the normalized requested alias, so a claim
//     served under the wrong K_claim cannot redirect a different alias.
//  4. Claimant binding to the carrier record: the envelope must be signed by
//     the claimant's TLD key (env.Signer == claim.ClaimantPK) AND be the TLD
//     record for the claimed tld_id (Record.Name decodes to zero labels with
//     tld_id == claim.TldID). Together with step 1's signature check this
//     means the claimant key itself published the claim — the §3.1
//     self-certification that step 3b's chain walk then re-proves at K_tld.
//  5. claims.VerifyFull(claim, effectivePoWDifficulty(claim, oracle),
//     witnessSet, constants.W): claimant consistency (tld_id ==
//     SHA-256(claimant_pk)), recomputed PoW at the difficulty recorded in
//     nonce[0] (Appendix A.4) or the network default — floored at the
//     source's gossiped difficulty when it implements DifficultyOracle — and
//     ≥ W = 5 DISTINCT CORROBORATING witness attestations (each node_pk
//     bound to its node_id, each signature a v2 attestation over the claim's
//     prefix hash, each attestation timestamp inside the corroboration band
//     around the claim's asserted timestamp). witnessSet, when non-nil, is
//     the converged WITNESS_SET (§7.3) named by the collecting walk — the 8
//     closest REACHED nodes to K_claim — and the quorum counts only
//     witnesses among them; nil keeps the legacy unenforced membership
//     (sparse views, legacy sources), where distinctness + binding + band
//     still hold.
//
// On success the returned claim's TldID is SHA-256(claimant_pk); resolution
// then PROCEEDS with the normal §9.2 step 3b chain walk, where the TLD record
// at K_tld must still verify against that tld_id — self-certification, so a
// bogus claim cannot manufacture records, only point elsewhere (§3.2, §10.3).
func verifyClaimEnvelope(env *wire.SignedEnvelope, alias string, now int64, oracle DifficultyOracle, witnessSet map[string]bool) *claims.AliasClaim {
	// (1) envelope signature + time window.
	if env == nil || !wire.IsBasicValid(env, uint64(now)) {
		return nil
	}
	return verifyClaimContents(env, alias, now, oracle, witnessSet)
}

// verifyClaimContents is verifyClaimEnvelope WITHOUT the §4.4 liveness gate
// (step 1): the full per-claim screen — claim decode, alias match, claim-ts
// sanity, claimant binding to the carrier, PoW, and the ≥ W corroborating
// witness quorum — over the envelope's signed CONTENT only, every check of
// which is timeless (signature, PoW, attestations all verify identically
// after the carrier expires). The §8.4 tombstone path reuses it exactly
// because a dead claim's evidence must still verify (see resolveClaimSet).
//
// PRECONDITION (the caller owns the §4.4 envelope-level checks — structure,
// signature, and on the live path the time window): env is non-nil with a
// non-nil Record whose envelope signature has been verified.
func verifyClaimContents(env *wire.SignedEnvelope, alias string, now int64, oracle DifficultyOracle, witnessSet map[string]bool) *claims.AliasClaim {
	if env == nil || env.Record == nil {
		return nil
	}
	// (2) claim decode (field 11 raw canonical CBOR).
	claim, cerr := claims.DecodeAliasClaim(env.Record.Claim)
	if cerr != nil {
		return nil
	}
	// (3) alias match.
	aliasN, aerr := naming.ValidateAlias(alias)
	if aerr != nil || claim.Alias != aliasN {
		return nil
	}
	// (3b) claim-timestamp sanity (§7.4 anti-forgery, defense in depth):
	// ordering is earliest-timestamp-first, so a future-dated claim could
	// outrank every honest one forever. Witnesses refuse such claims at
	// signing time; the resolver refuses them at verification time too.
	if int64(claim.Timestamp) > now+int64(constants.SkewTolerance) {
		return nil
	}
	// (4) claimant binding: the carrier is the claimant's own TLD record.
	if !bytes.Equal(env.Signer, claim.ClaimantPK) {
		return nil
	}
	labels, nameTldID, derr := naming.DecodeWireName(env.Record.Name)
	if derr != nil || len(labels) != 0 || !bytes.Equal(nameTldID, claim.TldID) {
		return nil
	}
	// (5) claimant consistency + PoW + ≥ W distinct corroborating witnesses,
	// optionally restricted to the converged WITNESS_SET. The PoW difficulty
	// is the A.4 inference (nonce[0] when sane, else PoWDifficultyInit),
	// floored at the source's gossiped network difficulty when it implements
	// DifficultyOracle.
	//
	// §7.5 FINALITY HORIZON ON MEMBERSHIP (v0.14.1): the WITNESS_SET
	// restriction is enforced only while the claim is inside its contest
	// window (now - claim.ts < CONTEST_WINDOW); an older claim — one §7.5(b)
	// already declares FINAL — verifies on its attestations alone
	// (signatures + corroboration band + distinctness, all timeless).
	// Rationale, found live fleet-wide 2026-09-01: membership compares
	// REGISTRATION-TIME witnesses against the verifier's CURRENT routing
	// view, and a claim carries exactly W witnesses, so every one of them
	// must still sit in the closest-8 FOREVER. Any churn — a witness node
	// departing (the Aug-31 name cleanup), or newer nodes pushing the
	// keyspace boundary (lucasvps, camalolo-box joining) — silently killed
	// every mature name whose claim it touched, directly against §8's
	// "ownership = liveness of the OWNER". The check's anti-fabrication
	// value is concentrated in the contestable window (a fabricated
	// backdated claim must displace a LIVE registration to matter, and
	// while it is inside the window its sybil witnesses must still be in
	// the verifier's view); after finality the attestations are historical
	// evidence no more re-derivable than the witnesses' availability. The
	// residual — grind sybil IDs into the true witness set AND hold them
	// for the full contest window — is the §12 Sybil bound, now priced in
	// 48 h of presence instead of forever (see the spec's §7.3 membership
	// bullet, amended in the same release).
	set := witnessSet
	if set != nil && now-int64(claim.Timestamp) >= int64(constants.ContestWindow) {
		set = nil
	}
	if !claims.VerifyFull(claim, effectivePoWDifficulty(claim, oracle), set, constants.W) {
		return nil
	}
	return claim
}

// effectivePoWDifficulty computes the difficulty bits a verified claim's PoW
// must meet — the ONE shared helper behind the §7.4 step-2 PoW check
// (verifyClaimEnvelope, used by both the legacy single-claim path and
// resolveClaimSet's per-claim filter).
//
// Appendix A.4 (lines 1004-1008): "claims are individually verified against
// any historically valid D ≥ POW_DIFFICULTY_INIT recorded with the claim
// (pow_bits SHOULD be recorded in nonce's first byte for this purpose)" —
// that is the legacy inference, exactly what claims.VerifyPoW applies for the
// InferDifficulty sentinel (-1): if Nonce is non-empty and Nonce[0] >=
// PoWDifficultyInit the difficulty is Nonce[0], else PoWDifficultyInit. A.4
// also retargets D network-wide ("Nodes gossip the current D in witness
// responses; clients use the median of the GET_CLOSEST nodes' advertised
// values"), so when the source implements DifficultyOracle the verifying node
// floors the check at its gossiped median:
//
//	effective = max(inferred-from-nonce, oracle floor)
//
// A claim minted below the network's current difficulty then fails
// verification even though its own recorded pow_bits are satisfied — the
// verifier-side enforcement of the retarget. Without an oracle the
// claims.InferDifficulty sentinel is returned, so the PoW check is
// byte-for-byte today's behavior.
//
// Coordinate systems: the oracle's floor is a NETWORK value anchored at the
// protocol baseline constants.PoWDifficultyInit (the dht gossip machinery
// floors there), while this verifier's inference baseline is the
// claims.PoWDifficultyInit shadow, which tests lower wholesale for fast
// mining (production leaves it at the constant). The floor is therefore
// translated into the verifier's baseline — floor -= (constants.PoWDifficultyInit -
// claims.PoWDifficultyInit) — so a lowered baseline shifts the whole
// difficulty scale uniformly. In production the translation is the identity
// and the rule is exactly max(inferred, floor); under the test downshift an
// oracle reporting the initial D behaves like no oracle at all.
func effectivePoWDifficulty(c *claims.AliasClaim, oracle DifficultyOracle) int {
	if oracle == nil {
		return claims.InferDifficulty
	}
	// Replicate claims.VerifyPoW's InferDifficulty inference (the sentinel's
	// documented rule); the hash itself is recomputed inside VerifyPoW at
	// whatever difficulty is returned here.
	baseline := int(claims.PoWDifficultyInit.Load())
	inferred := baseline
	if c != nil && len(c.Nonce) >= 1 && int(c.Nonce[0]) >= baseline {
		inferred = int(c.Nonce[0])
	}
	floor := oracle.NetworkDifficulty() - (constants.PoWDifficultyInit - baseline)
	// A.4: the check never drops below the verifier's POW_DIFFICULTY_INIT
	// baseline (a misbehaving oracle cannot lower it either).
	if floor < baseline {
		floor = baseline
	}
	if floor > inferred {
		return floor
	}
	return inferred
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
// constants.ResponseTTLCap, clamped to a non-negative uint32. All §4.3 table
// types are mapped (A, AAAA, NS, CNAME, TXT, MX, SRV, SSHFP, TLSA, CAA);
// unsupported or malformed rdata returns nil (the caller skips it).
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
		// A freens TXT rdata may exceed 255 bytes (§4.3 caps the record,
		// not the string), but one dns.TXT string is an RFC 1035
		// character-string (<= 255). Pre-v0.7.1 a longer rdata produced an
		// un-packable response and WriteMsg failed — the client got
		// silence instead of an answer. Chunk the rdata into <= 255-byte
		// character-strings (the standard multi-string TXT form; the
		// concatenated rdata is what round-trips).
		if len(rr.Rdata) == 0 {
			return &dns.TXT{Hdr: hdr, Txt: []string{""}}
		}
		txt := make([]string, 0, (len(rr.Rdata)+254)/255)
		for len(rr.Rdata) > 0 {
			n := len(rr.Rdata)
			if n > 255 {
				n = 255
			}
			txt = append(txt, string(rr.Rdata[:n]))
			rr.Rdata = rr.Rdata[n:]
		}
		return &dns.TXT{Hdr: hdr, Txt: txt}
	case wire.RRTypeNS:
		// §4.3: rdata = wire_name of target (freens) or DNS name (hybrid).
		// The hybrid form is emitted as-is when it is a valid DNS hostname.
		target, ok := dnsNameFromRdata(rr.Rdata)
		if !ok {
			return nil
		}
		hdr.Rrtype = dns.TypeNS
		return &dns.NS{Hdr: hdr, Ns: target}
	case wire.RRTypeCNAME:
		target, ok := dnsNameFromRdata(rr.Rdata)
		if !ok {
			return nil
		}
		hdr.Rrtype = dns.TypeCNAME
		return &dns.CNAME{Hdr: hdr, Target: target}
	case wire.RRTypeMX:
		// §4.3: uint16 preference (big-endian) || name.
		if len(rr.Rdata) < 3 { // 2 preference + at least 1 name byte
			return nil
		}
		target, ok := dnsNameFromRdata(rr.Rdata[2:])
		if !ok {
			return nil
		}
		hdr.Rrtype = dns.TypeMX
		return &dns.MX{
			Hdr:        hdr,
			Preference: binary.BigEndian.Uint16(rr.Rdata[0:2]),
			Mx:         target,
		}
	case wire.RRTypeSRV:
		// §4.3: uint16 priority, uint16 weight, uint16 port (big-endian),
		// then the target name.
		if len(rr.Rdata) < 7 { // 6 fixed + at least 1 name byte
			return nil
		}
		target, ok := dnsNameFromRdata(rr.Rdata[6:])
		if !ok {
			return nil
		}
		hdr.Rrtype = dns.TypeSRV
		return &dns.SRV{
			Hdr:      hdr,
			Priority: binary.BigEndian.Uint16(rr.Rdata[0:2]),
			Weight:   binary.BigEndian.Uint16(rr.Rdata[2:4]),
			Port:     binary.BigEndian.Uint16(rr.Rdata[4:6]),
			Target:   target,
		}
	case wire.RRTypeSSHFP:
		// §4.3: algorithm byte, fingerprint-type byte, fingerprint (rest).
		if len(rr.Rdata) < 3 {
			return nil
		}
		hdr.Rrtype = dns.TypeSSHFP
		return &dns.SSHFP{
			Hdr:         hdr,
			Algorithm:   rr.Rdata[0],
			Type:        rr.Rdata[1],
			FingerPrint: hex.EncodeToString(rr.Rdata[2:]),
		}
	case wire.RRTypeTLSA:
		// §4.3: usage, selector, matching-type bytes, certificate data (rest).
		if len(rr.Rdata) < 4 {
			return nil
		}
		hdr.Rrtype = dns.TypeTLSA
		return &dns.TLSA{
			Hdr:          hdr,
			Usage:        rr.Rdata[0],
			Selector:     rr.Rdata[1],
			MatchingType: rr.Rdata[2],
			Certificate:  hex.EncodeToString(rr.Rdata[3:]),
		}
	case wire.RRTypeCAA:
		// §4.3: flags byte, tag (length-prefixed byte string), value (rest).
		if len(rr.Rdata) < 2 {
			return nil
		}
		tagLen := int(rr.Rdata[1])
		if tagLen < 1 || 2+tagLen > len(rr.Rdata) {
			return nil
		}
		hdr.Rrtype = dns.TypeCAA
		return &dns.CAA{
			Hdr:   hdr,
			Flag:  rr.Rdata[0],
			Tag:   string(rr.Rdata[2 : 2+tagLen]),
			Value: string(rr.Rdata[2+tagLen:]),
		}
	default:
		// Unknown type codes MUST be preserved verbatim by clients (§4.3,
		// opaque forwarding) — but this resolver cannot map them to a dns.RR
		// without full rdata knowledge, so they are skipped (nil) as before.
		return nil
	}
}

// dnsNameFromRdata interprets the name portion of a §4.3 rdata field (NS,
// CNAME, MX tail, SRV target) in its hybrid DNS-name form: the bytes are the
// hostname string, trimmed of surrounding whitespace and terminated with the
// DNS root label (miekg/dns refuses to pack a non-FQDN target). ok is false
// for an empty or structurally invalid hostname (dns.IsDomainName), in which
// case the caller drops the RR.
func dnsNameFromRdata(b []byte) (string, bool) {
	s := strings.TrimSpace(string(b))
	if _, ok := dns.IsDomainName(s); !ok {
		return "", false
	}
	return dns.Fqdn(s), true
}

// ---------------------------------------------------------------------------
// Proactive refresh sweeper (§10.4 amended, second leg): the query-driven
// kicks (prefetch + stale-serve) only revalidate names a client is ASKING
// about; a name whose hits stop for longer than the stale window ages out
// and its next query walks cold (~seconds, found live on the desktop box).
// The sweeper closes that: every tick it revalidates the WARM SET —
// positive entries hit within the last refreshSweepHorizon whose data is
// (nearly) expired — so any name in recurring use is answered from cache
// forever, and each entry's data is re-verified continuously even with no
// client queries (a revocation or address change is learned proactively,
// not at the next client query).
// ---------------------------------------------------------------------------

const (
	// refreshSweepEvery is the sweeper tick.
	refreshSweepEvery = time.Minute
	// refreshSweepHorizon is the warm-set membership: entries hit within
	// this window keep being refreshed; older ones age out (their next
	// query walks once, then they're warm again).
	refreshSweepHorizon = 24 * 3600
	// refreshSweepBatch bounds refreshes kicked per tick so a large warm
	// set cannot stampede the DHT; the stale path keeps those answers
	// instant while the backlog drains.
	refreshSweepBatch = 16
)

// SweepRefreshes kicks the background refresh for every warm-set entry
// that needs one, returning how many kicks were issued. Exposed for tests;
// RunRefreshSweeper is the daemon-facing loop.
func (r *Resolver) SweepRefreshes(now int64) int {
	if r.Cache == nil {
		return 0
	}
	keys := r.Cache.SweepCandidates(now, refreshSweepHorizon, refreshSweepBatch)
	kicked := 0
	for _, k := range keys {
		r.kickRefresh(dns.Question{Name: k.name, Qtype: k.qtype, Qclass: k.qclass}, k)
		kicked++
	}
	return kicked
}

// RunRefreshSweeper runs SweepRefreshes every refreshSweepEvery until stop
// closes. Daemon-facing wiring (bgStop); a resolver without a cache is a
// no-op.
func (r *Resolver) RunRefreshSweeper(stop <-chan struct{}) {
	if r.Cache == nil {
		return
	}
	t := time.NewTicker(refreshSweepEvery)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			nowFn := r.Now
			if nowFn == nil {
				nowFn = func() int64 { return time.Now().Unix() }
			}
			r.SweepRefreshes(nowFn())
		}
	}
}
