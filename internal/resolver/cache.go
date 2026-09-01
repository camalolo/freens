package resolver

// This file implements the §10.4 caching rules (spec lines 849-857) for the
// DNS server path:
//
//   - Positive freens answers are cached for min(RR TTL, validity remaining),
//     each RR's TTL having already been clamped to min(rr.TTL, expires-now)
//     capped by RESPONSE_TTL_CAP when mapped (freensRRToDNS, §9.2 line 752).
//   - Negative freens answers (NXDOMAIN / NODATA) are cached for
//     constants.NegTTL (60 s, §9.2 step 3 line 744 / Appendix A).
//   - DNS-forwarded answers are NOT cached here: upstream TTLs are already
//     managed by the upstream recursors, and this cache only stores
//     freens-sourced outcomes (aa == true, i.e. the final answer came from
//     freensResolve).
//
// The cache is keyed on (qname, qtype, qclass), bounded to a configurable
// entry count (default 4096), and evicts the OLDEST entry when full. Entries
// also expire by TTL; a Get past the expiry is a MISS for negative entries
// and for positives past the serve-stale window (§10.4 amended: an expired
// positive answer inside the window is served immediately — it was fully
// validated when fetched — while ServeDNS revalidates it in the background;
// the refresh's putFreens replaces the entry either way). Cached RRs are
// deep-copied on retrieval with their TTLs decayed, so callers never share
// mutable RR pointers with the cache.
//
// Per §10.4 line 855 ("cached envelopes are re-verified on use after fetch")
// this cache stores VERIFICATION RESULTS (rrs, rcode, aa) for their validity
// period — never raw envelopes.

import (
	"sync"
	"time"

	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/metrics"
	"github.com/miekg/dns"
)

// DefaultCacheMaxEntries is the response-cache entry bound used when
// NewResponseCache is given a non-positive maxEntries (§10.4; eviction is
// oldest-first).
const DefaultCacheMaxEntries = 4096

// cacheSweepEvery is how many puts happen between full expired-sweeps. The
// pre-v0.7.1 code swept the WHOLE map on EVERY insert (O(4096) under the
// cache mutex all queries share); expiry is already enforced per-entry on
// Get, so a periodic sweep (plus oldest-eviction at capacity) keeps the same
// correctness at 1/64th the amortized insert cost.
const cacheSweepEvery = 64

// cacheKey identifies a cached outcome: the question name, type, and class.
// A question with different name/qtype/qclass is a different cache entry.
type cacheKey struct {
	name   string
	qtype  uint16
	qclass uint16
}

// cacheKeyFor builds the cache key of a DNS question.
func cacheKeyFor(q dns.Question) cacheKey {
	return cacheKey{name: q.Name, qtype: q.Qtype, qclass: q.Qclass}
}

// cacheEntry is a cached ResolveQuestion outcome plus its expiry (unix
// seconds) and insertion stamp (for oldest-first eviction).
type cacheEntry struct {
	rrs       []dns.RR // nil for negative entries
	rcode     int
	aa        bool
	expiresAt int64
	stamp     uint64 // insertion order, monotonically increasing
}

// ResponseCache is a bounded, thread-safe cache of freens resolution outcomes
// implementing the §10.4 caching rules. Construct with NewResponseCache; a
// zero-value cache is not usable (the map is nil).
type ResponseCache struct {
	mu         sync.Mutex
	entries    map[cacheKey]*cacheEntry
	maxEntries int
	now        func() int64 // wall-clock seconds
	nextStamp  uint64
	sinceSweep int // inserts since the last full expired-sweep (cadence: cacheSweepEvery)
	// hits/misses/staleServes optionally count get2() outcomes; nil (the
	// default, or a SetMetrics(nil) call) leaves the cache uninstrumented.
	hits   *metrics.Counter
	misses *metrics.Counter
	stales *metrics.Counter
}

// NewResponseCache builds an empty ResponseCache (§10.4). maxEntries <= 0
// defaults to DefaultCacheMaxEntries; a nil now function defaults to
// time.Now().Unix() (tests inject a deterministic clock).
func NewResponseCache(maxEntries int, now func() int64) *ResponseCache {
	if maxEntries <= 0 {
		maxEntries = DefaultCacheMaxEntries
	}
	clock := now
	if clock == nil {
		clock = func() int64 { return time.Now().Unix() }
	}
	return &ResponseCache{
		entries:    make(map[cacheKey]*cacheEntry),
		maxEntries: maxEntries,
		now:        clock,
	}
}

// Len returns the number of entries currently held (including not-yet-swept
// expired ones; expiry is enforced on Get and swept on insert).
func (c *ResponseCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// SetMetrics registers the cache hit/miss counters
// (freens_resolver_cache_hits_total / freens_resolver_cache_misses_total) on m.
// It may be called before first use; a nil registry (or no call) disables
// instrumentation. Call it once per cache on a given registry — the metrics
// package panics on duplicate registration.
func (c *ResponseCache) SetMetrics(m *metrics.Registry) {
	if m == nil {
		return
	}
	c.hits = m.NewCounter("freens_resolver_cache_hits_total",
		"Response-cache lookups served from a live cache entry (§10.4).")
	c.misses = m.NewCounter("freens_resolver_cache_misses_total",
		"Response-cache lookups absent or expired (resolver re-consulted the namespace).")
	c.stales = m.NewCounter("freens_resolver_cache_stale_total",
		"Expired positive answers served while a background refresh revalidated them (§10.4 serve-stale).")
}

// countHit/countMiss/countStale bump the optional counters (no-op when
// uninstrumented).
func (c *ResponseCache) countHit() {
	if c.hits != nil {
		c.hits.With().Inc()
	}
}

func (c *ResponseCache) countMiss() {
	if c.misses != nil {
		c.misses.With().Inc()
	}
}

func (c *ResponseCache) countStale() {
	if c.stales != nil {
		c.stales.With().Inc()
	}
}

// get returns the cached outcome for key, with every answer RR deep-copied
// and its TTL decayed to the remaining cache lifetime. ok is false on a miss
// or an expired entry (which is dropped). The hit/miss counters are bumped
// OUTSIDE the cache mutex (each does a strings.Join + its own lock; counting
// under c.mu serialized every query against every insert).
func (c *ResponseCache) get(key cacheKey) (rrs []dns.RR, rcode int, aa bool, ok bool) {
	rrs, rcode, aa, status := c.get2(key)
	return rrs, rcode, aa, status == cacheFresh
}

// cacheStatus classifies a get2 outcome: cacheFresh (live entry), cacheStale
// (expired POSITIVE entry still inside the §10.4 serve-stale window — the
// answer was fully validated when fetched, and ServeDNS will revalidate it
// in the background while serving this copy), or cacheMiss.
type cacheStatus int

const (
	cacheMiss cacheStatus = iota
	cacheFresh
	cacheStale
)

// staleTTL is the DNS TTL emitted when serving a STALE entry: short, so
// downstream stub resolvers re-ask soon and pick up the refreshed answer
// (or lose the stale crutch) instead of holding the old copy for a full
// record TTL.
const staleTTL = 30

// get2 is get() with the serve-stale dimension: an expired positive entry
// whose age past expiry is still within StaleServeSecs is returned with
// cacheStale instead of being dropped (negatives are ALWAYS dropped — a
// revoked name must go dark within its TTL + NegTTL, never later). The
// caller is expected to kick a background refresh for stale outcomes; the
// refresh's putFreens replaces the entry with fresh data either way.
func (c *ResponseCache) get2(key cacheKey) (rrs []dns.RR, rcode int, aa bool, status cacheStatus) {
	c.mu.Lock()
	e, hit := c.entries[key]
	if !hit {
		c.mu.Unlock()
		c.countMiss()
		return nil, 0, false, cacheMiss
	}
	now := c.now()
	if now < e.expiresAt {
		remaining := uint32(e.expiresAt - now)
		out := make([]dns.RR, len(e.rrs))
		for i, rr := range e.rrs {
			cp := dns.Copy(rr)
			cp.Header().Ttl = remaining
			out[i] = cp
		}
		rcode, aa = e.rcode, e.aa
		c.mu.Unlock()
		c.countHit()
		return out, rcode, aa, cacheFresh
	}
	// Expired: positive answers may serve stale (bounded); negatives and
	// anything past the stale window are dropped for a real re-resolve.
	if len(e.rrs) > 0 && now < e.expiresAt+int64(constants.StaleServeSecs) {
		remaining := uint32(e.expiresAt + int64(constants.StaleServeSecs) - now)
		if remaining > staleTTL {
			remaining = staleTTL
		}
		out := make([]dns.RR, len(e.rrs))
		for i, rr := range e.rrs {
			cp := dns.Copy(rr)
			cp.Header().Ttl = remaining
			out[i] = cp
		}
		rcode, aa = e.rcode, e.aa
		c.mu.Unlock()
		c.countStale()
		return out, rcode, aa, cacheStale
	}
	delete(c.entries, key)
	c.mu.Unlock()
	c.countMiss()
	return nil, 0, false, cacheMiss
}

// putFreens stores a freens-sourced (aa == true) ResolveQuestion outcome per
// §10.4:
//
//   - NOERROR with answers: cached for min(RR TTLs) seconds (each TTL already
//     being min(rr.TTL, expires-now) capped by RESPONSE_TTL_CAP); a zero
//     minimum TTL is not cached at all (DNS convention: TTL 0 = do not cache).
//   - NXDOMAIN or NODATA (NOERROR with no answers): cached for NegTTL
//     seconds.
//   - Any other rcode (REFUSED/SERVFAIL-class) is never cached.
//
// Non-freens outcomes (aa == false: DNS-forwarded, DENY) are ignored — §10.4
// covers only freens answers.
func (c *ResponseCache) putFreens(key cacheKey, rrs []dns.RR, rcode int, aa bool) {
	if !aa {
		return // DNS-forwarded / policy answers are not freens outcomes.
	}
	now := c.now()
	var e *cacheEntry
	switch {
	case rcode == dns.RcodeSuccess && len(rrs) > 0:
		ttl := int64(^uint32(0) >> 1) // start from "infinity" (max int32)
		for _, rr := range rrs {
			if t := int64(rr.Header().Ttl); t < ttl {
				ttl = t
			}
		}
		if ttl > constants.ResponseTTLCap {
			ttl = constants.ResponseTTLCap
		}
		if ttl <= 0 {
			return // TTL 0 answers must not be cached.
		}
		// Deep-copy the answer so later mutation by the DNS writer cannot
		// corrupt the cached entry.
		stored := make([]dns.RR, len(rrs))
		for i, rr := range rrs {
			stored[i] = dns.Copy(rr)
		}
		e = &cacheEntry{rrs: stored, rcode: rcode, aa: aa, expiresAt: now + ttl}
	case rcode == dns.RcodeNameError || (rcode == dns.RcodeSuccess && len(rrs) == 0):
		// §9.2 step 3: NXDOMAIN/NODATA negative-cached 60 s (§10.4 line 852).
		e = &cacheEntry{rrs: nil, rcode: rcode, aa: aa, expiresAt: now + int64(constants.NegTTL)}
	default:
		return // REFUSED / SERVFAIL are transient; never cached.
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.nextStamp++
	e.stamp = c.nextStamp
	// Periodic full sweep (per-entry expiry is enforced on Get regardless);
	// see cacheSweepEvery for why this is not per-insert.
	c.sinceSweep++
	if c.sinceSweep >= cacheSweepEvery {
		c.sweepExpiredLocked(now)
		c.sinceSweep = 0
	}
	if len(c.entries) >= c.maxEntries {
		c.evictOldestLocked()
	}
	c.entries[key] = e
}

// sweepExpiredLocked drops every entry past its expiry. Caller holds c.mu.
func (c *ResponseCache) sweepExpiredLocked(now int64) {
	for k, e := range c.entries {
		if now >= e.expiresAt {
			delete(c.entries, k)
		}
	}
}

// evictOldestLocked drops the entry with the smallest insertion stamp
// (oldest-first eviction, §10.4 bounded cache). Caller holds c.mu; assumes
// the cache is non-empty.
func (c *ResponseCache) evictOldestLocked() {
	var oldestKey cacheKey
	minStamp := ^uint64(0)
	found := false
	for k, e := range c.entries {
		if !found || e.stamp < minStamp {
			oldestKey, minStamp, found = k, e.stamp, true
		}
	}
	if found {
		delete(c.entries, oldestKey)
	}
}
