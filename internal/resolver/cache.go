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
// also expire by TTL; a Get past the expiry is a miss (the entry is dropped
// and the resolver re-consults the namespace). Cached RRs are deep-copied on
// retrieval with their TTLs decayed to the remaining validity, so callers
// never share mutable RR pointers with the cache.
//
// Per §10.4 line 855 ("cached envelopes are re-verified on use after fetch")
// this cache stores VERIFICATION RESULTS (rrs, rcode, aa) for their validity
// period — never raw envelopes.

import (
	"sync"
	"time"

	"github.com/laurent/freens/internal/constants"
	"github.com/miekg/dns"
)

// DefaultCacheMaxEntries is the response-cache entry bound used when
// NewResponseCache is given a non-positive maxEntries (§10.4; eviction is
// oldest-first).
const DefaultCacheMaxEntries = 4096

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

// get returns the cached outcome for key, with every answer RR deep-copied
// and its TTL decayed to the remaining cache lifetime. ok is false on a miss
// or an expired entry (which is dropped).
func (c *ResponseCache) get(key cacheKey) (rrs []dns.RR, rcode int, aa bool, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, hit := c.entries[key]
	if !hit {
		return nil, 0, false, false
	}
	now := c.now()
	if now >= e.expiresAt {
		delete(c.entries, key)
		return nil, 0, false, false
	}
	remaining := uint32(e.expiresAt - now)
	out := make([]dns.RR, len(e.rrs))
	for i, rr := range e.rrs {
		cp := dns.Copy(rr)
		cp.Header().Ttl = remaining
		out[i] = cp
	}
	return out, e.rcode, e.aa, true
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
	c.sweepExpiredLocked(now)
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
