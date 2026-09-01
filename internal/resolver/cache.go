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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
	lastHit   int64  // last CLIENT hit (fresh or stale serve) — the sweeper's warm-set membership; refreshes do NOT count, so abandoned names age out
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
	sinceSweep int  // inserts since the last full expired-sweep (cadence: cacheSweepEvery)
	dirty      bool // unseen state since the last SaveIfDirty (persistence)
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
		e.lastHit = now
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
		e.lastHit = now
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
		e = &cacheEntry{rrs: stored, rcode: rcode, aa: aa, expiresAt: now + ttl, lastHit: now}
	case rcode == dns.RcodeNameError || (rcode == dns.RcodeSuccess && len(rrs) == 0):
		// §9.2 step 3: NXDOMAIN/NODATA negative-cached 60 s (§10.4 line 852).
		e = &cacheEntry{rrs: nil, rcode: rcode, aa: aa, expiresAt: now + int64(constants.NegTTL), lastHit: now}
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
	c.dirty = true
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

// ---------------------------------------------------------------------------
// Persistence (restart resilience): the cache holds §10.4 VALIDATION
// RESULTS from the screened path — restoring one after a daemon restart is
// the same trust as keeping it in memory, and it makes upgrades/restarts
// invisible to clients (found live the hard way: the first browse after the
// v0.13.12 fleet upgrade walked cold through a warming daemon while the
// retry hit the cache — "first time didn't resolve, second worked").
// ---------------------------------------------------------------------------

// persistedEntry is the on-disk form of one entry (dns-cache.json). RRs are
// stored in wire format with their ORIGINAL TTLs (decay to remaining happens
// on retrieval, exactly as for in-memory entries).
type persistedEntry struct {
	Name      string   `json:"name"`
	Qtype     uint16   `json:"qtype"`
	Qclass    uint16   `json:"qclass"`
	Rcode     int      `json:"rcode"`
	AA        bool     `json:"aa"`
	ExpiresAt int64    `json:"expires_at"`
	RRs       [][]byte `json:"rrs"`
}

type persistedCache struct {
	SavedAt int64            `json:"saved_at"`
	Entries []persistedEntry `json:"entries"`
}

// markDirty flags the cache as having unseen state (putFreens). The save
// loop persists only dirty caches.
func (c *ResponseCache) markDirty() {
	c.mu.Lock()
	c.dirty = true
	c.mu.Unlock()
}

// SaveIfDirty writes the cache to path atomically (0600) when its state
// changed since the last save; reports whether a save happened.
func (c *ResponseCache) SaveIfDirty(path string) (bool, error) {
	c.mu.Lock()
	if !c.dirty {
		c.mu.Unlock()
		return false, nil
	}
	c.dirty = false
	saved := c.snapshotLocked()
	c.mu.Unlock()
	if err := writePersisted(path, saved); err != nil {
		c.markDirty() // the state is still unsaved — retry next tick
		return false, err
	}
	return true, nil
}

// snapshotLocked freezes the entries for serialization. Caller holds c.mu.
func (c *ResponseCache) snapshotLocked() *persistedCache {
	pc := &persistedCache{SavedAt: c.now(), Entries: make([]persistedEntry, 0, len(c.entries))}
	for k, e := range c.entries {
		pe := persistedEntry{
			Name: k.name, Qtype: k.qtype, Qclass: k.qclass,
			Rcode: e.rcode, AA: e.aa, ExpiresAt: e.expiresAt,
			RRs: make([][]byte, 0, len(e.rrs)),
		}
		for _, rr := range e.rrs {
			buf := make([]byte, 65535)
			n, err := dns.PackRR(rr, buf, 0, nil, false)
			if err != nil || n <= 0 {
				continue // one unparsable RR must not drop the entry
			}
			pe.RRs = append(pe.RRs, buf[:n])
		}
		pc.Entries = append(pc.Entries, pe)
	}
	return pc
}

// LoadFrom restores entries saved by SaveIfDirty. Entries already past their
// expiry ARE restored: an expired positive inside the §10.4 serve-stale
// window is exactly the validated answer the stale path serves while a
// background refresh revalidates — so a restart is invisible. Entries past
// the window (and negatives past NegTTL) simply miss on first use, as in
// memory. A corrupt/truncated file is ignored (start empty).
func (c *ResponseCache) LoadFrom(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var pc persistedCache
	if err := json.Unmarshal(b, &pc); err != nil {
		return fmt.Errorf("dns cache: %v", err)
	}
	restored := 0
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, pe := range pc.Entries {
		e := &cacheEntry{rcode: pe.Rcode, aa: pe.AA, expiresAt: pe.ExpiresAt, lastHit: pc.SavedAt}
		for _, wire := range pe.RRs {
			rr, _, err := dns.UnpackRR(wire, 0)
			if err != nil {
				e = nil
				break
			}
			e.rrs = append(e.rrs, rr)
		}
		if e == nil || (pe.AA && pe.Rcode == dns.RcodeSuccess && len(e.rrs) == 0) {
			continue // unparsable entry: skip, never fail the whole load
		}
		c.nextStamp++
		e.stamp = c.nextStamp
		c.entries[cacheKey{name: pe.Name, qtype: pe.Qtype, qclass: pe.Qclass}] = e
		restored++
	}
	return nil
}

// SweepCandidates returns the keys the proactive refresher should
// revalidate now: POSITIVE entries whose client hits are inside the warm
// horizon (recently used — a name abandoned for the horizon ages out and
// its next query simply walks, the pre-sweeper behavior) and whose data is
// expired or about to expire (within the prefetch window). Most-recently-
// hit first, bounded to limit so a big warm set degrades gracefully (the
// stale path keeps those answers instant while the backlog drains).
func (c *ResponseCache) SweepCandidates(now, horizonSecs int64, limit int) []cacheKey {
	type cand struct {
		key    cacheKey
		lastHi int64
	}
	var out []cand
	c.mu.Lock()
	for k, e := range c.entries {
		if len(e.rrs) == 0 {
			continue // negatives never refresh proactively
		}
		if now-e.lastHit > horizonSecs {
			continue // outside the warm set
		}
		if e.expiresAt >= now+prefetchWindow {
			continue // still fresh — prefetch-on-hit covers it
		}
		out = append(out, cand{k, e.lastHit})
	}
	c.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].lastHi > out[j].lastHi })
	if len(out) > limit {
		out = out[:limit]
	}
	keys := make([]cacheKey, len(out))
	for i, c := range out {
		keys[i] = c.key
	}
	return keys
}

// writePersisted replaces path atomically (same scheme as the daemon's
// other state files: temp in the same dir, rename over).
func writePersisted(path string, pc *persistedCache) error {
	b, err := json.MarshalIndent(pc, "", " ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".dns-cache-*.tmp")
	if err != nil {
		return err
	}
	if _, err = tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err = tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err = os.Chmod(tmp.Name(), 0o600); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return nil
}
