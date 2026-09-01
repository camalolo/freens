package resolver

// Tests for the §10.4 response cache (cache.go): cached hits avoid
// re-resolving, TTLs decay on the cached copy, negative entries expire after
// NegTTL on an injected clock, forwarded DNS answers are never cached, and
// the bound evicts the oldest entry.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/wire"
	"github.com/miekg/dns"
)

// ---------------------------------------------------------------------------
// Test doubles: a dns.ResponseWriter recorder and a counting RecordLookup.
// ---------------------------------------------------------------------------

// fakeResponseWriter records every Msg written through it.
type fakeResponseWriter struct {
	msgs []*dns.Msg
}

func (f *fakeResponseWriter) WriteMsg(m *dns.Msg) error {
	f.msgs = append(f.msgs, m)
	return nil
}
func (f *fakeResponseWriter) Write([]byte) (int, error) { return 0, nil }
func (f *fakeResponseWriter) RemoteAddr() net.Addr      { return nil }
func (f *fakeResponseWriter) LocalAddr() net.Addr       { return nil }
func (f *fakeResponseWriter) TsigStatus() error         { return nil }
func (f *fakeResponseWriter) TsigTimersOnly(bool)       {}
func (f *fakeResponseWriter) Hijack()                   {}
func (f *fakeResponseWriter) Close() error              { return nil }

// countingLookup wraps a fakeLookup and counts Lookup calls (atomic: ServeDNS
// may be exercised under -race).
type countingLookup struct {
	*fakeLookup
	calls int32
}

func (c *countingLookup) Lookup(ctx context.Context, wireName []byte, now int64) (*wire.SignedEnvelope, error) {
	atomic.AddInt32(&c.calls, 1)
	return c.fakeLookup.Lookup(ctx, wireName, now)
}

// serveOnce drives r.ServeDNS in-process and returns the written response.
func serveOnce(t *testing.T, r *Resolver, name string, qtype uint16) *dns.Msg {
	t.Helper()
	w := &fakeResponseWriter{}
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	r.ServeDNS(w, m)
	if len(w.msgs) != 1 {
		t.Fatalf("ServeDNS wrote %d msgs, want 1", len(w.msgs))
	}
	return w.msgs[0]
}

// ---------------------------------------------------------------------------
// Positive caching (§10.4: positive freens answers cached <= min TTL).
// ---------------------------------------------------------------------------

func TestServeDNSCacheHitAvoidsResolve(t *testing.T) {
	w := newFreensWorld(t)
	lookup := &countingLookup{fakeLookup: newFakeLookup()}
	lookup.put(w.tldEnv)
	lookup.put(w.wwwEnv)

	clock := int64(fixedNow)
	r := newResolver(configFor(t, w, RouteFREENS), lookup, nil)
	r.Cache = NewResponseCache(0, func() int64 { return clock })

	first := serveOnce(t, r, "www.foo.", dns.TypeA)
	if first.Rcode != dns.RcodeSuccess || len(first.Answer) != 1 || !first.Authoritative {
		t.Fatalf("first response = rcode %d, %d answers, aa %v", first.Rcode, len(first.Answer), first.Authoritative)
	}
	if got := atomic.LoadInt32(&lookup.calls); got != 2 { // TLD hop + www hop
		t.Fatalf("lookup calls after first query = %d, want 2", got)
	}

	// Second identical query must be served from cache: no new lookups.
	second := serveOnce(t, r, "www.foo.", dns.TypeA)
	if second.Rcode != dns.RcodeSuccess || len(second.Answer) != 1 {
		t.Fatalf("cached response = rcode %d, %d answers", second.Rcode, len(second.Answer))
	}
	if !second.Authoritative {
		t.Error("cached freens answer must keep AA=true")
	}
	if a, ok := second.Answer[0].(*dns.A); !ok || !a.A.Equal(w.wwwIPv4) {
		t.Errorf("cached answer = %v, want A %s", second.Answer[0], w.wwwIPv4)
	}
	if got := atomic.LoadInt32(&lookup.calls); got != 2 {
		t.Errorf("lookup calls after cached hit = %d, want 2 (cache must avoid re-resolving)", got)
	}

	// A different qtype is a different cache key → re-resolves.
	_ = serveOnce(t, r, "www.foo.", dns.TypeAAAA) // NODATA, negative-cached
	if got := atomic.LoadInt32(&lookup.calls); got != 4 {
		t.Errorf("lookup calls after a different qtype = %d, want 4", got)
	}
}

func TestServeDNSCachedTTLDecays(t *testing.T) {
	w := newFreensWorld(t)
	lookup := &countingLookup{fakeLookup: newFakeLookup()}
	lookup.put(w.tldEnv)
	lookup.put(w.wwwEnv)

	clock := int64(fixedNow)
	r := newResolver(configFor(t, w, RouteFREENS), lookup, nil)
	r.Cache = NewResponseCache(0, func() int64 { return clock })

	first := serveOnce(t, r, "www.foo.", dns.TypeA)
	if ttl := first.Answer[0].Header().Ttl; ttl != 600 {
		t.Fatalf("fresh TTL = %d, want 600", ttl)
	}

	clock += 200 // 200 s pass; the cached entry must decay to 400.
	second := serveOnce(t, r, "www.foo.", dns.TypeA)
	if ttl := second.Answer[0].Header().Ttl; ttl != 400 {
		t.Errorf("decayed TTL = %d, want 400", ttl)
	}
}

// ---------------------------------------------------------------------------
// Negative caching (§10.4 / §9.2 step 3: NXDOMAIN/NODATA cached NegTTL = 60 s).
// ---------------------------------------------------------------------------

func TestServeDNSNegativeCacheNXDOMAINExpiry(t *testing.T) {
	w := newFreensWorld(t)
	lookup := &countingLookup{fakeLookup: newFakeLookup()} // empty → NXDOMAIN

	clock := int64(fixedNow)
	r := newResolver(configFor(t, w, RouteFREENS), lookup, nil)
	r.Cache = NewResponseCache(0, func() int64 { return clock })

	first := serveOnce(t, r, "www.foo.", dns.TypeA)
	if first.Rcode != dns.RcodeNameError || !first.Authoritative {
		t.Fatalf("first response rcode = %d aa = %v, want NXDOMAIN/aa", first.Rcode, first.Authoritative)
	}
	callsAfterFirst := atomic.LoadInt32(&lookup.calls)
	if callsAfterFirst == 0 {
		t.Fatal("first query must consult the lookup")
	}

	// Within NegTTL: served from the negative cache, no new lookups.
	second := serveOnce(t, r, "www.foo.", dns.TypeA)
	if second.Rcode != dns.RcodeNameError {
		t.Fatalf("cached negative rcode = %d, want NXDOMAIN", second.Rcode)
	}
	if got := atomic.LoadInt32(&lookup.calls); got != callsAfterFirst {
		t.Errorf("lookups within NegTTL = %d, want %d (negative entry still fresh)", got, callsAfterFirst)
	}

	// Past NegTTL: the entry expired → re-resolve.
	clock += int64(constants.NegTTL) + 1
	third := serveOnce(t, r, "www.foo.", dns.TypeA)
	if third.Rcode != dns.RcodeNameError {
		t.Fatalf("re-resolved rcode = %d, want NXDOMAIN", third.Rcode)
	}
	if got := atomic.LoadInt32(&lookup.calls); got <= callsAfterFirst {
		t.Errorf("lookups after NegTTL expiry = %d, want > %d (entry must expire)", got, callsAfterFirst)
	}
}

func TestServeDNSNegativeCacheNODATA(t *testing.T) {
	w := newFreensWorld(t)
	lookup := &countingLookup{fakeLookup: newFakeLookup()}
	lookup.put(w.tldEnv)
	lookup.put(w.wwwEnv) // has A only; AAAA → NODATA

	clock := int64(fixedNow)
	r := newResolver(configFor(t, w, RouteFREENS), lookup, nil)
	r.Cache = NewResponseCache(0, func() int64 { return clock })

	first := serveOnce(t, r, "www.foo.", dns.TypeAAAA)
	if first.Rcode != dns.RcodeSuccess || len(first.Answer) != 0 {
		t.Fatalf("first response = rcode %d, %d answers (want NODATA)", first.Rcode, len(first.Answer))
	}
	callsAfterFirst := atomic.LoadInt32(&lookup.calls)

	// Repeat within NegTTL → cached NODATA, resolver not re-consulted.
	second := serveOnce(t, r, "www.foo.", dns.TypeAAAA)
	if second.Rcode != dns.RcodeSuccess || len(second.Answer) != 0 {
		t.Fatalf("cached NODATA = rcode %d, %d answers", second.Rcode, len(second.Answer))
	}
	if got := atomic.LoadInt32(&lookup.calls); got != callsAfterFirst {
		t.Errorf("lookups on cached NODATA = %d, want %d", got, callsAfterFirst)
	}
}

// ---------------------------------------------------------------------------
// DNS-forwarded answers are never cached (§10.4 covers freens only).
// ---------------------------------------------------------------------------

func TestServeDNSDoesNotCacheForwardedDNS(t *testing.T) {
	w := newFreensWorld(t)
	rr := &dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(93, 184, 216, 34)}
	up := &fakeUpstream{answer: []dns.RR{rr}, rcode: dns.RcodeSuccess}
	r := newResolver(configFor(t, w, RouteDNS), nil, up)
	r.Cache = NewResponseCache(0, nil)

	for i := 0; i < 2; i++ {
		resp := serveOnce(t, r, "example.com.", dns.TypeA)
		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
			t.Fatalf("query %d: rcode %d, %d answers", i, resp.Rcode, len(resp.Answer))
		}
	}
	if got := len(up.seen); got != 2 {
		t.Errorf("upstream saw %d queries, want 2 (forwarded answers must not be cached)", got)
	}
	if got := r.Cache.Len(); got != 0 {
		t.Errorf("cache holds %d entries after forwarded answers, want 0", got)
	}
}

// ---------------------------------------------------------------------------
// Direct ResponseCache unit tests: bound + oldest eviction, zero-TTL skip,
// and putFreens policy classes.
// ---------------------------------------------------------------------------

func testKey(i int) cacheKey {
	return cacheKey{name: fmt.Sprintf("n%d.foo.", i), qtype: dns.TypeA, qclass: dns.ClassINET}
}

func testA(t *testing.T, ttl uint32) dns.RR {
	t.Helper()
	return &dns.A{
		Hdr: dns.RR_Header{Name: "n.foo.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   net.IPv4(203, 0, 113, 1),
	}
}

func TestResponseCacheBoundEvictsOldest(t *testing.T) {
	clock := int64(fixedNow)
	c := NewResponseCache(4, func() int64 { return clock })

	for i := 0; i < 5; i++ {
		c.putFreens(testKey(i), []dns.RR{testA(t, 600)}, dns.RcodeSuccess, true)
	}
	if got := c.Len(); got != 4 {
		t.Fatalf("Len = %d, want 4 (bound enforced)", got)
	}
	// key 0 was the oldest → evicted; key 4 (newest) is present.
	if _, _, _, ok := c.get(testKey(0)); ok {
		t.Error("oldest entry should have been evicted")
	}
	if _, _, _, ok := c.get(testKey(4)); !ok {
		t.Error("newest entry should be present")
	}
}

func TestResponseCachePolicy(t *testing.T) {
	clock := int64(fixedNow)
	c := NewResponseCache(0, func() int64 { return clock })

	// Zero-TTL positives are not cached (do-not-cache convention).
	c.putFreens(testKey(0), []dns.RR{testA(t, 0)}, dns.RcodeSuccess, true)
	if _, _, _, ok := c.get(testKey(0)); ok {
		t.Error("TTL-0 answer must not be cached")
	}

	// aa=false (DNS-forwarded / policy) is ignored entirely.
	c.putFreens(testKey(1), []dns.RR{testA(t, 60)}, dns.RcodeSuccess, false)
	if _, _, _, ok := c.get(testKey(1)); ok {
		t.Error("non-freens outcome must not be cached")
	}

	// SERVFAIL is transient → never cached.
	c.putFreens(testKey(2), nil, dns.RcodeServerFailure, true)
	if _, _, _, ok := c.get(testKey(2)); ok {
		t.Error("SERVFAIL must not be cached")
	}

	// A positive entry expires after its min TTL — but stays RETAINED for
	// the §10.4 serve-stale window (get returns cacheStale, not a drop):
	// the entry only vanishes once the window itself passes.
	c.putFreens(testKey(3), []dns.RR{testA(t, 60)}, dns.RcodeSuccess, true)
	if _, _, _, ok := c.get(testKey(3)); !ok {
		t.Fatal("fresh positive entry should hit")
	}
	clock += 61
	if _, _, _, status := c.get2(testKey(3)); status != cacheStale {
		t.Errorf("expired positive inside the window = %v, want cacheStale", status)
	}
	if got := c.Len(); got != 1 {
		t.Errorf("Len inside the stale window = %d, want 1 (retained for revalidation)", got)
	}
	clock += int64(constants.StaleServeSecs)
	if _, _, _, ok := c.get(testKey(3)); ok {
		t.Error("positive entry must drop once the stale window passes")
	}
	if got := c.Len(); got != 0 {
		t.Errorf("Len after the stale window = %d, want 0", got)
	}
}

// ---------------------------------------------------------------------------
// Serve-stale-while-revalidate (§10.4 amended): an expired POSITIVE answer
// inside the stale window is served immediately while a background refresh
// revalidates it; negatives never serve stale; the fresh outcome — positive
// or negative — replaces the entry.
// ---------------------------------------------------------------------------

// waitForRefresh polls until the background revalidation has performed its
// lookups (the walk runs in a goroutine; tests need a deterministic join).
func waitForRefresh(t *testing.T, counter *int32, before int32) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(counter) > before {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("background refresh never ran (lookups stuck at %d)", before)
}

// failingLookup makes the TRANSPORT fail on demand (the real outage shape:
// DHT unreachable) without changing what the namespace knows. attempts
// counts every Lookup call INCLUDING the failing ones (inner.calls only
// sees the successes).
type failingLookup struct {
	*fakeLookup
	attempts int32
	fail     int32
}

func (f *failingLookup) Lookup(ctx context.Context, wireName []byte, now int64) (*wire.SignedEnvelope, error) {
	atomic.AddInt32(&f.attempts, 1)
	if atomic.LoadInt32(&f.fail) == 1 {
		return nil, errors.New("dht unreachable (test)")
	}
	return f.fakeLookup.Lookup(ctx, wireName, now)
}

func TestServeDNSStaleServedWhileRefreshing(t *testing.T) {
	w := newFreensWorld(t)
	lookup := &countingLookup{fakeLookup: newFakeLookup()}
	lookup.put(w.tldEnv)
	lookup.put(w.wwwEnv)

	var clock atomic.Int64
	clock.Store(int64(fixedNow))
	r := newResolver(configFor(t, w, RouteFREENS), lookup, nil)
	r.Cache = NewResponseCache(0, func() int64 { return clock.Load() })

	first := serveOnce(t, r, "www.foo.", dns.TypeA) // fresh walk, cached
	if first.Rcode != dns.RcodeSuccess {
		t.Fatalf("first rcode = %d", first.Rcode)
	}
	base := atomic.LoadInt32(&lookup.calls)

	// Past the RR TTL (600 s) but inside the stale window: answered from
	// the validated cache copy with a SHORT ttl, without blocking on the
	// walk — the refresh runs in the background.
	clock.Store(clock.Load() + 601)
	stale := serveOnce(t, r, "www.foo.", dns.TypeA)
	if stale.Rcode != dns.RcodeSuccess || len(stale.Answer) != 1 {
		t.Fatalf("stale response = rcode %d, %d answers", stale.Rcode, len(stale.Answer))
	}
	if a, ok := stale.Answer[0].(*dns.A); !ok || !a.A.Equal(w.wwwIPv4) {
		t.Fatalf("stale answer = %v, want A %s", stale.Answer[0], w.wwwIPv4)
	}
	if ttl := stale.Answer[0].Header().Ttl; ttl > 30 {
		t.Fatalf("stale TTL = %d, want ≤ %d so stubs re-ask soon", ttl, 30)
	}
	waitForRefresh(t, &lookup.calls, base)

	// The refresh re-cached: the next query is FRESH again (full TTL, no
	// new walk).
	fresh := serveOnce(t, r, "www.foo.", dns.TypeA)
	if got := atomic.LoadInt32(&lookup.calls); got != base+2 { // TLD + www hop
		t.Fatalf("lookup calls = %d, want %d", got, base+2)
	}
	if ttl := fresh.Answer[0].Header().Ttl; ttl != 600 {
		t.Fatalf("post-refresh TTL = %d, want 600", ttl)
	}
}

func TestServeDNSStaleWindowEndsInRealResolve(t *testing.T) {
	w := newFreensWorld(t)
	lookup := &countingLookup{fakeLookup: newFakeLookup()}
	lookup.put(w.tldEnv)
	lookup.put(w.wwwEnv)

	var clock atomic.Int64
	clock.Store(int64(fixedNow))
	r := newResolver(configFor(t, w, RouteFREENS), lookup, nil)
	r.Cache = NewResponseCache(0, func() int64 { return clock.Load() })

	serveOnce(t, r, "www.foo.", dns.TypeA)
	base := atomic.LoadInt32(&lookup.calls)

	// Past TTL AND the whole stale window: a genuine miss — the walk happens
	// synchronously again.
	clock.Store(clock.Load() + 601 + constants.StaleServeSecs + 1)
	miss := serveOnce(t, r, "www.foo.", dns.TypeA)
	if miss.Rcode != dns.RcodeSuccess || miss.Answer[0].Header().Ttl != 600 {
		t.Fatalf("post-window response = rcode %d ttl %d", miss.Rcode, miss.Answer[0].Header().Ttl)
	}
	if got := atomic.LoadInt32(&lookup.calls); got < base+2 {
		t.Fatalf("post-window lookups = %d, want the synchronous walk (≥ %d)", got, base+2)
	}
}

func TestServeDNSNegativeNeverServesStale(t *testing.T) {
	w := newFreensWorld(t)
	lookup := &countingLookup{fakeLookup: newFakeLookup()}
	lookup.put(w.tldEnv) // www.foo does not exist → NXDOMAIN, negative-cached

	var clock atomic.Int64
	clock.Store(int64(fixedNow))
	r := newResolver(configFor(t, w, RouteFREENS), lookup, nil)
	r.Cache = NewResponseCache(0, func() int64 { return clock.Load() })

	nx := serveOnce(t, r, "www.foo.", dns.TypeA)
	if nx.Rcode != dns.RcodeNameError {
		t.Fatalf("first rcode = %d", nx.Rcode)
	}
	base := atomic.LoadInt32(&lookup.calls)

	// Past NegTTL: a negative entry must be re-consulted SYNCHRONOUSLY —
	// serving stale NXDOMAINs would delay revocations and publications.
	clock.Store(clock.Load() + constants.NegTTL + 1)
	again := serveOnce(t, r, "www.foo.", dns.TypeA)
	if again.Rcode != dns.RcodeNameError {
		t.Fatalf("second rcode = %d", again.Rcode)
	}
	if got := atomic.LoadInt32(&lookup.calls); got <= base {
		t.Fatalf("negative expiry must re-resolve synchronously (calls %d → %d)", base, got)
	}
}

func TestServeDNSStaleRefreshLearnsRevocation(t *testing.T) {
	w := newFreensWorld(t)
	lookup := &countingLookup{fakeLookup: newFakeLookup()}
	lookup.put(w.tldEnv)
	lookup.put(w.wwwEnv)

	var clock atomic.Int64
	clock.Store(int64(fixedNow))
	r := newResolver(configFor(t, w, RouteFREENS), lookup, nil)
	r.Cache = NewResponseCache(0, func() int64 { return clock.Load() })

	serveOnce(t, r, "www.foo.", dns.TypeA)
	base := atomic.LoadInt32(&lookup.calls)

	// The name gets tombstoned while our cached copy ages out.
	tomb := revokedEnv(t, w, []string{"www"}, w.wwwEnv.Record.Sequence+1)
	lookup.put(tomb)

	// Stale window: the old answer still goes out (bounded), but the
	// background refresh sees the tombstone…
	clock.Store(clock.Load() + 601)
	stale := serveOnce(t, r, "www.foo.", dns.TypeA)
	if stale.Rcode != dns.RcodeSuccess {
		t.Fatalf("stale serve rcode = %d, want the last known good answer", stale.Rcode)
	}
	waitForRefresh(t, &lookup.calls, base)

	// …and the NEXT query reflects it: no stale crutch past a fresh
	// negative.
	clock.Store(clock.Load() + refreshKickEvery + 1)
	after := serveOnce(t, r, "www.foo.", dns.TypeA)
	if after.Rcode != dns.RcodeNameError {
		t.Fatalf("post-revocation rcode = %d, want NXDOMAIN", after.Rcode)
	}
}

func TestServeDNSStaleSurvivesFailedRefresh(t *testing.T) {
	w := newFreensWorld(t)
	lookup := &failingLookup{fakeLookup: newFakeLookup()}
	lookup.put(w.tldEnv)
	lookup.put(w.wwwEnv)
	// A transport-level failure (the real outage shape: DHT unreachable) —
	// NOT an authoritative "no record", which is a legitimate negative.

	var clock atomic.Int64
	clock.Store(int64(fixedNow))
	r := newResolver(configFor(t, w, RouteFREENS), lookup, nil)
	r.Cache = NewResponseCache(0, func() int64 { return clock.Load() })
	// The refresh throttle kicks off the resolver's own clock; tests advance
	// `clock` instead of sleeping, so point r.Now at it too.
	r.Now = func() int64 { return clock.Load() }

	serveOnce(t, r, "www.foo.", dns.TypeA)
	base := atomic.LoadInt32(&lookup.attempts)

	// Namespace goes UNREACHABLE: the refresh attempt errors out and must
	// not poison the cache.
	atomic.StoreInt32(&lookup.fail, 1)

	clock.Store(clock.Load() + 601)
	stale := serveOnce(t, r, "www.foo.", dns.TypeA)
	if stale.Rcode != dns.RcodeSuccess {
		t.Fatalf("stale serve rcode = %d", stale.Rcode)
	}
	waitForRefresh(t, &lookup.attempts, base)

	// Still inside the window: keep answering with the last known good
	// data (the outage-resilience point of the whole feature).
	clock.Store(clock.Load() + refreshKickEvery + 1)
	still := serveOnce(t, r, "www.foo.", dns.TypeA)
	if still.Rcode != dns.RcodeSuccess || len(still.Answer) != 1 {
		t.Fatalf("stale during outage = rcode %d, %d answers — the last known good answer must survive a failed refresh",
			still.Rcode, len(still.Answer))
	}

	// Recovery: the namespace answers again, the next refresh wins, and
	// the answer goes fresh (full TTL) instead of stale.
	atomic.StoreInt32(&lookup.fail, 0)
	base2 := atomic.LoadInt32(&lookup.attempts)
	clock.Store(clock.Load() + refreshKickEvery + 1)
	waitForRefresh(t, &lookup.attempts, base2)
	recovered := serveOnce(t, r, "www.foo.", dns.TypeA)
	if recovered.Rcode != dns.RcodeSuccess || recovered.Answer[0].Header().Ttl != 600 {
		t.Fatalf("post-recovery = rcode %d ttl %d, want fresh NOERROR ttl 600",
			recovered.Rcode, recovered.Answer[0].Header().Ttl)
	}
}
