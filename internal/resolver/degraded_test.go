// degraded_test.go — issue #1 resolver-side contract: a DEGRADED lookup
// (the DHT could not be interrogated: probe failures, nothing local) must
// answer SERVFAIL — which §10.4 never caches — so the next query retries,
// instead of a 60 s negative-cached NXDOMAIN for a name whose holders were
// alive the whole time. Field-observed on the 7-node LAN during reboots.
package resolver

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/camalolo/freens/internal/dht"
	"github.com/camalolo/freens/internal/wire"
	"github.com/miekg/dns"
)

// flakyClaimLookup serves the TLD record by claim lookup but can be flipped
// into degraded mode returning dht.ErrDegradedMiss.
type flakyClaimLookup struct {
	fakeClaimLookup
	degraded atomic.Bool
	calls    atomic.Int32
}

func (f *flakyClaimLookup) LookupClaim(ctx context.Context, alias string, now int64) (*wire.SignedEnvelope, error) {
	f.calls.Add(1)
	if f.degraded.Load() {
		return nil, dht.ErrDegradedMiss
	}
	return f.fakeClaimLookup.LookupClaim(ctx, alias, now)
}

// errLookup wraps fakeLookup, returning a fixed error from record Lookup.
type errLookup struct {
	fakeLookup
	err error
}

func (e *errLookup) Lookup(ctx context.Context, wireName []byte, now int64) (*wire.SignedEnvelope, error) {
	if e.err != nil {
		return nil, e.err
	}
	return e.fakeLookup.Lookup(ctx, wireName, now)
}

// TestDegradedClaimLookupIsSERVFAILAndUncached: degraded → SERVFAIL (never
// NXDOMAIN), and because SERVFAIL is not §10.4-cacheable, the retry after
// recovery actually re-queries and succeeds.
func TestDegradedClaimLookupIsSERVFAILAndUncached(t *testing.T) {
	w := newClaimedWorld(t, "foo")
	lookup := &flakyClaimLookup{fakeClaimLookup: *newFakeClaimLookup()}
	lookup.putClaim("foo", w.tldEnv)
	lookup.put(w.wwwEnv)

	clock := int64(fixedNow)
	r := newResolver(claimConfig(), lookup, nil)
	r.Cache = NewResponseCache(0, func() int64 { return clock })

	// Degraded window: every claim query answers SERVFAIL.
	lookup.degraded.Store(true)
	for i := 0; i < 3; i++ {
		msg := serveOnce(t, r, "www.foo.", dns.TypeA)
		if msg.Rcode != dns.RcodeServerFailure {
			t.Fatalf("degraded query %d: rcode = %d, want SERVFAIL", i, msg.Rcode)
		}
	}
	if got := lookup.calls.Load(); got < 3 {
		t.Fatalf("degraded answers were served from a cache (calls = %d); SERVFAIL must never be cached", got)
	}

	// Recovery: the very next query resolves (no negative entry to expire).
	lookup.degraded.Store(false)
	msg := serveOnce(t, r, "www.foo.", dns.TypeA)
	if msg.Rcode != dns.RcodeSuccess || len(msg.Answer) != 1 {
		t.Fatalf("post-recovery response = rcode %d with %d answers, want success/1", msg.Rcode, len(msg.Answer))
	}
}

// TestDegradedRecordLookupIsSERVFAIL: the record path (chain hop) surfaces
// the same way when Lookup itself returns ErrDegradedMiss.
func TestDegradedRecordLookupIsSERVFAIL(t *testing.T) {
	w := newFreensWorld(t)
	lookup := &errLookup{fakeLookup: *newFakeLookup(), err: dht.ErrDegradedMiss}
	lookup.put(w.tldEnv) // chain[0] fine; the www hop degrades

	clock := int64(fixedNow)
	r := newResolver(configFor(t, w, RouteFREENS), lookup, nil)
	r.Cache = NewResponseCache(0, func() int64 { return clock })

	msg := serveOnce(t, r, "www.foo.", dns.TypeA)
	if msg.Rcode != dns.RcodeServerFailure {
		t.Fatalf("degraded record hop: rcode = %d, want SERVFAIL", msg.Rcode)
	}
}
