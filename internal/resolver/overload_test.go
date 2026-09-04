package resolver

// overload_test.go pins the v0.9.2 overload behaviors:
//
//   - dht.ErrWalkBusy (walk budget exhausted) maps to SERVFAIL, never
//     NXDOMAIN — an overloaded resolver must not let "busy" masquerade as
//     "does not exist", because freens NXDOMAINs are negative-cached while
//     SERVFAILs never are. Covered for both claim paths (ClaimSetResolver
//     and the legacy ClaimResolver).
//   - MaxConcurrentResolutions: a distinct-question flood beyond the cap is
//     refused immediately (never queued) while followers of an in-flight
//     question keep sharing it for free.

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/dht"
	"github.com/camalolo/freens/internal/wire"
	"github.com/miekg/dns"
)

// busySetSource is a RecordLookup + ClaimSetResolver whose claim collection
// always fails with the given error (dht.ErrWalkBusy in these tests). Lookup
// is never reached: the claim layer fails first.
type busySetSource struct{ err error }

func (b *busySetSource) Lookup(context.Context, []byte, int64) (*wire.SignedEnvelope, error) {
	return nil, b.err
}

func (b *busySetSource) CollectClaims(context.Context, string, int64) ([]*wire.SignedEnvelope, error) {
	return nil, b.err
}

// busyClaimSource is the legacy ClaimResolver-only shape.
type busyClaimSource struct{ err error }

func (b *busyClaimSource) Lookup(context.Context, []byte, int64) (*wire.SignedEnvelope, error) {
	return nil, b.err
}

func (b *busyClaimSource) LookupClaim(context.Context, string, int64) (*wire.SignedEnvelope, error) {
	return nil, b.err
}

// freensOnlyConfig routes "footld" to freens with NO alias pin, so the claim
// layer (the path the walk refusal arrives on) actually runs.
func freensOnlyConfig(t *testing.T) *Config {
	t.Helper()
	cfg, err := ParseConfig("[tld-routes]\nfootld = freens\n")
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func busyQuestion() dns.Question {
	return dns.Question{Name: "www.footld.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
}

// TestWalkBusyClaimSetSERVFAILNotNXDOMAIN: the §7.4 set-collection refusal
// yields SERVFAIL (retryable, uncached) — not NXDOMAIN, which putFreens
// would negative-cache.
func TestWalkBusyClaimSetSERVFAILNotNXDOMAIN(t *testing.T) {
	r := newResolver(freensOnlyConfig(t), &busySetSource{err: dht.ErrWalkBusy}, nil)
	rrs, rcode, _, err := r.ResolveQuestion(context.Background(), busyQuestion())
	if err != nil {
		t.Fatalf("ResolveQuestion err: %v (SERVFAIL is reported via rcode)", err)
	}
	if rcode != dns.RcodeServerFailure {
		t.Fatalf("rcode = %d, want SERVFAIL(%d)", rcode, dns.RcodeServerFailure)
	}
	if len(rrs) != 0 {
		t.Errorf("busy resolution produced rrs=%v, want none", rrs)
	}
}

// TestWalkBusyLegacyClaimSERVFAILNotNXDOMAIN: same mapping on the legacy
// single-claim path.
func TestWalkBusyLegacyClaimSERVFAILNotNXDOMAIN(t *testing.T) {
	r := newResolver(freensOnlyConfig(t), &busyClaimSource{err: dht.ErrWalkBusy}, nil)
	_, rcode, _, err := r.ResolveQuestion(context.Background(), busyQuestion())
	if err != nil {
		t.Fatalf("ResolveQuestion err: %v", err)
	}
	if rcode != dns.RcodeServerFailure {
		t.Fatalf("rcode = %d, want SERVFAIL(%d)", rcode, dns.RcodeServerFailure)
	}
}

// TestWalkBusySERVFAILNeverCached: through the full ServeDNS path with a
// wired cache, a busy answer stays SERVFAIL on every query and the cache
// stays empty — no negative TTL ever parks on an overloaded alias.
func TestWalkBusySERVFAILNeverCached(t *testing.T) {
	r := newResolver(freensOnlyConfig(t), &busySetSource{err: dht.ErrWalkBusy}, nil)
	r.Cache = NewResponseCache(0, nil)

	for i := 0; i < 3; i++ {
		fw := &fakeResponseWriter{}
		r.ServeDNS(fw, new(dns.Msg).SetQuestion("www.footld.", dns.TypeA))
		if len(fw.msgs) != 1 {
			t.Fatalf("query %d: %d replies, want 1", i, len(fw.msgs))
		}
		if got := fw.msgs[0].Rcode; got != dns.RcodeServerFailure {
			t.Fatalf("query %d: rcode = %d, want SERVFAIL (never NXDOMAIN)", i, got)
		}
	}
	if n := r.Cache.Len(); n != 0 {
		t.Errorf("cache holds %d entries after busy SERVFAILs, want 0 (SERVFAIL is never cached)", n)
	}
}

// ---------------------------------------------------------------------------
// Resolution cap
// ---------------------------------------------------------------------------

// gatedBusySource delays every Lookup until released, counting calls — the
// leader-holds-the-slot fixture.
type gatedBusySource struct {
	release chan struct{}
	calls   atomic.Int32
}

func (g *gatedBusySource) Lookup(ctx context.Context, _ []byte, _ int64) (*wire.SignedEnvelope, error) {
	g.calls.Add(1)
	select {
	case <-g.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return nil, nil
}

func startCappedResolver(t *testing.T, max int) (*Resolver, *gatedBusySource) {
	t.Helper()
	src := &gatedBusySource{release: make(chan struct{})}
	// freens-only with a pin on the alias: the chain walk (Lookup) runs
	// deterministically without the claim layer. The pin must be a
	// well-formed 32-byte tld_id or EncodeWireName rejects hop 0 before the
	// gated Lookup is ever reached.
	cfg := freensOnlyConfig(t)
	cfg.AliasPins["footld"] = make([]byte, 32)
	r := New(cfg, src, nil)
	r.MaxConcurrentResolutions = max
	return r, src
}

// TestResolutionCapRefusesDistinctQuestions: with capacity 1 and one
// resolution in flight, a DISTINCT question is refused immediately with the
// overload error, while an IDENTICAL question still shares the in-flight
// resolution (followers never consume slots).
func TestResolutionCapRefusesDistinctQuestions(t *testing.T) {
	r, src := startCappedResolver(t, 1)

	qA := dns.Question{Name: "www.footld.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	qA2 := dns.Question{Name: "www.footld.", Qtype: dns.TypeA, Qclass: dns.ClassINET} // identical
	qB := dns.Question{Name: "other.footld.", Qtype: dns.TypeA, Qclass: dns.ClassINET}

	type out struct {
		rrs []dns.RR
		rc  int
		err error
		dur time.Duration
	}
	resA := make(chan out, 1)
	go func() {
		rrs, rc, _, err := r.resolveShared(context.Background(), qA, cacheKeyFor(qA))
		resA <- out{rrs, rc, err, 0}
	}()

	// Wait until the leader is provably inside its (gated) resolution.
	deadline := time.Now().Add(3 * time.Second)
	for src.calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if src.calls.Load() == 0 {
		t.Fatal("leader never started its resolution")
	}

	// Identical question: a follower — must NOT be refused...
	follDone := make(chan out, 1)
	go func() {
		rrs, rc, _, err := r.resolveShared(context.Background(), qA2, cacheKeyFor(qA2))
		follDone <- out{rrs, rc, err, 0}
	}()
	time.Sleep(50 * time.Millisecond) // let the follower park on the flight

	// Distinct question: refused fast.
	start := time.Now()
	_, _, _, err := r.resolveShared(context.Background(), qB, cacheKeyFor(qB))
	refusedIn := time.Since(start)
	if err == nil || !errors.Is(err, errResolverBusy) {
		t.Fatalf("distinct question under full budget: err = %v, want errResolverBusy", err)
	}
	if refusedIn > 500*time.Millisecond {
		t.Errorf("refusal took %v, want immediate (never queue)", refusedIn)
	}

	close(src.release)
	select {
	case <-resA:
	case <-time.After(3 * time.Second):
		t.Fatal("leader never finished after release")
	}
	// The follower wakes once the leader closes the flight (just after the
	// result is set), so wait rather than poll.
	select {
	case <-follDone:
	case <-time.After(3 * time.Second):
		t.Error("identical follower did not share the leader's flight (must be free under the cap)")
	}
	if n := src.calls.Load(); n != 1 {
		t.Errorf("Lookup called %d times, want 1 (single flight preserved)", n)
	}
}

// TestResolutionCapDisabled: a negative cap means unlimited — two distinct
// concurrent resolutions both run.
func TestResolutionCapDisabled(t *testing.T) {
	r, src := startCappedResolver(t, -1)

	var wg sync.WaitGroup
	for _, name := range []string{"a.footld.", "b.footld."} {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			q := dns.Question{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET}
			_, _, _, err := r.resolveShared(context.Background(), q, cacheKeyFor(q))
			if err != nil {
				t.Errorf("%s: err = %v, want nil (cap disabled)", name, err)
			}
		}(name)
	}
	// Both distinct resolutions must be in flight simultaneously.
	deadline := time.Now().Add(3 * time.Second)
	for src.calls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if src.calls.Load() < 2 {
		t.Fatal("second distinct resolution never started under a disabled cap")
	}
	close(src.release)
	wg.Wait()
}

// TestResolutionCapSERVFAILNeverCached: through ServeDNS with a wired cache,
// the capped-out refusal answers SERVFAIL and caches nothing.
func TestResolutionCapSERVFAILNeverCached(t *testing.T) {
	r, src := startCappedResolver(t, 1)
	r.Cache = NewResponseCache(0, nil)

	// Leader holds the only slot on a.footld.
	go func() {
		q := dns.Question{Name: "a.footld.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
		_, _, _, _ = r.resolveShared(context.Background(), q, cacheKeyFor(q))
	}()
	deadline := time.Now().Add(3 * time.Second)
	for src.calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	defer close(src.release)

	fw := &fakeResponseWriter{}
	r.ServeDNS(fw, new(dns.Msg).SetQuestion("b.footld.", dns.TypeA))
	if len(fw.msgs) != 1 {
		t.Fatalf("capped query: %d replies, want 1", len(fw.msgs))
	}
	if got := fw.msgs[0].Rcode; got != dns.RcodeServerFailure {
		t.Fatalf("capped query rcode = %d, want SERVFAIL", got)
	}
	if n := r.Cache.Len(); n != 0 {
		t.Errorf("cache holds %d entries, want 0", n)
	}
}
