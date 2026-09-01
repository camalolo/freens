package resolver

// Tests for the operational-metrics hooks (hardening part 1):
//
//   - Server.SetQueryCounter: freens_dns_queries_total{qtype,status} is
//     incremented exactly once per answered query, with the status derived
//     from the written response's rcode.
//   - ResponseCache.SetMetrics: freens_resolver_cache_hits_total /
//     freens_resolver_cache_misses_total at the get() decision points.

import (
	"bytes"
	"errors"
	"testing"

	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/metrics"
	"github.com/miekg/dns"
)

// The fakeResponseWriter test double (a dns.ResponseWriter recorder) is
// shared with cache_test.go in this package.

// newCountingServer builds a Server around res with a fresh registry-backed
// query counter, returning the server and the registry for exposition checks.
func newCountingServer(t *testing.T, res *Resolver) (*Server, *metrics.Registry) {
	t.Helper()
	reg := metrics.New()
	qc := reg.NewCounter("freens_dns_queries_total", "DNS queries answered.", "qtype", "status")
	s := NewServer("127.0.0.1:0", "udp", res)
	s.SetQueryCounter(qc)
	return s, reg
}

// exposition renders the registry (test helper).
func exposition(t *testing.T, reg *metrics.Registry) string {
	t.Helper()
	var buf bytes.Buffer
	if _, err := reg.WriteTo(&buf); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	return buf.String()
}

func TestServerQueryCounterIncrements(t *testing.T) {
	w := newFreensWorld(t)

	t.Run("freens hit counts noerror", func(t *testing.T) {
		lookup := newFakeLookup()
		lookup.put(w.tldEnv)
		lookup.put(w.wwwEnv)
		res := newResolver(configFor(t, w, RouteFREENS), lookup, nil)
		srv, reg := newCountingServer(t, res)

		fw := &fakeResponseWriter{}
		srv.handleDNS(fw, new(dns.Msg).SetQuestion("www.foo.", dns.TypeA))

		if len(fw.msgs) != 1 {
			t.Fatalf("wrote %d msgs, want 1 (exactly one count per query)", len(fw.msgs))
		}
		if got := exposition(t, reg); !bytes.Contains([]byte(got), []byte(`freens_dns_queries_total{qtype="A",status="noerror"} 1`)) {
			t.Errorf("exposition missing A/noerror series:\n%s", got)
		}
	})

	t.Run("freens miss counts nxdomain", func(t *testing.T) {
		res := newResolver(configFor(t, w, RouteFREENS), newFakeLookup(), nil)
		srv, reg := newCountingServer(t, res)

		fw := &fakeResponseWriter{}
		srv.handleDNS(fw, new(dns.Msg).SetQuestion("nope.foo.", dns.TypeAAAA))

		if fw.msgs[0].Rcode != dns.RcodeNameError {
			t.Fatalf("rcode = %d, want NXDOMAIN", fw.msgs[0].Rcode)
		}
		if got := exposition(t, reg); !bytes.Contains([]byte(got), []byte(`freens_dns_queries_total{qtype="AAAA",status="nxdomain"} 1`)) {
			t.Errorf("exposition missing AAAA/nxdomain series:\n%s", got)
		}
	})

	t.Run("upstream failure counts servfail", func(t *testing.T) {
		up := &fakeUpstream{err: errors.New("boom")}
		res := newResolver(configFor(t, w, RouteDNSFirst), newFakeLookup(), up)
		srv, reg := newCountingServer(t, res)

		fw := &fakeResponseWriter{}
		srv.handleDNS(fw, new(dns.Msg).SetQuestion("www.foo.", dns.TypeA))

		if fw.msgs[0].Rcode != dns.RcodeServerFailure {
			t.Fatalf("rcode = %d, want SERVFAIL", fw.msgs[0].Rcode)
		}
		if got := exposition(t, reg); !bytes.Contains([]byte(got), []byte(`freens_dns_queries_total{qtype="A",status="servfail"} 1`)) {
			t.Errorf("exposition missing A/servfail series:\n%s", got)
		}
	})

	t.Run("questionless FORMERR counts qtype none servfail", func(t *testing.T) {
		res := newResolver(configFor(t, w, RouteFREENS), newFakeLookup(), nil)
		srv, reg := newCountingServer(t, res)

		fw := &fakeResponseWriter{}
		srv.handleDNS(fw, new(dns.Msg))

		if fw.msgs[0].Rcode != dns.RcodeFormatError {
			t.Fatalf("rcode = %d, want FORMERR", fw.msgs[0].Rcode)
		}
		if got := exposition(t, reg); !bytes.Contains([]byte(got), []byte(`freens_dns_queries_total{qtype="none",status="servfail"} 1`)) {
			t.Errorf("exposition missing none/servfail series:\n%s", got)
		}
	})

	t.Run("two queries same series aggregate", func(t *testing.T) {
		res := newResolver(configFor(t, w, RouteFREENS), newFakeLookup(), nil)
		srv, reg := newCountingServer(t, res)

		for i := 0; i < 3; i++ {
			srv.handleDNS(&fakeResponseWriter{}, new(dns.Msg).SetQuestion("x.foo.", dns.TypeTXT))
		}
		if got := exposition(t, reg); !bytes.Contains([]byte(got), []byte(`freens_dns_queries_total{qtype="TXT",status="nxdomain"} 3`)) {
			t.Errorf("exposition missing aggregated TXT/nxdomain count:\n%s", got)
		}
	})
}

// TestServerWithoutQueryCounter: the default (no SetQueryCounter call) leaves
// serving fully functional — the wrapper is a pure passthrough.
func TestServerWithoutQueryCounter(t *testing.T) {
	w := newFreensWorld(t)
	res := newResolver(configFor(t, w, RouteFREENS), newFakeLookup(), nil)
	srv := NewServer("127.0.0.1:0", "udp", res) // no SetQueryCounter

	fw := &fakeResponseWriter{}
	srv.handleDNS(fw, new(dns.Msg).SetQuestion("x.foo.", dns.TypeA))
	if len(fw.msgs) != 1 || fw.msgs[0].Rcode != dns.RcodeNameError {
		t.Fatalf("passthrough failed: %d msgs, rcode %d", len(fw.msgs), fw.msgs[0].Rcode)
	}
}

// TestResponseCacheMetrics: hits/misses counters move exactly at the get()
// decision points, including the expired-entry-is-a-miss rule.
func TestResponseCacheMetrics(t *testing.T) {
	reg := metrics.New()
	now := int64(1_000_000)
	c := NewResponseCache(0, func() int64 { return now })
	c.SetMetrics(reg)

	key := cacheKeyFor(dns.Question{Name: "www.foo.", Qtype: dns.TypeA, Qclass: dns.ClassINET})

	// Miss: empty cache.
	if _, _, _, ok := c.get(key); ok {
		t.Fatal("first get should miss")
	}
	// Hit: stored freens outcome retrieved.
	rr := &dns.A{Hdr: dns.RR_Header{Name: "www.foo.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}}
	c.putFreens(key, []dns.RR{rr}, dns.RcodeSuccess, true)
	if _, _, _, ok := c.get(key); !ok {
		t.Fatal("second get should hit")
	}
	// An expired POSITIVE entry inside the §10.4 serve-stale window is
	// served stale (its own counter) — it is NOT a miss and NOT a hit.
	now += 61
	if _, _, _, status := c.get2(key); status != cacheStale {
		t.Fatalf("expired positive inside the window should serve stale, got %v", status)
	}
	// Past the stale window it is finally a miss (and the entry drops).
	now += int64(constants.StaleServeSecs)
	if _, _, _, ok := c.get(key); ok {
		t.Fatal("get past the stale window should miss")
	}

	got := exposition(t, reg)
	for _, want := range []string{
		"# TYPE freens_resolver_cache_hits_total counter\nfreens_resolver_cache_hits_total 1",
		"# TYPE freens_resolver_cache_misses_total counter\nfreens_resolver_cache_misses_total 2",
		"# TYPE freens_resolver_cache_stale_total counter\nfreens_resolver_cache_stale_total 1",
	} {
		if !bytes.Contains([]byte(got), []byte(want)) {
			t.Errorf("exposition missing %q:\n%s", want, got)
		}
	}
}

// TestResponseCacheNilMetricsUninstrumented: SetMetrics(nil) and no call at
// all both leave the cache fully functional with no counters attached.
func TestResponseCacheNilMetricsUninstrumented(t *testing.T) {
	c := NewResponseCache(0, nil)
	c.SetMetrics(nil) // must be a no-op, not a panic
	c.SetMetrics(metrics.NilRegistry())

	key := cacheKeyFor(dns.Question{Name: "a.b.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	if _, _, _, ok := c.get(key); ok {
		t.Fatal("empty cache must miss")
	}
	rr := &dns.A{Hdr: dns.RR_Header{Name: "a.b.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}}
	c.putFreens(key, []dns.RR{rr}, dns.RcodeSuccess, true)
	if _, _, _, ok := c.get(key); !ok {
		t.Fatal("stored entry must hit")
	}
}

// Compile-time interface check for the shared fake writer (cache_test.go).
var _ dns.ResponseWriter = (*fakeResponseWriter)(nil)
