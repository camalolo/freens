package resolver

// Tests for the upstream forwarder's per-server retry (found live on a
// fresh box: ONE slow cache-miss at a cold upstream SERVFAILed every lookup
// on the machine — the retry lands on the warmed answer) and for the
// background-refresh failure logging (state TRANSITIONS only, so an outage
// is one WARN line, not one per kick).

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDNSUpstreamRetriesSameServer(t *testing.T) {
	old := exchangeWith
	t.Cleanup(func() { exchangeWith = old })

	var calls int32
	exchangeWith = func(ctx context.Context, q *dns.Msg, addr, network string, timeout time.Duration) (*dns.Msg, error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			return nil, errors.New("i/o timeout (cold upstream cache-miss)")
		}
		resp := new(dns.Msg)
		resp.SetReply(q)
		return resp, nil
	}

	u := &DNSUpstream{Servers: []string{"192.0.2.53"}}
	q := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
	resp, err := u.Forward(context.Background(), q)
	if err != nil || resp == nil {
		t.Fatalf("forward = %v, %v — the retry must land on the warmed answer", resp, err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("exchanges = %d, want 2 (one failure + one retry)", got)
	}
}

func TestDNSUpstreamMovesToNextServerAfterAttempts(t *testing.T) {
	old := exchangeWith
	t.Cleanup(func() { exchangeWith = old })

	var calls int32
	exchangeWith = func(ctx context.Context, q *dns.Msg, addr, network string, timeout time.Duration) (*dns.Msg, error) {
		n := atomic.AddInt32(&calls, 1)
		if strings.HasPrefix(addr, "192.0.2.53:") {
			return nil, errors.New("dead first server")
		}
		_ = n
		resp := new(dns.Msg)
		resp.SetReply(q)
		return resp, nil
	}

	u := &DNSUpstream{Servers: []string{"192.0.2.53", "198.51.100.53"}}
	q := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
	if _, err := u.Forward(context.Background(), q); err != nil {
		t.Fatalf("forward = %v — must move on to the second server", err)
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Fatalf("exchanges = %d, want 3 (2 failed attempts on server 1 + 1 success on server 2)", got)
	}
}

func TestDNSUpstreamAttemptsExhausted(t *testing.T) {
	old := exchangeWith
	t.Cleanup(func() { exchangeWith = old })

	var calls int32
	exchangeWith = func(ctx context.Context, q *dns.Msg, addr, network string, timeout time.Duration) (*dns.Msg, error) {
		atomic.AddInt32(&calls, 1)
		return nil, errors.New("down")
	}

	u := &DNSUpstream{Servers: []string{"192.0.2.53", "198.51.100.53"}}
	if _, err := u.Forward(context.Background(), new(dns.Msg).SetQuestion("example.com.", dns.TypeA)); err == nil {
		t.Fatal("all upstreams down must error")
	}
	if got := atomic.LoadInt32(&calls); got != 4 {
		t.Fatalf("exchanges = %d, want 4 (2 attempts × 2 servers)", got)
	}
}

func TestRefreshFailureLogsTransitionsOnce(t *testing.T) {
	w := newFreensWorld(t)
	lookup := &failingLookup{fakeLookup: newFakeLookup()}
	lookup.put(w.tldEnv)
	lookup.put(w.wwwEnv)

	var clock atomic.Int64
	clock.Store(int64(fixedNow))
	r := newResolver(configFor(t, w, RouteFREENS), lookup, nil)
	r.Cache = NewResponseCache(0, func() int64 { return clock.Load() })
	r.Now = func() int64 { return clock.Load() }

	var logBuf syncWriter
	r.Logger = testLogger(&logBuf)

	serveOnce(t, r, "www.footld.", dns.TypeA) // fresh walk + cache

	// Namespace goes dark; the stale serve kicks a refresh → ONE WARN.
	atomic.StoreInt32(&lookup.fail, 1)
	base := atomic.LoadInt32(&lookup.attempts)
	clock.Store(clock.Load() + 601)
	serveOnce(t, r, "www.footld.", dns.TypeA)
	waitForRefresh(t, &lookup.attempts, base)

	// Another kick within the outage (sweeper/timer) must NOT log again.
	clock.Store(clock.Load() + 6)
	serveOnce(t, r, "www.footld.", dns.TypeA)
	waitForRefresh(t, &lookup.attempts, atomic.LoadInt32(&lookup.attempts))

	if n := strings.Count(logBuf.String(), "level=WARN"); n != 1 {
		t.Fatalf("WARN lines = %d, want exactly 1 (an outage logs once, not per kick):\n%s", n, logBuf.String())
	}
	if !strings.Contains(logBuf.String(), "www.footld") {
		t.Fatalf("WARN should name the name:\n%s", logBuf.String())
	}

	// Recovery: exactly one INFO, no new WARN.
	atomic.StoreInt32(&lookup.fail, 0)
	clock.Store(clock.Load() + 6)
	serveOnce(t, r, "www.footld.", dns.TypeA)
	waitForRefresh(t, &lookup.attempts, atomic.LoadInt32(&lookup.attempts))
	if n := strings.Count(logBuf.String(), "level=INFO"); n != 1 {
		t.Fatalf("INFO lines = %d, want exactly 1 (the recovery):\n%s", n, logBuf.String())
	}
	if n := strings.Count(logBuf.String(), "level=WARN"); n != 1 {
		t.Fatalf("WARN lines after recovery = %d, want still 1", n)
	}
}

// TestTruncatedWithoutTCPFallbackIsNotServed: a TC'd UDP answer whose TCP
// retry fails is an INCOMPLETE answer — serving it as final silently drops
// records, because nothing downstream re-sets TC on the client-facing
// response. The forward must treat the truncation as a failed exchange
// (next attempt/server, SERVFAIL if none) — found in the 2026-09-04 audit.
func TestTruncatedWithoutTCPFallbackIsNotServed(t *testing.T) {
	old := exchangeWith
	t.Cleanup(func() { exchangeWith = old })

	var tcpTried bool
	exchangeWith = func(ctx context.Context, q *dns.Msg, addr, network string, timeout time.Duration) (*dns.Msg, error) {
		if network == "tcp" {
			tcpTried = true
			return nil, errors.New("tcp unreachable")
		}
		resp := new(dns.Msg).SetReply(q)
		resp.Truncate(512) // set the TC bit like a real oversized UDP answer
		resp.Truncated = true
		return resp, nil
	}

	u := &DNSUpstream{Servers: []string{"192.0.2.53"}}
	q := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
	resp, err := u.Forward(context.Background(), q)
	if err == nil {
		t.Fatalf("forward served a TRUNCATED answer as final (%d answers, TC=%v) — records would be silently dropped", len(resp.Answer), resp.Truncated)
	}
	if !tcpTried {
		t.Error("the TCP retry was never attempted")
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Errorf("err = %v, want it to name the truncation", err)
	}
}

// TestTruncatedWithTCPFallbackServesTCP: the happy path — TC over UDP with
// a working TCP retry still returns the complete TCP answer.
func TestTruncatedWithTCPFallbackServesTCP(t *testing.T) {
	old := exchangeWith
	t.Cleanup(func() { exchangeWith = old })

	exchangeWith = func(ctx context.Context, q *dns.Msg, addr, network string, timeout time.Duration) (*dns.Msg, error) {
		resp := new(dns.Msg).SetReply(q)
		if network == "udp" {
			resp.Truncated = true
			return resp, nil
		}
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   []byte{192, 0, 2, 7},
		})
		return resp, nil
	}

	u := &DNSUpstream{Servers: []string{"192.0.2.53"}}
	q := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
	resp, err := u.Forward(context.Background(), q)
	if err != nil || len(resp.Answer) != 1 {
		t.Fatalf("forward = %v, %v — want the complete TCP answer", resp, err)
	}
}

// TestCacheKeysFoldCase (RFC 1035 §2.3.3): mixed-case spellings of the same
// name must share one cache entry — a case-sensitive key made Example.COM a
// miss for a cached example.com and split entries per spelling.
func TestCacheKeysFoldCase(t *testing.T) {
	a := cacheKeyFor(dns.Question{Name: "Example.COM.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	b := cacheKeyFor(dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	if a != b {
		t.Fatal("cache keys for case variants of one name differ — the cache is case-sensitive")
	}
}

// TestForwardAdvertisesEDNS: a query with no OPT is extended (on a copy) to
// advertise a 1232-byte UDP payload upstream — the classic 512-byte
// advertisement forced big answers into TC + TCP retry per lookup.
func TestForwardAdvertisesEDNS(t *testing.T) {
	old := exchangeWith
	t.Cleanup(func() { exchangeWith = old })

	var sawOPT bool
	exchangeWith = func(ctx context.Context, q *dns.Msg, addr, network string, timeout time.Duration) (*dns.Msg, error) {
		opt := q.IsEdns0()
		if opt == nil || opt.UDPSize() != upstreamEDNSPayload {
			t.Errorf("upstream query carried no EDNS0(%d) advertisement", upstreamEDNSPayload)
		} else {
			sawOPT = true
		}
		resp := new(dns.Msg).SetReply(q)
		return resp, nil
	}

	u := &DNSUpstream{Servers: []string{"192.0.2.53"}}
	q := new(dns.Msg).SetQuestion("big.example.com.", dns.TypeTXT)
	if _, err := u.Forward(context.Background(), q); err != nil {
		t.Fatalf("forward: %v", err)
	}
	if !sawOPT {
		t.Fatal("the EDNS advertisement was never exercised")
	}
	if q.IsEdns0() != nil {
		t.Error("Forward mutated the CALLER's query message (DoH re-marshals it verbatim)")
	}
}

// TestResolveMsgEchoesClientEDNS: a client advertising a large UDP payload
// gets that budget honored in the UDP truncation decision — serving a
// 4096-capable stub 512-byte truncation forced needless TCP fallback.
func TestResolveMsgEchoesClientEDNS(t *testing.T) {
	cfg, err := ParseConfig("[tld-routes]\n* = freens\n")
	if err != nil {
		t.Fatal(err)
	}
	r := New(cfg, nil, nil)

	q := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
	q.SetEdns0(4096, false)
	resp := r.ResolveMsg(context.Background(), q)
	if opt := resp.IsEdns0(); opt == nil || opt.UDPSize() != maxEDNSPayload {
		t.Fatalf("response OPT = %v, want the client's payload clamped to %d", opt, maxEDNSPayload)
	}

	// A classic (non-EDNS) client keeps classic framing: no OPT echoed.
	plain := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
	resp2 := r.ResolveMsg(context.Background(), plain)
	if resp2.IsEdns0() != nil {
		t.Error("non-EDNS query got an OPT echoed")
	}
}
