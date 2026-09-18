// upstream_hedge_test.go — the v0.19.5 hedged DoH fallback (server.go):
//
//   - a stalled-but-alive DoH leg must not hold a cold lookup hostage: the
//     plaintext fallback is raced after HedgeAfter and its answer wins
//     (the desktop 2026-09-18 incident: ~950 ms of dead DoH wait per
//     question, silently rescued by plaintext, nothing logged);
//   - a healthy DoH leg answers every query and the fallback stays idle;
//   - a FAST DoH failure starts the fallback immediately (no hedge delay);
//   - HedgeAfter < 0 keeps the strict serial semantics (the `freens doh`
//     health check tests the DoH leg itself, not the hedge);
//   - degradation/recovery is a logged TRANSITION, once, never per query;
//   - Ping rides the shared client as a well-formed throwaway query.
package resolver

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// dohStub is a controllable DoH endpoint: mode "ok" answers with one A
// record at ip; mode "down" answers status; mode "stall" sleeps delay (or
// until the request context dies) before answering. posts counts requests.
type dohStub struct {
	srv   *httptest.Server
	posts *int64
	mode  atomic.Value // string: "ok" | "down" | "stall"
	delay atomic.Value // time.Duration
}

func newDoHStub(t *testing.T, ip net.IP) *dohStub {
	t.Helper()
	s := &dohStub{}
	s.mode.Store("ok")
	s.delay.Store(time.Duration(0))
	var posts int64
	s.posts = &posts
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(s.posts, 1)
		body, _ := io.ReadAll(r.Body)
		switch s.mode.Load() {
		case "stall":
			select {
			case <-time.After(s.delay.Load().(time.Duration)):
			case <-r.Context().Done():
				return
			}
		case "down":
			http.Error(w, "stub down", http.StatusInternalServerError)
			return
		}
		q := new(dns.Msg)
		if err := q.Unpack(body); err != nil {
			http.Error(w, "bad query", http.StatusBadRequest)
			return
		}
		m := new(dns.Msg)
		m.SetReply(q)
		if len(q.Question) == 1 && q.Question[0].Qtype == dns.TypeA {
			m.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   ip,
			}}
		}
		w.Header().Set("Content-Type", DoHContentType)
		packed, _ := m.Pack()
		_, _ = w.Write(packed)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

// countingPlainServer answers every A question with ip and counts queries.
func countingPlainServer(t *testing.T, ip net.IP) (addr string, queries *int64) {
	t.Helper()
	var n int64
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, m *dns.Msg) {
		atomic.AddInt64(&n, 1)
		reply := new(dns.Msg)
		reply.SetReply(m)
		if len(m.Question) == 1 && m.Question[0].Qtype == dns.TypeA {
			reply.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   ip,
			}}
		}
		_ = w.WriteMsg(reply)
	})
	ds := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = ds.ActivateAndServe() }()
	t.Cleanup(func() { _ = ds.Shutdown() })
	return pc.LocalAddr().String(), &n
}

func answerIP(t *testing.T, resp *dns.Msg) net.IP {
	t.Helper()
	if resp == nil || len(resp.Answer) != 1 {
		t.Fatalf("expected exactly one answer, got %+v", resp)
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("answer is %T, want *dns.A", resp.Answer[0])
	}
	return a.A
}

// TestDoHUpstreamHedgeBeatsStalledDoH is THE regression test for the
// desktop cold-lookup incident: a DoH leg that stalls (firewall verdict
// latency, tarpit, black-holed flow) must not serialize behind it — the
// hedge fires, plaintext answers, and the caller gets an answer in roughly
// HedgeAfter + plaintext RTT instead of the full DoH timeout.
func TestDoHUpstreamHedgeBeatsStalledDoH(t *testing.T) {
	stub := newDoHStub(t, net.IPv4(203, 0, 113, 1))
	stub.mode.Store("stall")
	stub.delay.Store(1500 * time.Millisecond)
	plainAddr, plainQueries := countingPlainServer(t, net.IPv4(198, 51, 100, 2))

	u := &DoHUpstream{
		URL:        stub.srv.URL,
		Fallback:   &DNSUpstream{Servers: []string{plainAddr}, Timeout: time.Second},
		HedgeAfter: 100 * time.Millisecond,
		Timeout:    5 * time.Second,
	}
	t0 := time.Now()
	resp, err := u.Forward(context.Background(), new(dns.Msg).SetQuestion("stalled.test.", dns.TypeA))
	elapsed := time.Since(t0)
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if got := answerIP(t, resp); !got.Equal(net.IPv4(198, 51, 100, 2)) {
		t.Fatalf("answer = %s, want the plaintext fallback's 198.51.100.2 (the stalled DoH leg must not win)", got)
	}
	if elapsed >= 1200*time.Millisecond {
		t.Fatalf("Forward took %v — the hedge must answer long before the stalled DoH leg matters", elapsed)
	}
	if atomic.LoadInt64(plainQueries) == 0 {
		t.Error("plaintext fallback was never consulted")
	}
}

// TestDoHUpstreamHedgeIdleWhenDoHHealthy: a healthy DoH leg answers inside
// the hedge window, wins the race, and the plaintext fallback is never
// started (no query ever leaves the encrypted path).
func TestDoHUpstreamHedgeIdleWhenDoHHealthy(t *testing.T) {
	stub := newDoHStub(t, net.IPv4(203, 0, 113, 7))
	plainAddr, plainQueries := countingPlainServer(t, net.IPv4(198, 51, 100, 8))

	u := &DoHUpstream{
		URL:        stub.srv.URL,
		Fallback:   &DNSUpstream{Servers: []string{plainAddr}, Timeout: time.Second},
		HedgeAfter: 250 * time.Millisecond,
	}
	resp, err := u.Forward(context.Background(), new(dns.Msg).SetQuestion("healthy.test.", dns.TypeA))
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if got := answerIP(t, resp); !got.Equal(net.IPv4(203, 0, 113, 7)) {
		t.Fatalf("answer = %s, want the DoH leg's 203.0.113.7", got)
	}
	if n := atomic.LoadInt64(plainQueries); n != 0 {
		t.Errorf("plaintext fallback saw %d queries, want 0 — a healthy DoH leg must answer alone", n)
	}
}

// TestDoHUpstreamHedgeFiresImmediatelyOnDoHFailure: a DoH leg that fails
// FAST (connection refused, 5xx in milliseconds) must not make the caller
// wait out the hedge timer — the fallback starts the moment the failure is
// known.
func TestDoHUpstreamHedgeFiresImmediatelyOnDoHFailure(t *testing.T) {
	stub := newDoHStub(t, net.IPv4(203, 0, 113, 1))
	stub.mode.Store("down")
	plainAddr, _ := countingPlainServer(t, net.IPv4(198, 51, 100, 3))

	u := &DoHUpstream{
		URL:        stub.srv.URL,
		Fallback:   &DNSUpstream{Servers: []string{plainAddr}, Timeout: time.Second},
		HedgeAfter: 30 * time.Second, // huge: only the fast-failure path can beat it
	}
	t0 := time.Now()
	resp, err := u.Forward(context.Background(), new(dns.Msg).SetQuestion("fastfail.test.", dns.TypeA))
	elapsed := time.Since(t0)
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if got := answerIP(t, resp); !got.Equal(net.IPv4(198, 51, 100, 3)) {
		t.Fatalf("answer = %s, want the fallback's 198.51.100.3", got)
	}
	if elapsed >= 5*time.Second {
		t.Fatalf("Forward took %v — a fast DoH failure must start the fallback immediately, not after the hedge", elapsed)
	}
}

// TestDoHUpstreamHedgeDisabledKeepsSerial: HedgeAfter < 0 is the strict
// historical path — DoH first, plaintext only after a DoH failure (the
// `freens doh` health check relies on this to test the DoH leg itself).
func TestDoHUpstreamHedgeDisabledKeepsSerial(t *testing.T) {
	stub := newDoHStub(t, net.IPv4(203, 0, 113, 4))
	plainAddr, plainQueries := countingPlainServer(t, net.IPv4(198, 51, 100, 5))

	u := &DoHUpstream{
		URL:        stub.srv.URL,
		Fallback:   &DNSUpstream{Servers: []string{plainAddr}, Timeout: time.Second},
		HedgeAfter: -1,
	}
	// Healthy DoH: answered by DoH alone.
	resp, err := u.Forward(context.Background(), new(dns.Msg).SetQuestion("serial.test.", dns.TypeA))
	if err != nil {
		t.Fatalf("Forward (healthy): %v", err)
	}
	if got := answerIP(t, resp); !got.Equal(net.IPv4(203, 0, 113, 4)) {
		t.Fatalf("answer = %s, want DoH's 203.0.113.4", got)
	}
	if n := atomic.LoadInt64(plainQueries); n != 0 {
		t.Errorf("plaintext saw %d queries with the hedge disabled and DoH healthy, want 0", n)
	}
	// DoH down: the serial fallback still rescues (pre-v0.19.5 semantics).
	stub.mode.Store("down")
	resp, err = u.Forward(context.Background(), new(dns.Msg).SetQuestion("serial.test.", dns.TypeA))
	if err != nil {
		t.Fatalf("Forward (DoH down): %v", err)
	}
	if got := answerIP(t, resp); !got.Equal(net.IPv4(198, 51, 100, 5)) {
		t.Fatalf("answer = %s, want the serial fallback's 198.51.100.5", got)
	}
}

// TestDoHUpstreamNoFallbackUsesDoHOnly: no Fallback configured — the hedge
// is inert and a DoH failure surfaces as an error (DoH-only box).
func TestDoHUpstreamNoFallbackUsesDoHOnly(t *testing.T) {
	stub := newDoHStub(t, net.IPv4(203, 0, 113, 6))
	u := &DoHUpstream{URL: stub.srv.URL, Timeout: 2 * time.Second}
	resp, err := u.Forward(context.Background(), new(dns.Msg).SetQuestion("only.test.", dns.TypeA))
	if err != nil {
		t.Fatalf("Forward (healthy): %v", err)
	}
	if got := answerIP(t, resp); !got.Equal(net.IPv4(203, 0, 113, 6)) {
		t.Fatalf("answer = %s, want 203.0.113.6", got)
	}
	stub.mode.Store("down")
	if _, err := u.Forward(context.Background(), new(dns.Msg).SetQuestion("only.test.", dns.TypeA)); err == nil {
		t.Fatal("DoH failure without a fallback must error, not fabricate an answer")
	}
}

// TestDoHUpstreamBothLegsFail: hedged path with both legs dead returns a
// combined error naming both, never a partial answer.
func TestDoHUpstreamBothLegsFail(t *testing.T) {
	stub := newDoHStub(t, net.IPv4(203, 0, 113, 9))
	stub.mode.Store("down")
	u := &DoHUpstream{
		URL:        stub.srv.URL,
		Fallback:   &DNSUpstream{Servers: []string{"127.0.0.1:1"}, Timeout: 300 * time.Millisecond, Attempts: 1},
		HedgeAfter: 50 * time.Millisecond,
		Timeout:    2 * time.Second,
	}
	_, err := u.Forward(context.Background(), new(dns.Msg).SetQuestion("dead.test.", dns.TypeA))
	if err == nil {
		t.Fatal("both legs failed — Forward must error")
	}
	if !strings.Contains(err.Error(), "both failed") {
		t.Errorf("error should name both failed legs, got: %v", err)
	}
}

// TestDoHUpstreamDegradedTransitionLoggedOnce: sustained degradation logs
// exactly ONE WARN (never per query) and recovery exactly ONE INFO — the
// silent-fallback blind spot from the desktop incident must not return.
func TestDoHUpstreamDegradedTransitionLoggedOnce(t *testing.T) {
	stub := newDoHStub(t, net.IPv4(203, 0, 113, 10))
	plainAddr, _ := countingPlainServer(t, net.IPv4(198, 51, 100, 11))

	var logBuf syncWriter
	u := &DoHUpstream{
		URL:        stub.srv.URL,
		Fallback:   &DNSUpstream{Servers: []string{plainAddr}, Timeout: time.Second},
		HedgeAfter: 50 * time.Millisecond,
		Logger:     testLogger(&logBuf),
	}

	// Degraded stretch: DoH down, plaintext rescues — three lookups.
	stub.mode.Store("down")
	for i := 0; i < 3; i++ {
		if _, err := u.Forward(context.Background(), new(dns.Msg).SetQuestion("trans.test.", dns.TypeA)); err != nil {
			t.Fatalf("Forward %d (degraded): %v", i, err)
		}
	}
	logs := logBuf.String()
	if got := strings.Count(logs, "doh upstream degraded"); got != 1 {
		t.Errorf("degradation WARN count = %d, want exactly 1 (transitions only):\n%s", got, logs)
	}
	if !strings.Contains(logs, "level=WARN") {
		t.Errorf("degradation must log at WARN level:\n%s", logs)
	}

	// Recovery: DoH healthy again.
	stub.mode.Store("ok")
	for i := 0; i < 2; i++ {
		if _, err := u.Forward(context.Background(), new(dns.Msg).SetQuestion("trans.test.", dns.TypeA)); err != nil {
			t.Fatalf("Forward %d (recovered): %v", i, err)
		}
	}
	logs = logBuf.String()
	if got := strings.Count(logs, "doh upstream recovered"); got != 1 {
		t.Errorf("recovery INFO count = %d, want exactly 1:\n%s", got, logs)
	}
	if strings.Count(logs, "doh upstream degraded") != 1 {
		t.Error("recovery must not re-announce the degradation")
	}
}

// TestDoHUpstreamPing: the keepalive rides the shared client as one
// well-formed root-NS query and treats every outcome (including failure)
// as irrelevant.
func TestDoHUpstreamPing(t *testing.T) {
	var mu sync.Mutex
	var gotQ *dns.Msg
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		q := new(dns.Msg)
		if err := q.Unpack(body); err != nil {
			http.Error(w, "bad query", http.StatusBadRequest)
			return
		}
		mu.Lock()
		gotQ = q
		mu.Unlock()
	}))
	defer srv.Close()

	u := &DoHUpstream{URL: srv.URL}
	u.Ping() // must not panic, must send one query
	u.Ping() // and again: outcome ignored even when repeated
	mu.Lock()
	q := gotQ
	mu.Unlock()
	if q == nil {
		t.Fatal("Ping sent no query")
	}
	if len(q.Question) != 1 || q.Question[0].Name != "." || q.Question[0].Qtype != dns.TypeNS {
		t.Fatalf("ping question = %+v, want root NS", q.Question)
	}

	// Degenerate upstreams must be no-ops, never panics.
	(*DoHUpstream)(nil).Ping()
	(&DoHUpstream{}).Ping()
}
