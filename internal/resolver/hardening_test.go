package resolver

// hardening_test.go pins the v0.7.1 resolver hardening from the application
// audit: per-question single-flight (the cache-expiry stampede ran N identical
// DHT walks), >255 B TXT rdata chunking (an un-packable answer used to be
// silently dropped), UDP truncation (oversized answers vanished instead of
// TC+TCP fallback), and the RFC 8484 DoH upstream (the [upstream] doh config
// key was parsed but never wired — all upstream traffic was silently
// plaintext).

import (
	"bytes"
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

	"github.com/camalolo/freens/internal/wire"
	"github.com/miekg/dns"
)

// ---------------------------------------------------------------------------
// Single-flight
// ---------------------------------------------------------------------------

// gatedLookup is a RecordLookup whose Lookups block on a channel until the
// test releases them, counting invocations.
type gatedLookup struct {
	release chan struct{}
	calls   atomic.Int32
	env     *wire.SignedEnvelope
}

func (g *gatedLookup) Lookup(ctx context.Context, wireName []byte, now int64) (*wire.SignedEnvelope, error) {
	g.calls.Add(1)
	<-g.release
	return g.env, nil
}

// TestServeDNSSingleFlightCollapsesStampede: 8 concurrent identical queries
// during a slow resolution produce exactly ONE namespace Lookup; every
// caller still receives the answer.
func TestServeDNSSingleFlightCollapsesStampede(t *testing.T) {
	w := newFreensWorld(t)
	g := &gatedLookup{release: make(chan struct{}), env: w.tldEnv}
	cfg := configFor(t, w, RouteFREENS)
	r := newResolver(cfg, g, nil)
	r.Cache = NewResponseCache(0, func() int64 { return fixedNow })

	const n = 8
	responses := make(chan *dns.Msg, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			q := new(dns.Msg).SetQuestion("footld.", dns.TypeA)
			responses <- serveDNSOverUDP(t, r, q)
		}()
	}
	// Wait until the stampede has piled up (at least one Lookup entered the
	// gate; the flight map holds the leader; followers are parked), then
	// release.
	deadline := time.Now().Add(2 * time.Second)
	for g.calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond) // let the followers pile onto the flight
	close(g.release)
	wg.Wait()
	close(responses)

	if got := g.calls.Load(); got != 1 {
		t.Errorf("namespace lookups for %d concurrent identical queries = %d, want 1 (single-flight)", n, got)
	}
	served := 0
	for resp := range responses {
		served++
		if resp == nil || resp.Rcode != dns.RcodeSuccess {
			t.Errorf("follower response rcode = %v", resp)
		}
	}
	if served != n {
		t.Errorf("served %d of %d queriers", served, n)
	}
	// The leader cached the outcome: a fresh query is a pure cache hit.
	before := g.calls.Load()
	q := new(dns.Msg).SetQuestion("footld.", dns.TypeA)
	if resp := serveDNSOverUDP(t, r, q); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("post-flight query rcode = %d", resp.Rcode)
	}
	if got := g.calls.Load(); got != before {
		t.Errorf("cached outcome re-resolved (%d → %d lookups)", before, got)
	}
}

// ---------------------------------------------------------------------------
// TXT chunking + UDP truncation
// ---------------------------------------------------------------------------

// TestTXTMappingChunksLongRdata: a >255 B TXT rdata maps to multiple
// character-strings (RFC 1035) instead of an un-packable single string, and
// the full answer message Packs.
func TestTXTMappingChunksLongRdata(t *testing.T) {
	long := strings.Repeat("freens", 111) // 666 bytes
	rr, err := wire.TXT(long, 300)
	if err != nil {
		t.Fatal(err)
	}
	got := freensRRToDNS("long.footld.", rr, fixedNow+3600, fixedNow)
	txt, ok := got.(*dns.TXT)
	if !ok {
		t.Fatalf("mapping type = %T, want *dns.TXT", got)
	}
	var total int
	for _, s := range txt.Txt {
		if len(s) > 255 {
			t.Fatalf("character-string of %d bytes (> 255)", len(s))
		}
		total += len(s)
	}
	if total != len(long) {
		t.Fatalf("chunked rdata totals %d bytes, want %d", total, len(long))
	}
	// The packing failure this fixes: a message carrying the mapped RR
	// must Pack cleanly.
	m := new(dns.Msg)
	m.SetReply(new(dns.Msg).SetQuestion("long.footld.", dns.TypeTXT))
	m.Answer = []dns.RR{txt}
	if _, err := m.Pack(); err != nil {
		t.Fatalf("Pack with long TXT: %v", err)
	}
}

// TestUDPResponseTruncated: an answer larger than the 512-byte UDP budget is
// truncated with TC set (client retries over TCP) instead of vanishing as an
// oversized datagram.
func TestUDPResponseTruncated(t *testing.T) {
	w := newFreensWorld(t)
	// A record with three ~300 B TXT RRs → >512 B wire answer.
	rec, err := wire.NewRecord(w.wwwEnv.Record.Name, w.tldKP.Public(), 2,
		uint64(fixedNow-10), uint64(fixedNow+3600))
	if err != nil {
		t.Fatal(err)
	}
	big := strings.Repeat("x", 300)
	for i := 0; i < 3; i++ {
		rr, err := wire.TXT(big, 300)
		if err != nil {
			t.Fatal(err)
		}
		rec.RRset = append(rec.RRset, rr)
	}
	bigEnv, err := wire.SignRecord(rec, w.tldKP)
	if err != nil {
		t.Fatal(err)
	}
	lookup := &twoHopLookup{tld: w.tldEnv, name: bigEnv}
	r := newResolver(configFor(t, w, RouteFREENS), lookup, nil)
	r.Cache = NewResponseCache(0, func() int64 { return fixedNow })

	q := new(dns.Msg).SetQuestion("www.footld.", dns.TypeTXT)
	resp := serveDNSOverUDP(t, r, q)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d", resp.Rcode)
	}
	if !resp.Truncated {
		t.Errorf("TC not set on a >512 B UDP answer (len(answer)=%d)", len(resp.Answer))
	}
}

// twoHopLookup serves the TLD record for the TLD wire name and `name` for
// everything else (the minimal two-hop chain fixture).
type twoHopLookup struct {
	tld  *wire.SignedEnvelope
	name *wire.SignedEnvelope
}

func (s *twoHopLookup) Lookup(ctx context.Context, wireName []byte, now int64) (*wire.SignedEnvelope, error) {
	if bytes.Equal(wireName, s.tld.Record.Name) {
		return s.tld, nil
	}
	return s.name, nil
}

// ---------------------------------------------------------------------------
// DoH upstream
// ---------------------------------------------------------------------------

// TestDoHUpstreamForwards: a packed query goes out as POST
// application/dns-message and the 200 response body is decoded.
func TestDoHUpstreamForwards(t *testing.T) {
	answer := new(dns.Msg)
	answer.SetReply(new(dns.Msg).SetQuestion("example.com.", dns.TypeA))
	answer.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.IPv4(93, 184, 216, 34),
	}}
	var gotContentType, gotMethod string
	var gotQuery *dns.Msg
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		gotMethod = req.Method
		gotContentType = req.Header.Get("Content-Type")
		body, _ := io.ReadAll(req.Body)
		q := new(dns.Msg)
		if err := q.Unpack(body); err == nil {
			gotQuery = q
		}
		w.Header().Set("Content-Type", "application/dns-message")
		packed, _ := answer.Pack()
		_, _ = w.Write(packed)
	}))
	defer srv.Close()

	u := &DoHUpstream{URL: srv.URL}
	resp, err := u.Forward(context.Background(), new(dns.Msg).SetQuestion("example.com.", dns.TypeA))
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if gotMethod != http.MethodPost || gotContentType != "application/dns-message" {
		t.Errorf("request = %s %q, want POST application/dns-message", gotMethod, gotContentType)
	}
	if gotQuery == nil || len(gotQuery.Question) != 1 || gotQuery.Question[0].Name != "example.com." {
		t.Errorf("DoH body did not carry the query: %+v", gotQuery)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("response answers = %d, want 1", len(resp.Answer))
	}
}

// TestDoHUpstreamFallsBackToPlaintext: when DoH fails (500 here), the query
// is retried against the Fallback DNSUpstream servers.
func TestDoHUpstreamFallsBackToPlaintext(t *testing.T) {
	// A plaintext UDP DNS server answering with a fixed A record.
	upAnswer := new(dns.Msg)
	upAnswer.SetReply(new(dns.Msg).SetQuestion("fallback.test.", dns.TypeA))
	upAnswer.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "fallback.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.IPv4(192, 0, 2, 1),
	}}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, m *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(m) // echoes the request's ID, question, etc.
		reply.Answer = upAnswer.Answer
		_ = w.WriteMsg(reply)
	})
	ds := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = ds.ActivateAndServe() }()
	defer func() { _ = ds.Shutdown() }()

	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer broken.Close()

	u := &DoHUpstream{
		URL:      broken.URL,
		Fallback: &DNSUpstream{Servers: []string{pc.LocalAddr().String()}},
	}
	resp, err := u.Forward(context.Background(), new(dns.Msg).SetQuestion("fallback.test.", dns.TypeA))
	if err != nil {
		t.Fatalf("Forward with fallback: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("fallback answers = %d, want 1", len(resp.Answer))
	}
}
