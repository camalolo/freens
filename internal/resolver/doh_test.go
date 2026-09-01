// doh_test.go — the RFC 8484 server handler (doh.go) and the DoH upstream
// bootstrap fix (server.go) covered as black-box HTTP/DNS:
//
//   - bootstrap: a hostname DoH URL is dialed via IPs resolved from the
//     PLAINTEXT fallback servers (the v0.14.0 loop fix — the OS resolver
//     must never be consulted for the endpoint's own name when it IS this
//     daemon);
//   - handler: GET ?dns= / POST, content/media-type errors, size cap,
//     FORMERR, SERVFAIL-when-unwired, Cache-Control, metrics.
package resolver

import (
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/metrics"
	"github.com/miekg/dns"
)

// startPlainDNSServer serves a fixed answer set over UDP on 127.0.0.1,
// returning the listen address. Registered answers are matched by name.
func startPlainDNSServer(t *testing.T, answers map[string][]dns.RR) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, m *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(m)
		for name, rrs := range answers {
			if strings.EqualFold(name, m.Question[0].Name) {
				reply.Answer = rrs
				break
			}
		}
		_ = w.WriteMsg(reply)
	})
	ds := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = ds.ActivateAndServe() }()
	t.Cleanup(func() { _ = ds.Shutdown() })
	return pc.LocalAddr().String()
}

// startDoHEndpoint serves a canned DNS answer over HTTP (the "public" DoH
// provider stand-in). The URL's HOST is the hostname under test; the caller
// must point tcp at it via the bootstrap under test.
func startDoHEndpoint(t *testing.T, name string, answer []dns.RR) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		q := new(dns.Msg)
		if err := q.Unpack(body); err != nil || len(q.Question) == 0 {
			http.Error(w, "bad query", http.StatusBadRequest)
			return
		}
		m := new(dns.Msg)
		m.SetReply(q)
		if len(answer) > 0 {
			m.Answer = answer
		}
		w.Header().Set("Content-Type", DoHContentType)
		packed, _ := m.Pack()
		_, _ = w.Write(packed)
	}))
}

// TestDoHUpstreamBootstrapsEndpointViaFallback is THE regression test for
// the v0.14.0 bootstrap-loop fix (found by design + verified on the fleet):
// with resolv.conf → the daemon, the OS resolver IS the forwarder, so a
// hostname DoH URL must be resolved through the plaintext fallback servers
// and the IP pinned onto the dial. Here the DoH URL host "doh.test." is
// resolvable ONLY by the fake plaintext server; if the forwarder consulted
// the OS resolver instead, the dial would fail (doh.test does not exist
// outside this test's fake zone) and Forward would error.
func TestDoHUpstreamBootstrapsEndpointViaFallback(t *testing.T) {
	answer := []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.IPv4(93, 184, 216, 34),
	}}

	// The fake "provider": an HTTPS server whose URL host we claim is
	// "doh.test" — but the server itself listens on 127.0.0.1, so the
	// bootstrap resolution's job is to hand the dialer 127.0.0.1.
	provider := startDoHEndpoint(t, "example.com.", answer)
	defer provider.Close()

	provHost, provPort, err := net.SplitHostPort(strings.TrimPrefix(provider.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	provIP := net.ParseIP(provHost)

	// The fake "plaintext upstream": authoritative for the A record of
	// "doh.test." → the provider's address.
	boot := startPlainDNSServer(t, map[string][]dns.RR{
		"doh.test.": {&dns.A{
			Hdr: dns.RR_Header{Name: "doh.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   provIP,
		}},
	})

	// The URL host makes the http.Transport dial "doh.test:<port>". The
	// custom dialer must resolve doh.test via `boot`, pin the provider IP,
	// and connect. http.Client == nil is essential: that is the path whose
	// transport carries the bootstrap dialer (a caller-supplied Client is
	// its own transport's business).
	u := &DoHUpstream{
		URL:      "http://doh.test:" + provPort + "/dns-query", // http: httptest provider is plaintext; the dialer bootstrap is what is under test
		Fallback: &DNSUpstream{Servers: []string{boot}},
		Timeout:  10 * time.Second,
	}
	resp, err := u.Forward(context.Background(), new(dns.Msg).SetQuestion("example.com.", dns.TypeA))
	if err != nil {
		t.Fatalf("Forward over bootstrapped endpoint: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("answers = %d, want 1 (the provider answered, so the bootstrap dial worked)", len(resp.Answer))
	}
}

// TestDoHUpstreamEndpointIsPinnedInCache: with the pin cache primed, the
// dialer answers from the cache WITHOUT consulting the fallback servers —
// the stale-pins-beat-dark policy keeps a working endpoint answering even
// while the plaintext servers (the only bootstrap source) are down.
func TestDoHUpstreamEndpointIsPinnedInCache(t *testing.T) {
	answer := []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.IPv4(203, 0, 113, 7),
	}}
	provider := startDoHEndpoint(t, "example.com.", answer)
	defer provider.Close()
	provHost, provPort, err := net.SplitHostPort(strings.TrimPrefix(provider.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}

	u := &DoHUpstream{
		URL:      "http://cached.test:" + provPort + "/dns-query",
		Fallback: &DNSUpstream{Servers: []string{"127.0.0.1:1"}}, // unreachable
		Timeout:  2 * time.Second,
	}
	// Prime the pin cache by hand.
	u.bootMu.Lock()
	u.bootIPs = []net.IP{net.ParseIP(provHost)}
	u.bootAt = time.Now()
	u.bootMu.Unlock()

	resp, err := u.Forward(context.Background(), new(dns.Msg).SetQuestion("example.com.", dns.TypeA))
	if err != nil {
		t.Fatalf("Forward with primed pin cache: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("answers = %d, want 1", len(resp.Answer))
	}
}

// ---------------------------------------------------------------------------
// The RFC 8484 server handler
// ---------------------------------------------------------------------------

// cannedResolver resolves every question to one canned answer (the fake
// response's ID/question echo miekg handles via SetReply).
type cannedResolver struct {
	answer []dns.RR
}

func (c *cannedResolver) ResolveMsg(_ context.Context, m *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(m)
	if len(c.answer) > 0 {
		resp.Answer = c.answer
	}
	return resp
}

func testDoHHandler() *DoHHandler {
	return &DoHHandler{Resolver: &cannedResolver{answer: []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.IPv4(93, 184, 216, 34),
	}}}}
}

func packQuestion(t *testing.T, name string, qtype uint16) []byte {
	t.Helper()
	b, err := new(dns.Msg).SetQuestion(name, qtype).Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func doHGET(t *testing.T, h *DoHHandler, query string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/dns-query?dns="+query, nil)
	h.ServeHTTP(rec, req)
	return rec
}

func TestDoHHandlerPOST(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/dns-query",
		strings.NewReader(string(packQuestion(t, "example.com.", dns.TypeA))))
	req.Header.Set("Content-Type", DoHContentType)
	testDoHHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != DoHContentType {
		t.Errorf("Content-Type = %q, want %q", ct, DoHContentType)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "max-age=60" {
		t.Errorf("Cache-Control = %q, want max-age=60 (min answer TTL)", cc)
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(rec.Body.Bytes()); err != nil {
		t.Fatalf("response body is not a DNS message: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Errorf("answers = %d, want 1", len(resp.Answer))
	}
	if resp.Question[0].Name != "example.com." {
		t.Errorf("question echo = %q", resp.Question[0].Name)
	}
}

func TestDoHHandlerGET(t *testing.T) {
	// RFC 8484 §4.1.1: base64url, padding optional.
	for _, enc := range []string{
		base64RawURL(packQuestion(t, "example.com.", dns.TypeA)),
		// padded variant tolerated
		base64URLPadded(packQuestion(t, "example.com.", dns.TypeA)),
	} {
		rec := doHGET(t, testDoHHandler(), enc)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET status = %d, want 200", rec.Code)
		}
		resp := new(dns.Msg)
		if err := resp.Unpack(rec.Body.Bytes()); err != nil {
			t.Fatalf("GET response is not a DNS message: %v", err)
		}
		if len(resp.Answer) != 1 {
			t.Errorf("GET answers = %d, want 1", len(resp.Answer))
		}
	}
}

func TestDoHHandlerBadRequests(t *testing.T) {
	h := testDoHHandler()

	// Wrong method.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/dns-query", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("PUT status = %d, want 405", rec.Code)
	}
	if allow := rec.Header().Get("Allow"); allow != "GET, POST" {
		t.Errorf("Allow = %q, want GET, POST", allow)
	}

	// POST with a non-DNS content type.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/dns-query", strings.NewReader("hi"))
	req.Header.Set("Content-Type", "text/plain")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("bad content type status = %d, want 415", rec.Code)
	}

	// GET without the dns parameter.
	if rec := doHGET(t, h, ""); rec.Code != http.StatusBadRequest {
		t.Errorf("missing param status = %d, want 400", rec.Code)
	}

	// GET with undecodable base64url.
	if rec := doHGET(t, h, "!!!!"); rec.Code != http.StatusBadRequest {
		t.Errorf("bad base64 status = %d, want 400", rec.Code)
	}

	// Oversized POST body.
	rec = httptest.NewRecorder()
	big := strings.Repeat("A", maxDoHQueryBytes+1)
	req = httptest.NewRequest(http.MethodPost, "/dns-query", strings.NewReader(big))
	req.Header.Set("Content-Type", DoHContentType)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversize status = %d, want 413", rec.Code)
	}
}

// TestDoHHandlerFORMERR: a decodable DNS message with no question answers
// FORMERR as a DNS payload (HTTP 200) — the RFC 8484 way of surfacing a DNS
// error the client can still parse.
func TestDoHHandlerFORMERR(t *testing.T) {
	empty := new(dns.Msg) // no question
	packed, err := empty.Pack()
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/dns-query", strings.NewReader(string(packed)))
	req.Header.Set("Content-Type", DoHContentType)
	testDoHHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (FORMERR travels as a DNS payload)", rec.Code)
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(rec.Body.Bytes()); err != nil {
		t.Fatalf("FORMERR body is not a DNS message: %v", err)
	}
	if resp.Rcode != dns.RcodeFormatError {
		t.Errorf("rcode = %d, want FORMERR(1)", resp.Rcode)
	}
}

// TestDoHHandlerSERVFAILWhenUnwired: no MsgResolver ⇒ every query answers
// SERVFAIL as a DNS payload, never a bare HTTP error.
func TestDoHHandlerSERVFAILWhenUnwired(t *testing.T) {
	h := &DoHHandler{} // Resolver nil
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/dns-query",
		strings.NewReader(string(packQuestion(t, "example.com.", dns.TypeA))))
	req.Header.Set("Content-Type", DoHContentType)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(rec.Body.Bytes()); err != nil {
		t.Fatalf("body is not a DNS message: %v", err)
	}
	if resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("rcode = %d, want SERVFAIL(2)", resp.Rcode)
	}
}

// TestDoHHandlerCountsQueries: answered queries land in the shared
// {qtype,status} counter, same labels as the UDP/TCP servers.
func TestDoHHandlerCountsQueries(t *testing.T) {
	reg := metrics.New()
	c := reg.NewCounter("freens_dns_queries_total", "q", "qtype", "status")
	h := &DoHHandler{Resolver: testDoHHandler().Resolver, Queries: c}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/dns-query",
		strings.NewReader(string(packQuestion(t, "example.com.", dns.TypeA))))
	req.Header.Set("Content-Type", DoHContentType)
	h.ServeHTTP(rec, req)

	if got := exposition(t, reg); !strings.Contains(got, `freens_dns_queries_total{qtype="A",status="noerror"} 1`) {
		t.Errorf("counter series missing/uncounted:\n%s", got)
	}
}

// base64RawURL / base64URLPadded are tiny helpers keeping the RFC 8484
// padding matrix explicit.
func base64RawURL(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func base64URLPadded(b []byte) string {
	return base64.URLEncoding.EncodeToString(b)
}
