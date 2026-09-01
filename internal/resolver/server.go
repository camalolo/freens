package resolver

// This file implements the §9.1 DNS server (UDP + TCP) on github.com/miekg/dns
// and a concrete Upstream that forwards to conventional recursive resolvers.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/camalolo/freens/internal/metrics"
	"github.com/miekg/dns"
)

// Server is a UDP or TCP DNS server that answers queries via a *Resolver.
// network is "udp" or "tcp".
type Server struct {
	dnsSrv   *dns.Server
	resolver *Resolver
	network  string
	// queries optionally counts every answered query by (qtype, status);
	// nil (the default) disables instrumentation.
	queries *metrics.Counter
}

// NewServer builds a Server bound to addr on the given network ("udp"/"tcp").
// The underlying *dns.Server (exposed via DNSServer) is configured but not yet
// listening; call ListenAndServe to start it. A test may pre-bind a socket and
// assign it to DNSServer().PacketConn / Listener before calling ListenAndServe
// to learn the ephemeral port up front.
func NewServer(addr, network string, res *Resolver) *Server {
	s := &Server{resolver: res, network: network}
	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handleDNS)
	s.dnsSrv = &dns.Server{Addr: addr, Net: network, Handler: mux}
	return s
}

// SetQueryCounter installs a pre-registered counter (expected label layout
// "qtype", "status") that is incremented once per answered query. Passing nil
// (or never calling) leaves the server uninstrumented, so existing callers are
// unaffected. Multiple servers (udp + tcp) may share one counter.
func (s *Server) SetQueryCounter(c *metrics.Counter) { s.queries = c }

// handleDNS is the mux entry point: it wraps the resolver's ServeDNS with a
// recording dns.ResponseWriter so the query outcome (rcode) can be counted,
// then delegates. With no counter installed it is a pure passthrough.
func (s *Server) handleDNS(w dns.ResponseWriter, m *dns.Msg) {
	if s.queries == nil {
		s.resolver.ServeDNS(w, m)
		return
	}
	mw := &metricsWriter{ResponseWriter: w, queries: s.queries, qtype: qtypeLabel(m)}
	s.resolver.ServeDNS(mw, m)
}

// metricsWriter is a dns.ResponseWriter that counts the written response's
// status before delegating. Only WriteMsg is intercepted (it is the sole
// response path in Resolver.ServeDNS); every other method is inherited.
type metricsWriter struct {
	dns.ResponseWriter
	queries *metrics.Counter
	qtype   string
}

// WriteMsg forwards the response and counts it as qtype{noerror|nxdomain|servfail}.
func (w *metricsWriter) WriteMsg(resp *dns.Msg) error {
	w.queries.With(w.qtype, statusLabel(resp.Rcode)).Inc()
	return w.ResponseWriter.WriteMsg(resp)
}

// statusLabel maps a dns rcode onto the exported status dimension. Only the
// three statuses the resolver actually emits are distinguished (§9.2):
// NOERROR, NXDOMAIN, and everything else (SERVFAIL/REFUSED/FORMERR-class) as
// "servfail".
func statusLabel(rcode int) string {
	switch rcode {
	case dns.RcodeSuccess:
		return "noerror"
	case dns.RcodeNameError:
		return "nxdomain"
	default:
		return "servfail"
	}
}

// qtypeLabel renders the question's type as the exported qtype dimension
// ("A", "TXT", …; unknown codes as TYPE<n>; "none" for FORMERR messages
// carrying no question).
func qtypeLabel(m *dns.Msg) string {
	if len(m.Question) == 0 {
		return "none"
	}
	if s, ok := dns.TypeToString[m.Question[0].Qtype]; ok {
		return s
	}
	return fmt.Sprintf("TYPE%d", m.Question[0].Qtype)
}

// DNSServer returns the underlying miekg/dns Server, so callers (typically
// tests) can read the bound address or inject a pre-bound PacketConn/Listener.
func (s *Server) DNSServer() *dns.Server { return s.dnsSrv }

// ListenAndServe starts the DNS server. If DNSServer().PacketConn or
// DNSServer().Listener is already set, ActivateAndServe semantics are used
// (serving on the existing socket — required to learn an ephemeral port up
// front); otherwise the server binds its own socket from Addr/Net.
func (s *Server) ListenAndServe() error {
	if s.dnsSrv == nil {
		return errors.New("resolver: server not initialized")
	}
	if s.dnsSrv.PacketConn != nil || s.dnsSrv.Listener != nil {
		return s.dnsSrv.ActivateAndServe()
	}
	return s.dnsSrv.ListenAndServe()
}

// Shutdown stops the server gracefully (closing the listening socket and
// draining in-flight requests per miekg/dns semantics).
func (s *Server) Shutdown() error {
	if s.dnsSrv == nil {
		return nil
	}
	return s.dnsSrv.Shutdown()
}

// ServeDNS implements dns.Handler so a *Resolver can be served directly by a
// dns.Server (no Server wrapper required). It resolves via ResolveMsg and
// writes the response with the datagram framing rules (UDP truncation, see
// writeReply).
func (r *Resolver) ServeDNS(w dns.ResponseWriter, m *dns.Msg) {
	writeReply(w, r.ResolveMsg(context.Background(), m))
}

// ResolveMsg answers one DNS query message and returns the response message
// (never nil; the echoed question + rcode/answers/AA per §9.2). It is the
// message-level twin of ServeDNS for transports that are NOT miekg/dns
// listeners: the RFC 8484 DoH handler (doh.go) and the admin socket's
// /dns-query relay (which fronts the webui's DoH face). Every semantic —
// the §10.4 cache, serve-stale, single-flight, the overload cap, AA
// marking — is byte-for-byte the UDP/TCP path's; only the transport framing
// differs (UDP truncation stays with writeReply; HTTPS needs none).
func (r *Resolver) ResolveMsg(ctx context.Context, m *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(m)
	resp.RecursionAvailable = r.Upstream != nil || r.Freens != nil

	if len(m.Question) == 0 {
		resp.Rcode = dns.RcodeFormatError
		return resp
	}

	q := m.Question[0]
	ck := cacheKeyFor(q)

	// §10.4: consult the response cache BEFORE resolving so a cached hit
	// never re-executes the lookup chain. Only freens-sourced outcomes are
	// ever stored (putFreens ignores aa == false), so DNS-forwarded answers
	// always reach the upstream.
	//
	// Serve-stale-while-revalidate (§10.4 amended): an expired POSITIVE
	// answer inside the stale window is answered immediately — it carries
	// exactly the validation the fresh answer would (short TTL so stubs
	// re-ask soon) — while kickRefresh revalidates in the background. The
	// user-visible effect: the walk cost (~100 ms LAN, seconds over WAN)
	// stops landing on the client; a revoked/rotated name still goes dark
	// within TTL + refresh duration, because the fresh outcome — positive
	// OR negative — replaces the entry.
	if r.Cache != nil {
		rrs, rcode, aa, status := r.Cache.get2(ck)
		switch status {
		case cacheFresh:
			// Prefetch (unbound-style): a fresh answer with ≤60 s of TTL
			// left refreshes in the background NOW, so a name in active use
			// never reaches expiry at all — the stale path stays reserved
			// for genuinely idle names and outages. Same throttle/single-
			// flight rules as the stale refresh, so this is bounded.
			if len(rrs) > 0 && rrs[0].Header().Ttl <= prefetchWindow {
				r.kickRefresh(q, ck)
			}
			resp.Rcode = rcode
			resp.Answer = rrs
			resp.Authoritative = aa
			return resp
		case cacheStale:
			r.kickRefresh(q, ck)
			resp.Rcode = rcode
			resp.Answer = rrs
			resp.Authoritative = aa
			return resp
		}
	}

	// resolveShared: single-flight the resolution (concurrent identical
	// queries share one DHT walk; the leader caches the outcome per §10.4 —
	// which is why the old putFreens call moved inside it).
	rrs, rcode, aa, err := r.resolveShared(ctx, q, ck)
	if err != nil {
		resp.Rcode = dns.RcodeServerFailure
		return resp
	}
	resp.Rcode = rcode
	resp.Answer = rrs
	// AA reflects whether the FINAL answer was produced by the authoritative
	// freens source (returned by ResolveQuestion as `aa`). DNS-forwarded
	// answers and DENY are non-authoritative. Per RFC 1035 §4.1.1 the AA bit
	// is meaningful for any rcode that an authoritative server would emit
	// (including NXDOMAIN/NODATA), so we set it verbatim from the resolver.
	resp.Authoritative = aa
	return resp
}

// writeReply sends resp, truncating UDP responses that exceed the classic
// 512-byte datagram budget so the client sees TC + TCP fallback instead of a
// silently-dropped oversized datagram (miekg/dns never frames UDP errors for
// us; pre-v0.7.1 a >512 B answer simply vanished — found auditing the TXT
// paths). No-op truncation for TCP.
func writeReply(w dns.ResponseWriter, resp *dns.Msg) {
	if addr := w.RemoteAddr(); addr != nil {
		if _, isUDP := addr.(*net.UDPAddr); isUDP {
			resp.Truncate(dns.MinMsgSize)
		}
	}
	_ = w.WriteMsg(resp)
}

// DNSUpstream is a concrete Upstream that forwards queries to a list of
// conventional recursive resolvers (e.g. ["9.9.9.9", "149.112.112.112"]) using
// github.com/miekg/dns. Servers without an explicit port get ":53" appended.
// On a UDP response with the TC (truncated) bit set, the query is retried over
// TCP (§9.2 step 4 "same protocol" with standard fallback).
type DNSUpstream struct {
	Servers []string      // host or host:port
	Net     string        // "udp" (default) or "tcp"
	Timeout time.Duration // per-attempt timeout; default 5s
	// Attempts is the per-server retry count (default 2, glibc-style).
	// ONE attempt per server made a single slow cache-miss at a cold
	// upstream fatal to the whole box: the daemon SERVFAILed, every app
	// saw "server misbehaving", and the upstream — which HAD received the
	// query and cached the answer — was never asked again (found live on
	// camalolo-box: `freens upgrade` died three times on github.com before
	// the upstream warmed). The retry lands on the warmed answer.
	Attempts int
}

// Forward implements Upstream. It tries each server in order, retrying
// each server up to Attempts times before moving on; the first non-error,
// non-nil response wins. A truncated UDP response triggers a single TCP
// retry against the same server.
func (u *DNSUpstream) Forward(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	if u == nil || len(u.Servers) == 0 {
		return nil, errors.New("resolver: no upstream servers configured")
	}
	net0 := u.Net
	if net0 == "" {
		net0 = "udp"
	}
	timeout := u.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	attempts := u.Attempts
	if attempts <= 0 {
		attempts = 2
	}
	var lastErr error
	for _, srv := range u.Servers {
		addr := ensureDNSPort(srv)
		for attempt := 0; attempt < attempts; attempt++ {
			resp, err := exchangeWith(ctx, q, addr, net0, timeout)
			if err != nil {
				lastErr = err
				continue
			}
			if resp == nil {
				lastErr = errors.New("resolver: upstream returned no response")
				continue
			}
			// TC bit on UDP → retry over TCP against the same server.
			if resp.Truncated && net0 == "udp" {
				if r2, err := exchangeWith(ctx, q, addr, "tcp", timeout); err == nil && r2 != nil {
					return r2, nil
				}
			}
			return resp, nil
		}
	}
	if lastErr != nil {
		return nil, fmt.Errorf("resolver: all upstreams failed: %w", lastErr)
	}
	return nil, errors.New("resolver: all upstreams failed")
}

// exchangeWith wraps dns.Client.ExchangeContext so tests can substitute it.
var exchangeWith = func(ctx context.Context, q *dns.Msg, addr, network string, timeout time.Duration) (*dns.Msg, error) {
	c := &dns.Client{Net: network, Timeout: timeout}
	resp, _, err := c.ExchangeContext(ctx, q, addr)
	return resp, err
}

// ensureDNSPort appends ":53" to a bare host so miekg/dns (which requires
// host:port) accepts it. Existing host:port forms are returned unchanged.
func ensureDNSPort(srv string) string {
	if _, _, err := net.SplitHostPort(srv); err == nil {
		return srv
	}
	return srv + ":53"
}

// DoHUpstream is an Upstream that forwards over RFC 8484 DNS-over-HTTPS
// (POST application/dns-message), honoring the [upstream] doh config key
// that existed pre-v0.7.1 but was silently never wired (every query —
// including, under the old dns-first default, freens-namespace names —
// left in plaintext UDP). Fallback is the plain DNSUpstream server list:
// when DoH fails (network, 4xx/5xx, malformed response) the query is
// retried over conventional DNS rather than erroring out, so wiring DoH
// never reduces availability. A nil Fallback makes DoH the only path.
//
// Bootstrap loop (v0.14.0): the DoH endpoint's own HOSTNAME is resolved via
// the plaintext Fallback servers — never the OS resolver. With the fleet's
// standard wiring (resolv.conf → 127.0.0.1) the OS resolver IS this daemon,
// so an OS-resolved dial of "dns.example.com" would route the bootstrap
// lookup straight back into RouteDNS → this very DoHUpstream → another
// OS-resolved dial: a self-deadlock that SERVFAILed every forwarded name
// (single-flight deduplicates the loop into one wedged flight). IP-form
// endpoint URLs (the shipped presets use https://9.9.9.9/dns-query and
// https://1.1.1.1/dns-query) never need bootstrapping at all; hostname URLs
// get Fallback-resolved IPs pinned onto the dialer (SNI + certificate
// verification still use the URL's hostname — only the TCP dial is pinned).
// When the Fallback cannot answer (no servers, all down), dialing degrades
// to the OS resolver — correct on boxes whose resolv.conf does NOT point
// here, and merely slow (bounded by the request timeout) on boxes that do.
type DoHUpstream struct {
	URL      string        // the DoH endpoint (e.g. https://dns.example/dns-query)
	Timeout  time.Duration // per-request timeout; default 5 s
	Client   *http.Client  // default: a client whose dialer bootstraps via Fallback
	Fallback *DNSUpstream  // optional plaintext fallback (tried after DoH fails)

	// Bootstrap state: the endpoint host's pinned IPs and when they were
	// resolved. Guarded by bootMu; refreshed lazily after bootstrapRefresh
	// (and re-pinned only on success — a failed re-resolve keeps serving on
	// the last known-good IPs rather than going dark).
	bootMu  sync.Mutex
	bootIPs []net.IP
	bootAt  time.Time
}

// bootstrapRefresh is how long a pinned DoH-endpoint IP stays trusted before
// the next connection attempt re-resolves it (DoH endpoints are anycast and
// near-immortal; this bounds staleness without per-request DNS chatter).
const bootstrapRefresh = 5 * time.Minute

// Forward implements Upstream: one DoH POST of the packed query; on success
// (HTTP 200 with a decodable DNS message) the response is returned as-is.
func (u *DoHUpstream) Forward(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	if u == nil || u.URL == "" {
		return nil, errors.New("resolver: no DoH URL configured")
	}
	timeout := u.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	client := u.httpClient(timeout)
	payload, err := q.Pack()
	if err != nil {
		return nil, fmt.Errorf("resolver: pack query for DoH: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.URL, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("resolver: DoH request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := client.Do(req)
	if err != nil {
		return u.fallbackOr(ctx, q, fmt.Errorf("resolver: DoH round trip: %w", err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return u.fallbackOr(ctx, q, fmt.Errorf("resolver: DoH status %d", resp.StatusCode))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return u.fallbackOr(ctx, q, fmt.Errorf("resolver: DoH body: %w", err))
	}
	out := new(dns.Msg)
	if err := out.Unpack(body); err != nil {
		return u.fallbackOr(ctx, q, fmt.Errorf("resolver: DoH response unpack: %w", err))
	}
	return out, nil
}

// httpClient builds the request client. A caller-supplied Client (the test
// seam, or an embedder with special transport needs) wins untouched;
// otherwise the client gets a transport whose dialer pins the endpoint host
// to Fallback-resolved IPs (see the bootstrap-loop note on DoHUpstream).
func (u *DoHUpstream) httpClient(timeout time.Duration) *http.Client {
	if u.Client != nil {
		return u.Client
	}
	t := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          4,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		DialContext:           u.dialContext,
	}
	return &http.Client{Timeout: timeout, Transport: t}
}

// dialContext is the transport's connection dialer: the DoH endpoint's
// hostname (if any) is resolved through the plaintext Fallback servers and
// the IP pinned onto the TCP dial. TLS is NOT affected — the http.Transport
// wraps the conn itself, verifying the certificate against the URL's
// hostname (ServerName), so a pinned IP can never silently redirect trust.
func (u *DoHUpstream) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// Not host:port — dial verbatim and let the failure speak.
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	if net.ParseIP(host) == nil {
		if ips, ierr := u.bootstrapIPs(ctx, host); ierr == nil && len(ips) > 0 {
			addr = net.JoinHostPort(ips[0].String(), port)
		}
		// Bootstrap failed → OS resolver. On the standard wiring that is
		// this daemon and the lookup SERVFAILs quickly (its own upstream
		// attempt is the outer call); the dial error then falls through to
		// fallbackOr, which is exactly the plaintext path we want anyway.
	}
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

// bootstrapIPs returns pinned IPs for host, resolving (re-pinning) them via
// the Fallback servers when the cache is empty or stale.
func (u *DoHUpstream) bootstrapIPs(ctx context.Context, host string) ([]net.IP, error) {
	u.bootMu.Lock()
	defer u.bootMu.Unlock()
	if len(u.bootIPs) > 0 && time.Since(u.bootAt) < bootstrapRefresh {
		return u.bootIPs, nil
	}
	ips, err := u.resolveViaFallback(ctx, host)
	if err != nil || len(ips) == 0 {
		if len(u.bootIPs) > 0 {
			return u.bootIPs, nil // stale beats dark
		}
		if err == nil {
			err = errors.New("resolver: no bootstrap answer for " + host)
		}
		return nil, err
	}
	u.bootIPs = ips
	u.bootAt = time.Now()
	return ips, nil
}

// resolveViaFallback asks the plaintext servers for host's A records (AAAA
// as a fallback when no A exists) using the same exchange seam as the plain
// forwarder, so tests can stand in for the network.
func (u *DoHUpstream) resolveViaFallback(ctx context.Context, host string) ([]net.IP, error) {
	if u.Fallback == nil || len(u.Fallback.Servers) == 0 {
		return nil, errors.New("resolver: no plaintext fallback servers to bootstrap the DoH endpoint")
	}
	timeout := u.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		q := new(dns.Msg)
		q.SetQuestion(dns.Fqdn(host), qtype)
		q.RecursionDesired = true
		for _, srv := range u.Fallback.Servers {
			resp, err := exchangeWith(ctx, q, ensureDNSPort(srv), "udp", timeout)
			if err != nil || resp == nil || resp.Rcode != dns.RcodeSuccess {
				continue
			}
			var ips []net.IP
			for _, rr := range resp.Answer {
				switch r := rr.(type) {
				case *dns.A:
					ips = append(ips, r.A)
				case *dns.AAAA:
					ips = append(ips, r.AAAA)
				}
			}
			if len(ips) > 0 {
				return ips, nil
			}
		}
	}
	return nil, nil
}

// fallbackOr retries q over the plaintext Fallback (if any) after a DoH
// failure, chaining both errors; without a fallback the DoH error is
// returned as-is.
func (u *DoHUpstream) fallbackOr(ctx context.Context, q *dns.Msg, dohErr error) (*dns.Msg, error) {
	if u.Fallback == nil {
		return nil, dohErr
	}
	resp, err := u.Fallback.Forward(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("%v (plaintext fallback also failed: %w)", dohErr, err)
	}
	return resp, nil
}

// prefetchWindow is how little TTL a FRESH cache answer may have left
// before its next hit triggers a background refresh (serve-stale §10.4,
// prefetch leg): names in active use are refreshed BEFORE they expire, so
// the answering path never leaves the cache for them.
const prefetchWindow = 60
