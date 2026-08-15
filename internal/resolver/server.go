package resolver

// This file implements the §9.1 DNS server (UDP + TCP) on github.com/miekg/dns
// and a concrete Upstream that forwards to conventional recursive resolvers.

import (
	"context"
	"errors"
	"fmt"
	"net"
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
// dns.Server (no Server wrapper required). It builds a response Msg with the
// echoed question, the answer RRs from ResolveQuestion, and the matching
// rcode/AA flags.
func (r *Resolver) ServeDNS(w dns.ResponseWriter, m *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetReply(m)
	resp.RecursionAvailable = r.Upstream != nil || r.Freens != nil

	if len(m.Question) == 0 {
		resp.Rcode = dns.RcodeFormatError
		_ = w.WriteMsg(resp)
		return
	}

	q := m.Question[0]

	// §10.4: consult the response cache BEFORE resolving so a cached hit
	// never re-executes the lookup chain. Only freens-sourced outcomes are
	// ever stored (putFreens ignores aa == false), so DNS-forwarded answers
	// always reach the upstream.
	var ck cacheKey
	caching := r.Cache != nil
	if caching {
		ck = cacheKeyFor(q)
		if rrs, rcode, aa, ok := r.Cache.get(ck); ok {
			resp.Rcode = rcode
			resp.Answer = rrs
			resp.Authoritative = aa
			_ = w.WriteMsg(resp)
			return
		}
	}

	rrs, rcode, aa, err := r.ResolveQuestion(context.Background(), q)
	if err != nil {
		resp.Rcode = dns.RcodeServerFailure
		_ = w.WriteMsg(resp)
		return
	}
	resp.Rcode = rcode
	resp.Answer = rrs
	// AA reflects whether the FINAL answer was produced by the authoritative
	// freens source (returned by ResolveQuestion as `aa`). DNS-forwarded
	// answers and DENY are non-authoritative. Per RFC 1035 §4.1.1 the AA bit
	// is meaningful for any rcode that an authoritative server would emit
	// (including NXDOMAIN/NODATA), so we set it verbatim from the resolver.
	resp.Authoritative = aa
	if caching {
		r.Cache.putFreens(ck, rrs, rcode, aa)
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
}

// Forward implements Upstream. It tries each server in order; the first
// non-error, non-nil response wins. A truncated UDP response triggers a single
// TCP retry against the same server.
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
	var lastErr error
	for _, srv := range u.Servers {
		addr := ensureDNSPort(srv)
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
	if lastErr != nil {
		return nil, fmt.Errorf("resolver: all upstreams failed: %w", lastErr)
	}
	return nil, errors.New("resolver: all upstreams failed")
}

// exchangeWith wraps dns.Client.ExchangeContext so tests can substitute it.
func exchangeWith(ctx context.Context, q *dns.Msg, addr, network string, timeout time.Duration) (*dns.Msg, error) {
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
