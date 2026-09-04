// dns.go — the v0.14.0 DoH relay endpoints (spec §9.6):
//
//	POST /dns-query  raw DNS wire query in, wire response out. This is the
//	                 bridge the freens-web DoH face forwards to: the §9.2
//	                 resolver lives in the DAEMON process, and the webui
//	                 (which owns the only HTTPS listener) relays /dns-query
//	                 requests here over this socket.
//	POST /reload     re-read freens.conf and hot-apply what is safe to apply
//	                 without a restart (currently: the [upstream] forwarder
//	                 — plain or DoH — via the resolver's UpstreamRef).
//
// Both endpoints are OPTIONAL and 503 until the daemon wires them
// (SetDNSHandler / SetReloader) — the established SetTLSProvider idiom, so
// old daemons simply answer 503 and the webui degrades gracefully.
package admin

import (
	"context"
	"io"
	"net/http"
)

// maxDNSQueryBytes caps a /dns-query body. Mirrors resolver.maxDoHQueryBytes
// (the same RFC 8484 §4.1 headroom rule) without importing the resolver
// package: the handler is transport plumbing, its cap is a local constant.
const maxDNSQueryBytes = 64 << 10

// SetDNSHandler wires the wire-DNS relay (fn nil ⇒ /dns-query answers 503).
// Mutex-guarded: the daemon wires it after the serve goroutine is already
// answering /status (the resolver is built later in main than the admin
// server).
func (s *Server) SetDNSHandler(fn func(ctx context.Context, query []byte) ([]byte, error)) {
	s.mu.Lock()
	s.dnsResolve = fn
	s.mu.Unlock()
}

// dnsHandler returns the wired relay (or nil).
func (s *Server) dnsHandler() func(ctx context.Context, query []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dnsResolve
}

// SetReloader wires the config hot-reload (fn nil ⇒ /reload answers 503).
// The returned string is a human summary of what was applied.
func (s *Server) SetReloader(fn func() (string, error)) {
	s.mu.Lock()
	s.reloadConf = fn
	s.mu.Unlock()
}

// SetAllowReserved mirrors the daemon's §7.7 override flag into the admin
// face (naming/reserved.go): with it off (the default), the claim hop of
// /resolve and its helpers treats a reserved-TLD alias (com, localhost, …)
// as claim-less — "a node running without -allow-reserved never accepts a
// freens .com" holds on the admin endpoints too, not just the DNS face.
func (s *Server) SetAllowReserved(b bool) {
	s.mu.Lock()
	s.allowReserved = b
	s.mu.Unlock()
}

// allowReservedEnabled reports the §7.7 override state.
func (s *Server) allowReservedEnabled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.allowReserved
}

// reloader returns the wired reloader (or nil).
func (s *Server) reloader() func() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reloadConf
}

// handleDNSQuery relays one raw DNS wire query to the daemon's resolver.
// Binary in, binary out — the only admin endpoint that is NOT JSON (the
// payload is exactly what an RFC 8484 request body would carry).
func (s *Server) handleDNSQuery(w http.ResponseWriter, r *http.Request) {
	fn := s.dnsHandler()
	if fn == nil {
		writeErr(w, http.StatusServiceUnavailable, "dns resolver unavailable")
		return
	}
	if ct := r.Header.Get("Content-Type"); ct != "application/dns-message" {
		writeErr(w, http.StatusUnsupportedMediaType, "content type must be application/dns-message")
		return
	}
	payload, err := io.ReadAll(io.LimitReader(r.Body, maxDNSQueryBytes+1))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read error: "+err.Error())
		return
	}
	if len(payload) > maxDNSQueryBytes {
		writeErr(w, http.StatusRequestEntityTooLarge, "query too large")
		return
	}
	_ = r.Body.Close()
	ctx, cancel := capped(r)
	defer cancel()
	resp, err := fn(ctx, payload)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "dns resolve failed: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp)
}

// handleReload asks the daemon to re-read its config file and apply the
// hot-swappable parts. The response names what changed; the error text is
// the config problem when the re-read itself failed.
func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	fn := s.reloader()
	if fn == nil {
		writeErr(w, http.StatusServiceUnavailable, "reload not available")
		return
	}
	_ = r.Body.Close()
	msg, err := fn()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.log.Info("admin: config reloaded", "applied", msg)
	writeJSON(w, http.StatusOK, map[string]string{"reloaded": msg})
}
