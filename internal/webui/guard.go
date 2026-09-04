// guard.go — the network gate and middleware chain: CIDR allowlist, auth,
// and the CSRF header check for mutations. Ordered outermost-first:
//
//	gate(CIDR) → logging → auth → csrf(method≠GET) → handler
//
// Static assets and the health endpoint bypass auth (the login page needs
// the stylesheet; nothing there is sensitive).
package webui

import (
	"errors"
	"net"
	"net/http"
	"strings"
	"time"
)

var (
	errWeakPassword    = errors.New("password must be at least 8 characters")
	errBadLogin        = errors.New("wrong password")
	errNotBootstrapped = errors.New("no password set yet")
)

// gate rejects requests whose source IP is outside the allowlist with a
// plain 403 (no redirect, no session probing — the public side learns
// nothing beyond "there is a server").
func (s *Server) gate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.gateOpen {
			next.ServeHTTP(w, r)
			return
		}
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		ip := net.ParseIP(host)
		if ip == nil || !containsAny(s.allow, ip) {
			http.Error(w, "403 forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireAuth redirects anonymous browsers to /login (302 for navigations)
// and answers 401 for API-ish requests that carry the htmx header. In
// bootstrap state (no password yet) every page redirects to /bootstrap so
// the FIRST visit sets the admin password — nothing is browsable before
// that exists.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.auth.bootstrapped() {
			if strings.HasPrefix(r.URL.Path, "/bootstrap") || strings.HasPrefix(r.URL.Path, "/static") ||
				r.URL.Path == "/healthz" {
				next.ServeHTTP(w, r)
				return
			}
			http.Redirect(w, r, "/bootstrap", http.StatusSeeOther)
			return
		}
		if s.auth.validSession(sessionFromRequest(r)) {
			next.ServeHTTP(w, r)
			return
		}
		if r.Header.Get("HX-Request") == "true" || r.Header.Get("X-Requested-With") != "" {
			w.Header().Set("HX-Redirect", "/login")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})
}

// requireCSRF enforces the custom-header check on mutations. htmx stamps
// every request it issues with `HX-Request: true`; non-htmx AJAX callers
// conventionally send `X-Requested-With: XMLHttpRequest`. Either satisfies
// the gate — the CSRF property comes from the header being CUSTOM: a
// cross-site form post cannot set request headers at all, and a cross-site
// fetch/XHR cannot set them without a CORS approval this server never
// grants. (v0.15.2 fix: the gate used to demand X-Requested-With only,
// which htmx does NOT send — every real-browser mutation 400'd while the
// Go tests, which set the header by hand, stayed green.)
func requireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead &&
			r.Header.Get("X-Requested-With") != "XMLHttpRequest" &&
			r.Header.Get("HX-Request") == "" {
			http.Error(w, "missing CSRF header", http.StatusBadRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// logRequests is a compact one-line access log (Info level: this server has
// no CLI polling noise).
func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		s.log.Info("webui: request",
			"method", r.Method, "path", r.URL.Path, "remote", remoteIP(r),
			"dur", time.Since(start).Round(time.Microsecond))
	})
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
