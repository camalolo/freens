// hardening_test.go — regressions for the 2026-09-13 hardening pass:
// the sameSite guard on the pre-session auth POSTs (/login, /bootstrap),
// the Secure session-cookie flag under the mixed-dialect TLS listener, and
// the plaintext redirect face's gate + Host validation.
package webui

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newHardeningServer builds a gated server (loopback /8) whose admin
// password is already set, plus its full wrapped Handler.
func newHardeningServer(t *testing.T) (*Server, http.Handler) {
	t.Helper()
	dir := t.TempDir()
	home := filepath.Join(dir, "freens")
	if err := os.MkdirAll(filepath.Join(home, "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	s, err := New(&Config{HomeDir: home, Allow: "127.0.0.0/8"}, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.auth.setPassword("correct horse"); err != nil {
		t.Fatal(err)
	}
	return s, s.Handler()
}

// TestSameSiteGuardBlocksCrossSiteAuthPosts: the auth POSTs run before any
// session (and therefore before requireCSRF), so they carry the
// Origin/Sec-Fetch-Site check instead. A cross-site form post — the
// bootstrap-password-planting attack — must be refused.
func TestSameSiteGuardBlocksCrossSiteAuthPosts(t *testing.T) {
	s, h := newHardeningServer(t)

	post := func(path, secFetchSite, origin string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "http://x"+path,
			strings.NewReader(url.Values{"password": {"whatever"}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "127.0.0.1:1111"
		if secFetchSite != "" {
			req.Header.Set("Sec-Fetch-Site", secFetchSite)
		}
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}

	// Cross-site by Fetch Metadata — refused even with a matching Origin.
	for _, path := range []string{"/login", "/bootstrap"} {
		if w := post(path, "cross-site", "http://x"); w.Code != http.StatusForbidden {
			t.Errorf("%s with Sec-Fetch-Site: cross-site = %d, want 403", path, w.Code)
		}
		// A same-site (sibling-origin) post is refused too: this UI's forms
		// are same-origin by construction.
		if w := post(path, "same-site", "http://x"); w.Code != http.StatusForbidden {
			t.Errorf("%s with Sec-Fetch-Site: same-site = %d, want 403", path, w.Code)
		}
	}

	// No metadata: a mismatching Origin is refused...
	if w := post("/bootstrap", "", "http://evil.example"); w.Code != http.StatusForbidden {
		t.Errorf("/bootstrap with foreign Origin = %d, want 403", w.Code)
	}
	// ...and a malformed one too.
	if w := post("/bootstrap", "", "http://x\\@evil"); w.Code != http.StatusForbidden {
		t.Errorf("/bootstrap with malformed Origin = %d, want 403", w.Code)
	}

	// Same-origin metadata or a matching Origin both still log in cleanly
	// (the correct password redirects to /).
	for _, hdrs := range [][2]string{
		{"Sec-Fetch-Site", "same-origin"},
		{"Origin", "http://x"},
	} {
		req := httptest.NewRequest("POST", "http://x/login",
			strings.NewReader(url.Values{"password": {"correct horse"}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set(hdrs[0], hdrs[1])
		req.RemoteAddr = "127.0.0.1:1111"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
			t.Errorf("login with %s=%s = %d %q, want 303 /",
				hdrs[0], hdrs[1], w.Code, w.Header().Get("Location"))
		}
	}

	// Non-browser clients (curl, scripts, tests): no metadata, no Origin —
	// still allowed. A wrong password giving the normal 303 redirect
	// (not 403) proves the guard passed the request through.
	req := httptest.NewRequest("POST", "http://x/login",
		strings.NewReader(url.Values{"password": {"wrong"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "127.0.0.1:1111"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), "err=") {
		t.Errorf("headerless (curl-style) login = %d %q, want the normal error redirect",
			w.Code, w.Header().Get("Location"))
	}

	_ = s // password pre-set above
}

// TestSessionCookieSecureWhenTLSActive: under the mixed-dialect listener the
// session cookie must carry Secure so it never rides the plaintext 308 face
// (HSTS only protects after the first plaintext response). Plain-HTTP
// installs keep a working cookie.
func TestSessionCookieSecureWhenTLSActive(t *testing.T) {
	s, _ := newHardeningServer(t)

	login := func(secure bool) *httptest.ResponseRecorder {
		s.tlsActive.Store(secure)
		req := httptest.NewRequest("POST", "http://x/login",
			strings.NewReader(url.Values{"password": {"correct horse"}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.RemoteAddr = "127.0.0.1:1111"
		w := httptest.NewRecorder()
		s.handleLoginPost(w, req)
		return w
	}

	cookies := func(w *httptest.ResponseRecorder) string {
		for _, c := range w.Result().Cookies() {
			if c.Name == sessionCookie {
				return c.Raw
			}
		}
		return ""
	}

	if raw := cookies(login(true)); raw == "" || !strings.Contains(strings.ToLower(raw), "secure") {
		t.Errorf("TLS-active login Set-Cookie = %q, want the Secure attribute", raw)
	}
	if raw := cookies(login(false)); raw == "" || strings.Contains(strings.ToLower(raw), "secure") {
		t.Errorf("plain-HTTP login Set-Cookie = %q, want NO Secure attribute (plain installs must keep working)", raw)
	}
}

// TestRedirectToTLSPinsAndValidatesHost: the redirect rebuilds its target
// from a strictly validated host (and preserves the port), refusing Host
// headers that could smuggle content into the Location header.
func TestRedirectToTLSPinsAndValidatesHost(t *testing.T) {
	s, _ := newHardeningServer(t)

	req := func(host string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "http://listener/name", nil)
		r.Host = host
		r.RemoteAddr = "127.0.0.1:1111" // inside the gate: reach the handler
		w := httptest.NewRecorder()
		s.redirectToTLS(w, r)
		return w
	}

	if w := req("camalolo.example"); w.Code != http.StatusPermanentRedirect ||
		w.Header().Get("Location") != "https://camalolo.example/name" {
		t.Errorf("plain host = %d %q", w.Code, w.Header().Get("Location"))
	}
	if w := req("camalolo.example:8090"); w.Code != http.StatusPermanentRedirect ||
		w.Header().Get("Location") != "https://camalolo.example:8090/name" {
		t.Errorf("host:port = %d %q", w.Code, w.Header().Get("Location"))
	}
	if w := req("192.168.1.16"); w.Code != http.StatusPermanentRedirect ||
		w.Header().Get("Location") != "https://192.168.1.16/name" {
		t.Errorf("literal IP = %d %q", w.Code, w.Header().Get("Location"))
	}

	for _, bad := range []string{
		"",              // empty
		"bad host",      // space: header-smuggling classic
		"user@evil.com", // userinfo
		"evil.com/x",    // path
		"evil.com:80:90",
		"n@..evil:1",
	} {
		if w := req(bad); w.Code != http.StatusBadRequest {
			t.Errorf("Host %q = %d, want 400", bad, w.Code)
		}
	}
}

// TestPlaintextFaceBehindGate: the plaintext redirect server must sit behind
// the SAME CIDR gate as the mux — pre-fix a WAN-reachable box answered
// internet scanners with a redirect + fingerprint instead of a 403.
func TestPlaintextFaceBehindGate(t *testing.T) {
	s, _ := newHardeningServer(t)
	h := s.gate(http.HandlerFunc(s.redirectToTLS))

	req := func(remote, host string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "http://listener/", nil)
		r.Host = host
		r.RemoteAddr = remote
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	if w := req("8.8.8.8:4444", "camalolo.example"); w.Code != http.StatusForbidden {
		t.Errorf("off-allowlist plaintext request = %d, want 403", w.Code)
	}
	if w := req("127.0.0.1:9999", "camalolo.example"); w.Code != http.StatusPermanentRedirect {
		t.Errorf("on-allowlist plaintext request = %d, want the 308 redirect", w.Code)
	}
}
