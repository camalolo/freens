// doh_webui_test.go — the §9.6 serve face and Settings surface:
// /dns-query gating (off ⇒ 404, on ⇒ relay through a REAL admin server),
// the root-CA download, and the settings mutation's config round-trip.
package webui

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/admin"
	"github.com/camalolo/freens/internal/confedit"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/keychain"
	"github.com/miekg/dns"
)

// newDohFixture: a webui Server over a temp home, wired to a REAL admin
// server whose DNS handler answers a canned A record. Gated to loopback so
// httptest requests pass.
func newDohFixture(t *testing.T) (*Server, *httptest.Server, string) {
	t.Helper()
	dir := t.TempDir()
	homeDirPath := filepath.Join(dir, "freens")
	if err := mkdirAll(filepath.Join(homeDirPath, "keys"), 0o700); err != nil {
		t.Fatal(err)
	}

	// The "daemon": an admin server with a canned resolver.
	asrv := admin.New(nil, nil, "v-test", slog.Default())
	asrv.SetDNSHandler(func(ctx context.Context, query []byte) ([]byte, error) {
		q := new(dns.Msg)
		if err := q.Unpack(query); err != nil {
			return nil, err
		}
		resp := new(dns.Msg)
		resp.SetReply(q)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120},
			A:   []byte{203, 0, 113, 5},
		})
		return resp.Pack()
	})
	sock := filepath.Join(dir, "admin.sock")
	done := make(chan error, 1)
	go func() { done <- asrv.ListenAndServe(sock) }()
	t.Cleanup(func() { _ = asrv.Close() })
	deadline := time.Now().Add(5 * time.Second)
	for !admin.Alive(sock) {
		if time.Now().After(deadline) {
			t.Fatal("admin server did not come up")
		}
		time.Sleep(10 * time.Millisecond)
	}

	s, err := New(&Config{HomeDir: homeDirPath, Allow: "127.0.0.0/8"}, sock, nil)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, ts, homeDirPath
}

// seedKeychain stores a plaintext owner key for alias (TLS/CA derivation).
func seedKeychain(t *testing.T, keysDir, alias string) {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := keychain.Save(keychain.OwnerKeyPath(keysDir, alias), kp, ""); err != nil {
		t.Fatal(err)
	}
}

func TestDoHQueryOffByDefault(t *testing.T) {
	_, ts, _ := newDohFixture(t)
	resp, err := http.Get(ts.URL + "/dns-query?dns=AAAA")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("serve off: GET /dns-query = %d, want 404 (bare, like any disabled path)", resp.StatusCode)
	}
}

func TestDoHQueryRelayWhenOn(t *testing.T) {
	s, ts, homeDirPath := newDohFixture(t)

	// Flip serve on exactly the way the CLI would.
	if err := confedit.Set(s.confPath(), "doh", "serve", "true"); err != nil {
		t.Fatal(err)
	}
	s.invalidateDohState()

	// GET with a base64url-encoded query for example.com A.
	q := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
	packed, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get(ts.URL + "/dns-query?dns=" + base64URLQuery(packed))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/dns-message" {
		t.Errorf("content type = %q", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	answer := new(dns.Msg)
	if err := answer.Unpack(body); err != nil {
		t.Fatalf("reply is not a DNS message: %v", err)
	}
	if len(answer.Answer) != 1 || answer.Answer[0].String() == "" {
		t.Errorf("answers = %d, want the canned relay answer", len(answer.Answer))
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "max-age=120" {
		t.Errorf("Cache-Control = %q, want max-age=120", cc)
	}
	_ = homeDirPath
}

// TestDoHQuery404IsCheapAndStable: a second query after the cache has
// warmed still reflects serve-on, and flipping serve off (cache invalidated)
// turns the endpoint back off without a restart.
func TestDoHQueryToggleWithoutRestart(t *testing.T) {
	s, _, _ := newDohFixture(t)
	if err := confedit.Set(s.confPath(), "doh", "serve", "true"); err != nil {
		t.Fatal(err)
	}
	s.invalidateDohState()
	if _, serve := s.dohState(); !serve {
		t.Fatal("serve should be on")
	}
	if err := confedit.Set(s.confPath(), "doh", "serve", "false"); err != nil {
		t.Fatal(err)
	}
	s.invalidateDohState()
	if _, serve := s.dohState(); serve {
		t.Fatal("serve should be off")
	}
}

func TestDoHRootPEM(t *testing.T) {
	_, ts, homeDirPath := newDohFixture(t)

	// No keychain yet → 404 with the explanation.
	resp, err := http.Get(ts.URL + "/api/doh/root.pem")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("no keychain: status = %d, want 404", resp.StatusCode)
	}

	seedKeychain(t, filepath.Join(homeDirPath, "keys"), "camalolo")
	resp, err = http.Get(ts.URL + "/api/doh/root.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "BEGIN CERTIFICATE") {
		t.Errorf("root.pem is not a PEM certificate:\n%.80s", body)
	}
}

func TestSettingsMutationWritesConf(t *testing.T) {
	s, ts, homeDirPath := newDohFixture(t)
	seedKeychain(t, filepath.Join(homeDirPath, "keys"), "camalolo")

	// Bootstrap an admin session like a browser would.
	c := newUClient(t)
	c.bootstrap(ts.URL)

	form := url.Values{
		"upstream_mode": {"quad9"},
		"serve":         {"on"},
	}
	if code := c.post(ts.URL+"/api/settings/doh", form, true); code != http.StatusOK {
		t.Fatalf("mutation = %d", code)
	}

	up, hasUp, err := confedit.Get(s.confPath(), "upstream", "doh")
	if err != nil || !hasUp || up != "https://9.9.9.9/dns-query" {
		t.Fatalf("upstream conf = %q %v %v", up, hasUp, err)
	}
	serve, _, err := confedit.Get(s.confPath(), "doh", "serve")
	if err != nil || serve != "true" {
		t.Fatalf("serve conf = %q %v", serve, err)
	}

	// The page reflects the new state.
	pageCode, body := getBody(t, c, ts.URL+"/settings")
	if pageCode != http.StatusOK {
		t.Fatalf("settings page = %d", pageCode)
	}
	if !strings.Contains(body, "https://9.9.9.9/dns-query") {
		t.Error("settings page does not show the upstream URL")
	}
	if !strings.Contains(body, "checked") {
		t.Error("settings page does not show serve checked")
	}
}

func TestDoHTestButton(t *testing.T) {
	s, ts, homeDirPath := newDohFixture(t)
	seedKeychain(t, filepath.Join(homeDirPath, "keys"), "camalolo")
	// Serve on + a name: the full loopback HTTPS path is exercised live
	// on the fleet; here the plain fallback path (no TLS listener in the
	// fixture) must at least reach the relay.
	if err := confedit.Set(s.confPath(), "doh", "serve", "true"); err != nil {
		t.Fatal(err)
	}
	s.invalidateDohState()

	c := newUClient(t)
	c.bootstrap(ts.URL)
	code := c.post(ts.URL+"/api/doh/test", url.Values{"name": {"example.com"}}, true)
	if code != http.StatusOK {
		t.Fatalf("test mutation = %d", code)
	}
}

func TestSettingsPageRendersWhenOff(t *testing.T) {
	_, ts, _ := newDohFixture(t)
	c := newUClient(t)
	c.bootstrap(ts.URL)
	code, body := getBody(t, c, ts.URL+"/settings")
	if code != http.StatusOK {
		t.Fatalf("settings = %d", code)
	}
	if !strings.Contains(body, "Encrypted upstream") {
		t.Error("page missing the upstream control")
	}
	// A keychain-less box: no client URL, and the register hint instead.
	if !strings.Contains(body, "No keychain name yet") {
		t.Error("page should explain the missing name")
	}
}

// getBody is uclient.get plus the body text (the auth pages' GET only
// returns a status).
func getBody(t *testing.T, c *uclient, u string) (int, string) {
	t.Helper()
	resp, err := c.http.Get(u)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(b)
}
