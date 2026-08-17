// webui_test.go — the UI's own security and behavior tests: gate, auth
// bootstrap/login/lockout, CSRF, and page rendering against a fake daemon;
// the ops engine is integration-tested with a REAL admin server in
// webui_ops_test.go.
package webui

import (
	"context"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/camalolo/freens/internal/admin"
	"github.com/camalolo/freens/internal/dht"
	"github.com/camalolo/freens/internal/wire"
)

// fakeDaemon answers everything the pages ask, deterministically.
type fakeDaemon struct {
	mu      sync.Mutex
	status  admin.Status
	resolve map[string]*admin.Resolved
	get     map[string]*wire.SignedEnvelope
	pubs    []*wire.SignedEnvelope
	witness int
	failOn  string // method name to fail ("Resolve", "Store", …)
}

func newFakeDaemon() *fakeDaemon {
	return &fakeDaemon{
		status: admin.Status{Running: true, Version: "v-test", NodeID: "aa11", Peers: 3, StoreEnvs: 4},
		resolve: map[string]*admin.Resolved{
			"alice": {Found: true, Name: "alice", Sequence: 2, Owner: "abcd",
				RRset: []admin.RR{{Type: 1, TTL: 300, Text: "203.0.113.10"}}},
			"revoked": {Found: false, Revoked: true, Name: "revoked"},
		},
		get:     map[string]*wire.SignedEnvelope{},
		witness: 6,
	}
}

func (f *fakeDaemon) fail(method string) error {
	if f.failOn == method {
		return context.DeadlineExceeded
	}
	return nil
}

func (f *fakeDaemon) Status(ctx context.Context) (*admin.Status, error) {
	if err := f.fail("Status"); err != nil {
		return nil, err
	}
	s := f.status
	return &s, nil
}

func (f *fakeDaemon) Peers(ctx context.Context) ([]dht.Peer, error) {
	return []dht.Peer{{Addr: "10.0.0.2:15353", PublicKey: []byte{1}, Confirmed: 1700000000}}, nil
}

func (f *fakeDaemon) Resolve(ctx context.Context, name string) (*admin.Resolved, error) {
	if err := f.fail("Resolve"); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if r, ok := f.resolve[name]; ok {
		return r, nil
	}
	return &admin.Resolved{Found: false}, nil
}

func (f *fakeDaemon) Publish(ctx context.Context, env *wire.SignedEnvelope) (int, error) {
	f.mu.Lock()
	f.pubs = append(f.pubs, env)
	f.mu.Unlock()
	return 1, nil
}

func (f *fakeDaemon) PublishClaim(ctx context.Context, env *wire.SignedEnvelope) error {
	_, err := f.Publish(ctx, env)
	return err
}

func (f *fakeDaemon) Get(ctx context.Context, key []byte) (*wire.SignedEnvelope, error) {
	return f.get[string(key)], nil
}

func (f *fakeDaemon) Witness(ctx context.Context, alias string, tldID, claimant []byte, ts uint64, nonce, powHash []byte) ([][]byte, error) {
	return nil, nil // overridden where needed
}

func (f *fakeDaemon) Store(ctx context.Context) (*admin.StoreResponse, error) {
	if err := f.fail("Store"); err != nil {
		return nil, err
	}
	return &admin.StoreResponse{Count: 1, Entries: []admin.StoreEntry{{
		Key: "aabb", Labels: []string{"www"}, TldIDB32: "tld", Alias: "alice",
		Sequence: 1, ExpiresIn: 3600, Claim: true, RRs: []admin.RR{{Type: 1, Text: "203.0.113.7"}},
	}}}, nil
}

func (f *fakeDaemon) Difficulty(ctx context.Context) (*admin.Difficulty, error) {
	return &admin.Difficulty{Difficulty: 24, WitnessQuorum: 5, WitnessSet: 8, RetargetBlock: 2016}, nil
}

// newTestServer builds a Server with the fake daemon, a loopback-only gate,
// and a temp home; returns the Server and a live httptest server.
func newTestServer(t *testing.T, d Daemon) (*Server, *httptest.Server) {
	t.Helper()
	dir := t.TempDir()
	homeDirPath := filepath.Join(dir, "freens")
	if err := os.MkdirAll(filepath.Join(homeDirPath, "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	s, err := New(&Config{HomeDir: homeDirPath, Allow: "127.0.0.0/8"}, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if d != nil {
		s.d = d
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, ts
}

// uclient is a browser-ish client: real cookie jar, optional CSRF header.
type uclient struct {
	t    *testing.T
	http *http.Client
	csrf bool
}

func newUClient(t *testing.T) *uclient {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &uclient{t: t, http: &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse // observe redirects as 303s
	}}}
}

func (c *uclient) get(u string) int {
	resp, err := c.http.Get(u)
	if err != nil {
		c.t.Fatalf("GET %s: %v", u, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func (c *uclient) post(u string, form url.Values, withCSRF bool) int {
	req, err := http.NewRequest("POST", u, strings.NewReader(form.Encode()))
	if err != nil {
		c.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if withCSRF {
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatalf("POST %s: %v", u, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// bootstrapAndPassword: fresh client goes through /bootstrap.
func (c *uclient) bootstrap(u string) {
	if code := c.post(u+"/bootstrap", url.Values{
		"password": {"hunter2x"}, "password2": {"hunter2x"},
	}, false); code != 303 {
		c.t.Fatalf("bootstrap = %d, want 303", code)
	}
}

func TestAuthFlow(t *testing.T) {
	_, ts := newTestServer(t, newFakeDaemon())
	c := newUClient(t)

	// Anonymous: redirected to the login flow.
	if code := c.get(ts.URL + "/"); code != 303 {
		t.Errorf("anonymous / = %d, want 303", code)
	}

	// Bootstrap sets the password and signs in.
	c.bootstrap(ts.URL)
	if code := c.get(ts.URL + "/"); code != 200 {
		t.Errorf("post-bootstrap / = %d, want 200", code)
	}

	// A second bootstrap now redirects to login (password already set).
	if code := c.post(ts.URL+"/bootstrap", url.Values{
		"password": {"other1234"}, "password2": {"other1234"},
	}, false); code != 303 {
		t.Errorf("re-bootstrap = %d, want 303", code)
	}

	// Wrong password does not authenticate.
	if code := c.post(ts.URL+"/login", url.Values{"password": {"nope"}}, false); code != 303 {
		t.Errorf("wrong login = %d, want 303", code)
	}
}

func TestLoginLockout(t *testing.T) {
	s, ts := newTestServer(t, newFakeDaemon())
	if err := s.auth.setPassword("correct horse"); err != nil {
		t.Fatal(err)
	}
	c := newUClient(t)
	for i := 0; i < maxLoginFails; i++ {
		if code := c.post(ts.URL+"/login", url.Values{"password": {"wrong"}}, false); code != 303 {
			t.Fatalf("wrong login %d = %d", i, code)
		}
	}
	if !s.auth.lockedOut("127.0.0.1") {
		t.Fatal("5 failures should lock the source IP")
	}
	// The correct password is refused while locked.
	if code := c.post(ts.URL+"/login", url.Values{"password": {"correct horse"}}, false); code != 303 {
		t.Fatal("locked login must still redirect")
	}
	if code := c.get(ts.URL + "/"); code != 303 {
		t.Errorf("locked IP got authenticated access: %d", code)
	}
}

func TestGateBlocksOutsideCIDR(t *testing.T) {
	dir := t.TempDir()
	s, err := New(&Config{HomeDir: dir, Allow: "192.168.1.0/24"}, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	req := httptest.NewRequest("GET", "http://x/", nil)
	req.RemoteAddr = "8.8.8.8:1234"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("outside CIDR = %d, want 403", w.Code)
	}
	req2 := httptest.NewRequest("GET", "http://x/", nil)
	req2.RemoteAddr = "192.168.1.9:4444"
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, req2)
	if w2.Code == http.StatusForbidden {
		t.Error("inside CIDR must not be 403")
	}
}

func TestCSRFHeaderRequiredOnMutations(t *testing.T) {
	_, ts := newTestServer(t, newFakeDaemon())
	c := newUClient(t)
	c.bootstrap(ts.URL)
	// Without the header: 400. With it: passes CSRF (may 4xx on validation
	// after, but NOT 400-missing-CSRF).
	code := c.post(ts.URL+"/api/renew", url.Values{"name": {"alice"}}, false)
	if code != http.StatusBadRequest {
		t.Errorf("mutation without CSRF header = %d, want 400", code)
	}
	code2 := c.post(ts.URL+"/api/renew", url.Values{"name": {"alice"}}, true)
	if code2 == http.StatusBadRequest {
		t.Errorf("mutation WITH header still 400 (CSRF check too strict?)")
	}
}

func TestPagesRender(t *testing.T) {
	f := newFakeDaemon()
	_, ts := newTestServer(t, f)
	c := newUClient(t)
	c.bootstrap(ts.URL)
	for _, path := range []string{"/", "/names", "/register", "/store", "/lookup", "/network", "/keys", "/login"} {
		if code := c.get(ts.URL + path); code != 200 {
			t.Errorf("GET %s = %d, want 200", path, code)
		}
	}
	// Daemon-down resilience: every page still renders.
	f2 := newFakeDaemon()
	f2.failOn = "Status"
	_, ts2 := newTestServer(t, f2)
	c2 := newUClient(t)
	c2.bootstrap(ts2.URL)
	for _, path := range []string{"/", "/names", "/store", "/network"} {
		if code := c2.get(ts2.URL + path); code != 200 {
			t.Errorf("daemon-down GET %s = %d, want 200", path, code)
		}
	}
}

func TestStaticServed(t *testing.T) {
	_, ts := newTestServer(t, newFakeDaemon())
	c := newUClient(t) // static needs no session
	for _, path := range []string{"/static/app.css", "/static/htmx.min.js", "/healthz"} {
		if code := c.get(ts.URL + path); code != 200 {
			t.Errorf("GET %s = %d, want 200", path, code)
		}
	}
}

func TestAutoAllowlistSkipsWAN(t *testing.T) {
	nets, err := AutoAllowlists()
	if err != nil {
		t.Fatal(err)
	}
	// Loopback is always present; a public IP is never admitted.
	if !containsAny(nets, ipMust("127.0.0.1")) {
		t.Error("loopback not allowed")
	}
	if containsAny(nets, ipMust("8.8.8.8")) {
		t.Error("a public IP fell into the auto-allowlist")
	}
}

func ipMust(s string) net.IP {
	return net.ParseIP(s)
}

// TestLoginPageNoRedirectLoop is the live "too many redirects" regression
// (v0.6.2): GET /login must never require a session — with a password set
// it renders the form; without one it redirects ONCE to /bootstrap.
func TestLoginPageNoRedirectLoop(t *testing.T) {
	s, ts := newTestServer(t, newFakeDaemon())
	c := newUClient(t)

	// No password yet: /login → single 303 to /bootstrap (which renders).
	if code := c.get(ts.URL + "/login"); code != 303 {
		t.Errorf("GET /login before bootstrap = %d, want 303 (to /bootstrap)", code)
	}

	// Password set, no session: /login must RENDER (200) — previously this
	// redirected to itself forever.
	if err := s.auth.setPassword("somepass123"); err != nil {
		t.Fatal(err)
	}
	if code := c.get(ts.URL + "/login"); code != 200 {
		t.Errorf("GET /login without a session = %d, want 200 (was a redirect loop)", code)
	}
	// And /bootstrap now bounces ONCE to /login (which renders).
	if code := c.get(ts.URL + "/bootstrap"); code != 303 {
		t.Errorf("GET /bootstrap after bootstrap = %d, want 303 (to /login)", code)
	}
}
