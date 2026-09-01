// certs_test.go — the Certificates page and its four mutations, against a
// fixture nginx tree (never the test box's own nginx) and a real keychain
// in a temp home.
package webui

import (
	"context"
	"encoding/base32"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/camalolo/freens/internal/admin"
	"github.com/camalolo/freens/internal/certmgr"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/keychain"
)

// tldB32For mirrors the display form pages use for store matching.
func tldB32For(t *testing.T, kp *crypto.Keypair) string {
	t.Helper()
	id, err := crypto.TldID(kp.Public())
	if err != nil {
		t.Fatal(err)
	}
	return strings.ToLower(strings.TrimRight(base32.StdEncoding.EncodeToString(id), "="))
}

// fixtureNginx points s.nginx at a synthetic config tree whose runner
// always succeeds and records nothing else — no real nginx is ever exec'd.
func fixtureNginx(t *testing.T, s *Server, serverName string) string {
	t.Helper()
	root := t.TempDir()
	conf := filepath.Join(root, "nginx.conf")
	content := "events { }\nhttp {\n  server {\n    listen 80;\n    server_name " + serverName + ";\n    root /var/www;\n  }\n}\n"
	if err := os.WriteFile(conf, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	s.nginx = &certmgr.NginxEnv{
		Binary:   "nginx",
		ConfPath: conf,
		Runner: func(ctx context.Context, name string, args ...string) (certmgr.ExecResult, error) {
			return certmgr.ExecResult{}, nil
		},
	}
	return conf
}

// postForm posts with the CSRF header and returns status + toast headers.
func (c *uclient) postForm(u string, form url.Values) (int, string, string) {
	c.t.Helper()
	req, err := http.NewRequest("POST", u, strings.NewReader(form.Encode()))
	if err != nil {
		c.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatalf("POST %s: %v", u, err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)
	// X-Toast is URL-escaped for the X-Toast header transport (app.js
	// unescapes before rendering); tests compare the plain text.
	toast, _ := url.QueryUnescape(resp.Header.Get("X-Toast"))
	return resp.StatusCode, toast, resp.Header.Get("X-Toast-Kind")
}

// certsTestEnv: temp-home server with a real plaintext owner key for
// "alice", the fake daemon answering the store with alice's sub-name, and
// the fixture nginx tree wired in.
type certsTestEnv struct {
	t       *testing.T
	s       *Server
	ts      *httptest.Server
	c       *uclient
	home    string
	keysDir string
	conf    string
}

func newCertsTestEnv(t *testing.T) *certsTestEnv {
	t.Helper()
	dir := t.TempDir()
	homeDir := filepath.Join(dir, "freens")
	keysDir := filepath.Join(homeDir, "keys")
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		t.Fatal(err)
	}
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := keychain.Save(keychain.OwnerKeyPath(keysDir, "alice"), kp, ""); err != nil {
		t.Fatal(err)
	}

	d := newFakeDaemon()
	d.mu.Lock()
	d.storeEntries = []admin.StoreEntry{{
		Key: "aabb", Labels: []string{"www"}, TldIDB32: tldB32For(t, kp), Alias: "alice",
		Sequence: 1, ExpiresIn: 3600,
	}}
	d.mu.Unlock()

	s, err := New(&Config{HomeDir: homeDir, Allow: "127.0.0.0/8"}, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	s.d = d
	env := &certsTestEnv{t: t, s: s, home: homeDir, keysDir: keysDir}
	env.conf = fixtureNginx(t, s, "www.alice")
	env.ts = httptest.NewServer(s.Handler())
	t.Cleanup(env.ts.Close)
	env.c = newUClient(t)
	env.c.bootstrap(env.ts.URL)
	return env
}

func TestCertsPageRendersNamesAndNginx(t *testing.T) {
	e := newCertsTestEnv(t)
	resp, err := e.c.http.Get(e.ts.URL + "/certs")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("GET /certs = %d", resp.StatusCode)
	}
	text := string(body)
	for _, want := range []string{"Certificates", "alice", "www.alice", "not issued", "nginx", "Renew all due"} {
		if !strings.Contains(text, want) {
			t.Errorf("page missing %q", want)
		}
	}
	if !strings.Contains(text, "www.alice</option>") {
		t.Errorf("the matching server block should offer www.alice preselected")
	}
}

func TestCertIssueThenRenewViaUI(t *testing.T) {
	e := newCertsTestEnv(t)

	// Issue + track.
	code, toast, kind := e.c.postForm(e.ts.URL+"/api/cert/issue", url.Values{"name": {"www.alice"}})
	if code != 200 || kind != "" {
		t.Fatalf("issue = %d kind=%q toast=%q", code, kind, toast)
	}
	if !strings.Contains(toast, "issued www.alice") {
		t.Fatalf("issue toast = %q", toast)
	}
	st, err := certmgr.LoadState(e.home, "www.alice")
	if err != nil {
		t.Fatalf("not tracked: %v", err)
	}
	if _, err := os.Stat(st.CertPath); err != nil {
		t.Fatalf("cert file missing: %v", err)
	}

	// Renew (forced — a fresh leaf is never due).
	code, toast, kind = e.c.postForm(e.ts.URL+"/api/cert/renew",
		url.Values{"name": {"www.alice"}, "force": {"true"}})
	if code != 200 || kind != "" {
		t.Fatalf("renew = %d kind=%q toast=%q", code, kind, toast)
	}
	if !strings.Contains(toast, "renewed www.alice") {
		t.Fatalf("renew toast = %q", toast)
	}

	// Bulk renew on an all-fresh table: the daily-timer no-op path.
	code, toast, kind = e.c.postForm(e.ts.URL+"/api/cert/renew", url.Values{"name": {"*"}})
	if code != 200 || kind != "" || !strings.Contains(toast, "nothing to renew") {
		t.Fatalf("bulk renew = %d kind=%q toast=%q", code, kind, toast)
	}
}

func TestCertEncryptedKeyAsksForPassphrase(t *testing.T) {
	e := newCertsTestEnv(t)
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := keychain.Save(keychain.OwnerKeyPath(e.keysDir, "vault"), kp, "sekret"); err != nil {
		t.Fatal(err)
	}

	code, toast, kind := e.c.postForm(e.ts.URL+"/api/cert/issue", url.Values{"name": {"vault"}})
	if code != 200 || kind != "error" {
		t.Fatalf("issue w/o passphrase = %d kind=%q toast=%q", code, kind, toast)
	}
	if !strings.Contains(toast, "passphrase") {
		t.Fatalf("toast should ask for the passphrase: %q", toast)
	}

	code, toast, kind = e.c.postForm(e.ts.URL+"/api/cert/issue",
		url.Values{"name": {"vault"}, "passphrase": {"sekret"}})
	if code != 200 || kind != "" {
		t.Fatalf("issue with passphrase = %d kind=%q toast=%q", code, kind, toast)
	}
	if _, err := certmgr.LoadState(e.home, "vault"); err != nil {
		t.Fatalf("encrypted-key issue did not track: %v", err)
	}
}

func TestCertNginxInstallViaUI(t *testing.T) {
	e := newCertsTestEnv(t)

	// No certificate yet: the install path issues one first (EnsureTracked).
	code, toast, kind := e.c.postForm(e.ts.URL+"/api/cert/nginx", url.Values{
		"name": {"www.alice"}, "server": {"www.alice"},
	})
	if code != 200 || kind != "" {
		t.Fatalf("nginx install = %d kind=%q toast=%q", code, kind, toast)
	}
	if !strings.Contains(toast, "nginx -t ok") {
		t.Fatalf("install toast = %q", toast)
	}
	b, err := os.ReadFile(e.conf)
	if err != nil {
		t.Fatal(err)
	}
	st, err := certmgr.LoadState(e.home, "www.alice")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "ssl_certificate "+st.CertPath+";") {
		t.Fatalf("config not edited:\n%s", b)
	}
	if _, err := os.Stat(e.conf + ".freens-pre"); err != nil {
		t.Fatalf("no backup: %v", err)
	}
	if len(st.NginxFiles) != 1 {
		t.Fatalf("deployment not tracked: %+v", st.NginxFiles)
	}

	// Second install: idempotent no-op toast.
	code, toast, kind = e.c.postForm(e.ts.URL+"/api/cert/nginx", url.Values{
		"name": {"www.alice"}, "server": {"www.alice"},
	})
	if code != 200 || kind != "" || !strings.Contains(toast, "already serves") {
		t.Fatalf("second install = %d kind=%q toast=%q", code, kind, toast)
	}
}

func TestCertNginxNoBlockToastsTheMiss(t *testing.T) {
	e := newCertsTestEnv(t)
	code, _, kind := e.c.postForm(e.ts.URL+"/api/cert/nginx", url.Values{
		"name": {"www.alice"}, "server": {"other.example"},
	})
	if code != 200 || kind != "error" {
		t.Fatalf("install to a missing block = %d kind=%q", code, kind)
	}
}

func TestCertNginxReloadViaUI(t *testing.T) {
	e := newCertsTestEnv(t)
	code, toast, kind := e.c.postForm(e.ts.URL+"/api/cert/nginx/reload", nil)
	if code != 200 || kind != "" {
		t.Fatalf("reload = %d kind=%q toast=%q", code, kind, toast)
	}
	if !strings.Contains(toast, "reloaded") {
		t.Fatalf("reload toast = %q", toast)
	}
}

func TestCertNginxCloneViaUI(t *testing.T) {
	e := newCertsTestEnv(t)
	// The base fixture's only block serves "www.alice" (an EDIT target);
	// the clone path needs no block matching the freens name at all, so
	// re-point the fixture at an unrelated server_name.
	conf2 := fixtureNginx(t, e.s, "unrelated.local")
	e.conf = conf2
	root := filepath.Dir(conf2)
	avail := filepath.Join(root, "sites-available")
	if err := os.MkdirAll(avail, 0o755); err != nil {
		t.Fatal(err)
	}
	enabled := filepath.Join(root, "sites-enabled")
	if err := os.MkdirAll(enabled, 0o755); err != nil {
		t.Fatal(err)
	}
	src := "server {\n  listen 443 ssl;\n  server_name shop.alice;\n  ssl_certificate /etc/le/shop.pem;\n  ssl_certificate_key /etc/le/shop.key;\n  root /var/www/shop;\n}\n"
	if err := os.WriteFile(filepath.Join(avail, "shop.alice"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../sites-available/shop.alice", filepath.Join(enabled, "shop.alice")); err != nil {
		t.Fatal(err)
	}

	code, toast, kind := e.c.postForm(e.ts.URL+"/api/cert/nginx", url.Values{
		"name": {"www.alice"}, "clone_source": {"shop.alice"},
	})
	if code != 200 || kind != "" {
		t.Fatalf("clone = %d kind=%q toast=%q", code, kind, toast)
	}
	if !strings.Contains(toast, "cloned") || !strings.Contains(toast, "shop.alice") {
		t.Fatalf("clone toast = %q", toast)
	}
	real := filepath.Join(avail, "freens-www.alice")
	b, err := os.ReadFile(real)
	if err != nil {
		t.Fatalf("clone file missing: %v", err)
	}
	text := string(b)
	st, err := certmgr.LoadState(e.home, "www.alice")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"server_name www.alice;",
		"ssl_certificate " + st.CertPath + ";",
		"root /var/www/shop;",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("clone missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "/etc/le/") {
		t.Fatalf("foreign cert leaked into the clone:\n%s", text)
	}
	// Source untouched.
	srcAfter, _ := os.ReadFile(filepath.Join(avail, "shop.alice"))
	if string(srcAfter) != src {
		t.Fatal("source vhost modified by the clone")
	}
	if len(st.NginxFiles) != 1 || st.NginxFiles[0] != real {
		t.Fatalf("renewal tracking = %v, want [%s]", st.NginxFiles, real)
	}
}
