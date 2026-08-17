// security_fixes_test.go — regressions for the v0.6.x security-audit
// fixes: the bootstrap check-and-set race (F1), prefix-keyed login lockout
// (F2), the mandatory register passphrase (F3), and the daemon Status
// cache (F4). Server-level tests reuse the fake-daemon fixture from
// webui_test.go; the register rejection needs no daemon at all (it fires
// before any I/O); the cache test runs a one-endpoint fake admin server
// on a unix socket so round trips can be counted.
package webui

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/admin"
	"github.com/camalolo/freens/internal/keychain"
)

// locClient is a browser-ish client that does NOT follow redirects and
// reports the Location it would have gone to (the handlers speak 303 +
// Location, so the target is the assertion surface).
type locClient struct {
	t *testing.T
	c *http.Client
}

func newLocClient(t *testing.T) *locClient {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &locClient{t: t, c: &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}}
}

func (l *locClient) post(u string, form url.Values) (int, string) {
	resp, err := l.c.PostForm(u, form)
	if err != nil {
		l.t.Fatalf("POST %s: %v", u, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("Location")
}

func (l *locClient) get(u string) (int, string) {
	resp, err := l.c.Get(u)
	if err != nil {
		l.t.Fatalf("GET %s: %v", u, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("Location")
}

// TestBootstrapConcurrentSingleWinner: N simultaneous POST /bootstrap on a
// fresh auth store — the bootMu check-and-set (F1) must let exactly ONE
// win; every loser takes the /login redirect, and only the winner's
// password authenticates afterwards.
func TestBootstrapConcurrentSingleWinner(t *testing.T) {
	s, ts := newTestServer(t, newFakeDaemon()) // fresh auth: no hash file
	const n = 8
	pws := make([]string, n)
	for i := range pws {
		pws[i] = fmt.Sprintf("racer-%d-secret", i)
	}
	locations := make([]string, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			lc := newLocClient(t)
			<-start // fire all POSTs at once
			_, loc := lc.post(ts.URL+"/bootstrap", url.Values{
				"password": {pws[i]}, "password2": {pws[i]},
			})
			locations[i] = loc
		}(i)
	}
	close(start)
	wg.Wait()

	winner := -1
	for i, loc := range locations {
		switch loc {
		case "/":
			if winner >= 0 {
				t.Fatalf("two bootstraps won (%d and %d) — check-and-set not atomic", winner, i)
			}
			winner = i
		case "/login":
			// loser: same redirect a sequential second POST gets
		default:
			t.Errorf("goroutine %d: Location = %q, want \"/\" or \"/login\"", i, loc)
		}
	}
	if winner < 0 {
		t.Fatal("no bootstrap winner among the concurrent POSTs")
	}
	if !s.auth.bootstrapped() {
		t.Fatal("no admin password exists after the race")
	}

	// The winner's password is THE admin password: login succeeds and the
	// minted session renders the dashboard. Run this before the loser
	// checks — failures and successes share one /24 bucket since F2, and
	// the n-1 loser probes below would lock it out.
	lc := newLocClient(t)
	if code, loc := lc.post(ts.URL+"/login", url.Values{"password": {pws[winner]}}); code != 303 || loc != "/" {
		t.Errorf("winner login = %d %q, want 303 \"/\"", code, loc)
	}
	if code, _ := lc.get(ts.URL + "/"); code != 200 {
		t.Errorf("winner session GET / = %d, want 200", code)
	}
	// No loser's password may authenticate (checked against the store so
	// the /24 lockout cannot mask a second winner).
	for i, pw := range pws {
		if i == winner {
			continue
		}
		if _, err := s.auth.checkPassword("127.0.0.1", pw); err == nil {
			t.Errorf("loser password %d authenticated — bootstrap crowned two admins", i)
		}
	}
}

// TestLoginLockoutCountsByPrefix: 5 failures from one IPv4 lock the whole
// /24 (a sibling address in it is refused), while a client in a DIFFERENT
// allowed /24 keeps a clean bucket (F2).
func TestLoginLockoutCountsByPrefix(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "freens")
	if err := os.MkdirAll(filepath.Join(home, "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	// The gate admits both loopback /8 and 192.168.5.0/24 so the sibling
	// in another /24 is a legal client whose lock state we can probe.
	s, err := New(&Config{HomeDir: home, Allow: "127.0.0.0/8,192.168.5.0/24"}, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.auth.setPassword("correct horse"); err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	login := func(remote, pw string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "http://x/login",
			strings.NewReader(url.Values{"password": {pw}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = remote // the gate + lockout read this
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}

	// Burn the counter from 127.0.0.5 only.
	for i := 0; i < maxLoginFails; i++ {
		if w := login("127.0.0.5:1234", "wrong"); w.Code != 303 {
			t.Fatalf("warmup failure %d = %d, want 303", i, w.Code)
		}
	}
	// A same-/24 sibling is locked — even with the CORRECT password.
	if !s.auth.lockedOut("127.0.0.9") {
		t.Error("127.0.0.9 (same /24 as 127.0.0.5) is not locked after 5 failures")
	}
	if w := login("127.0.0.9:1234", "correct horse"); w.Code != 303 ||
		!strings.Contains(w.Header().Get("Location"), "too+many") {
		t.Errorf("same-/24 login = %d %q, want the lockout redirect",
			w.Code, w.Header().Get("Location"))
	}
	// A different /24 is a different bucket: not locked, and the correct
	// password there logs in cleanly.
	if s.auth.lockedOut("192.168.5.2") {
		t.Error("192.168.5.2 inherited the lock from the unrelated 127.0.0.0/24 bucket")
	}
	if w := login("192.168.5.2:1234", "correct horse"); w.Code != 303 || w.Header().Get("Location") != "/" {
		t.Errorf("different-/24 login = %d %q, want 303 \"/\"",
			w.Code, w.Header().Get("Location"))
	}
}

// TestFailKeyPrefixes pins failKey's masking itself (the /24 and /64
// reductions the lockout counts by, plus the pass-through fallbacks).
func TestFailKeyPrefixes(t *testing.T) {
	for in, want := range map[string]string{
		"127.0.0.3":             "127.0.0.0",
		"192.168.5.2":           "192.168.5.0",
		"::ffff:127.0.0.3":      "127.0.0.0", // 4-in-6 counts as IPv4
		"fd00:aa:bb:cc:1:2:3:4": "fd00:aa:bb:cc::",
		"not-an-ip":             "not-an-ip",
	} {
		if got := failKey(in); got != want {
			t.Errorf("failKey(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestRegisterRejectsEmptyPassphrase: no passphrase → a user-visible
// error BEFORE anything is generated or written (the keys dir must stay
// empty — audit F3's plaintext-keyfile silent write).
func TestRegisterRejectsEmptyPassphrase(t *testing.T) {
	keys := filepath.Join(t.TempDir(), "keys")
	if err := mkdirAll(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	ops := &opsEnv{keysDir: keys, d: newFakeDaemon()} // daemon never reached
	_, err := ops.Register(context.Background(), RegisterInput{Alias: "plain", IP: "203.0.113.5"}, nil)
	if err == nil {
		t.Fatal("empty passphrase must be rejected")
	}
	var re *registerError
	if !errorsAs(err, &re) {
		t.Fatalf("err = %v, want a user-visible registerError", err)
	}
	if !strings.Contains(err.Error(), "passphrase") {
		t.Errorf("error %q does not tell the user about the passphrase", err)
	}
	entries, err := os.ReadDir(keys)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("keys dir not empty after the rejected register: %v", entries)
	}
	if fileExists(keychain.OwnerKeyPath(keys, "plain")) {
		t.Error("owner key was written despite the rejection")
	}
}

// TestDaemonClientStatusCache: the Daemon wrapper's 1 s Status cache —
// bursts share one daemon round trip, failures are never cached, and an
// expired entry refetches (audit F4). Uses a one-endpoint fake admin
// server on a unix socket so hits can be counted exactly.
func TestDaemonClientStatusCache(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "admin.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var hits, fail int32
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		if atomic.LoadInt32(&fail) != 0 {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "boom"})
			return
		}
		_ = json.NewEncoder(w).Encode(admin.Status{Running: true, Version: "v-cache", NodeID: "cafe"})
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	d := NewDaemonClient(sock)
	ctx := context.Background()

	// Three calls inside the TTL = one daemon round trip (base()'s
	// version fetch + the page's own Status + one more, deduplicated).
	for i := 0; i < 3; i++ {
		st, err := d.Status(ctx)
		if err != nil || st == nil || st.Version != "v-cache" {
			t.Fatalf("Status %d = %+v, %v", i, st, err)
		}
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("status hits = %d, want 1 (burst did not share the cache)", got)
	}

	// Let the entry go stale, then fail the daemon: failures must NOT be
	// cached (each erroring call hits the socket again).
	time.Sleep(statusTTL + 100*time.Millisecond)
	atomic.StoreInt32(&fail, 1)
	for i := 0; i < 2; i++ {
		if _, err := d.Status(ctx); err == nil {
			t.Fatal("erroring Status unexpectedly succeeded")
		}
	}
	if got := atomic.LoadInt32(&hits); got != 3 {
		t.Fatalf("status hits after failures = %d, want 3 (failures were cached)", got)
	}

	// Recovered daemon: the very next call refetches (and caches again).
	atomic.StoreInt32(&fail, 0)
	if _, err := d.Status(ctx); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&hits); got != 4 {
		t.Fatalf("status hits after recovery = %d, want 4", got)
	}
}
