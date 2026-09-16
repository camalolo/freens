// fixes_test.go — regressions for the 2026-09-16 webui/admin fix batch:
// the SetName apex guard (no-publish variant), sequence-discovery error
// propagation (the phantom seq-1 class), the missing lookupempty fragment,
// the job-state reader race, the login-fail bucket prune, the security
// headers, the logout cross-site guard, and the Settings page's
// reload-on-GET fix. Server-level tests reuse the fake-daemon fixture from
// webui_test.go.
package webui

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/dht"
	"github.com/camalolo/freens/internal/keychain"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/wire"
)

// getFailDaemon is a fakeDaemon whose Get fails (a degraded discovery walk
// — the socket-down / walk-failure case currentSequence used to swallow).
type getFailDaemon struct {
	*fakeDaemon
	err error
}

func (g *getFailDaemon) Get(ctx context.Context, key []byte) (*wire.SignedEnvelope, error) {
	return nil, g.err
}

// seedApexEnvelope stores a signed apex envelope for alias at sequence seq
// in the fake daemon's Get map, and returns the wireName it lives under.
func seedApexEnvelope(t *testing.T, f *fakeDaemon, alias string, seq uint64) []byte {
	t.Helper()
	kp := genKP(t)
	tldID, err := crypto.TldID(kp.Public())
	if err != nil {
		t.Fatal(err)
	}
	wn, err := naming.EncodeWireName(nil, alias, tldID)
	if err != nil {
		t.Fatal(err)
	}
	now := uint64(time.Now().Unix())
	rec, err := wire.NewRecord(wn, kp.Public(), seq, now, now+3600)
	if err != nil {
		t.Fatal(err)
	}
	rr, err := wire.A(net.IP{203, 0, 113, 9}.To4(), 300)
	if err != nil {
		t.Fatal(err)
	}
	rec.RRset = []*wire.RR{rr}
	env, err := wire.SignRecord(rec, kp)
	if err != nil {
		t.Fatal(err)
	}
	key, err := dht.KeyForWireName(wn)
	if err != nil {
		t.Fatal(err)
	}
	f.get[string(key)] = env
	return wn
}

// --- item 1: the SetName apex guard ---------------------------------------

// TestOpsSetNameApexGuardNoPublish: the fake-daemon half of the apex-guard
// regression (the live half is TestOpsSetNameRefusesApex). The guard must
// fire BEFORE anything is published, and a sub-name target keeps working.
func TestOpsSetNameApexGuardNoPublish(t *testing.T) {
	f := newFakeDaemon()
	keys := t.TempDir()
	ops := &opsEnv{keysDir: keys, d: f}

	if _, err := ops.SetName(context.Background(), "alice", "203.0.113.5", 300, ""); err == nil {
		t.Fatal("SetName on the apex must refuse")
	} else if !strings.Contains(err.Error(), "apex itself") {
		t.Errorf("error %q does not name the apex refusal", err)
	}
	if len(f.pubs) != 0 {
		t.Fatalf("refused apex publish still published %d envelope(s)", len(f.pubs))
	}

	// Sub-name target still publishes (seq 1 — the fake Get map is empty).
	if err := keychain.Save(keychain.OwnerKeyPath(keys, "alice"), genKP(t), ""); err != nil {
		t.Fatal(err)
	}
	seq, err := ops.SetName(context.Background(), "www.alice", "203.0.113.5", 300, "")
	if err != nil || seq != 1 {
		t.Fatalf("sub-name SetName = %d, %v (the guard must not touch sub-names)", seq, err)
	}
	if len(f.pubs) != 1 {
		t.Fatalf("sub-name publish count = %d, want 1", len(f.pubs))
	}
}

// --- item 5: sequence discovery must not swallow GET errors ---------------

// testWireName builds a valid wireName (zero labels, a synthetic tld_id) so
// KeyForWireName accepts it and the test key really reaches the daemon Get.
func testWireName(t *testing.T, b byte) []byte {
	t.Helper()
	wn, err := naming.EncodeWireName(nil, "probe", bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return wn
}

func TestSequenceDiscoveryFailureAbortsPublish(t *testing.T) {
	f := newFakeDaemon()
	getErr := context.DeadlineExceeded
	broken := &getFailDaemon{fakeDaemon: f, err: getErr}
	ops := &opsEnv{keysDir: t.TempDir(), d: broken}
	ctx := context.Background()

	// currentSequence itself: a Get error is an error, never a silent seq 1.
	if _, err := ops.currentSequence(ctx, testWireName(t, 0x01)); err == nil {
		t.Fatal("currentSequence must fail when the discovery Get fails")
	} else if !strings.Contains(err.Error(), "sequence discovery failed") {
		t.Errorf("error %q does not carry the retry wording", err)
	}

	// SetName: fails instead of publishing a globally-losing sequence.
	if err := keychain.Save(keychain.OwnerKeyPath(ops.keysDir, "alice"), genKP(t), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := ops.SetName(ctx, "www.alice", "203.0.113.5", 300, ""); err == nil {
		t.Fatal("SetName must fail when sequence discovery fails")
	} else if !strings.Contains(err.Error(), "sequence discovery failed") {
		t.Errorf("error %q does not carry the retry wording", err)
	}
	if len(f.pubs) != 0 {
		t.Fatalf("failed-discovery SetName still published %d envelope(s)", len(f.pubs))
	}

	// Renew: the Get error must NOT read as "nothing to renew".
	if _, err := ops.Renew(ctx, "www.alice", "", false); err == nil {
		t.Fatal("Renew must fail when discovery fails")
	} else if strings.Contains(err.Error(), "nothing to renew") {
		t.Errorf("Renew masked the walk failure as nothing-to-renew: %v", err)
	} else if !strings.Contains(err.Error(), "sequence discovery failed") {
		t.Errorf("error %q does not carry the retry wording", err)
	}
	if len(f.pubs) != 0 {
		t.Fatalf("failed-discovery Renew still published %d envelope(s)", len(f.pubs))
	}
}

func TestSequenceDiscoveryReadsNetworkSequence(t *testing.T) {
	f := newFakeDaemon()
	wn := seedApexEnvelope(t, f, "seeded", 7)
	ops := &opsEnv{keysDir: t.TempDir(), d: f}
	seq, err := ops.currentSequence(context.Background(), wn)
	if err != nil {
		t.Fatalf("currentSequence: %v", err)
	}
	if seq != 8 {
		t.Errorf("currentSequence = %d, want 8 (network's 7 + 1)", seq)
	}
	// Nothing stored anywhere: the NEXT sequence is 1 — but only on a
	// clean (nil, nil) miss, never on a failed walk.
	seq, err = ops.currentSequence(context.Background(), testWireName(t, 0x02))
	if err != nil || seq != 1 {
		t.Errorf("fresh-name currentSequence = %d, %v; want 1, nil", seq, err)
	}
}

// --- item 2: the lookupempty fragment --------------------------------------

func TestDNSProbeEmptyNameRendersHint(t *testing.T) {
	_, ts := newTestServer(t, newFakeDaemon())
	c := newUClient(t)
	c.bootstrap(ts.URL)
	for _, q := range []string{"/api/dns", "/api/dns?name=%20%20", "/api/dns?name=."} {
		code, body := getBody(t, c, ts.URL+q)
		if code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200 (pre-fix: 500, no such fragment)", q, code)
		}
		if !strings.Contains(body, "Type a name to look up.") {
			t.Errorf("GET %s did not render the empty-lookup hint", q)
		}
	}
}

// --- item 3: job-state reads are race-free ---------------------------------

// TestJobStateConcurrentReads hammers the dashboard's readers while a job
// runner finishes. Run with -race: pre-fix, the runner wrote Done/Err/Result
// under j.mu while recentJobs/runningLocked/the pruner read them under
// jobsMu — a data race on every render.
func TestJobStateConcurrentReads(t *testing.T) {
	s := &Server{jobs: map[string]*job{}}
	id := s.startJob("race probe", func(ctx context.Context, progress func(string)) (any, error) {
		for i := 0; i < 5; i++ {
			progress("step")
			time.Sleep(2 * time.Millisecond)
		}
		return &RegisterResult{Alias: "race"}, nil
	})

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		// The exact read paths a dashboard render takes.
		_ = s.recentJobs()
		s.jobsMu.Lock()
		_ = s.runningLocked()
		s.jobsMu.Unlock()
		j := s.job(id)
		if j == nil {
			t.Fatal("started job not found in the map")
		}
		v := s.viewOf(j)
		if v.JobDone {
			if v.JobError != "" {
				t.Fatalf("job failed: %s", v.JobError)
			}
			if v.JobResult == nil {
				t.Fatal("finished job lost its Result snapshot")
			}
			for _, rj := range s.recentJobs() {
				if rj.Label == "race probe" && rj.State != "done" {
					t.Errorf("recentJobs state = %q, want done", rj.State)
				}
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("job never finished")
}

// --- item 7: login rate-limit buckets are pruned ---------------------------

func TestLoginFailBucketsArePruned(t *testing.T) {
	a := newAuthStore("")

	// Bucket 1: an expired window (backdated past loginWindow, never locked).
	// failKey takes the bare source IP (recordFail is fed remoteIP).
	a.recordFail("10.1.2.3") // → key 10.1.2.0
	// Bucket 2: a LIVE lock (5 failures just now).
	for i := 0; i < maxLoginFails; i++ {
		a.recordFail("10.9.9.9") // → key 10.9.9.0, locked
	}
	a.mu.Lock()
	a.fails["10.1.2.0"].firstAt = time.Now().Add(-2 * loginWindow)
	a.mu.Unlock()

	// A third source's failure drives the prune pass.
	a.recordFail("10.200.0.1")

	a.mu.Lock()
	_, expiredKept := a.fails["10.1.2.0"]
	_, lockedKept := a.fails["10.9.9.0"]
	_, freshKept := a.fails["10.200.0.0"]
	a.mu.Unlock()
	if expiredKept {
		t.Error("quiesced bucket (window over, no lock) survived the prune")
	}
	if !lockedKept {
		t.Error("live-lock bucket was pruned — the lockout would silently lapse")
	}
	if !freshKept {
		t.Error("fresh bucket was pruned — counting would reset on every failure")
	}
	// The live lock still locks (semantics unchanged).
	if !a.lockedOut("10.9.9.7") {
		t.Error("locked bucket lost its lock")
	}
}

// --- item 8: security headers -----------------------------------------------

func TestSecurityHeadersOnResponses(t *testing.T) {
	_, ts := newTestServer(t, newFakeDaemon())
	c := newUClient(t)
	c.bootstrap(ts.URL)
	for _, path := range []string{"/", "/login", "/static/app.css"} {
		resp, err := c.http.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		h := resp.Header
		resp.Body.Close()
		for hdr, want := range map[string]string{
			"X-Content-Type-Options": "nosniff",
			"X-Frame-Options":        "DENY",
			"Referrer-Policy":        "no-referrer",
		} {
			if got := h.Get(hdr); got != want {
				t.Errorf("GET %s: %s = %q, want %q", path, hdr, got, want)
			}
		}
	}
}

// --- item 6: GET /settings must not reload the daemon -----------------------

func TestSettingsPageReloadFlagWithoutMutation(t *testing.T) {
	// Running daemon (real admin socket): the page says changes apply live.
	_, ts, _ := newDohFixture(t)
	c := newUClient(t)
	c.bootstrap(ts.URL)
	code, body := getBody(t, c, ts.URL+"/settings")
	if code != http.StatusOK {
		t.Fatalf("settings = %d", code)
	}
	if !strings.Contains(body, "Applied live") {
		t.Error("settings page with a live daemon does not say changes apply live")
	}

	// No daemon: the not-running note instead (and no reload call — there
	// is no daemon to hit; the page must still render 200).
	_, ts2 := newTestServer(t, newFakeDaemon())
	c2 := newUClient(t)
	c2.bootstrap(ts2.URL)
	code2, body2 := getBody(t, c2, ts2.URL+"/settings")
	if code2 != http.StatusOK {
		t.Fatalf("settings without a daemon = %d", code2)
	}
	if !strings.Contains(body2, "daemon is not running") {
		t.Error("settings page without a daemon does not explain the apply-on-start state")
	}
}
