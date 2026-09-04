package webui

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestRegisterReservedAliasRendersRefusal: the live "render error" report
// (2026-09-04, desktop — a §7.7 "com" attempt). The register page inlines
// jobfragment, which evaluates fields the PAGE struct does not carry — the
// v0.6.0-era call passed the page data, so every re-attached progress card
// 500'd ("render error") on EVERY webui registration, and the operator
// never saw the actual refusal. The page must render 200 with the job's
// view, and the fragment must carry the reserved-alias message.
func TestRegisterReservedAliasRendersRefusal(t *testing.T) {
	s, ts := newTestServer(t, newFakeDaemon())
	c := newUClient(t)
	c.bootstrap(ts.URL)

	code := c.post(ts.URL+"/api/register", url.Values{
		"alias":      {"com"},
		"passphrase": {"correct horse"},
		"ip":         {"203.0.113.5"},
	}, true)
	if code != http.StatusOK {
		t.Fatalf("register start = %d, want 200 (HX-Redirect)", code)
	}

	// Find the started job.
	s.jobsMu.Lock()
	var jid string
	for id := range s.jobs {
		jid = id
	}
	s.jobsMu.Unlock()
	if jid == "" {
		t.Fatal("no job started")
	}
	// Let the job runner finish (the refusal is immediate). Done is
	// written under the JOB's mutex — poll under the same lock (-race).
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		s.jobsMu.Lock()
		j := s.jobs[jid]
		s.jobsMu.Unlock()
		if j == nil {
			t.Fatal("job vanished")
		}
		j.mu.Lock()
		done := j.Done
		j.mu.Unlock()
		if done {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	get := func(path string) (int, string) {
		req, _ := http.NewRequest("GET", ts.URL+path, nil)
		resp, err := c.http.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(b)
	}

	pageCode, pageBody := get("/register?job=" + jid)
	t.Logf("register page: %d, len=%d", pageCode, len(pageBody))
	if pageCode != http.StatusOK {
		t.Errorf("register page = %d (FULL-PAGE RENDER ERROR REPRODUCED)", pageCode)
	}
	fragCode, fragBody := get("/api/job/" + jid)
	t.Logf("job fragment: %d, failed-badge=%v, has-msg=%v", fragCode,
		strings.Contains(fragBody, "badge bad"), strings.Contains(fragBody, "reserved"))
	if fragCode != http.StatusOK {
		t.Errorf("job fragment = %d (FRAGMENT RENDER ERROR REPRODUCED)", fragCode)
	}
	if !strings.Contains(fragBody, "badge bad") {
		t.Errorf("fragment does not show the failed badge:\n%s", fragBody)
	}
	if !strings.Contains(fragBody, "reserved") {
		t.Errorf("fragment does not carry the §7.7 refusal message:\n%s", fragBody)
	}
}
