package main

// Tests for the operational-hardening (part 1) helpers: -peers-file parsing
// (parsePeersFile), the SIGHUP reload path's no-file branch, and the -metrics
// HTTP endpoint handler (newMetricsHandler). Kept fast and in-process (no full
// daemon spin-up, which would need privileged ports and process signals).

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/laurent/freens/internal/dht"
	"github.com/laurent/freens/internal/metrics"
)

// pkHex builds a valid 64-hex-char Ed25519 public key string (64 chars of a
// repeating pattern).
func pkHex(seed string) string {
	var b strings.Builder
	for i := 0; b.Len() < 64; i++ {
		b.WriteByte(seed[i%len(seed)])
	}
	return b.String()
}

func TestParsePeersFile(t *testing.T) {
	content := "\n" +
		"# bootstrap peers (managed by ops)\n" +
		"10.0.0.1:15353#" + pkHex("aa") + "\n" +
		"   # indented comment\n" +
		"\t\n" +
		"node2.example:15353#" + pkHex("bb") + "\r\n" +
		"10.0.0.3:15353#deadbeef\n" + // bad hex length
		"10.0.0.4:15353\n" + // missing #pk
		"#10.0.0.5:15353#" + pkHex("ff") + "\n" + // commented out
		"\n"

	peers := parsePeersFile(content)
	if len(peers) != 2 {
		t.Fatalf("got %d peers, want 2: %+v", len(peers), peers)
	}
	want0 := dht.Peer{Addr: "10.0.0.1:15353"}
	if peers[0].Addr != want0.Addr || len(peers[0].PublicKey) != 32 {
		t.Errorf("peers[0] = %+v, want addr %s with 32-byte pk", peers[0], want0.Addr)
	}
	if peers[1].Addr != "node2.example:15353" {
		t.Errorf("peers[1].Addr = %q (CRLF line must parse)", peers[1].Addr)
	}
	if len(peers[0].PublicKey) == 0 || string(peers[0].PublicKey) == string(peers[1].PublicKey) {
		t.Errorf("peer keys must decode to distinct 32-byte values")
	}
}

func TestParsePeersFileEmpty(t *testing.T) {
	if got := parsePeersFile(""); got != nil {
		t.Errorf("empty file → %v, want nil", got)
	}
	if got := parsePeersFile("# only\n# comments\n\n"); got != nil {
		t.Errorf("comment-only file → %v, want nil", got)
	}
}

// TestParsePeersFileMatchesParsePeersEntry: a single peers-file line and the
// same -peers CSV entry must produce the identical dht.Peer (the flag help
// promises "same format as -peers").
func TestParsePeersFileMatchesParsePeersEntry(t *testing.T) {
	entry := "192.0.2.7:15353#" + pkHex("c0")
	fromFile := parsePeersFile(entry)
	fromCSV := parsePeers(entry)
	if len(fromFile) != 1 || len(fromCSV) != 1 {
		t.Fatalf("file %d / csv %d peers, want 1 each", len(fromFile), len(fromCSV))
	}
	if fromFile[0].Addr != fromCSV[0].Addr ||
		string(fromFile[0].PublicKey) != string(fromCSV[0].PublicKey) {
		t.Errorf("mismatch: file %+v vs csv %+v", fromFile[0], fromCSV[0])
	}
}

// TestNewMetricsHandler exercises the /metrics and /healthz routes against a
// real registry.
func TestNewMetricsHandler(t *testing.T) {
	reg := metrics.New()
	ctr := reg.NewCounter("freens_test_total", "test counter", "l")
	ctr.With("v").Add(2)
	g := reg.NewGauge("freens_test_gauge", "test gauge")
	g.With().Set(7)
	h := newMetricsHandler(reg)

	t.Run("metrics", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		res := rec.Result()
		if res.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", res.StatusCode)
		}
		if ct := res.Header.Get("Content-Type"); ct != "text/plain; version=0.0.4; charset=utf-8" {
			t.Errorf("Content-Type = %q", ct)
		}
		body := rec.Body.String()
		for _, want := range []string{
			"# TYPE freens_test_total counter",
			`freens_test_total{l="v"} 2`,
			"# TYPE freens_test_gauge gauge",
			"freens_test_gauge 7",
		} {
			if !strings.Contains(body, want) {
				t.Errorf("body missing %q:\n%s", want, body)
			}
		}
	})

	t.Run("healthz", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		res := rec.Result()
		if res.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", res.StatusCode)
		}
		if body := strings.TrimSpace(rec.Body.String()); body != "ok" {
			t.Errorf("body = %q, want ok", body)
		}
	})

	t.Run("metrics on nil registry writes nothing", func(t *testing.T) {
		rec := httptest.NewRecorder()
		newMetricsHandler(metrics.NilRegistry()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		if rec.Body.Len() != 0 {
			t.Errorf("body = %q, want empty", rec.Body.String())
		}
	})
}

// TestParsePeersFileBadEntriesDontPanic is a fuzz-ish sanity pass over
// malformed lines (each must be skipped, not fatal).
func TestParsePeersFileBadEntriesDontPanic(t *testing.T) {
	for _, line := range []string{
		"#",
		"a#",
		"#b",
		"x#zzzz",
		"x#" + strings.Repeat("0", 63),
		strings.Repeat("0", 70),
	} {
		_ = parsePeersFile(line)
	}
}
