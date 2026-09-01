// confedit_test.go — line surgery on freens.conf must never lose operator
// comments, must round-trip through the resolver's own parser, and must be
// idempotent + atomic. Each test below pins one of those guarantees.
package confedit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/camalolo/freens/internal/resolver"
)

const fleetShape = `; freens.conf — camalolo's main daemon
; notes kept here on purpose (the upnp lesson, the pppd saga)

[listen]
udp = 127.0.0.1:5300
tcp = 127.0.0.1:5300

[upstream]
; conventional forwarders; doh rides on top as encrypted-preferred
servers = 9.9.9.9, 1.1.1.1

[dht]
port = 15353

[tld-routes]
freens = freens-first
* = dns-first
`

func writeConf(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "freens.conf")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func readConf(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestGet(t *testing.T) {
	path := writeConf(t, fleetShape)

	if v, ok, err := Get(path, "upstream", "servers"); err != nil || !ok || v != "9.9.9.9, 1.1.1.1" {
		t.Errorf("Get servers = %q %v %v", v, ok, err)
	}
	if _, ok, _ := Get(path, "upstream", "doh"); ok {
		t.Error("doh must be absent before any Set")
	}
	if _, ok, _ := Get(path, "nope", "x"); ok {
		t.Error("unknown section must not be found")
	}
	// Case-insensitive section/key.
	if v, ok, _ := Get(path, "UPSTREAM", "SERVERS"); !ok || v != "9.9.9.9, 1.1.1.1" {
		t.Errorf("case-insensitive lookup = %q %v", v, ok)
	}
	// Commented-out lines never match.
	path2 := writeConf(t, "[upstream]\n;doh = https://old.example/dns-query\n")
	if _, ok, _ := Get(path2, "upstream", "doh"); ok {
		t.Error("a commented-out doh line must not count as set")
	}
	// Missing file: not an error, just not found.
	if _, ok, err := Get(filepath.Join(t.TempDir(), "absent.conf"), "upstream", "doh"); ok || err != nil {
		t.Errorf("missing file: ok=%v err=%v, want false/nil", ok, err)
	}
}

func TestSetReplacesInPlaceAndKeepsComments(t *testing.T) {
	path := writeConf(t, fleetShape)
	if err := Set(path, "upstream", "doh", "https://9.9.9.9/dns-query"); err != nil {
		t.Fatal(err)
	}
	out := readConf(t, path)

	// The new line landed at the end of [upstream], AFTER its comment.
	want := "doh = https://9.9.9.9/dns-query"
	if !strings.Contains(out, want) {
		t.Fatalf("edited file lost %q:\n%s", want, out)
	}
	dohIdx := strings.Index(out, want)
	cmtIdx := strings.Index(out, "; conventional forwarders")
	serversIdx := strings.Index(out, "servers = 9.9.9.9")
	if !(cmtIdx < serversIdx && serversIdx < dohIdx && dohIdx < strings.Index(out, "[dht]")) {
		t.Errorf("doh line inserted in the wrong place:\n%s", out)
	}
	// Everything else survived verbatim.
	for _, keep := range []string{"; notes kept here on purpose", "udp = 127.0.0.1:5300", "port = 15353", "freens = freens-first"} {
		if !strings.Contains(out, keep) {
			t.Errorf("comment/line %q lost:\n%s", keep, out)
		}
	}

	// And the resolver's parser agrees.
	cfg, err := resolver.ParseConfig(out)
	if err != nil {
		t.Fatalf("edited conf no longer parses: %v", err)
	}
	if cfg.UpstreamDoH != "https://9.9.9.9/dns-query" {
		t.Errorf("parser UpstreamDoH = %q", cfg.UpstreamDoH)
	}
}

func TestSetRemovesKey(t *testing.T) {
	path := writeConf(t, fleetShape)
	if err := Set(path, "upstream", "doh", "https://9.9.9.9/dns-query"); err != nil {
		t.Fatal(err)
	}
	if err := Set(path, "upstream", "doh", ""); err != nil {
		t.Fatal(err)
	}
	out := readConf(t, path)
	if strings.Contains(out, "dns-query") {
		t.Errorf("removal left the key behind:\n%s", out)
	}
	if !strings.Contains(out, "servers = 9.9.9.9") {
		t.Errorf("removal ate a neighbor:\n%s", out)
	}
}

func TestSetCreatesMissingSection(t *testing.T) {
	path := writeConf(t, fleetShape)
	if err := Set(path, "doh", "serve", "true"); err != nil {
		t.Fatal(err)
	}
	out := readConf(t, path)
	if !strings.Contains(out, "\n[doh]\nserve = true\n") {
		t.Errorf("missing section not appended cleanly:\n%s", out)
	}
	v, ok, err := Get(path, "doh", "serve")
	if err != nil || !ok || v != "true" {
		t.Errorf("Get serve = %q %v %v", v, ok, err)
	}
}

func TestSetIdempotentAndBackedUp(t *testing.T) {
	path := writeConf(t, fleetShape)
	if err := Set(path, "upstream", "doh", "https://9.9.9.9/dns-query"); err != nil {
		t.Fatal(err)
	}
	first := readConf(t, path)

	// Backup exists after the first real change.
	if b, err := os.ReadFile(path + ".pre-doh"); err != nil || string(b) != fleetShape {
		t.Errorf("pre-doh backup missing/wrong: %v", err)
	}

	// Re-applying the same value: no mtime change, backup untouched.
	fi1, _ := os.Stat(path)
	if err := Set(path, "upstream", "doh", "https://9.9.9.9/dns-query"); err != nil {
		t.Fatal(err)
	}
	fi2, _ := os.Stat(path)
	if !fi1.ModTime().Equal(fi2.ModTime()) {
		t.Error("idempotent Set rewrote the file")
	}
	if got := readConf(t, path); got != first {
		t.Error("idempotent Set changed content")
	}

	// A second DIFFERENT value rolls the backup to the previous state.
	if err := Set(path, "upstream", "doh", "https://1.1.1.1/dns-query"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path + ".pre-doh")
	if err != nil || string(b) != first {
		t.Errorf("backup should hold the previous generation: %v", err)
	}
}

func TestSetPreservesMode(t *testing.T) {
	path := writeConf(t, "[upstream]\nservers = 9.9.9.9\n")
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := Set(path, "upstream", "doh", "https://9.9.9.9/dns-query"); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o640 {
		t.Errorf("mode = %v, want the original 0640", fi.Mode().Perm())
	}
}

func TestSetURLWithColonsSurvives(t *testing.T) {
	// A DoH URL contains ':'; the parser's first-separator rule must see it
	// as a VALUE, not a 'key : value' delimiter.
	path := writeConf(t, "[upstream]\nservers = 9.9.9.9\n")
	url := "https://dns.example:8443/dns-query?x=1"
	if err := Set(path, "upstream", "doh", url); err != nil {
		t.Fatal(err)
	}
	v, ok, err := Get(path, "upstream", "doh")
	if err != nil || !ok || v != url {
		t.Errorf("round trip = %q %v %v, want %q", v, ok, err, url)
	}
}
