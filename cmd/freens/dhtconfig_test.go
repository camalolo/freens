package main

// dhtconfig_test.go — the [dht] config section: parsing (comments, other
// sections ignored, unknown keys rejected, boolean validation) and the
// flag > config > default precedence helpers the daemon merges with.

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseDHTConfig(t *testing.T) {
	text := `
; resolver sections are not ours
[tld-routes]
mytld = freens

[dht]
listen = 0.0.0.0:15353
node-seed = @/etc/freens/node.key
peers = 192.0.2.10:15353#aabb..cc
peers-file = /etc/freens/peers.txt
advertise = 203.0.113.7:15353
stun = stun.example.net:3478
turn = :3478
turn-relay = 192.0.2.20:3478
persist = /var/lib/freens
passive = false
upnp = false
`
	cfg, err := parseDHTConfig(text)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Listen != "0.0.0.0:15353" || cfg.NodeSeed != "@/etc/freens/node.key" ||
		cfg.PeersFile != "/etc/freens/peers.txt" || cfg.Advertise != "203.0.113.7:15353" ||
		cfg.Stun != "stun.example.net:3478" || cfg.Turn != ":3478" ||
		cfg.TurnRelay != "192.0.2.20:3478" || cfg.Persist != "/var/lib/freens" {
		t.Fatalf("parsed %+v", cfg)
	}
	if cfg.Passive || !cfg.UPnPOff {
		t.Fatalf("booleans: passive=%v upnpOff=%v", cfg.Passive, cfg.UPnPOff)
	}
	// The [tld-routes] line must not have leaked into [dht] parsing.
	if cfg.Peers == "mytld = freens" {
		t.Fatal("section boundary leaked")
	}
	// Full-line comments only (same convention as resolver.ParseConfig);
	// an inline ; is VALUE text. Documented behavior, pinned here.
	if _, err := parseDHTConfig("[dht]\nlisten = :1 ; trailing\n"); err != nil {
		t.Fatalf("inline-comment line rejected: %v", err)
	}
}

func TestParseDHTConfigRejects(t *testing.T) {
	for name, text := range map[string]string{
		"unknown key":  "[dht]\nbogus = 1\n",
		"bad passive":  "[dht]\npassive = yes\n",
		"bad upnp":     "[dht]\nupnp = off\n",
		"no equals":    "[dht]\nlisten\n",
		"unterminated": "[dht\nlisten = :1\n",
	} {
		if _, err := parseDHTConfig(text); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if _, err := parseDHTConfig("[dht]\nupnp = true\n"); err != nil {
		t.Fatalf("upnp = true rejected: %v", err) // explicit no-op is fine
	}
}

func TestLoadDHTConfigFile(t *testing.T) {
	if cfg, err := loadDHTConfig(""); err != nil || cfg.Listen != "" {
		t.Fatalf("empty path: %+v %v", cfg, err)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "freens.conf")
	if err := os.WriteFile(p, []byte("[dht]\nlisten = :15353\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadDHTConfig(p)
	if err != nil || cfg.Listen != ":15353" {
		t.Fatalf("file load: %+v %v", cfg, err)
	}
	if _, err := loadDHTConfig(filepath.Join(dir, "nope")); err == nil {
		t.Fatal("missing file accepted")
	}
}

func TestPickPrecedence(t *testing.T) {
	// flag > config > default
	if got := pickString(true, "flag", "cfg", "def"); got != "flag" {
		t.Fatalf("flag lost: %s", got)
	}
	if got := pickString(false, "flag", "cfg", "def"); got != "cfg" {
		t.Fatalf("config lost: %s", got)
	}
	if got := pickString(false, "", "", "def"); got != "def" {
		t.Fatalf("default lost: %s", got)
	}
	if pickBool(true, false, true, false) {
		t.Fatal("explicit flag=false was overridden by config=true")
	}
	if !pickBool(false, false, true, false) {
		t.Fatal("config=true ignored")
	}
	if pickBool(false, false, false, false) {
		t.Fatal("nothing set but true")
	}
}
