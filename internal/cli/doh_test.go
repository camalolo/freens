// doh_test.go — `freens doh` verb behavior against a temp home: preset
// resolution, config round-trips through the resolver's parser, the live
// reload hint when no daemon runs, and the relay test's no-daemon error.
// (The admin endpoints themselves are covered in internal/admin; the full
// HTTPS leg is a fleet test.)
package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/camalolo/freens/internal/confedit"
	"github.com/camalolo/freens/internal/home"
	"github.com/camalolo/freens/internal/resolver"
)

func TestDohUpstreamPreset(t *testing.T) {
	tempHome(t)
	if err := cmdDoh([]string{"upstream", "quad9"}); err != nil {
		t.Fatalf("upstream quad9: %v", err)
	}
	v, ok, err := confedit.Get(home.ConfPath(), "upstream", "doh")
	if err != nil || !ok || v != "https://9.9.9.9/dns-query" {
		t.Fatalf("config doh = %q ok=%v err=%v", v, ok, err)
	}
	// The daemon's parser must accept what the verb wrote.
	b, rerr := os.ReadFile(home.ConfPath())
	if rerr != nil {
		t.Fatal(rerr)
	}
	cfg, perr := resolver.ParseConfig(string(b))
	if perr != nil {
		t.Fatalf("edited conf does not parse: %v", perr)
	}
	if cfg.UpstreamDoH != "https://9.9.9.9/dns-query" {
		t.Errorf("parser sees %q", cfg.UpstreamDoH)
	}
}

func TestDohUpstreamOffAndCustom(t *testing.T) {
	tempHome(t)
	if err := cmdDoh([]string{"upstream", "cloudflare"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdDoh([]string{"upstream", "off"}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := confedit.Get(home.ConfPath(), "upstream", "doh"); ok {
		t.Error("off must clear the doh key")
	}
	// Custom URL.
	if err := cmdDoh([]string{"upstream", "https://dns.mybox.example/dns-query"}); err != nil {
		t.Fatal(err)
	}
	if v, ok, _ := confedit.Get(home.ConfPath(), "upstream", "doh"); !ok || v != "https://dns.mybox.example/dns-query" {
		t.Errorf("custom URL = %q", v)
	}
	// Garbage refused (plain http non-loopback).
	if err := cmdDoh([]string{"upstream", "http://dns.example/dns-query"}); err == nil {
		t.Error("plain http non-loopback must be refused")
	}
	if err := cmdDoh([]string{"upstream", "nonsense"}); err == nil {
		t.Error("garbage must be refused")
	}
}

func TestDohServeToggle(t *testing.T) {
	tempHome(t)
	if err := cmdDoh([]string{"serve", "on"}); err != nil {
		t.Fatal(err)
	}
	v, ok, _ := confedit.Get(home.ConfPath(), "doh", "serve")
	if !ok || v != "true" {
		t.Fatalf("serve = %q ok=%v, want true", v, ok)
	}
	if err := cmdDoh([]string{"serve", "off"}); err != nil {
		t.Fatal(err)
	}
	v, _, _ = confedit.Get(home.ConfPath(), "doh", "serve")
	if v != "false" {
		t.Errorf("serve after off = %q", v)
	}
	// Parser accepts the [doh] section silently (unknown sections are
	// forward-compat), so the daemon must not choke on it.
	b, err := os.ReadFile(home.ConfPath())
	if err != nil {
		t.Fatal(err)
	}
	if _, perr := resolver.ParseConfig(string(b)); perr != nil {
		t.Errorf("parser rejected [doh]: %v", perr)
	}
}

func TestDohStatusOutput(t *testing.T) {
	tempHome(t)
	_ = cmdDoh([]string{"upstream", "quad9"})
	_ = cmdDoh([]string{"serve", "on"})
	out, err := captureStdout(t, func() error { return cmdDoh(nil) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "DoH https://9.9.9.9/dns-query") {
		t.Errorf("status missing upstream line:\n%s", out)
	}
	if !strings.Contains(out, "serve:    on") {
		t.Errorf("status missing serve line:\n%s", out)
	}
	if !strings.Contains(out, "daemon:   not running") {
		t.Errorf("status should note the absent daemon:\n%s", out)
	}
}

func TestDohTestNeedsDaemon(t *testing.T) {
	tempHome(t)
	err := cmdDoh([]string{"test"})
	if err == nil || !strings.Contains(err.Error(), "no running freens daemon") {
		t.Fatalf("test without daemon: err=%v, want the no-daemon explanation", err)
	}
}
