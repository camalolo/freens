package cli

import (
	"net"
	"testing"
)

// The DNS-outage invariant (2026-09-17 desktop lesson): a wired adapter is
// NEVER loopback-alone — the daemon's death must degrade to a slower
// lookup, never to a machine with no DNS.
func TestAdapterServerList(t *testing.T) {
	// First wire: the adapter's real upstreams become the failover chain,
	// topped up with the public pair (more fallbacks = more resilience;
	// the invariant is at least one non-loopback entry).
	got := adapterServerList([]string{"192.168.1.1", "1.1.1.1"}, "127.0.0.1")
	want := []string{"127.0.0.1", "192.168.1.1", "1.1.1.1", "9.9.9.9"}
	eq := len(got) == len(want)
	if eq {
		for i := range want {
			if got[i] != want[i] {
				eq = false
			}
		}
	}
	if !eq {
		t.Fatalf("adapterServerList(first run) = %v, want %v", got, want)
	}

	// Re-run poisoning: the captured list is loopback-only (a previous
	// setup already wired it) — the public fallback pair must appear, and
	// no loopback may ever be a failover entry.
	got = adapterServerList([]string{"127.0.0.1"}, "127.0.0.1")
	if len(got) != 3 || got[0] != "127.0.0.1" || got[1] != "1.1.1.1" || got[2] != "9.9.9.9" {
		t.Fatalf("adapterServerList(re-run) = %v, want loopback + public pair", got)
	}

	// Cap: loopback + at most three failovers.
	many := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"}
	got = adapterServerList(many, "127.0.0.1")
	if len(got) != 4 {
		t.Fatalf("adapterServerList(capped) = %d entries, want 4", len(got))
	}
}

func TestStripLoopbackOnlyAdapters(t *testing.T) {
	in := []dnsAdapter{
		{Alias: "Ethernet", Servers: []string{"127.0.0.1"}},             // poisoned: all-loopback
		{Alias: "Wi-Fi", Servers: []string{"192.168.1.1", "127.0.0.1"}}, // real upstream kept
	}
	out := stripLoopbackOnlyAdapters(in)
	if len(out) != 1 || out[0].Alias != "Wi-Fi" {
		t.Fatalf("stripLoopbackOnlyAdapters = %+v, want only Wi-Fi kept", out)
	}
}

func TestResolvFallbacks(t *testing.T) {
	conf := "# comment\nnameserver 127.0.0.1\nnameserver 192.168.1.1\nnameserver 1.1.1.1\nnameserver 9.9.9.9\n"
	got := resolvFallbacks(conf)
	if len(got) != 2 || got[0] != "192.168.1.1" || got[1] != "1.1.1.1" {
		t.Fatalf("resolvFallbacks = %v, want [192.168.1.1 1.1.1.1] (loopback dropped, capped at 2)", got)
	}
	if got := resolvFallbacks("nameserver 127.0.0.1\nnameserver ::1\n"); len(got) != 0 {
		t.Fatalf("resolvFallbacks(loopback-only) = %v, want empty", got)
	}
}

// isLoopbackIP: only true literals count — an empty or hostname string
// must not be treated as the daemon's own resolver.
func TestIsLoopbackIP(t *testing.T) {
	if !isLoopbackIP("127.0.0.1") || !isLoopbackIP("::1") {
		t.Fatal("loopback literals not recognized")
	}
	if isLoopbackIP("192.168.1.1") || isLoopbackIP("") || isLoopbackIP("localhost") {
		t.Fatal("non-loopback strings misclassified")
	}
	if net.ParseIP("bogus") != nil {
		t.Fatal("sanity: bogus parsed as IP")
	}
}
