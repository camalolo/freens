package cli

// upgrade_vantage_test.go — the dial-vantage rule: private/loopback
// addresses of REMOTE peers are only worth dialing when one of this
// machine's interfaces shares the subnet (user-reported during the
// v0.19.10 roll: the friend's WAN VPS burned its upgrade swarm dialing
// other LANs' 192.168.1.x and counted the impossible dials as peer
// failures).

import (
	"net"
	"runtime"
	"strings"
	"testing"

	"github.com/camalolo/freens/internal/dht"
)

func testNets() []*net.IPNet {
	// Simulated local vantage: one LAN subnet + a public address + loopback.
	_, lan, _ := net.ParseCIDR("192.168.1.16/24")
	_, pub, _ := net.ParseCIDR("93.184.216.34/32")
	_, lo, _ := net.ParseCIDR("127.0.0.1/8")
	return []*net.IPNet{lan, pub, lo}
}

func TestAddrViable(t *testing.T) {
	nets := testNets()
	cases := []struct {
		addr string
		want bool
		note string
	}{
		{"192.168.1.32:15353", true, "own-LAN address: viable"},
		{"10.0.0.5:15353", false, "another LAN's private address: never reachable"},
		{"93.184.216.34:15353", true, "public address: always worth dialing"},
		{"127.0.0.1:15353", true, "loopback lives on every machine (on-box heal pattern)"},
		{"freens.camalolo.com:15353", true, "hostname: resolves; viability unknown until dialed"},
		{"[fe80::1]:15353", false, "link-local from a different interface: unreachable"},
	}
	for _, c := range cases {
		if got := addrViable(c.addr, nets); got != c.want {
			t.Errorf("addrViable(%q) = %v, want %v (%s)", c.addr, got, c.want, c.note)
		}
	}
}

func TestDialPlanOrderAndDedupe(t *testing.T) {
	nets := testNets()
	p := dht.Peer{
		Addr: "192.168.1.32:15353",
		Alts: []dht.AddrState{
			{Addr: "192.168.1.32:15353"}, // duplicate of preferred
			{Addr: "10.9.9.9:15353"},     // foreign LAN: dropped
			{Addr: "61.223.34.65:15354"}, // public alt: kept
			{Addr: "192.168.1.32:15452"}, // own-LAN chair port: kept
		},
	}
	plan := dialPlan(p, nets)
	want := []string{"192.168.1.32:15353", "61.223.34.65:15354", "192.168.1.32:15452"}
	if len(plan) != len(want) {
		t.Fatalf("plan = %v, want %v", plan, want)
	}
	for i := range want {
		if plan[i] != want[i] {
			t.Fatalf("plan = %v, want %v (order matters: preferred first)", plan, want)
		}
	}
}

func TestDialPlanAllUnviableIsEmpty(t *testing.T) {
	// The WAN-vantage peer looking at a LAN-only node: no dialable
	// address at all → the peer is excluded from the rotation entirely
	// (never dialed, never struck, never in the failure list).
	nets := testNets()
	p := dht.Peer{
		Addr: "10.0.0.5:15353",
		Alts: []dht.AddrState{{Addr: "172.16.0.9:15353"}},
	}
	if plan := dialPlan(p, nets); len(plan) != 0 {
		t.Fatalf("plan = %v, want empty", plan)
	}
	if got := viablePeers([]dht.Peer{p}, nets, new(int)); len(got) != 0 {
		t.Fatalf("viablePeers kept an unviable peer: %v", got)
	}
}

// TestSyntheticReleaseCoversPlatform: a PINNED-tag upgrade never touches
// the GitHub API — the synthesized release must carry every asset the
// flow needs (own-platform tarball + manifest + SHA256SUMS) with
// deterministic download URLs.
func TestSyntheticReleaseCoversPlatform(t *testing.T) {
	rel := syntheticRelease("v9.9.9")
	if rel.TagName != "v9.9.9" {
		t.Fatalf("tag = %q", rel.TagName)
	}
	need := map[string]bool{
		"SHA256SUMS.txt":           false,
		upgradeManifestAssetName(): false,
		"freens-" + runtime.GOOS + "-" + runtime.GOARCH + ".tar.gz": false,
	}
	var urls []string
	for _, a := range rel.Assets {
		if _, ok := need[a.Name]; ok {
			need[a.Name] = true
		}
		urls = append(urls, a.BrowserDownload)
	}
	for n, found := range need {
		if !found {
			t.Errorf("synthetic release missing asset %q", n)
		}
	}
	for _, u := range urls {
		if !strings.HasPrefix(u, "https://github.com/camalolo/freens/releases/download/v9.9.9/") {
			t.Errorf("asset URL not the deterministic download form: %q", u)
		}
	}
}
