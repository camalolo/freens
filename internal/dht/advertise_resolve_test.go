package dht

// advertise_resolve_test.go — hostname-shaped Advertise re-resolution
// (advertise_resolve.go): the monitor adopts the resolver's answer,
// follows a changed IP at runtime, keeps the current advertisement while
// resolution fails (then self-heals), and no-ops for IP-literal and
// malformed inputs. DNS is replaced by injecting a fake resolver and the
// interval is shortened via setAdvertiseResolveKnobs (both race-safe: the
// knobs are mutex-guarded because tests flip them while the monitor
// goroutine runs). Observable through the exported Advertised() getter.

import (
	"net"
	"sync"
	"testing"
	"time"
)

// fakeResolver installs a resolver stub returning one mutex-guarded
// answer regardless of the queried name. The returned func re-points the
// answer; the returned restore reinstates the real knobs.
func fakeResolver(t *testing.T) (setIP func(string), restore func()) {
	t.Helper()
	var mu sync.Mutex
	ip := "127.0.0.1"
	restore = setAdvertiseResolveKnobs(
		func(_, _ string) (*net.UDPAddr, error) {
			mu.Lock()
			defer mu.Unlock()
			return &net.UDPAddr{IP: net.ParseIP(ip), Port: 15353}, nil
		},
		50*time.Millisecond,
	)
	return func(v string) {
		mu.Lock()
		ip = v
		mu.Unlock()
	}, restore
}

// startResolveNode starts a minimal direct-UDP node with NO Advertise (so
// Start's one-shot validation never touches DNS); the caller drives the
// advertisement purely through StartAdvertiseResolve.
func startResolveNode(t *testing.T) *Node {
	t.Helper()
	n, err := NewNode(NodeConfig{
		Keypair:    mustKeypair(t),
		ListenAddr: "127.0.0.1:0",
		Store:      NewEnvelopeStore(0, nil),
	})
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	if err := n.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	return n
}

// waitAdvertised polls the exported Advertised() getter until want (or the
// stun-style 5s deadline passes).
func waitAdvertised(t *testing.T, n *Node, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for n.Advertised() != want && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := n.Advertised(); got != want {
		t.Fatalf("Advertised() = %q, want %q (within 5s)", got, want)
	}
}

// TestAdvertiseResolveFollowsHostname: the monitor adopts the first
// resolution, then follows an IP change at runtime — both visible through
// the exported Advertised() getter, same-port preserved.
func TestAdvertiseResolveFollowsHostname(t *testing.T) {
	setIP, restore := fakeResolver(t)
	defer restore()

	n := startResolveNode(t)
	defer n.Close()

	n.StartAdvertiseResolve("seed.example.net:15353")
	waitAdvertised(t, n, "127.0.0.1:15353")

	// PPPoE re-dial: the hostname now resolves elsewhere; the monitor must
	// re-advertise within a few (shortened) intervals.
	setIP("127.0.0.2")
	waitAdvertised(t, n, "127.0.0.2:15353")
}

// TestAdvertiseResolveStartsFromValidatedAddress: when Start already
// validated the hostname (advertised() non-empty), the monitor's
// bookkeeping starts from that address — a differing resolution is adopted
// on the first tick, and a stable resolution afterwards never churns the
// advertisement.
func TestAdvertiseResolveStartsFromValidatedAddress(t *testing.T) {
	_, restore := fakeResolver(t)
	defer restore()

	n := startResolveNode(t)
	defer n.Close()
	if err := n.UpdateAdvertise("192.0.2.9:15353"); err != nil {
		t.Fatalf("UpdateAdvertise seed: %v", err)
	}

	n.StartAdvertiseResolve("seed.example.net:15353")
	waitAdvertised(t, n, "127.0.0.1:15353")

	// Stable resolution from here: advertisement must stay put.
	time.Sleep(250 * time.Millisecond)
	if got := n.Advertised(); got != "127.0.0.1:15353" {
		t.Fatalf("Advertised() = %q after stable re-resolves, want unchanged 127.0.0.1:15353", got)
	}
}

// TestAdvertiseResolveIPAndMalformedNoop: an IP-literal orig (nothing to
// re-resolve) and malformed values never start a monitor — observable as
// the advertisement never changing even though the fake resolver would
// have answered.
func TestAdvertiseResolveIPAndMalformedNoop(t *testing.T) {
	_, restore := fakeResolver(t)
	defer restore()

	n := startResolveNode(t)
	defer n.Close()
	if err := n.UpdateAdvertise("203.0.113.10:15353"); err != nil {
		t.Fatalf("UpdateAdvertise: %v", err)
	}
	for _, orig := range []string{
		"203.0.113.11:15353", // IP literal
		"seed.example.net",   // no port
		":15353",             // no host
		"seed.example.net:0", // invalid port
		"seed.example.net:notaport",
		"", // empty
	} {
		n.StartAdvertiseResolve(orig)
	}
	time.Sleep(300 * time.Millisecond)
	if got := n.Advertised(); got != "203.0.113.10:15353" {
		t.Fatalf("Advertised() = %q, want the untouched 203.0.113.10:15353 (no monitor should have run)", got)
	}
}

// TestAdvertiseResolveFailureKeepsCurrent: an unresolvable hostname keeps
// the current advertisement (the DDNS record may be briefly gone
// mid-re-dial); the monitor keeps trying and adopts the address once the
// resolver answers again — the self-heal path.
func TestAdvertiseResolveFailureKeepsCurrent(t *testing.T) {
	var mu sync.Mutex
	failing := true
	restore := setAdvertiseResolveKnobs(
		func(_, addr string) (*net.UDPAddr, error) {
			mu.Lock()
			fail := failing
			mu.Unlock()
			if fail {
				return nil, &net.DNSError{Err: "test: nxdomain", Name: addr, IsNotFound: true}
			}
			return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 15353}, nil
		},
		50*time.Millisecond,
	)
	defer restore()

	n := startResolveNode(t)
	defer n.Close()
	if err := n.UpdateAdvertise("192.0.2.7:15353"); err != nil {
		t.Fatalf("UpdateAdvertise seed: %v", err)
	}

	n.StartAdvertiseResolve("seed.example.net:15353")
	time.Sleep(250 * time.Millisecond)
	if got := n.Advertised(); got != "192.0.2.7:15353" {
		t.Fatalf("Advertised() = %q while resolution fails, want kept 192.0.2.7:15353", got)
	}

	// DNS heals: the next tick adopts the fresh address.
	mu.Lock()
	failing = false
	mu.Unlock()
	waitAdvertised(t, n, "127.0.0.1:15353")
}
