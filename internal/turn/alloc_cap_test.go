package turn

// alloc_cap_test.go pins the two allocation-table bounds: the daemon-wide
// MaxTotalAllocs gate (a rejected Allocate draws 508 before any relay
// socket/goroutine exists) and the per-IP counter map staying bounded by
// live clients (entries deleted at zero on expiry and release).

import (
	"net"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/crypto"
)

// rawAllocate sends one signed Allocate from a throwaway socket (a fresh
// 5-tuple, so it counts as a distinct client) and returns the decoded
// response — the TestAuthRejectsBadSignatures pattern minus the mis-signing.
func rawAllocate(t *testing.T, srv *Server, lifetimeSec uint32) *message {
	t.Helper()
	sa, err := srv.Addr()
	if err != nil {
		t.Fatalf("Addr: %v", err)
	}
	raw, err := net.DialUDP("udp", nil, sa)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	m, err := newTxID(methodAllocate, classRequest)
	if err != nil {
		t.Fatal(err)
	}
	m.add(attrLifetime, be32(lifetimeSec))
	sign(m, kp.Public(), kp.Sign)
	b, err := m.encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Write(b); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	_ = raw.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := raw.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("no response to Allocate: %v", err)
	}
	resp, err := parseMessage(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// waitAllocations polls until the server holds n live allocations (the
// TestRefreshKeepsAllocation polling pattern).
func waitAllocations(t *testing.T, srv *Server, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for srv.Allocations() != n && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := srv.Allocations(); got != n {
		t.Fatalf("allocations = %d, want %d", got, n)
	}
}

// perIPHas reports whether ip still has a perIP entry (tests are in-package;
// a stale zero entry is exactly what must NOT survive expiry/release).
func perIPHas(srv *Server, ip string) bool {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	_, ok := srv.perIP[ip]
	return ok
}

// TestTotalAllocationCap: with MaxTotalAllocs=2 a third DISTINCT client's
// Allocate draws 508 and creates no relay socket/allocation; freeing one
// slot re-admits a fresh client (the cap is a gate, not a wedge).
func TestTotalAllocationCap(t *testing.T) {
	srv := newTestServer(t, func(c *ServerConfig) { c.MaxTotalAllocs = 2 })
	c1 := dialTest(t, srv)
	dialTest(t, srv) // two concurrent clients: under the per-IP default
	waitAllocations(t, srv, 2)

	resp := rawAllocate(t, srv, 600)
	if resp.class != classError {
		t.Fatalf("over-cap Allocate got class %d, want error", resp.class)
	}
	if code, _ := decodeErrorCode(resp.get(attrErrorCode)); code != errInsufficientCapacity {
		t.Fatalf("over-cap Allocate code %d, want %d", code, errInsufficientCapacity)
	}
	waitAllocations(t, srv, 2) // nothing was created by the rejected request

	_ = c1.Close() // best-effort Lifetime-0 Refresh release
	waitAllocations(t, srv, 1)
	dialTest(t, srv)
	waitAllocations(t, srv, 2)
}

// TestPerIPMapGCOnExpiry: an expired allocation's per-IP entry is deleted,
// not left as a stale zero (the map is otherwise only rebuilt in Close).
func TestPerIPMapGCOnExpiry(t *testing.T) {
	srv := newTestServer(t, nil)
	// A raw Allocate (no client refresh loop) with a 1s lifetime so the
	// allocation genuinely expires.
	resp := rawAllocate(t, srv, 1)
	if resp.class != classSuccess {
		t.Fatalf("Allocate got class %d, want success", resp.class)
	}
	if !perIPHas(srv, "127.0.0.1") {
		t.Fatal("perIP missing 127.0.0.1 while allocation is live")
	}
	waitAllocations(t, srv, 0)
	if perIPHas(srv, "127.0.0.1") {
		t.Fatal("perIP still holds 127.0.0.1 after expiry; map would grow unboundedly")
	}
}

// TestPerIPMapGCOnRelease: the explicit Lifetime-0 Refresh release path
// drops the per-IP entry too.
func TestPerIPMapGCOnRelease(t *testing.T) {
	srv := newTestServer(t, nil)
	c := dialTest(t, srv)
	waitAllocations(t, srv, 1)
	if !perIPHas(srv, "127.0.0.1") {
		t.Fatal("perIP missing 127.0.0.1 while allocation is live")
	}
	_ = c.Close()
	waitAllocations(t, srv, 0)
	if perIPHas(srv, "127.0.0.1") {
		t.Fatal("perIP still holds 127.0.0.1 after release; map would grow unboundedly")
	}
}
