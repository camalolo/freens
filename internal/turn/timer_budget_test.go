package turn

// timer_budget_test.go pins two relay-lifetime fixes:
//
//   - Refresh must REPLACE the allocation's expiry timer, not stack a new
//     dormant time.AfterFunc per refresh (the old code armed an unbounded
//     pile of closures, each pinning the allocation until long after its
//     actual expiry). Pinned in-package: the previous timer reports
//     already-stopped after the next refresh, and the allocation expires
//     exactly once after refreshes stop.
//   - The shared payload budget: client WriteTo refuses payloads that
//     would encode past maxMessageLen (they'd be silently dropped at the
//     receiver's parse), an at-budget payload round-trips byte-intact in
//     both directions, and an oversized inbound peer datagram is dropped
//     by the relay loop instead of relayed truncated.

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/crypto"
)

// captureLog counts log lines by message (Warn/Debug included), so tests
// can assert "allocation expired" happened exactly once and that the relay
// loop actually dropped (not relayed) an oversized datagram.
type captureLog struct {
	mu    sync.Mutex
	lines map[string]int
}

func newCaptureLog() *captureLog { return &captureLog{lines: make(map[string]int)} }

func (l *captureLog) Info(msg string, _ ...any) {
	l.mu.Lock()
	l.lines[msg]++
	l.mu.Unlock()
}
func (l *captureLog) Warn(msg string, _ ...any) { l.Info(msg) }
func (l *captureLog) Debug(msg string, _ ...any) {
	l.mu.Lock()
	l.lines[msg]++
	l.mu.Unlock()
}

func (l *captureLog) count(msg string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lines[msg]
}

// TestRefreshReplacesExpiryTimer: N refreshes leave exactly ONE armed
// timer (the latest), the previous ones are stopped, and after refreshes
// stop the allocation expires exactly once.
func TestRefreshReplacesExpiryTimer(t *testing.T) {
	log := newCaptureLog()
	srv := newTestServer(t, func(c *ServerConfig) { c.DefaultLifetime = time.Second; c.Log = log })
	sa, err := srv.Addr()
	if err != nil {
		t.Fatal(err)
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

	// roundTrip sends one signed request from the SAME 5-tuple and reads
	// the response (the rawAllocate pattern, but the socket stays open).
	roundTrip := func(method uint16, lifetime uint32) {
		t.Helper()
		m, err := newTxID(method, classRequest)
		if err != nil {
			t.Fatal(err)
		}
		m.add(attrLifetime, be32(lifetime))
		sign(m, kp.Public(), kp.Sign)
		b, err := m.encode()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := raw.Write(b); err != nil {
			t.Fatal(err)
		}
		_ = raw.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 512)
		n, _, err := raw.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("%#x round trip: %v", method, err)
		}
		resp, err := parseMessage(buf[:n])
		if err != nil {
			t.Fatal(err)
		}
		if resp.class != classSuccess {
			code, reason := decodeErrorCode(resp.get(attrErrorCode))
			t.Fatalf("%#x got error %d (%s)", method, code, reason)
		}
	}

	key := raw.LocalAddr().String()
	roundTrip(methodAllocate, 1)
	srv.mu.Lock()
	a := srv.allocs[key]
	srv.mu.Unlock()
	if a == nil {
		t.Fatal("no allocation after Allocate")
	}

	// Refresh several times; after each, the PREVIOUS timer must be
	// stopped and a new one armed. Lifetimes are 1s and refreshes 100ms
	// apart, so a captured timer cannot legitimately fire between capture
	// and check — Stop()==true here would mean the server left it armed.
	timerOf := func() *time.Timer {
		a.mu.Lock()
		defer a.mu.Unlock()
		return a.timer
	}
	const refreshes = 4
	prev := timerOf()
	for i := 0; i < refreshes; i++ {
		time.Sleep(100 * time.Millisecond)
		roundTrip(methodRefresh, 1)
		cur := timerOf()
		if cur == nil {
			t.Fatalf("refresh %d left no timer armed", i)
		}
		if prev == cur {
			t.Fatalf("refresh %d did not replace the expiry timer", i)
		}
		if prev != nil && prev.Stop() {
			t.Fatalf("refresh %d did not STOP the previous expiry timer (stacking)", i)
		}
		prev = cur
	}

	// Stop refreshing; the single remaining timer must expire the
	// allocation, exactly once.
	deadline := time.Now().Add(3 * time.Second)
	for srv.Allocations() != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := srv.Allocations(); got != 0 {
		t.Fatalf("allocation never expired after refreshes stopped")
	}
	if n := log.count("turn: allocation expired"); n != 1 {
		t.Fatalf("allocation expired %d times, want exactly 1", n)
	}
	// The expiry stopped/cleared the timer bookkeeping too.
	if timerOf() != nil {
		t.Fatal("timer still recorded after expiry")
	}
}

// dropLog is the relay-loop's oversized-datagram Debug line.
const dropLog = "turn: oversized peer datagram dropped"

// TestPayloadBudget: the tunnel budget is enforced at both ends — client
// WriteTo refuses oversize with an error, at-budget payloads round-trip
// byte-intact both ways, and an oversized inbound datagram is dropped by
// the relay loop (never relayed truncated).
func TestPayloadBudget(t *testing.T) {
	log := newCaptureLog()
	srv := newTestServer(t, func(c *ServerConfig) { c.Log = log })
	c := dialTest(t, srv)
	relayed := c.RelayedAddr()
	peer := newUDPPeer(t)

	// EGRESS: oversize refused before anything is sent.
	big := bytes.Repeat([]byte{0xA5}, maxDataPayload+1)
	if n, err := c.WriteTo(big, peer.addr); err == nil {
		t.Fatalf("oversize WriteTo accepted (%d bytes sent)", n)
	}

	// At-budget round trip, client → peer (encodes to a body of exactly
	// maxMessageLen: the largest payload the receiver must still parse).
	pay := bytes.Repeat([]byte{0x5A}, maxDataPayload)
	if n, err := c.WriteTo(pay, peer.addr); err != nil || n != len(pay) {
		t.Fatalf("at-budget WriteTo: %d %v", n, err)
	}
	data, _ := peer.recv(t, 2*time.Second)
	if data == nil || !bytes.Equal(data, pay) {
		t.Fatalf("at-budget payload mangled: got %d bytes", len(data))
	}

	// At-budget round trip, peer → client.
	if _, err := peer.conn.WriteToUDP(pay, relayed); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	if err := c.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, _, err := c.ReadFrom(buf)
	if err != nil || !bytes.Equal(buf[:n], pay) {
		t.Fatalf("at-budget reply mangled: %d %v", n, err)
	}

	// INGRESS: a datagram larger than the relay read buffer arrives
	// truncated; the relay loop must DROP it, then relay a following
	// marker intact (proving the loop is alive and the oversize was not
	// relayed as a corrupt prefix).
	over := bytes.Repeat([]byte{0xCC}, maxRelayedReadBuf+64)
	marker := []byte("after-the-drop")
	if _, err := peer.conn.WriteToUDP(over, relayed); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.conn.WriteToUDP(marker, relayed); err != nil {
		t.Fatal(err)
	}
	got, _, err := c.ReadFrom(buf)
	if err != nil {
		t.Fatalf("marker never arrived after the oversized drop: %v", err)
	}
	if !bytes.Equal(buf[:got], marker) {
		t.Fatalf("read %d bytes, want the %d-byte marker (oversize relayed?)", got, len(marker))
	}
	// The drop is the server's doing (a Debug line), not the client's
	// parse silently saving the day — exactly one drop, no more.
	if n := log.count(dropLog); n != 1 {
		t.Fatalf("relay loop dropped %d oversized datagrams, want exactly 1", n)
	}
}
