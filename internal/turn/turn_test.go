package turn

// turn_test.go pins the RFC 8656 subset end-to-end: codec round trips, the
// auth scheme, the server's allocation/permission/lifetime machinery, and
// the client Conn's transparent tunnel (WriteTo → Send indication → peer
// sees the RELAYED source; peer → relayed address → Data indication →
// ReadFrom).

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/stun"
)

// newTestServer starts a TURN server on an ephemeral loopback port.
func newTestServer(t *testing.T, mut func(*ServerConfig)) *Server {
	t.Helper()
	cfg := ServerConfig{ListenAddr: "127.0.0.1:0"}
	if mut != nil {
		mut(&cfg)
	}
	s, err := ListenTURN(cfg)
	if err != nil {
		t.Fatalf("ListenTURN: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// dialTest allocates on srv with a fresh node key.
func dialTest(t *testing.T, srv *Server) *Conn {
	t.Helper()
	a, err := srv.Addr()
	if err != nil {
		t.Fatalf("Addr: %v", err)
	}
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	c, err := (&Client{Server: a.String(), NodeKey: kp}).Dial(context.Background())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// udpPeer is a plain socket playing a DHT peer.
type udpPeer struct {
	conn *net.UDPConn
	addr *net.UDPAddr
}

func newUDPPeer(t *testing.T) *udpPeer {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	a, _ := net.ResolveUDPAddr("udp", conn.LocalAddr().String())
	return &udpPeer{conn: conn, addr: a}
}

func (p *udpPeer) recv(t *testing.T, timeout time.Duration) ([]byte, *net.UDPAddr) {
	t.Helper()
	if err := p.conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	n, from, err := p.conn.ReadFromUDP(buf)
	if err != nil {
		return nil, nil
	}
	return buf[:n], from
}

// TestServerClientEndToEnd: allocation, WriteTo through the tunnel (peer
// sees the RELAYED source), and ReadFrom for the reply path.
func TestServerClientEndToEnd(t *testing.T) {
	srv := newTestServer(t, nil)
	c := dialTest(t, srv)
	relayed := c.RelayedAddr()
	if relayed == nil || relayed.Port == 0 {
		t.Fatalf("no relayed address: %v", relayed)
	}
	sa, _ := srv.Addr()
	if relayed.Port == sa.Port {
		t.Fatal("relayed port equals the server control port")
	}
	peer := newUDPPeer(t)

	if n, err := c.WriteTo([]byte("knock-knock"), peer.addr); err != nil || n != len("knock-knock") {
		t.Fatalf("WriteTo: %d %v", n, err)
	}
	data, from := peer.recv(t, 2*time.Second)
	if data == nil {
		t.Fatal("peer never received the tunnelled payload")
	}
	if !bytes.Equal(data, []byte("knock-knock")) {
		t.Fatalf("payload mangled: %q", data)
	}
	if from.String() != relayed.String() {
		t.Fatalf("peer saw source %v, want the relayed %v", from, relayed)
	}

	// Reply to the RELAYED address; the client must read it with the
	// peer as the source.
	if _, err := peer.conn.WriteToUDP([]byte("who-there"), relayed); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	if err := c.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, src, err := c.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if !bytes.Equal(buf[:n], []byte("who-there")) || src.String() != peer.addr.String() {
		t.Fatalf("reply path wrong: %q from %v", buf[:n], src)
	}
}

// TestPermissionEnforcement: a peer the client never wrote to is NOT
// relayed (TURN anti-spam).
func TestPermissionEnforcement(t *testing.T) {
	srv := newTestServer(t, nil)
	c := dialTest(t, srv)
	relayed := c.RelayedAddr()
	stranger := newUDPPeer(t)

	if _, err := stranger.conn.WriteToUDP([]byte("spam"), relayed); err != nil {
		t.Fatal(err)
	}
	if err := c.SetDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if n, _, err := c.ReadFrom(make([]byte, 128)); err == nil {
		t.Fatalf("unpermitted stranger was relayed: %d bytes", n)
	}
	// The same peer becomes reachable the moment the client initiates.
	if _, err := c.WriteTo([]byte("hello"), stranger.addr); err != nil {
		t.Fatal(err)
	}
	if _, err := stranger.conn.WriteToUDP([]byte("ok"), relayed); err != nil {
		t.Fatal(err)
	}
	if err := c.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.ReadFrom(make([]byte, 128)); err != nil {
		t.Fatalf("permitted peer not relayed after initiation: %v", err)
	}
}

// TestAuthRejectsBadSignatures: unsigned and tampered Allocate requests
// draw 401; the client surfaces it.
func TestAuthRejectsBadSignatures(t *testing.T) {
	srv := newTestServer(t, nil)
	sa, err := srv.Addr()
	if err != nil {
		t.Fatal(err)
	}

	// Unsigned Allocate via a raw socket.
	raw, _ := net.DialUDP("udp", nil, sa)
	defer raw.Close()
	m, _ := newTxID(methodAllocate, classRequest)
	m.add(attrLifetime, be32(600))
	b, _ := m.encode()
	if _, err := raw.Write(b); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	_ = raw.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := raw.ReadFromUDP(buf)
	if err != nil {
		t.Fatal("no response to unsigned Allocate")
	}
	resp, err := parseMessage(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if resp.class != classError {
		t.Fatalf("unsigned Allocate got class %d, want error", resp.class)
	}
	if code, _ := decodeErrorCode(resp.get(attrErrorCode)); code != 401 {
		t.Fatalf("error code %d, want 401", code)
	}

	// Signed with the WRONG key (signature over a different node key's
	// bytes does not verify).
	kp, _ := crypto.Generate()
	other, _ := crypto.Generate()
	m2, _ := newTxID(methodAllocate, classRequest)
	m2.add(attrLifetime, be32(600))
	sign(m2, kp.Public(), other.Sign)
	b2, _ := m2.encode()
	if _, err := raw.Write(b2); err != nil {
		t.Fatal(err)
	}
	_ = raw.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err = raw.ReadFromUDP(buf)
	if err != nil {
		t.Fatal("no response to mis-signed Allocate")
	}
	resp2, err2 := parseMessage(buf[:n])
	if err2 != nil {
		t.Fatal(err2)
	}
	if code, _ := decodeErrorCode(resp2.get(attrErrorCode)); code != 401 {
		t.Fatalf("mis-signed Allocate code %d, want 401", code)
	}
}

// TestRefreshKeepsAllocation: with a 1s server default lifetime the refresh
// loop keeps the allocation past 3s; Close releases it promptly.
func TestRefreshKeepsAllocation(t *testing.T) {
	srv := newTestServer(t, func(c *ServerConfig) { c.DefaultLifetime = time.Second })
	c := dialTest(t, srv)
	relayed := c.RelayedAddr()

	// Park a reader so refresh responses are absorbed, not queued.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			if err := c.SetDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
				return
			}
			if _, _, err := c.ReadFrom(make([]byte, 128)); err != nil {
				return
			}
		}
	}()

	time.Sleep(3 * time.Second) // > 3× the default lifetime: only refreshes keep it
	if got := srv.Allocations(); got != 1 {
		t.Fatalf("allocations = %d after 3s with 1s lifetime, want 1 (refresh failed?)", got)
	}
	_ = c.Close()
	wg.Wait()
	deadline := time.Now().Add(2 * time.Second)
	for srv.Allocations() != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := srv.Allocations(); got != 0 {
		t.Fatalf("allocations = %d after Close, want 0", got)
	}
	_ = relayed // (silence linters; the address itself is checked elsewhere)
}

// TestPerIPAllocationCap: MaxAllocsPerIP=2 rejects a third concurrent Dial.
func TestPerIPAllocationCap(t *testing.T) {
	srv := newTestServer(t, func(c *ServerConfig) { c.MaxAllocsPerIP = 2 })
	dialTest(t, srv)
	dialTest(t, srv)
	sa, _ := srv.Addr()
	kp, _ := crypto.Generate()
	if _, err := (&Client{Server: sa.String(), NodeKey: kp}).Dial(context.Background()); err == nil {
		t.Fatal("third concurrent allocation from the same IP succeeded; want 438")
	}
}

// TestBindingOnTurnPort: the server answers plain STUN Binding, so -turn
// doubles as a -stun target.
func TestBindingOnTurnPort(t *testing.T) {
	srv := newTestServer(t, nil)
	sa, err := srv.Addr()
	if err != nil {
		t.Fatal(err)
	}
	got, err := (&stun.Client{Server: sa.String()}).Discover(context.Background())
	if err != nil {
		t.Fatalf("stun Discover against TURN port: %v", err)
	}
	if got == nil || got.Port == 0 {
		t.Fatalf("bad reflexive address %v", got)
	}
}

// TestCodecMethodClasses: msgType/splitMsgType round-trip the 5 TURN
// methods × 4 classes and hit the RFC's exact wire values.
func TestCodecMethodClasses(t *testing.T) {
	want := map[[2]uint16]uint16{
		{methodAllocate, classRequest}:         0x0003,
		{methodAllocate, classSuccess}:         0x0103,
		{methodAllocate, classError}:           0x0113,
		{methodRefresh, classRequest}:          0x0004,
		{methodRefresh, classSuccess}:          0x0104,
		{methodSend, classIndication}:          0x0016,
		{methodData, classIndication}:          0x0017,
		{methodCreatePermission, classRequest}: 0x0008,
		{methodCreatePermission, classSuccess}: 0x0108,
		{methodBinding, classRequest}:          0x0001,
		{methodBinding, classSuccess}:          0x0101,
	}
	for mc, w := range want {
		if got := msgType(mc[0], mc[1]); got != w {
			t.Fatalf("msgType(%#x,%d) = %#04x, want %#04x", mc[0], mc[1], got, w)
		}
		m, c := splitMsgType(w)
		if m != mc[0] || c != mc[1] {
			t.Fatalf("splitMsgType(%#04x) = (%#x,%d), want (%#x,%d)", w, m, c, mc[0], mc[1])
		}
	}
}

// TestErrorCodeRoundTrip.
func TestErrorCodeRoundTrip(t *testing.T) {
	for _, code := range []int{401, 437, 438, 508} {
		got, _ := decodeErrorCode(encodeErrorCode(code, "x"))
		if got != code {
			t.Fatalf("code %d round-tripped as %d", code, got)
		}
	}
}

// TestAuthMessageDerivation: the signed bytes bind txid, key, and lifetime —
// flipping any lifetime byte must invalidate.
func TestAuthMessageDerivation(t *testing.T) {
	kp, _ := crypto.Generate()
	m, _ := newTxID(methodAllocate, classRequest)
	m.add(attrLifetime, be32(600))
	sign(m, kp.Public(), kp.Sign)
	if !verifyAuth(m, crypto.Verify) {
		t.Fatal("well-formed auth rejected")
	}
	tampered, _ := newTxID(methodAllocate, classRequest)
	tampered.add(attrLifetime, be32(600))
	sign(tampered, kp.Public(), kp.Sign)
	// Flip the lifetime AFTER signing (as an attacker would).
	for _, vs := range tampered.attr {
		_ = vs
	}
	tampered.attr[attrLifetime] = [][]byte{be32(601)}
	if verifyAuth(tampered, crypto.Verify) {
		t.Fatal("post-signature lifetime tamper verified — auth derivation broken")
	}
	_ = ed25519.SignatureSize
}

// TestServerNeverPanicsOnGarbage: malformed datagrams are dropped, and the
// server keeps serving afterwards.
func TestServerNeverPanicsOnGarbage(t *testing.T) {
	srv := newTestServer(t, nil)
	sa, err := srv.Addr()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := net.DialUDP("udp", nil, sa)
	defer raw.Close()
	garbage := [][]byte{
		nil, {}, {0x00}, make([]byte, 19), // short
		append([]byte{0x00, 0x03, 0xFF, 0xFF}, make([]byte, 16)...),                         // length overrun
		append([]byte{0x00, 0x03, 0x00, 0x04, 0x21, 0x12, 0xA4, 0x42}, make([]byte, 12)...), // no cookie issue: cookie ok, body junk
		bytes.Repeat([]byte{0xFF}, 1500),
	}
	for _, g := range garbage {
		_, _ = raw.Write(g)
	}
	time.Sleep(50 * time.Millisecond)
	// Still alive:
	c := dialTest(t, srv)
	peer := newUDPPeer(t)
	if _, err := c.WriteTo([]byte("still-alive"), peer.addr); err != nil {
		t.Fatal(err)
	}
	if data, _ := peer.recv(t, 2*time.Second); data == nil {
		t.Fatal("server stopped serving after garbage")
	}
}

// TestXORAddressIPv6RoundTrip keeps the v6 path honest.
func TestXORAddressIPv6RoundTrip(t *testing.T) {
	m, _ := newTxID(methodData, classIndication)
	a := &net.UDPAddr{IP: net.ParseIP("::1"), Port: 65535}
	v, err := xorAddr(a, m.txid)
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 20 {
		t.Fatalf("v6 value length %d, want 20", len(v))
	}
	got, err := decodeXORAddr(v, m.txid)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != a.String() {
		t.Fatalf("round trip: %v ≠ %v", got, a)
	}
}

// TestServerClientEndToEndIPv6 — allocation, tunneled WriteTo (peer sees the
// v6 RELAYED source), and ReadFrom reply, all over [::1]. Skipped where v6
// loopback is unavailable.
func TestServerClientEndToEndIPv6(t *testing.T) {
	if c, err := net.Dial("udp6", "[::1]:1"); err != nil {
		t.Skip("no IPv6 loopback")
	} else {
		_ = c.Close()
	}
	srv := newTestServer(t, func(c *ServerConfig) { c.ListenAddr = "[::1]:0" })
	a, err := srv.Addr()
	if err != nil {
		t.Fatal(err)
	}
	kp, _ := crypto.Generate()
	cl, err := (&Client{Server: a.String(), NodeKey: kp}).Dial(context.Background())
	if err != nil {
		t.Fatalf("Dial over v6: %v", err)
	}
	t.Cleanup(func() { _ = cl.Close() })
	relayed := cl.RelayedAddr()
	if relayed == nil || relayed.IP == nil || relayed.IP.To4() != nil {
		t.Fatalf("relayed address %v, want IPv6", relayed)
	}
	// v6 "peer" socket.
	pconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("::1")})
	if err != nil {
		t.Skipf("v6 peer socket: %v", err)
	}
	t.Cleanup(func() { _ = pconn.Close() })
	peerAddr, _ := net.ResolveUDPAddr("udp", pconn.LocalAddr().String())

	if _, err := cl.WriteTo([]byte("v6knock"), peerAddr); err != nil {
		t.Fatalf("WriteTo over v6: %v", err)
	}
	_ = pconn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, from, err := pconn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("peer never received: %v", err)
	}
	if !bytes.Equal(buf[:n], []byte("v6knock")) || from.String() != relayed.String() {
		t.Fatalf("peer got %q from %v (want relayed %v)", buf[:n], from, relayed)
	}
	if _, err := pconn.WriteToUDP([]byte("v6back"), relayed); err != nil {
		t.Fatal(err)
	}
	_ = cl.SetDeadline(time.Now().Add(2 * time.Second))
	if _, src, err := cl.ReadFrom(make([]byte, 128)); err != nil || src.String() != peerAddr.String() {
		t.Fatalf("ReadFrom over v6: %v %v", src, err)
	}
}
