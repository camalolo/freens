package stun

// stun_test.go exercises the RFC 5389 subset end-to-end on loopback: a real
// Client/Server Binding round-trip, the client's response-validation
// rejections (table-driven), the MAPPED-ADDRESS fallback and XOR precedence,
// and the server's ignore-then-answer behavior.
//
// The test-side attribute builders below intentionally REIMPLEMENT the §15
// encoders from the RFC text rather than reusing stun.go's, so a bug in the
// production encoder cannot hide behind a tautological test.

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// --- test-side RFC 5389 encoders (independent of stun.go) -----------------

// tHeader builds a §6 message of typ around attrs (each padded per §15).
func tHeader(typ uint16, txid []byte, attrs ...[]byte) []byte {
	body := make([]byte, 0, maxMessageLen)
	for _, a := range attrs {
		body = append(body, a...)
		for len(body)%4 != 0 { // §15: pad each value to a 4-byte boundary
			body = append(body, 0)
		}
	}
	m := make([]byte, headerLen+len(body))
	binary.BigEndian.PutUint16(m[0:2], typ)
	binary.BigEndian.PutUint16(m[2:4], uint16(len(body)))
	binary.BigEndian.PutUint32(m[4:8], magicCookie)
	copy(m[8:headerLen], txid)
	copy(m[headerLen:], body)
	return m
}

// tAttr wraps one attribute value in the §15 TLV header.
func tAttr(typ uint16, val []byte) []byte {
	b := make([]byte, attrHdrLen+len(val))
	binary.BigEndian.PutUint16(b[0:2], typ)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(val)))
	copy(b[attrHdrLen:], val)
	return b
}

// tXORValue encodes a §15.2 XOR-MAPPED-ADDRESS value for ip:port under txid
// (IPv4 form: port ^ 0x2112, address ^ cookie).
func tXORValue(ip net.IP, port int, txid []byte) []byte {
	cookie := [4]byte{0x21, 0x12, 0xa4, 0x42}
	p := uint16(port) ^ 0x2112
	v := []byte{0, familyIPv4, byte(p >> 8), byte(p)} // §15.2: zero byte first
	ip4 := ip.To4()
	for i := range ip4 {
		v = append(v, ip4[i]^cookie[i])
	}
	return v
}

// tPlainValue encodes a §15.1 MAPPED-ADDRESS value (no XOR).
func tPlainValue(ip net.IP, port int) []byte {
	p := uint16(port)
	v := []byte{0, familyIPv4, byte(p >> 8), byte(p)} // §15.1: zero byte first
	return append(v, ip.To4()...)
}

// startFake binds a loopback UDP socket answering every datagram with
// fn's reply (nil ⇒ silence) and returns its address. Closed via t.Cleanup.
type fakeReply func(req []byte, src *net.UDPAddr) []byte

func startFake(t *testing.T, fn fakeReply) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("fake STUN listen: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, readBufSize)
		for {
			n, src, err := conn.ReadFromUDP(buf)
			if err != nil {
				return // socket closed
			}
			req := append([]byte(nil), buf[:n]...)
			peer := *src
			if out := fn(req, &peer); len(out) > 0 {
				_, _ = conn.WriteToUDP(out, &peer)
			}
		}
	}()
	return conn.LocalAddr().String()
}

// --- client + server round-trip -------------------------------------------

// TestServerClientRoundTrip: a Discover over a socket the test owns must
// return exactly that socket's local address as observed by the real server
// (on loopback the reflexive address IS the local one).
func TestServerClientRoundTrip(t *testing.T) {
	t.Parallel()
	srv, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer srv.Close()
	raddr, err := srv.Addr()
	if err != nil {
		t.Fatalf("Addr: %v", err)
	}

	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		t.Fatalf("dial stun server: %v", err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	txid := make([]byte, txidLen)
	for i := range txid {
		txid[i] = byte(i + 1)
	}
	got, err := bindingRoundTrip(ctx, conn, txid)
	if err != nil {
		t.Fatalf("bindingRoundTrip: %v", err)
	}
	if local := conn.LocalAddr().String(); got.String() != local {
		t.Fatalf("reflexive address %v != socket local address %v", got, local)
	}
}

// TestClientRejectsMalformedResponses: every malformed / mismatched response
// must produce a descriptive error, never an address.
func TestClientRejectsMalformedResponses(t *testing.T) {
	t.Parallel()
	replyIP := net.IPv4(203, 0, 113, 7) // TEST-NET-3: never ours
	cases := []struct {
		name  string
		reply fakeReply
	}{
		{"garbage bytes", func([]byte, *net.UDPAddr) []byte {
			return []byte("this is definitively not a STUN message")
		}},
		{"two-byte stub", func([]byte, *net.UDPAddr) []byte {
			return []byte{0x01, 0x01}
		}},
		{"wrong type (binding error response)", func(req []byte, src *net.UDPAddr) []byte {
			return tHeader(0x0111, req[8:headerLen],
				tAttr(attrXORMappedAddress, tXORValue(src.IP, src.Port, req[8:headerLen])))
		}},
		{"wrong type (binding indication)", func(req []byte, src *net.UDPAddr) []byte {
			return tHeader(0x0011, req[8:headerLen],
				tAttr(attrXORMappedAddress, tXORValue(src.IP, src.Port, req[8:headerLen])))
		}},
		{"bad magic cookie", func(req []byte, src *net.UDPAddr) []byte {
			m := tHeader(msgBindingSuccess, req[8:headerLen],
				tAttr(attrXORMappedAddress, tXORValue(src.IP, src.Port, req[8:headerLen])))
			m[4] = 0 // RFC 3489-style header: no cookie
			return m
		}},
		{"transaction id mismatch", func(req []byte, src *net.UDPAddr) []byte {
			other := append([]byte(nil), req[8:headerLen]...)
			other[0] ^= 0xff
			return tHeader(msgBindingSuccess, other,
				tAttr(attrXORMappedAddress, tXORValue(replyIP, 4444, other)))
		}},
		{"truncated body", func(req []byte, src *net.UDPAddr) []byte {
			// Length field promises an 8-byte attribute; none is sent.
			m := make([]byte, headerLen)
			binary.BigEndian.PutUint16(m[0:2], msgBindingSuccess)
			binary.BigEndian.PutUint16(m[2:4], 8)
			binary.BigEndian.PutUint32(m[4:8], magicCookie)
			copy(m[8:headerLen], req[8:headerLen])
			return m
		}},
		{"length field above sanity bound", func(req []byte, src *net.UDPAddr) []byte {
			m := tHeader(msgBindingSuccess, req[8:headerLen],
				tAttr(attrXORMappedAddress, tXORValue(src.IP, src.Port, req[8:headerLen])))
			binary.BigEndian.PutUint16(m[2:4], 600) // > 548
			return m
		}},
		{"attribute overruns message", func(req []byte, src *net.UDPAddr) []byte {
			m := tHeader(msgBindingSuccess, req[8:headerLen],
				tAttr(attrXORMappedAddress, tXORValue(src.IP, src.Port, req[8:headerLen])))
			// Shrink the message length so the attribute no longer fits.
			binary.BigEndian.PutUint16(m[2:4], uint16(len(m)-headerLen-4))
			return m
		}},
		{"no address attribute at all", func(req []byte, src *net.UDPAddr) []byte {
			return tHeader(msgBindingSuccess, req[8:headerLen],
				tAttr(0x8022, []byte("freens-test"))) // SOFTWARE, §15.10
		}},
		{"bad address family", func(req []byte, src *net.UDPAddr) []byte {
			return tHeader(msgBindingSuccess, req[8:headerLen],
				tAttr(attrXORMappedAddress, []byte{0x07, 0x00, 0x00, 1, 2, 3, 4}))
		}},
		{"ipv4 value with ipv6 length", func(req []byte, src *net.UDPAddr) []byte {
			return tHeader(msgBindingSuccess, req[8:headerLen],
				tAttr(attrXORMappedAddress, append([]byte{0, familyIPv6, 0, 0}, replyIP.To4()...)))
		}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := (&Client{Server: startFake(t, tc.reply)}).Discover(context.Background())
			if err == nil {
				t.Fatalf("Discover should reject %q, got address %v", tc.name, got)
			}
			if got != nil {
				t.Fatalf("Discover(%q) returned error AND address %v", tc.name, got)
			}
		})
	}
}

// TestClientMappedAddressFallback: with no XOR attribute present the legacy
// §15.1 MAPPED-ADDRESS is honored (a known address is fed through so the
// equality is exact, not self-referential).
func TestClientMappedAddressFallback(t *testing.T) {
	t.Parallel()
	want := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 9), Port: 47654} // TEST-NET-2
	addr := startFake(t, func(req []byte, src *net.UDPAddr) []byte {
		return tHeader(msgBindingSuccess, req[8:headerLen],
			tAttr(attrMappedAddress, tPlainValue(want.IP, want.Port)))
	})
	got, err := (&Client{Server: addr}).Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover (MAPPED fallback): %v", err)
	}
	if !got.IP.Equal(want.IP) || got.Port != want.Port {
		t.Fatalf("fallback address = %v, want %v", got, want)
	}
}

// TestClientPrefersXOROverMapped: when both attributes are present the §15.2
// XOR-MAPPED-ADDRESS wins over the legacy plain one.
func TestClientPrefersXOROverMapped(t *testing.T) {
	t.Parallel()
	xorWant := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 1111}
	plainDecoy := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 8), Port: 2222}
	addr := startFake(t, func(req []byte, src *net.UDPAddr) []byte {
		txid := req[8:headerLen]
		return tHeader(msgBindingSuccess, txid,
			tAttr(attrMappedAddress, tPlainValue(plainDecoy.IP, plainDecoy.Port)),
			tAttr(attrXORMappedAddress, tXORValue(xorWant.IP, xorWant.Port, txid)))
	})
	got, err := (&Client{Server: addr}).Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if !got.IP.Equal(xorWant.IP) || got.Port != xorWant.Port {
		t.Fatalf("address = %v, want the XOR-MAPPED-ADDRESS %v", got, xorWant)
	}
}

// TestParseXORAddressIPv6: the §15.2 IPv6 form (address XOR cookie||txid,
// 20-byte value) parses — unit-level, since the test host may lack IPv6.
func TestParseXORAddressIPv6(t *testing.T) {
	t.Parallel()
	txid := make([]byte, txidLen)
	for i := range txid {
		txid[i] = byte(0xa0 + i)
	}
	ip := net.ParseIP("2001:db8::1")
	key := make([]byte, 16)
	binary.BigEndian.PutUint32(key[0:4], magicCookie)
	copy(key[4:], txid)
	val := make([]byte, 0, 20)
	p := uint16(4040) ^ 0x2112
	val = append(val, 0, familyIPv6, byte(p>>8), byte(p)) // §15.2: zero byte first
	for i := 0; i < 16; i++ {
		val = append(val, ip.To16()[i]^key[i])
	}
	msg := tHeader(msgBindingSuccess, txid, tAttr(attrXORMappedAddress, val))
	got, err := parseBindingResponse(msg, txid)
	if err != nil {
		t.Fatalf("parseBindingResponse (IPv6): %v", err)
	}
	if !got.IP.Equal(ip) || got.Port != 4040 {
		t.Fatalf("IPv6 reflexive address = %v, want [2001:db8::1]:4040", got)
	}
}

// TestDiscoverRequiresServer: the pinned Client contract makes Server
// REQUIRED; an empty one errors before any socket work.
func TestDiscoverRequiresServer(t *testing.T) {
	t.Parallel()
	if _, err := (&Client{}).Discover(context.Background()); err == nil {
		t.Fatal("Discover with empty Server should error")
	}
}

// TestDiscoverContextCancel: a ctx cancellation returns promptly even while
// the server stays silent (the 3 s cap must not swallow it).
func TestDiscoverContextCancel(t *testing.T) {
	t.Parallel()
	addr := startFake(t, func([]byte, *net.UDPAddr) []byte { return nil }) // silence
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	if _, err := (&Client{Server: addr}).Discover(ctx); err == nil {
		t.Fatal("Discover against a silent server with a canceled ctx should error")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Discover ignored ctx cancellation (took %v)", elapsed)
	}
}

// --- server behavior -------------------------------------------------------

// TestServerAddrAndClose: Listen on :0 binds a concrete loopback address,
// Close is idempotent, and Addr errors afterwards.
func TestServerAddrAndClose(t *testing.T) {
	t.Parallel()
	srv, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	a, err := srv.Addr()
	if err != nil {
		t.Fatalf("Addr: %v", err)
	}
	if a.Port == 0 || !a.IP.IsLoopback() {
		t.Fatalf("bound address %v, want a concrete loopback one", a)
	}
	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := srv.Close(); err != nil {
		t.Fatalf("second Close should be idempotent, got %v", err)
	}
	if _, err := srv.Addr(); err == nil {
		t.Fatal("Addr after Close should error")
	}
}

// TestServerIgnoresNonBindingTraffic: garbage, a Binding SUCCESS (wrong
// direction), and a cookie-less request all go unanswered — then a real
// Binding Request on the same socket still gets a correct reply.
func TestServerIgnoresNonBindingTraffic(t *testing.T) {
	t.Parallel()
	srv, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer srv.Close()
	raddr, err := srv.Addr()
	if err != nil {
		t.Fatalf("Addr: %v", err)
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		t.Fatalf("dial stun server: %v", err)
	}
	defer conn.Close()

	txid := make([]byte, txidLen)
	for i := range txid {
		txid[i] = byte(0x10 + i)
	}
	if _, err := conn.Write([]byte("garbage that is not stun")); err != nil {
		t.Fatalf("write garbage: %v", err)
	}
	if _, err := conn.Write(buildBindingSuccess(txid, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999})); err != nil {
		t.Fatalf("write success-as-request: %v", err)
	}
	legacy := buildBindingRequest(txid)
	legacy[4] ^= 0xff // corrupt the magic cookie
	if _, err := conn.Write(legacy); err != nil {
		t.Fatalf("write cookie-less request: %v", err)
	}

	// None of the above may be answered.
	if err := conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 128)
	if n, err := conn.Read(buf); err == nil {
		t.Fatalf("server answered %d bytes to non-Binding traffic", n)
	}

	// A well-formed request on the SAME socket still gets the right answer.
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("reset deadline: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	got, err := bindingRoundTrip(ctx, conn, txid)
	if err != nil {
		t.Fatalf("bindingRoundTrip after ignored traffic: %v", err)
	}
	if local := conn.LocalAddr().String(); got.String() != local {
		t.Fatalf("reflexive address %v != socket local address %v", got, local)
	}
}

// TestServerClientRoundTripIPv6 — the codec and sockets are family-agnostic
// (§15.2 XOR covers IPv6 with cookie||txid); pin the loopback v6 path end
// to end. Skipped where [::1] is unavailable.
func TestServerClientRoundTripIPv6(t *testing.T) {
	c, err := net.Dial("udp6", "[::1]:1")
	if err != nil {
		t.Skip("no IPv6 loopback")
	}
	_ = c.Close()
	srv, err := Listen("[::1]:0")
	if err != nil {
		t.Fatalf("Listen v6: %v", err)
	}
	defer srv.Close()
	sa, err := srv.Addr()
	if err != nil {
		t.Fatal(err)
	}
	if sa.IP.To4() != nil {
		t.Fatalf("bound %v, want v6", sa)
	}
	got, err := (&Client{Server: sa.String()}).Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover over v6: %v", err)
	}
	if got == nil || got.IP == nil || got.IP.To4() != nil || got.Port == 0 {
		t.Fatalf("reflexive address %v, want IPv6 with a port", got)
	}
}
