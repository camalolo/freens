// Package stun implements the RFC 5389 subset freens needs for §6.2 NAT
// traversal: the classic STUN (Session Traversal Utilities for NAT) Binding
// exchange over UDP. A Client sends one Binding Request and decodes the
// XOR-MAPPED-ADDRESS the server derives from the observed datagram source —
// that server-reflexive public address is what a NAT'd node advertises to its
// DHT peers (exactly like an explicit NodeConfig.Advertise). A Server answers
// Binding Requests with precisely that address; it exists so tests (and
// LAN-only deployments) can run the whole discovery path without external
// infrastructure.
//
// Scope, deliberately narrow (research-grade protocol code):
//
//   - RFC 5389, not RFC 8489: classic STUN with the fixed 0x2112A442 magic
//     cookie and 96-bit crypto/random transaction IDs (§6).
//   - UDP only.
//   - No authentication: the Binding method's short-term credential machinery
//     (§10) adds nothing when the client only wants ITS OWN reflexive
//     address — a spoofed reply must still echo the client's unguessable
//     txid and arrive on the connected socket, which is the real defense.
//   - No FINGERPRINT (§8) or alternate-server: STUN runs on its own port
//     here, never demultiplexed with other protocols.
//   - The client sends a SINGLE request per Discover — no RFC 2988
//     retransmission schedule — because the dht monitor retries whole
//     discoveries at stunRefreshInterval granularity and each Discover must
//     stay bounded at 3 s. Loss recovery is the loop's job, not the
//     transaction's.
//
// Wire format (RFC 5389 §6): every message is a 20-byte header —
//
//	0                   1                   2                   3
//	| type (2) | length (2) | magic cookie (4) | transaction id (12) |
//
// followed by `length` bytes of attributes. Each attribute is type (2),
// length (2), value, with the value zero-padded to a 4-byte boundary (§15);
// the padding bytes are not counted in the attribute length.
package stun

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// RFC 5389 constants.
const (
	// magicCookie is the §6 fixed 32-bit value separating STUN from legacy
	// RFC 3489 traffic. It also keys the XOR-MAPPED-ADDRESS obfuscation
	// (§15.2): port ^ 0x2112 (its top half) and, for IPv4, address ^ cookie.
	magicCookie uint32 = 0x2112A442

	// headerLen: message type (2) + message length (2) + cookie (4) +
	// transaction ID (12) — §6.
	headerLen = 20

	// txidLen is the 96-bit transaction ID length (§6). Generated with
	// crypto/rand so a spoofed reply must guess 96 bits to be accepted.
	txidLen = 12

	// attrHdrLen: attribute type (2) + attribute length (2) (§15).
	attrHdrLen = 4

	// readBufSize bounds one response datagram read. STUN Binding messages
	// are tens of bytes; 2048 is far above maxMessageLen+headerLen and far
	// below the 64 KiB UDP ceiling.
	readBufSize = 2048

	// msgBindingRequest is the Binding method, request class (§13 table:
	// 0b00 method 0x001 → 0x0001).
	msgBindingRequest uint16 = 0x0001
	// msgBindingSuccess is the Binding method, success response class
	// (0b10 << 14 | 0x001 → 0x0101).
	msgBindingSuccess uint16 = 0x0101

	// attrMappedAddress is the §15.1 legacy (RFC 3489-compatible) plain
	// reflexive address; accepted only when XOR-MAPPED-ADDRESS is absent.
	attrMappedAddress uint16 = 0x0001
	// attrXORMappedAddress is the §15.2 preferred reflexive address.
	attrXORMappedAddress uint16 = 0x0020

	// Address family bytes (§15.1).
	familyIPv4 byte = 0x01
	familyIPv6 byte = 0x02

	// maxMessageLen is a hard sanity ceiling on the header's length field
	// (bytes counted AFTER the 20-byte header, §6). A real Binding exchange
	// is ~48 bytes on the wire; anything past 548 is not an exchange this
	// client will walk, and the bound keeps a hostile reply from ballooning
	// the attribute scan.
	maxMessageLen = 548

	// discoverTimeout caps one whole Discover (send + wait) at 3 s, per the
	// project's §6.2 contract. A ctx deadline earlier than this wins.
	discoverTimeout = 3 * time.Second
)

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

// Client performs one-shot RFC 5389 Binding discoveries. The zero value is
// not usable: Server is REQUIRED.
type Client struct {
	// Server is the STUN server as "host:port" (e.g. "stun.example.net:3478"
	// or "10.0.0.4:3478"). REQUIRED.
	Server string
}

// Discover sends one RFC 5389 Binding Request over a fresh UDP socket dialed
// to Client.Server, waits at most 3 s (or the ctx deadline, whichever is
// sooner) for the Binding Success response, and returns the reflexive
// address observed by the server: the XOR-MAPPED-ADDRESS (§15.2) when
// present, falling back to the legacy MAPPED-ADDRESS (§15.1) only when the
// XOR attribute is absent.
//
// Validation before any address is trusted (a spoofed or broken reply must
// never reach the caller): response type 0x0101, magic cookie 0x2112A442,
// exact transaction-ID echo, message length ≤ 548 and consistent with the
// datagram, and a clean TLV attribute walk over 4-byte-aligned values.
//
// The socket is fresh per call — the reflexive address is only meaningful
// for the exact 5-tuple it was observed on, so reusing a socket across
// servers or calls would poison the result.
func (c *Client) Discover(ctx context.Context) (*net.UDPAddr, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if c.Server == "" {
		return nil, errors.New("stun: Client.Server is required")
	}
	raddr, err := net.ResolveUDPAddr("udp", c.Server)
	if err != nil {
		return nil, fmt.Errorf("stun: resolve server %q: %w", c.Server, err)
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, fmt.Errorf("stun: dial %q: %w", c.Server, err)
	}
	defer conn.Close()

	// §6: the transaction ID is 96 bits of crypto-random material. Anything
	// less would let an off-path spoofer precompute replies.
	txid := make([]byte, txidLen)
	if _, err := rand.Read(txid); err != nil {
		return nil, fmt.Errorf("stun: generate transaction id: %w", err)
	}
	return bindingRoundTrip(ctx, conn, txid)
}

// bindingRoundTrip is Discover's send/receive/parse core, split out so tests
// can drive it over a socket they own and compare the result against that
// socket's local address. It sends one Binding Request on the connected
// conn, awaits the response (bounded by discoverTimeout and ctx), and
// validates it against txid.
func bindingRoundTrip(ctx context.Context, conn *net.UDPConn, txid []byte) (*net.UDPAddr, error) {
	if _, err := conn.Write(buildBindingRequest(txid)); err != nil {
		return nil, fmt.Errorf("stun: send binding request: %w", err)
	}
	resp, err := readResponse(ctx, conn)
	if err != nil {
		return nil, err
	}
	return parseBindingResponse(resp, txid)
}

// readResponse awaits one datagram on the connected conn, bounded by
// discoverTimeout and by ctx cancellation (which returns promptly — the
// reader goroutine is abandoned to the socket's deadline and exits when the
// caller's deferred conn.Close unblocks its read).
func readResponse(ctx context.Context, conn *net.UDPConn) ([]byte, error) {
	deadline := time.Now().Add(discoverTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	type result struct {
		buf []byte
		err error
	}
	ch := make(chan result, 1) // buffered: the reader never leaks on send
	go func() {
		buf := make([]byte, readBufSize)
		n, err := conn.Read(buf)
		if err != nil && n <= 0 {
			ch <- result{nil, err}
			return
		}
		ch <- result{buf[:n], nil}
	}()

	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, fmt.Errorf("stun: read response: %w", r.err)
		}
		return r.buf, nil
	case <-timer.C:
		return nil, fmt.Errorf("stun: no response within %v", discoverTimeout)
	case <-ctx.Done():
		return nil, fmt.Errorf("stun: discovery canceled: %w", ctx.Err())
	}
}

// buildBindingRequest encodes a minimal Binding Request (§6 header, zero
// attributes): type 0x0001, length 0, cookie, txid.
func buildBindingRequest(txid []byte) []byte {
	m := make([]byte, headerLen)
	binary.BigEndian.PutUint16(m[0:2], msgBindingRequest)
	binary.BigEndian.PutUint16(m[2:4], 0) // no attributes
	binary.BigEndian.PutUint32(m[4:8], magicCookie)
	copy(m[8:headerLen], txid)
	return m
}

// parseBindingResponse validates one Binding Success response against the
// transaction that elicited it and extracts the reflexive address
// (XOR-MAPPED-ADDRESS preferred, §15.2; MAPPED-ADDRESS only as a legacy
// fallback, §15.1). Every violation returns a descriptive error — a STUN
// reply that fails any check is indistinguishable from garbage and must not
// be trusted for advertisement.
func parseBindingResponse(msg, txid []byte) (*net.UDPAddr, error) {
	if len(msg) < headerLen {
		return nil, fmt.Errorf("stun: response is %d bytes, shorter than the %d-byte header", len(msg), headerLen)
	}
	if mtype := binary.BigEndian.Uint16(msg[0:2]); mtype != msgBindingSuccess {
		return nil, fmt.Errorf("stun: response type 0x%04x, want 0x%04x (Binding Success)", mtype, msgBindingSuccess)
	}
	if cookie := binary.BigEndian.Uint32(msg[4:8]); cookie != magicCookie {
		return nil, fmt.Errorf("stun: magic cookie 0x%08x, want 0x%08x", cookie, magicCookie)
	}
	if !bytes.Equal(msg[8:headerLen], txid) {
		return nil, errors.New("stun: transaction ID mismatch (reply does not echo our request)")
	}
	mlen := int(binary.BigEndian.Uint16(msg[2:4]))
	if mlen > maxMessageLen {
		return nil, fmt.Errorf("stun: message length %d exceeds sanity bound %d", mlen, maxMessageLen)
	}
	if headerLen+mlen > len(msg) {
		return nil, fmt.Errorf("stun: truncated message: length field promises %d attribute bytes, datagram carries %d", mlen, len(msg)-headerLen)
	}

	// Attribute walk (§15): TLV with 4-byte-aligned values. Any structural
	// violation aborts the whole parse.
	var xorAddr, plainAddr *net.UDPAddr
	off, end := headerLen, headerLen+mlen
	for off < end {
		if end-off < attrHdrLen {
			return nil, errors.New("stun: truncated attribute header")
		}
		at := binary.BigEndian.Uint16(msg[off : off+2])
		al := int(binary.BigEndian.Uint16(msg[off+2 : off+4]))
		off += attrHdrLen
		if al > end-off {
			return nil, fmt.Errorf("stun: attribute 0x%04x length %d overruns the message", at, al)
		}
		val := msg[off : off+al]
		switch at {
		case attrXORMappedAddress:
			if xorAddr == nil { // first occurrence wins
				a, err := parseXORAddress(val, txid)
				if err != nil {
					return nil, fmt.Errorf("stun: XOR-MAPPED-ADDRESS: %w", err)
				}
				xorAddr = a
			}
		case attrMappedAddress:
			if plainAddr == nil {
				a, err := parseMappedAddress(val)
				if err != nil {
					return nil, fmt.Errorf("stun: MAPPED-ADDRESS: %w", err)
				}
				plainAddr = a
			}
		}
		off += (al + 3) &^ 3 // skip value + zero padding to a 4-byte boundary
	}

	if xorAddr != nil {
		return xorAddr, nil
	}
	if plainAddr != nil {
		return plainAddr, nil // legacy pre-cookie server: still a valid observation
	}
	return nil, errors.New("stun: response carries neither XOR-MAPPED-ADDRESS nor MAPPED-ADDRESS")
}

// splitAddress splits an address-attribute value (§15.1 layout) into family,
// port and raw address bytes, validating the raw length against the family.
func splitAddress(val []byte) (fam byte, port uint16, raw []byte, err error) {
	if len(val) < 4 {
		return 0, 0, nil, fmt.Errorf("value is %d bytes, want at least 4 (family+port+address)", len(val))
	}
	fam = val[0]
	port = binary.BigEndian.Uint16(val[1:3])
	raw = val[3:]
	switch fam {
	case familyIPv4:
		if len(raw) != 4 {
			return 0, 0, nil, fmt.Errorf("IPv4 address is %d bytes, want 4", len(raw))
		}
	case familyIPv6:
		if len(raw) != 16 {
			return 0, 0, nil, fmt.Errorf("IPv6 address is %d bytes, want 16", len(raw))
		}
	default:
		return 0, 0, nil, fmt.Errorf("unknown address family 0x%02x", fam)
	}
	return fam, port, raw, nil
}

// parseXORAddress decodes a §15.2 XOR-MAPPED-ADDRESS value: family(1),
// port(2), address(4|16). The port is XORed with 0x2112 (the most
// significant 16 bits of the magic cookie); an IPv4 address is XORed byte-
// for-byte with the 4-byte cookie; an IPv6 address is XORed with the
// concatenation of the cookie and the 12-byte transaction ID (16 bytes).
func parseXORAddress(val, txid []byte) (*net.UDPAddr, error) {
	fam, port, raw, err := splitAddress(val)
	if err != nil {
		return nil, err
	}
	port ^= uint16(magicCookie >> 16)
	ip := make(net.IP, len(raw))
	switch fam {
	case familyIPv4:
		var cookie [4]byte
		binary.BigEndian.PutUint32(cookie[:], magicCookie)
		for i := range raw {
			ip[i] = raw[i] ^ cookie[i]
		}
	case familyIPv6:
		var key [16]byte // cookie || txid (§15.2)
		binary.BigEndian.PutUint32(key[0:4], magicCookie)
		copy(key[4:], txid)
		for i := range raw {
			ip[i] = raw[i] ^ key[i]
		}
	}
	return &net.UDPAddr{IP: ip, Port: int(port)}, nil
}

// parseMappedAddress decodes a §15.1 MAPPED-ADDRESS value — the same
// family/port/address layout without any XOR, kept from RFC 3489 for
// compatibility with ancient servers.
func parseMappedAddress(val []byte) (*net.UDPAddr, error) {
	_, port, raw, err := splitAddress(val)
	if err != nil {
		return nil, err
	}
	ip := make(net.IP, len(raw))
	copy(ip, raw)
	return &net.UDPAddr{IP: ip, Port: int(port)}, nil
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

// Server is a minimal RFC 5389 STUN server: it answers well-formed Binding
// Requests with a Binding Success carrying the XOR-MAPPED-ADDRESS derived
// from the observed UDP source, and silently ignores everything else (§7.1:
// "the server ... MUST discard ... non-Binding / malformed messages" — never
// answer unparseable traffic, it is indistinguishable from spoofing probes).
//
// The serve loop is started internally by Listen, mirroring dht.Node's
// Start-owned-loops shape; Close stops it and joins the goroutine.
type Server struct {
	conn *net.UDPConn
	addr *net.UDPAddr // concrete bound address, captured once at Listen

	closed    atomic.Bool
	closeOnce sync.Once
	closeErr  error
	wg        sync.WaitGroup
}

// Listen binds a UDP socket at addr (e.g. "127.0.0.1:0" or ":3478") and
// starts the serve loop. The caller eventually calls Close.
func Listen(addr string) (*Server, error) {
	laddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("stun: resolve %q: %w", addr, err)
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, fmt.Errorf("stun: listen %q: %w", addr, err)
	}
	bound, err := net.ResolveUDPAddr("udp", conn.LocalAddr().String())
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("stun: resolve bound address: %w", err)
	}
	s := &Server{conn: conn, addr: bound}
	s.wg.Add(1)
	go s.serve()
	return s, nil
}

// Addr returns the concrete bound UDP address (useful when Listen was given
// ":0"). It errors after Close.
func (s *Server) Addr() (*net.UDPAddr, error) {
	if s.closed.Load() {
		return nil, errors.New("stun: server closed")
	}
	dup := *s.addr
	dup.IP = append(net.IP(nil), s.addr.IP...)
	return &dup, nil
}

// Close shuts the socket and waits for the serve loop to exit. Idempotent.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		s.closeErr = s.conn.Close()
		s.wg.Wait()
	})
	return s.closeErr
}

// serve is the read loop: one datagram at a time, reply only to well-formed
// Binding Requests. Requests may carry attributes (unknown ones are simply
// not examined — §15 unknown comprehension-optional attributes are ignored;
// Binding itself needs none of them).
func (s *Server) serve() {
	defer s.wg.Done()
	buf := make([]byte, readBufSize)
	for {
		n, raddr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			if s.closed.Load() {
				return
			}
			continue // transient read error (e.g. a spurious ICMP wakeup)
		}
		if !isBindingRequest(buf[:n]) {
			continue // not a Binding Request: silently ignore (§7.1)
		}
		resp := buildBindingSuccess(buf[8:headerLen], raddr)
		if _, err := s.conn.WriteToUDP(resp, raddr); err != nil && s.closed.Load() {
			return
		}
	}
}

// isBindingRequest reports whether m is a structurally well-formed Binding
// Request: full 20-byte header (§6), type 0x0001, the RFC 5389 magic cookie
// (a legacy RFC 3489 request has no cookie and is not worth answering), a
// sane length field, and an attribute area that walks cleanly as aligned
// TLVs. Semantics of the attributes are not examined.
func isBindingRequest(m []byte) bool {
	if len(m) < headerLen {
		return false
	}
	if binary.BigEndian.Uint16(m[0:2]) != msgBindingRequest {
		return false
	}
	if binary.BigEndian.Uint32(m[4:8]) != magicCookie {
		return false
	}
	mlen := int(binary.BigEndian.Uint16(m[2:4]))
	if mlen > maxMessageLen || headerLen+mlen > len(m) {
		return false
	}
	off, end := headerLen, headerLen+mlen
	for off < end {
		if end-off < attrHdrLen {
			return false
		}
		al := int(binary.BigEndian.Uint16(m[off+2 : off+4]))
		off += attrHdrLen + ((al + 3) &^ 3) // header + value + padding
		if off > end {
			return false // attribute (with padding) overruns the message
		}
	}
	return true
}

// buildBindingSuccess encodes the 0x0101 reply for txid, echoing the
// observed source raddr as an XOR-MAPPED-ADDRESS (§15.2): family, port ^
// 0x2112, then the address — IPv4 XORed with the cookie, IPv6 XORed with
// (cookie || txid). One 8- or 20-byte attribute, already 4-byte aligned, so
// no padding byte is needed.
func buildBindingSuccess(txid []byte, raddr *net.UDPAddr) []byte {
	fam := familyIPv4
	raw := raddr.IP.To4()
	if raw == nil {
		fam = familyIPv6
		raw = raddr.IP.To16()
	}
	vlen := 3 + len(raw) // family(1) + port(2) + address

	msg := make([]byte, headerLen+attrHdrLen+vlen)
	binary.BigEndian.PutUint16(msg[0:2], msgBindingSuccess)
	binary.BigEndian.PutUint16(msg[2:4], uint16(attrHdrLen+vlen)) // exactly one attribute
	binary.BigEndian.PutUint32(msg[4:8], magicCookie)
	copy(msg[8:headerLen], txid) // §5.3.2: echo the request's transaction ID

	off := headerLen
	binary.BigEndian.PutUint16(msg[off:off+2], attrXORMappedAddress)
	binary.BigEndian.PutUint16(msg[off+2:off+4], uint16(vlen))
	off += attrHdrLen
	msg[off] = fam
	binary.BigEndian.PutUint16(msg[off+1:off+3], uint16(raddr.Port)^uint16(magicCookie>>16))
	off += 3
	if fam == familyIPv4 {
		var cookie [4]byte
		binary.BigEndian.PutUint32(cookie[:], magicCookie)
		for i := range raw {
			msg[off+i] = raw[i] ^ cookie[i]
		}
	} else {
		var key [16]byte // cookie || txid (§15.2)
		binary.BigEndian.PutUint32(key[0:4], magicCookie)
		copy(key[4:], txid)
		for i := range raw {
			msg[off+i] = raw[i] ^ key[i]
		}
	}
	return msg
}
