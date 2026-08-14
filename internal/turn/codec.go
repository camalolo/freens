// Package turn implements the freens subset of TURN (RFC 8656, "Traversal
// Using Relays around NAT") over the RFC 5389 STUN message format: a
// community relay SERVER (nodes with spare bandwidth relay for the network)
// and a client Conn (a symmetric-NAT node's tunnel for ALL peer UDP).
//
// # Scope
//
// Methods: Allocate (0x003), Refresh (0x004), Send indication (0x006), Data
// indication (0x007), CreatePermission (0x008), plus plain STUN Binding on
// the server socket (so a -turn daemon doubles as a -stun server). Classes:
// request / indication / success / error. Attributes: XOR-PEER-ADDRESS
// (0x0012), DATA (0x0013), XOR-RELAYED-ADDRESS (0x0016), LIFETIME (0x000D),
// ERROR-CODE (0x0009), and the custom comprehension-optional auth pair
// NODE-KEY (0x8022) / NODE-SIGNATURE (0x8023).
//
// Deliberately SKIPPED (documented simplifications, none load-bearing at
// DHT traffic rates):
//
//   - ChannelData / ChannelBind: Send/Data indications carry ~20 bytes of
//     overhead per datagram; channel binding exists to shave that for media
//     streams. freens datagrams are small and rare by comparison.
//   - FINGERPRINT, ICE, TCP/TLS transports, EVEN-PORT/DONT-FRAGMENT.
//   - The RFC's digest (MESSAGE-INTEGRITY) auth — replaced by the
//     freens-native scheme below, since both ends of this protocol are
//     freens nodes.
//
// # Authentication
//
// Allocate/Refresh/CreatePermission requests carry NODE-KEY (an Ed25519
// node public key) and NODE-SIGNATURE, an Ed25519 signature over
//
//	"freens-turn-v1" || txid(12) || node_key(32) || lifetime_be(8)
//
// where lifetime is the request's LIFETIME attribute value (0 when absent)
// as a big-endian uint64 SECONDS. txid is fresh crypto/rand per request, so
// the signed bytes are a challenge-response: replaying a captured request
// from a different 5-tuple fails (the allocation is bound to the source
// address), and same-tuple replays are idempotent-ish (an Allocate replaces
// the caller's existing allocation; a Refresh re-extends).
//
// Abuse posture, stated plainly: possession of SOME freens node key is cheap
// (anyone can generate one), so the signature binds allocations to an
// identity, not to an ACL. The real gates are the server's per-IP
// allocation cap, bounded lifetimes with mandatory refresh, per-allocation
// permission lists, and the failed-auth rate limit. Operators wanting
// stronger policy should front the port (firewall) or run the relay for a
// known community only.
//
// # Permissions and what a relayed node can do
//
// TURN relays only traffic to/from peers the CLIENT has created a
// permission for (full IP:port here — stricter than the RFC's IP-scoped
// rule, and simpler). Our client creates permissions lazily on first
// WriteTo, so a relayed freens node can do everything it INITIATES:
// bootstrap, bucket refresh, iterative lookups, publishes, pings — the
// DHT's whole active vocabulary. What it cannot receive is UNSOLICITED
// inbound from peers it has never contacted: a stranger's datagram to the
// relayed address is dropped at the relay (standard TURN anti-spam). In
// Kademlia terms the relayed node is a full participant but a poor
// "closest node" target; lookups tolerate this (they proceed to the next
// candidate), and the §6.4 republish timer keeps its records available on
// reachable nodes.
package turn

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
)

// ---------------------------------------------------------------------------
// Constants (RFC 5389 §6 / RFC 8656 §13)
// ---------------------------------------------------------------------------

const (
	magicCookie uint32 = 0x2112A442
	headerLen          = 20 // type(2) len(2) cookie(4) txid(12)
	txidLen            = 12
	attrHdrLen         = 4

	// Classes (2 bits split across the message type: C1 at bit 8, C0 at
	// bit 4 — RFC 5389 §5).
	classRequest    = 0
	classIndication = 1
	classSuccess    = 2
	classError      = 3

	// Methods.
	methodBinding          uint16 = 0x001
	methodAllocate         uint16 = 0x003
	methodRefresh          uint16 = 0x004
	methodSend             uint16 = 0x006
	methodData             uint16 = 0x007
	methodCreatePermission uint16 = 0x008

	// Attributes.
	attrErrorCode         uint16 = 0x0009
	attrLifetime          uint16 = 0x000D
	attrXORPeerAddress    uint16 = 0x0012
	attrData              uint16 = 0x0013
	attrXORRelayedAddress uint16 = 0x0016
	attrXORMappedAddress  uint16 = 0x0020
	// Custom comprehension-optional auth attributes (0x8000+ range: a
	// standard TURN server that does not know them ignores them and fails
	// the request on its own auth terms).
	attrNodeKey       uint16 = 0x8022
	attrNodeSignature uint16 = 0x8023

	familyIPv4 byte = 0x01
	familyIPv6 byte = 0x02

	// maxMessageLen caps the header length field (bytes after the header).
	maxMessageLen = 2048

	// authTag domain-separates the node-key signature (mirrors
	// wire.RecoverySigningTag).
	authTag = "freens-turn-v1"
)

// msgType packs method + class into the 14-bit STUN message type
// (RFC 5389 §5: M11..M8 C1 M7..M4 C0 M3..M0).
func msgType(method, class uint16) uint16 {
	return ((method & 0x1F80) << 2) | ((class & 2) << 7) | ((method & 0x0070) << 1) | ((class & 1) << 4) | (method & 0x000F)
}

// splitMsgType unpacks a STUN message type into method + class (the inverse
// of msgType: method bits 11..7 live at type bits 13..9, bits 6..4 at bits
// 7..5, bits 3..0 at the bottom; C1/C0 at bits 8/4).
func splitMsgType(t uint16) (method, class uint16) {
	method = ((t & 0x3E00) >> 2) | ((t & 0x00E0) >> 1) | (t & 0x000F)
	class = ((t & 0x0100) >> 7) | ((t & 0x0010) >> 4)
	return method, class
}

// ---------------------------------------------------------------------------
// Message
// ---------------------------------------------------------------------------

// message is one decoded/encodable STUN/TURN datagram. Attributes are kept
// per-type as ordered value lists (CreatePermission may repeat
// XOR-PEER-ADDRESS); single-valued access goes through get.
type message struct {
	method uint16
	class  uint16
	txid   [txidLen]byte
	attr   map[uint16][][]byte
}

func newMessage(method, class uint16) *message {
	return &message{method: method, class: class, attr: make(map[uint16][][]byte)}
}

// newTxID returns a message with a fresh crypto/rand transaction id — the
// replay-challenge of the auth scheme.
func newTxID(method, class uint16) (*message, error) {
	m := newMessage(method, class)
	if _, err := rand.Read(m.txid[:]); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *message) add(t uint16, v []byte) { m.attr[t] = append(m.attr[t], append([]byte(nil), v...)) }
func (m *message) get(t uint16) []byte {
	if vs := m.attr[t]; len(vs) > 0 {
		return vs[0]
	}
	return nil
}
func (m *message) all(t uint16) [][]byte { return m.attr[t] }

// lifetime returns the request's LIFETIME attribute in seconds (0 absent).
func (m *message) lifetime() uint32 {
	if v := m.get(attrLifetime); len(v) == 4 {
		return binary.BigEndian.Uint32(v)
	}
	return 0
}

// encode renders the message: header + attributes in ascending type order
// (deterministic; TURN does not mandate ordering), values padded to 4 bytes.
func (m *message) encode() ([]byte, error) {
	types := make([]uint16, 0, len(m.attr))
	for t := range m.attr {
		types = append(types, t)
	}
	for i := 1; i < len(types); i++ { // tiny insertion sort; few attrs
		for j := i; j > 0 && types[j] < types[j-1]; j-- {
			types[j], types[j-1] = types[j-1], types[j]
		}
	}
	out := make([]byte, headerLen, 128)
	binary.BigEndian.PutUint16(out[0:2], msgType(m.method, m.class))
	binary.BigEndian.PutUint32(out[4:8], magicCookie)
	copy(out[8:20], m.txid[:])
	for _, t := range types {
		for _, v := range m.attr[t] {
			pad := (4 - len(v)%4) % 4
			off := len(out)
			for k := 0; k < 4+len(v)+pad; k++ {
				out = append(out, 0)
			}
			binary.BigEndian.PutUint16(out[off:], t)
			binary.BigEndian.PutUint16(out[off+2:], uint16(len(v)))
			copy(out[off+4:], v)
		}
	}
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)-headerLen))
	return out, nil
}

// parseMessage decodes a datagram. Unknown attribute types are ignored
// (their bytes are skipped via the TLV length); malformed input yields an
// error, never a panic.
func parseMessage(data []byte) (*message, error) {
	if len(data) < headerLen {
		return nil, fmt.Errorf("turn: short datagram (%d bytes)", len(data))
	}
	t := binary.BigEndian.Uint16(data[0:2])
	mlen := binary.BigEndian.Uint16(data[2:4])
	if mlen > maxMessageLen {
		return nil, fmt.Errorf("turn: message length %d exceeds cap %d", mlen, maxMessageLen)
	}
	if binary.BigEndian.Uint32(data[4:8]) != magicCookie {
		return nil, fmt.Errorf("turn: bad magic cookie")
	}
	if int(mlen)+headerLen > len(data) {
		return nil, fmt.Errorf("turn: header length %d overruns datagram (%d)", mlen, len(data))
	}
	method, class := splitMsgType(t)
	m := &message{method: method, class: class, attr: make(map[uint16][][]byte)}
	copy(m.txid[:], data[8:20])
	body := data[headerLen : headerLen+int(mlen)]
	for off := 0; off+attrHdrLen <= len(body); {
		at := binary.BigEndian.Uint16(body[off : off+2])
		al := int(binary.BigEndian.Uint16(body[off+2 : off+4]))
		if al > maxMessageLen || off+attrHdrLen+al > len(body) {
			return nil, fmt.Errorf("turn: attribute 0x%04x length %d overruns body", at, al)
		}
		m.attr[at] = append(m.attr[at], append([]byte(nil), body[off+attrHdrLen:off+attrHdrLen+al]...))
		off += attrHdrLen + al + ((4 - al%4) % 4) // TLV values are 4-byte aligned
	}
	return m, nil
}

// ---------------------------------------------------------------------------
// XOR addresses (RFC 5389 §15.2)
// ---------------------------------------------------------------------------

// decodeXORAddr parses an XOR-encoded address attribute value.
func decodeXORAddr(v []byte, txid [txidLen]byte) (*net.UDPAddr, error) {
	if len(v) < 8 {
		return nil, fmt.Errorf("turn: xor address too short (%d)", len(v))
	}
	fam := v[1]
	port := (int(v[2])<<8 | int(v[3])) ^ int(magicCookie>>16)
	var mask [16]byte
	binary.BigEndian.PutUint32(mask[0:4], magicCookie)
	copy(mask[4:], txid[:])
	switch fam {
	case familyIPv4:
		if len(v) != 8 {
			return nil, fmt.Errorf("turn: ipv4 xor address length %d", len(v))
		}
		ip := make([]byte, 4)
		for i := 0; i < 4; i++ {
			ip[i] = v[4+i] ^ mask[i]
		}
		return &net.UDPAddr{IP: ip, Port: port}, nil
	case familyIPv6:
		if len(v) != 20 {
			return nil, fmt.Errorf("turn: ipv6 xor address length %d", len(v))
		}
		ip := make([]byte, 16)
		for i := 0; i < 16; i++ {
			ip[i] = v[4+i] ^ mask[i]
		}
		return &net.UDPAddr{IP: ip, Port: port}, nil
	default:
		return nil, fmt.Errorf("turn: unknown address family 0x%02x", fam)
	}
}

// xorAddr renders an address attribute value: 0x00, family, xport, xaddr —
// port ^ (cookie>>16); IPv4 ^ cookie; IPv6 ^ (cookie||txid).
func xorAddr(a *net.UDPAddr, txid [txidLen]byte) ([]byte, error) {
	var fam byte
	var raw []byte
	if ip4 := a.IP.To4(); ip4 != nil {
		fam, raw = familyIPv4, ip4
	} else if a.IP.To16() != nil {
		fam, raw = familyIPv6, a.IP.To16()
	} else {
		return nil, fmt.Errorf("turn: unusable address %v", a.IP)
	}
	v := make([]byte, 4+len(raw))
	v[0], v[1] = 0, fam
	p := uint16(a.Port) ^ uint16(magicCookie>>16)
	v[2], v[3] = byte(p>>8), byte(p)
	var mask [16]byte
	binary.BigEndian.PutUint32(mask[0:4], magicCookie)
	copy(mask[4:], txid[:])
	for i := range raw {
		v[4+i] = raw[i] ^ mask[i]
	}
	return v, nil
}

// ---------------------------------------------------------------------------
// ERROR-CODE (RFC 5389 §15.6)
// ---------------------------------------------------------------------------

// encodeErrorCode builds the ERROR-CODE value for a 3-digit code (class =
// hundreds digit, 3 bits) and reason phrase.
func encodeErrorCode(code int, reason string) []byte {
	v := make([]byte, 4+len(reason))
	class, number := code/100, code%100
	v[2] = byte(class) | byte(number>>8)<<3
	v[3] = byte(number)
	copy(v[4:], reason)
	return v
}

// decodeErrorCode extracts (code, reason) from an ERROR-CODE value.
func decodeErrorCode(v []byte) (int, string) {
	if len(v) < 4 {
		return 0, ""
	}
	class := int(v[2] & 0x07)
	number := int(v[2]&0xF8)<<5 | int(v[3])
	return class*100 + number, string(v[4:])
}

// ---------------------------------------------------------------------------
// Auth (see package comment)
// ---------------------------------------------------------------------------

// authMessage is the canonical byte string a node key signs: domain tag,
// transaction id, the node key itself, and the request's LIFETIME seconds as
// a big-endian uint64 (0 when the attribute is absent — the value signed is
// exactly the value the message carries, verified symmetrically).
func authMessage(txid [txidLen]byte, nodeKey []byte, lifetimeSec uint32) []byte {
	out := make([]byte, 0, len(authTag)+txidLen+len(nodeKey)+8)
	out = append(out, authTag...)
	out = append(out, txid[:]...)
	out = append(out, nodeKey...)
	var lt [8]byte
	binary.BigEndian.PutUint64(lt[:], uint64(lifetimeSec))
	out = append(out, lt[:]...)
	return out
}

// sign adds NODE-KEY + NODE-SIGNATURE to a request using kp.
func sign(m *message, nodeKey []byte, signFn func([]byte) []byte) {
	m.add(attrNodeKey, nodeKey)
	m.add(attrNodeSignature, signFn(authMessage(m.txid, nodeKey, m.lifetime())))
}

// verifyAuth checks a request's NODE-KEY/NODE-SIGNATURE pair. verifyFn is
// crypto.Verify (injected to avoid an import cycle in tests; in this package
// there is none, but keeping it a parameter mirrors crypto.Verify's shape).
func verifyAuth(m *message, verifyFn func(pub, sig, msg []byte) bool) bool {
	key := m.get(attrNodeKey)
	sig := m.get(attrNodeSignature)
	if len(key) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return verifyFn(key, sig, authMessage(m.txid, key, m.lifetime()))
}
