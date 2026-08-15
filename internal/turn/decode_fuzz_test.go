package turn

// decode_fuzz_test.go — Go native fuzz targets for the TURN datagram codec:
// parseMessage (every relay datagram passes through it, server AND client)
// and decodeXORAddr (XOR-PEER/RELAYED/MAPPED address attribute values).
//
// Properties asserted on every input:
//
//   - neither decoder ever panics on arbitrary bytes;
//   - when parseMessage succeeds, the message's own canonical encoder must
//     succeed and re-parse to the SAME method, class, transaction id and
//     attribute set (encode is the canonical form — a datagram that parses
//     but cannot be canonically re-encoded would desynchronize the relay);
//   - when decodeXORAddr succeeds, the address survives the canonical
//     xorAddr -> decodeXORAddr round trip (net.IP.Equal deliberately treats
//     an IPv4 address and its v4-mapped IPv6 form as equal, so the v6->v4
//     canonicalization of v4-mapped inputs is covered).
//
// Without -fuzz these run only the seed corpus as fast unit tests (<1 ms).

import (
	"bytes"
	"net"
	"testing"

	"github.com/camalolo/freens/internal/crypto"
)

// FuzzParseMessage: no panic; on success encode() must succeed and re-parse
// to the same method/class (canonical round trip).
func FuzzParseMessage(f *testing.F) {
	// A realistic signed Allocate request (auth attribute bytes need not
	// verify for the parse path).
	req, err := newTxID(methodAllocate, classRequest)
	if err != nil {
		f.Fatal(err)
	}
	kp, err := crypto.Generate()
	if err != nil {
		f.Fatal(err)
	}
	req.add(attrLifetime, []byte{0, 0, 2, 88}) // 600 s
	sign(req, kp.Public(), kp.Sign)
	reqBytes, err := req.encode()
	if err != nil {
		f.Fatal(err)
	}

	// A Data indication carrying an XOR-PEER-ADDRESS and DATA payload.
	ind, err := newTxID(methodData, classIndication)
	if err != nil {
		f.Fatal(err)
	}
	peerV, err := xorAddr(&net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 4444}, ind.txid)
	if err != nil {
		f.Fatal(err)
	}
	ind.add(attrXORPeerAddress, peerV)
	ind.add(attrData, []byte("opaque dht payload"))
	indBytes, err := ind.encode()
	if err != nil {
		f.Fatal(err)
	}

	badCookie := append([]byte{}, reqBytes...)
	badCookie[4] = 0

	f.Add(reqBytes)
	f.Add(indBytes)
	f.Add([]byte("garbage"))
	f.Add([]byte{})
	f.Add(reqBytes[:12])        // short datagram
	f.Add(reqBytes[:headerLen]) // header only
	f.Add(badCookie)            // magic cookie mismatch

	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := parseMessage(data)
		if err != nil {
			return // clean rejection is fine; panics are not
		}
		enc, err := m.encode()
		if err != nil {
			t.Fatalf("encode() after successful parse: %v", err)
		}
		m2, err := parseMessage(enc)
		if err != nil {
			t.Fatalf("re-parse of canonical encode() failed: %v", err)
		}
		if m2.method != m.method || m2.class != m.class {
			t.Fatalf("method/class changed across canonical round trip: (%d,%d) -> (%d,%d)",
				m.method, m.class, m2.method, m2.class)
		}
		if m2.txid != m.txid {
			t.Fatalf("txid changed across canonical round trip: %x -> %x", m.txid, m2.txid)
		}
		if len(m2.attr) != len(m.attr) {
			t.Fatalf("attribute type count changed: %d -> %d", len(m.attr), len(m2.attr))
		}
		for at, vs := range m.attr {
			ws := m2.attr[at]
			if len(ws) != len(vs) {
				t.Fatalf("attribute 0x%04x value count changed: %d -> %d", at, len(vs), len(ws))
			}
			for i := range vs {
				if !bytes.Equal(vs[i], ws[i]) {
					t.Fatalf("attribute 0x%04x[%d] changed across round trip", at, i)
				}
			}
		}
	})
}

// FuzzDecodeXORAddr: no panic on arbitrary (value, txid); on success the
// decoded address round-trips through the canonical xorAddr encoder.
func FuzzDecodeXORAddr(f *testing.F) {
	var txid [txidLen]byte
	for i := range txid {
		txid[i] = byte(0x90 + i)
	}
	v4, err := xorAddr(&net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 1111}, txid)
	if err != nil {
		f.Fatal(err)
	}
	v6, err := xorAddr(&net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 4040}, txid)
	if err != nil {
		f.Fatal(err)
	}

	f.Add(v4, txid[:])
	f.Add(v6, txid[:])
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7}, txid[:]) // plausible-but-short
	f.Add([]byte{0, 7, 1, 2}, txid[:])             // unknown family
	f.Add([]byte{}, txid[:])
	f.Add(bytes.Repeat([]byte{0}, 32), txid[:]) // over-long value

	f.Fuzz(func(t *testing.T, v, txid []byte) {
		var id [txidLen]byte
		copy(id[:], txid)
		addr, err := decodeXORAddr(v, id)
		if err != nil {
			return
		}
		if addr == nil || addr.IP == nil || (len(addr.IP) != 4 && len(addr.IP) != 16) {
			t.Fatalf("success with malformed address: %v", addr)
		}
		if addr.Port < 0 || addr.Port > 65535 {
			t.Fatalf("port out of range: %d", addr.Port)
		}
		re, err := xorAddr(addr, id)
		if err != nil {
			t.Fatalf("xorAddr of decoded address failed: %v", err)
		}
		addr2, err := decodeXORAddr(re, id)
		if err != nil {
			t.Fatalf("decodeXORAddr of re-encoded address failed: %v", err)
		}
		if !addr2.IP.Equal(addr.IP) || addr2.Port != addr.Port {
			t.Fatalf("canonical round trip changed the address: %v -> %v", addr, addr2)
		}
	})
}
