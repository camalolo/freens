package stun

// decode_fuzz_test.go — Go native fuzz target for the client-side Binding
// response parser. parseBindingResponse consumes a datagram from the network
// (possibly a spoofed or broken reply) checked against the transaction that
// elicited it, so it must never panic on arbitrary bytes.
//
// Property asserted on every input:
//
//   - no panic (nil addr + error is the sanctioned rejection shape);
//   - on success the returned address is sane: non-nil, IP is 4 or 16 bytes,
//     port within 0..65535. (There is no client-path re-encoder to round-trip
//     through; buildBindingSuccess is server-side and keyed on the observed
//     datagram source, not on a parsed address.)
//
// Both the datagram AND the expected transaction id are fuzzed — the fuzzer
// must be able to discover the txid-echo requirement on its own.
//
// Builders below are fuzz-file-local (fz* names) so this target never depends
// on test helpers elsewhere in the package.
//
// Without -fuzz these run only the seed corpus as fast unit tests (<1 ms).

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func fzAttr(typ uint16, val []byte) []byte {
	b := make([]byte, attrHdrLen+len(val))
	binary.BigEndian.PutUint16(b[0:2], typ)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(val)))
	copy(b[attrHdrLen:], val)
	return b
}

// fzHeader assembles a §6 message (values padded per §15) from TLV attrs.
func fzHeader(typ uint16, txid []byte, attrs ...[]byte) []byte {
	body := make([]byte, 0, 64)
	for _, a := range attrs {
		body = append(body, a...)
		for len(body)%4 != 0 {
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

// fzXORv4 encodes a §15.2 XOR-MAPPED-ADDRESS value (IPv4 form).
func fzXORv4(ip net.IP, port int, txid []byte) []byte {
	cookie := [4]byte{0x21, 0x12, 0xa4, 0x42}
	p := uint16(port) ^ uint16(magicCookie>>16)
	v := []byte{0, familyIPv4, byte(p >> 8), byte(p)}
	ip4 := ip.To4()
	for i := range ip4 {
		v = append(v, ip4[i]^cookie[i])
	}
	return v
}

// fzXORv6 encodes a §15.2 XOR-MAPPED-ADDRESS value (IPv6 form: address XOR
// cookie||txid).
func fzXORv6(ip net.IP, port int, txid []byte) []byte {
	var key [16]byte
	binary.BigEndian.PutUint32(key[0:4], magicCookie)
	copy(key[4:], txid)
	p := uint16(port) ^ uint16(magicCookie>>16)
	v := []byte{0, familyIPv6, byte(p >> 8), byte(p)}
	ip6 := ip.To16()
	for i := 0; i < 16; i++ {
		v = append(v, ip6[i]^key[i])
	}
	return v
}

// fzPlain encodes a §15.1 MAPPED-ADDRESS value (no XOR).
func fzPlain(ip net.IP, port int) []byte {
	p := uint16(port)
	v := []byte{0, familyIPv4, byte(p >> 8), byte(p)}
	return append(v, ip.To4()...)
}

// FuzzParseBindingResponse: never panic on (data, txid); sanity-check any
// address the parser does return.
func FuzzParseBindingResponse(f *testing.F) {
	txid := bytes.Repeat([]byte{0xA5}, txidLen)

	goodV4 := fzHeader(msgBindingSuccess, txid,
		fzAttr(attrXORMappedAddress, fzXORv4(net.IPv4(203, 0, 113, 7), 1111, txid)))
	both := fzHeader(msgBindingSuccess, txid,
		fzAttr(attrMappedAddress, fzPlain(net.IPv4(198, 51, 100, 8), 2222)),
		fzAttr(attrXORMappedAddress, fzXORv4(net.IPv4(203, 0, 113, 7), 1111, txid)))
	goodV6 := fzHeader(msgBindingSuccess, txid,
		fzAttr(attrXORMappedAddress, fzXORv6(net.ParseIP("2001:db8::1"), 4040, txid)))
	legacyOnly := fzHeader(msgBindingSuccess, txid,
		fzAttr(attrMappedAddress, fzPlain(net.IPv4(198, 51, 100, 8), 2222)))
	wrongType := append([]byte{}, goodV4...)
	wrongType[0], wrongType[1] = 0x00, 0x01 // Binding Request type
	badCookie := append([]byte{}, goodV4...)
	badCookie[4] = 0
	shortAttr := fzHeader(msgBindingSuccess, txid,
		fzAttr(attrXORMappedAddress, fzXORv4(net.IPv4(203, 0, 113, 7), 1111, txid)[:6]))

	f.Add(goodV4, txid)
	f.Add(both, txid)
	f.Add(goodV6, txid)
	f.Add(legacyOnly, txid)
	f.Add([]byte("garbage"), txid)
	f.Add([]byte{}, txid)
	f.Add(goodV4[:10], txid)                           // shorter than the 20-byte header
	f.Add(goodV4[:20], txid)                           // header only: no address attribute
	f.Add(wrongType, txid)                             // type 0x0001 instead of 0x0101
	f.Add(badCookie, txid)                             // magic cookie mismatch
	f.Add(shortAttr, txid)                             // attribute value truncated
	f.Add(goodV4, txid[:11])                           // expected-txid length mismatch
	f.Add(goodV4, bytes.Repeat([]byte{0x5A}, txidLen)) // txid mismatch

	f.Fuzz(func(t *testing.T, data, txid []byte) {
		addr, err := parseBindingResponse(data, txid)
		if err != nil {
			return // rejection (with nil addr) is the sanctioned failure shape
		}
		if addr == nil {
			t.Fatal("parseBindingResponse returned (nil, nil)")
		}
		if addr.IP == nil || (len(addr.IP) != 4 && len(addr.IP) != 16) {
			t.Fatalf("success with malformed IP: %v", addr.IP)
		}
		if addr.Port < 0 || addr.Port > 65535 {
			t.Fatalf("port out of range: %d", addr.Port)
		}
	})
}
