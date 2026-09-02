package dht

// nodes_wire_test.go — the {nodes} advertisement hygiene added 2026-09-02:
// hostname-shaped contacts must never ride the wire (they encoded as EMPTY
// ip bytes, which receivers decoded into literal "<nil>:port" contacts —
// found live on the community fleet), and parse-side garbage (empty /
// unspecified ip bytes from old peers) must be skipped rather than learned.
// Also pins the IPv6 round-trip: 16-byte ip entries decode back to bracketed
// "[v6]:port" contact addrs.

import (
	"bytes"
	"net"
	"testing"
)

func mustWireContact(t *testing.T, addr string) *NodeContact {
	t.Helper()
	id := bytes.Repeat([]byte{0xA5}, 32)
	c, err := NewNodeContact(id, bytes.Repeat([]byte{0x5A}, 32), addr, 1234)
	if err != nil {
		t.Fatalf("NewNodeContact(%q): %v", addr, err)
	}
	return c
}

// TestEncodeNodesSkipsHostnameAddrs: a hostname-shaped contact (seeds.conf
// pins the community seed as a hostname) produces NO {nodes} entry — its
// literal addrs (preferred or alts) still do.
func TestEncodeNodesSkipsHostnameAddrs(t *testing.T) {
	c := mustWireContact(t, "freens.camalolo.com:15353")
	c.Alts = []AddrState{
		{Addr: "192.168.1.16:15353", LastSeen: 130},
		{Addr: "220.132.135.54:15353", LastSeen: 120},
	}
	entries := encodeNodes([]*NodeContact{c})
	if len(entries) != 2 {
		t.Fatalf("encodeNodes emitted %d entries for 1 hostname + 2 literal addrs, want 2", len(entries))
	}
	for _, e := range entries {
		ea := e.([]any)
		if ipBytes, ok := ea[0].([]byte); !ok || len(ipBytes) == 0 {
			t.Fatalf("entry carries empty/missing ip bytes: %#v (the <nil> bug)", ea)
		}
	}
	parsed := parseNodes(entries)
	if len(parsed) != 2 {
		t.Fatalf("round-trip learned %d contacts, want 2", len(parsed))
	}
	for _, p := range parsed {
		if !bytes.Equal(p.NodeID, c.NodeID) {
			t.Fatalf("entry learned under wrong node id")
		}
		if p.Addr != "192.168.1.16:15353" && p.Addr != "220.132.135.54:15353" {
			t.Fatalf("learned unexpected addr %q", p.Addr)
		}
	}
}

// TestParseNodesSkipsGarbageIPBytes: entries with empty (the old-peer
// encoding of a hostname) or unspecified ip bytes are skipped, not learned
// as "<nil>:port" / "0.0.0.0:port" contacts.
func TestParseNodesSkipsGarbageIPBytes(t *testing.T) {
	id := bytes.Repeat([]byte{0x01}, 32)
	pk := bytes.Repeat([]byte{0x02}, 32)
	// Entries are shaped exactly as CBOR delivers them ([]byte rdata).
	raw := []any{
		[]any{[]byte{}, uint64(15353), id, pk},                                  // empty ip bytes -> "<nil>:15353"
		[]any{make([]byte, 4), uint64(15353), id, pk},                           // 0.0.0.0 -> unspecified
		[]any{make([]byte, 16), uint64(15353), id, pk},                          // :: -> unspecified
		[]any{[]byte(net.ParseIP("203.0.113.7").To4()), uint64(9999), id, pk},   // valid v4
		[]any{[]byte(net.ParseIP("2001:db8::1").To16()), uint64(15353), id, pk}, // valid v6
	}
	got := parseNodes(raw)
	if len(got) != 2 {
		t.Fatalf("parseNodes kept %d of 5 entries, want 2 (the two valid ones): %+v", len(got), got)
	}
	if got[0].Addr != "203.0.113.7:9999" {
		t.Errorf("entry 0 = %q, want 203.0.113.7:9999", got[0].Addr)
	}
	if got[1].Addr != "[2001:db8::1]:15353" {
		t.Errorf("entry 1 = %q, want [2001:db8::1]:15353", got[1].Addr)
	}
}

// TestEncodeParseIPv6RoundTrip: a literal v6 contact encodes 16 ip bytes and
// decodes back to the bracketed dialable form.
func TestEncodeParseIPv6RoundTrip(t *testing.T) {
	c := mustWireContact(t, "[2001:db8::42]:15353")
	entries := encodeNodes([]*NodeContact{c})
	if len(entries) != 1 {
		t.Fatalf("encodeNodes emitted %d entries, want 1", len(entries))
	}
	if ipBytes := entries[0].([]any)[0].([]byte); len(ipBytes) != net.IPv6len {
		t.Fatalf("v6 addr encoded as %d ip bytes, want 16", len(ipBytes))
	}
	parsed := parseNodes(entries)
	if len(parsed) != 1 || parsed[0].Addr != "[2001:db8::42]:15353" {
		t.Fatalf("v6 round-trip = %+v, want one [2001:db8::42]:15353 contact", parsed)
	}
}

// TestAdvertiseableAddr pins the predicate directly (the name is the spec).
func TestAdvertiseableAddr(t *testing.T) {
	cases := map[string]bool{
		"192.168.1.16:15353":        true,
		"220.132.135.54:1024":       true,
		"[2001:db8::1]:15353":       true,
		"[::]:15353":                false, // unspecified advertises nothing dialable
		"0.0.0.0:15353":             false,
		"freens.camalolo.com:15353": false, // hostname: local-dialable, not wire-able
		"<nil>:15353":               false,
		":15353":                    false,
		"freens.camalolo.com":       false, // no port
	}
	for addr, want := range cases {
		if got := advertiseableAddr(addr); got != want {
			t.Errorf("advertiseableAddr(%q) = %v, want %v", addr, got, want)
		}
	}
}
