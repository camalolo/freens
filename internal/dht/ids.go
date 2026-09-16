// Package dht implements the freens distributed hash table primitives:
// the Kademlia XOR distance metric (specifications.md §6.2), the rotating
// HMAC-SHA256 write-token issuer/verifier (§6.3), and the 256-bucket routing
// table (§6.2).
//
// This file (ids.go) ports the pure-std-lib XOR metric helpers from
// archive/python-v0.1/freens/dht/ids.py. All functions operate on raw 32-byte
// IDs (Node ID = SHA-256(node_public_key), 32 bytes / 256 bits). Distances are
// the bitwise XOR of two IDs interpreted as big-endian unsigned integers, so
// smaller == closer — the canonical Kademlia convention.
package dht

import (
	"encoding/hex"
	"fmt"

	"github.com/camalolo/freens/internal/constants"
)

// IDLen is the length of a freens node ID in bytes (32; 256 bits). It mirrors
// constants.NodeIDLen and is kept here as a package-local handle so the dht
// package is self-documenting.
const IDLen = constants.NodeIDLen

// checkID validates that x is exactly IDLen bytes and returns it. It is the
// Go analogue of ids._check_id in the Python reference.
func checkID(x []byte, name string) error {
	if len(x) != IDLen {
		return fmt.Errorf("dht: %s must be %d bytes, got %d", name, IDLen, len(x))
	}
	return nil
}

// CompareDistance reports which of a or b is closer to target under the XOR
// metric: -1 if a is closer, +1 if b is closer, and 0 if the two are
// equidistant. The XOR(target,a) and XOR(target,b) results are each 32 bytes;
// comparing them bytewise from the most-significant byte is exactly a
// big-endian unsigned-numeric comparison, which is the canonical Kademlia
// ordering.
//
// Implementation note: the comparison is computed BYTE-BY-TELE on the stack
// (xor of one byte from each side at a time) — it allocates NOTHING. This
// function is the comparator inside every shortlist sort of every iterative
// walk and every RoutingTable.Closest call; the previous
// XORBytes-then-bytes.Compare shape heap-allocated two 32-byte slices per
// comparison, which profiling showed as thousands of avoidable allocations
// per lookup (GC pressure on the arm64 fleet).
//
// Golden vector (by construction):
//
//	CompareDistance(bytes(32), bytes(32), 0x01+bytes(31)) == -1  // a is target itself
//
// CompareDistance assumes well-formed (32-byte) inputs; on a length mismatch
// it returns 0 since the function has no error channel.
func CompareDistance(target, a, b []byte) int {
	if len(target) != IDLen || len(a) != IDLen || len(b) != IDLen {
		return 0
	}
	for i := 0; i < IDLen; i++ {
		da := target[i] ^ a[i]
		db := target[i] ^ b[i]
		if da != db {
			if da < db {
				return -1
			}
			return 1
		}
	}
	return 0
}

// bitLenU8 returns the bit-length of a byte — the index of its highest set
// bit plus one. 0xff -> 8, 0x80 -> 8, 0x40 -> 7, 0x01 -> 1, 0x00 -> 0.
func bitLenU8(b byte) int {
	n := 0
	for b != 0 {
		b >>= 1
		n++
	}
	return n
}

// CommonPrefixLength returns the number of leading bits shared by a and b
// (0..256). 256 means a == b. Bits are counted from the most-significant bit
// (bit 0) of byte 0.
//
// The scan is per-byte: each fully-matching zero-XOR byte contributes 8; for
// the first non-zero XOR byte d, (8 - bitLenU8(d)) is the count of additional
// shared bits before the split within that byte.
//
// Golden vectors (by construction):
//
//	CommonPrefixLength(bytes(32), bytes(32))            == 256
//	CommonPrefixLength(0x80+bytes(31), bytes(32))       == 0   // differ at MSB
//	CommonPrefixLength(0x40+bytes(31), bytes(32))       == 1   // 0x40=01000000
//	CommonPrefixLength(0x01+bytes(31), bytes(32))       == 7   // 0x01=00000001
//	CommonPrefixLength(bytes(31)+0x01, bytes(32))       == 255
func CommonPrefixLength(a, b []byte) (int, error) {
	if err := checkID(a, "a"); err != nil {
		return 0, err
	}
	if err := checkID(b, "b"); err != nil {
		return 0, err
	}
	shared := 0
	for i := 0; i < IDLen; i++ {
		d := a[i] ^ b[i]
		if d == 0 {
			shared += 8
			continue
		}
		// d != 0: its highest set bit marks the first differing position
		// within this byte. (8 - bitLenU8(d)) is the number of additional
		// shared bits before the split.
		shared += 8 - bitLenU8(d)
		break
	}
	return shared, nil
}

// HexID returns the lowercase hex encoding of a 32-byte ID (64 chars), for
// diagnostics. Returns "" if x is not a valid 32-byte ID.
func HexID(x []byte) string {
	if err := checkID(x, "x"); err != nil {
		return ""
	}
	return hex.EncodeToString(x)
}
