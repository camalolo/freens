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
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"github.com/laurent/freens/internal/constants"
)

// IDLen is the length of a freens node ID in bytes (32; 256 bits). It mirrors
// constants.NodeIDLen and is kept here as a package-local handle so the dht
// package is self-documenting.
const IDLen = constants.NodeIDLen

// bitsPerID is the bit-width of a node ID (IDLen * 8 = 256).
const bitsPerID = IDLen * 8

// checkID validates that x is exactly IDLen bytes and returns it. It is the
// Go analogue of ids._check_id in the Python reference.
func checkID(x []byte, name string) error {
	if len(x) != IDLen {
		return fmt.Errorf("dht: %s must be %d bytes, got %d", name, IDLen, len(x))
	}
	return nil
}

// XORBytes returns the bitwise XOR of two 32-byte IDs as a freshly allocated
// 32-byte slice. It returns an error if either argument is not exactly IDLen
// bytes.
//
// Golden vectors (by construction):
//
//	XORBytes(bytes(32), bytes(32))          == bytes(32)
//	XORBytes(bytes(32), 0xff*32)            == 0xff*32
//	XORBytes(0x01+bytes(31), bytes(32))     == 0x01+bytes(31)
func XORBytes(a, b []byte) ([]byte, error) {
	if err := checkID(a, "a"); err != nil {
		return nil, err
	}
	if err := checkID(b, "b"); err != nil {
		return nil, err
	}
	out := make([]byte, IDLen)
	for i := 0; i < IDLen; i++ {
		out[i] = a[i] ^ b[i]
	}
	return out, nil
}

// CompareDistance reports which of a or b is closer to target under the XOR
// metric: -1 if a is closer, +1 if b is closer, and 0 if the two are
// equidistant. The XOR(target,a) and XOR(target,b) results are each 32 bytes;
// bytes.Compare on them is exactly a big-endian unsigned-numeric comparison
// (leading bytes dominate), which is the canonical Kademlia ordering.
//
// Golden vector (by construction):
//
//	CompareDistance(bytes(32), bytes(32), 0x01+bytes(31)) == -1  // a is target itself
//
// CompareDistance assumes well-formed (32-byte) inputs; on a length mismatch
// it returns 0 since the function has no error channel.
func CompareDistance(target, a, b []byte) int {
	da, errA := XORBytes(target, a)
	db, errB := XORBytes(target, b)
	if errA != nil || errB != nil {
		return 0
	}
	return bytes.Compare(da, db)
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

// BucketIndex returns the k-bucket index (0..255) for otherID relative to
// selfID. Per the Kademlia rule, bucket i holds contacts that share exactly i
// leading bits with selfID, so the index equals the common-prefix length of
// selfID and otherID.
//
// It returns an error if the IDs are equal (an ID never routes to itself; its
// common prefix length would be 256, which is not a valid bucket) or if
// either input is the wrong length.
//
// Examples:
//
//	BucketIndex(bytes(32), 0x80+bytes(31)) == 0   // differ at MSB
//	BucketIndex(bytes(32), bytes(31)+0x01) == 255 // differ only at LSB
func BucketIndex(selfID, otherID []byte) (int, error) {
	cpl, err := CommonPrefixLength(selfID, otherID)
	if err != nil {
		return 0, err
	}
	if cpl == bitsPerID {
		return 0, errors.New("dht: an ID never routes to itself; no valid bucket")
	}
	return cpl, nil
}

// SortByDistance stably sorts ids in place ascending by XOR distance to
// target. All ids and target are validated up front so a malformed id does
// not slip through after partial sorting.
func SortByDistance(target []byte, ids [][]byte) error {
	if err := checkID(target, "target"); err != nil {
		return err
	}
	for i, id := range ids {
		if err := checkID(id, fmt.Sprintf("ids[%d]", i)); err != nil {
			return err
		}
	}
	sort.SliceStable(ids, func(i, j int) bool {
		return CompareDistance(target, ids[i], ids[j]) < 0
	})
	return nil
}

// KClosest returns the k IDs nearest to target, ascending by XOR distance. If
// fewer than k IDs are available, all are returned (still sorted). The input
// slice is not mutated; a fresh slice is returned.
//
// k must be non-negative.
func KClosest(target []byte, ids [][]byte, k int) ([][]byte, error) {
	if k < 0 {
		return nil, fmt.Errorf("dht: k must be non-negative, got %d", k)
	}
	cp := make([][]byte, len(ids))
	copy(cp, ids)
	if err := SortByDistance(target, cp); err != nil {
		return nil, err
	}
	if k > len(cp) {
		k = len(cp)
	}
	return cp[:k], nil
}

// HexID returns the lowercase hex encoding of a 32-byte ID (64 chars), for
// diagnostics. Returns "" if x is not a valid 32-byte ID.
func HexID(x []byte) string {
	if err := checkID(x, "x"); err != nil {
		return ""
	}
	return hex.EncodeToString(x)
}
