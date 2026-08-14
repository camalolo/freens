package dht

import (
	"bytes"
	"strings"
	"testing"
)

// zeroID returns a fresh 32-byte zero ID.
func zeroID() []byte { return make([]byte, IDLen) }

// ffID returns a fresh 32-byte ID of all 0xff.
func ffID() []byte { return bytes.Repeat([]byte{0xff}, IDLen) }

// idWithPrefix returns a 32-byte ID whose first byte is first and whose
// remaining 31 bytes are zero.
func idWithPrefix(first byte) []byte {
	x := make([]byte, IDLen)
	x[0] = first
	return x
}

// idWithSuffix returns a 32-byte ID whose first 31 bytes are zero and whose
// last byte is last.
func idWithSuffix(last byte) []byte {
	x := make([]byte, IDLen)
	x[IDLen-1] = last
	return x
}

func TestXORBytes(t *testing.T) {
	t.Parallel()

	z := zeroID()
	ff := ffID()

	got, err := XORBytes(z, z)
	if err != nil {
		t.Fatalf("XORBytes(zero,zero) unexpected error: %v", err)
	}
	if !bytes.Equal(got, z) {
		t.Fatalf("XORBytes(zero,zero) = %x, want %x", got, z)
	}

	got, err = XORBytes(z, ff)
	if err != nil {
		t.Fatalf("XORBytes(zero,ff) unexpected error: %v", err)
	}
	if !bytes.Equal(got, ff) {
		t.Fatalf("XORBytes(zero,ff) = %x, want %x", got, ff)
	}

	// Error on a 31-byte input.
	_, err = XORBytes(z, make([]byte, 31))
	if err == nil {
		t.Fatal("XORBytes(zero, 31-byte) want error, got nil")
	}

	// Error on first arg wrong length.
	_, err = XORBytes(make([]byte, 31), z)
	if err == nil {
		t.Fatal("XORBytes(31-byte, zero) want error, got nil")
	}
}

func TestCompareDistance(t *testing.T) {
	t.Parallel()

	z := zeroID()
	near := idWithPrefix(0x01) // distance to z = 0x01 || zeros
	if got := CompareDistance(z, z, near); got != -1 {
		t.Fatalf("CompareDistance(zero, zero, 0x01+zeros) = %d, want -1 (a closer)", got)
	}
	if got := CompareDistance(z, near, z); got != 1 {
		t.Fatalf("CompareDistance(zero, 0x01+zeros, zero) = %d, want 1 (b closer)", got)
	}
	if got := CompareDistance(z, z, z); got != 0 {
		t.Fatalf("CompareDistance(zero, zero, zero) = %d, want 0 (equal)", got)
	}
}

func TestCommonPrefixLength(t *testing.T) {
	t.Parallel()

	z := zeroID()

	cases := []struct {
		name string
		a, b []byte
		want int
	}{
		{"equal", z, zeroID(), 256},
		{"differ at MSB", idWithPrefix(0x80), z, 0},
		{"share bit 0, differ at 1", idWithPrefix(0x40), z, 1},
		{"share bits 0-6, differ at 7", idWithPrefix(0x01), z, 7},
		{"differ only at LSB", idWithSuffix(0x01), z, 255},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CommonPrefixLength(tc.a, tc.b)
			if err != nil {
				t.Fatalf("CommonPrefixLength unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("CommonPrefixLength(%x, %x) = %d, want %d", tc.a, tc.b, got, tc.want)
			}
		})
	}

	// Error on wrong length.
	if _, err := CommonPrefixLength(z, make([]byte, 31)); err == nil {
		t.Fatal("CommonPrefixLength(zero, 31-byte) want error, got nil")
	}
}

func TestBucketIndex(t *testing.T) {
	t.Parallel()

	z := zeroID()

	idx, err := BucketIndex(z, idWithPrefix(0x80))
	if err != nil {
		t.Fatalf("BucketIndex(zero, 0x80+zeros) unexpected error: %v", err)
	}
	if idx != 0 {
		t.Fatalf("BucketIndex(zero, 0x80+zeros) = %d, want 0", idx)
	}

	idx, err = BucketIndex(z, idWithSuffix(0x01))
	if err != nil {
		t.Fatalf("BucketIndex(zero, zeros+0x01) unexpected error: %v", err)
	}
	if idx != 255 {
		t.Fatalf("BucketIndex(zero, zeros+0x01) = %d, want 255", idx)
	}

	// Error when IDs are equal (an ID never routes to itself).
	_, err = BucketIndex(z, zeroID())
	if err == nil {
		t.Fatal("BucketIndex(self, self) should error")
	}
	// ids.go returns errors.New(...) for the self-collision — there is no
	// exported sentinel to errors.Is against, so assert the message mentions
	// the self-collision. (The prior errors.Is(err, err) check was tautology:
	// an error always Is itself, so it could never fail.)
	if !strings.Contains(err.Error(), "itself") {
		t.Fatalf("BucketIndex(self, self) error should mention the self-collision, got: %v", err)
	}

	// Error on wrong length.
	_, err = BucketIndex(z, make([]byte, 31))
	if err == nil {
		t.Fatal("BucketIndex(zero, 31-byte) want error, got nil")
	}
}

func TestSortByDistance(t *testing.T) {
	t.Parallel()

	z := zeroID()
	one := idWithPrefix(0x01)
	ff := ffID()

	// Unsorted input: ff (farthest), 0x01 (close), zero (target itself).
	in := [][]byte{ff, one, z}
	if err := SortByDistance(z, in); err != nil {
		t.Fatalf("SortByDistance unexpected error: %v", err)
	}
	// Want: zero (closest, ==target), then 0x01, then ff.
	want := [][]byte{z, one, ff}
	for i := range want {
		if !bytes.Equal(in[i], want[i]) {
			t.Fatalf("SortByDistance[%d] = %x, want %x (full: %x)", i, in[i], want[i], in)
		}
	}
}

func TestSortByDistanceStable(t *testing.T) {
	t.Parallel()

	z := zeroID()
	// Two IDs equidistant from zero (both 0x01 in byte 0): stable sort must
	// preserve their relative input order.
	a := idWithPrefix(0x01)
	b := idWithPrefix(0x01) // same first byte, equal distance to z
	in := [][]byte{a, b}
	if err := SortByDistance(z, in); err != nil {
		t.Fatalf("SortByDistance unexpected error: %v", err)
	}
	if !bytes.Equal(in[0], a) || !bytes.Equal(in[1], b) {
		t.Fatalf("SortByDistance not stable: %x", in)
	}
}

func TestKClosest(t *testing.T) {
	t.Parallel()

	z := zeroID()
	one := idWithPrefix(0x01)
	two := idWithPrefix(0x02)
	ff := ffID()

	in := [][]byte{ff, two, one, z}
	got, err := KClosest(z, in, 2)
	if err != nil {
		t.Fatalf("KClosest unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("KClosest returned %d items, want 2", len(got))
	}
	// Closest two ascending: zero (==target), then 0x01.
	if !bytes.Equal(got[0], z) {
		t.Fatalf("KClosest[0] = %x, want zero", got[0])
	}
	if !bytes.Equal(got[1], one) {
		t.Fatalf("KClosest[1] = %x, want 0x01+zeros", got[1])
	}

	// Input list must not be mutated by KClosest.
	if !bytes.Equal(in[0], ff) {
		t.Fatalf("KClosest mutated input[0]: %x", in[0])
	}

	// k greater than available returns all (still sorted).
	got, err = KClosest(z, in, 99)
	if err != nil {
		t.Fatalf("KClosest(k>len) unexpected error: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("KClosest(k>len) returned %d, want 4", len(got))
	}

	// Negative k is an error.
	_, err = KClosest(z, in, -1)
	if err == nil {
		t.Fatal("KClosest(k=-1) want error, got nil")
	}
}

func TestHexID(t *testing.T) {
	t.Parallel()

	z := zeroID()
	if got := HexID(z); got != "0000000000000000000000000000000000000000000000000000000000000000" {
		t.Fatalf("HexID(zero) = %q, want 64 zeros", got)
	}
	if got := HexID(make([]byte, 31)); got != "" {
		t.Fatalf("HexID(31-byte) = %q, want empty", got)
	}
}
