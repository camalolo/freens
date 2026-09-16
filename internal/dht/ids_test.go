package dht

import "testing"

// zeroID returns a fresh 32-byte zero ID.
func zeroID() []byte { return make([]byte, IDLen) }

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
