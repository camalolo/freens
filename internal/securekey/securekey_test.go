// securekey_test.go — round trip, wrong passphrase, tamper detection,
// hostile-parameter refusal, legacy-plaintext detection.
package securekey

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	seed := bytes.Repeat([]byte{0xab}, 32)
	enc, err := EncryptSeed(seed, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !IsEncrypted(enc) {
		t.Fatal("encrypted file not detected")
	}
	if IsEncrypted([]byte("00112233445566778899aabbccddeeff0011\n")) {
		t.Fatal("legacy hex detected as encrypted")
	}
	got, err := DecryptSeed(enc, "correct horse battery staple")
	if err != nil || !bytes.Equal(got, seed) {
		t.Fatalf("round trip: %v %v", got, err)
	}
	if _, err := DecryptSeed(enc, "wrong"); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("wrong passphrase = %v, want ErrWrongPassphrase", err)
	}
}

func TestTamperDetection(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, 32)
	enc, _ := EncryptSeed(seed, "pass")
	enc[len(enc)-1] ^= 0xff // flip one ciphertext bit
	if _, err := DecryptSeed(enc, "pass"); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("tampered file opened: %v", err)
	}
}

func TestHostileParametersRefused(t *testing.T) {
	seed := bytes.Repeat([]byte{9}, 32)
	enc, _ := EncryptSeed(seed, "pass")
	// Rewrite the N field to something absurd (2^30): DecryptSeed must
	// refuse before ever calling scrypt.
	binary.BigEndian.PutUint32(enc[len(Magic):len(Magic)+4], 1<<30)
	if _, err := DecryptSeed(enc, "pass"); err == nil || !strings.Contains(err.Error(), "unsupported scrypt parameters") {
		t.Fatalf("hostile N accepted: %v", err)
	}
}

// TestMaxBoundParametersStillRefused: the old bounds check admitted
// N=2^22/r=32/p=8 (~16 GiB of scrypt state — an OOM bomb for the arm64
// box) from a tampered keyfile. The allowlist refuses ANY deviation from
// the writer's parameters — including these in-bounds-but-not-ours values —
// with a clean error BEFORE scrypt runs (the allowlist is checked ahead of
// the scrypt.Key call, so a hostile header costs O(1) work).
func TestMaxBoundParametersStillRefused(t *testing.T) {
	seed := bytes.Repeat([]byte{9}, 32)
	enc, _ := EncryptSeed(seed, "pass")
	for _, tc := range []struct {
		name    string
		n, r, p uint32
	}{
		{"N=2^22", 1 << 22, 8, 1},
		{"r=32", 1 << 15, 32, 1},
		{"p=8", 1 << 15, 8, 8},
		{"N=2^21", 1 << 21, 8, 1},
	} {
		tampered := append([]byte(nil), enc...)
		binary.BigEndian.PutUint32(tampered[len(Magic):len(Magic)+4], tc.n)
		binary.BigEndian.PutUint32(tampered[len(Magic)+4:len(Magic)+8], tc.r)
		binary.BigEndian.PutUint32(tampered[len(Magic)+8:len(Magic)+12], tc.p)
		_, err := DecryptSeed(tampered, "pass")
		if err == nil {
			t.Fatalf("%s: tampered parameters accepted", tc.name)
		}
		if !strings.Contains(err.Error(), "unsupported scrypt parameters") {
			t.Fatalf("%s: wrong error: %v", tc.name, err)
		}
		if strings.Contains(err.Error(), "wrong passphrase") {
			t.Fatalf("%s: misreported as a wrong passphrase", tc.name)
		}
	}
	// Control: the untouched envelope (the writer's exact parameters) still
	// opens — the allowlist must not lock out legitimate keyfiles.
	if got, err := DecryptSeed(enc, "pass"); err != nil || !bytes.Equal(got, seed) {
		t.Fatalf("legitimate envelope refused after parameter hardening: %v", err)
	}
}
