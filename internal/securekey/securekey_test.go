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
	if _, err := DecryptSeed(enc, "pass"); err == nil || !strings.Contains(err.Error(), "implausible") {
		t.Fatalf("hostile N accepted: %v", err)
	}
}
