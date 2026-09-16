// Package securekey encrypts freens owner/recovery keyfiles at rest with a
// passphrase: scrypt (N=2^15, r=8, p=1) derives an AES-256-GCM key; the
// file format is a versioned, self-describing envelope
//
//	"FREENSK1" || N,r,p (3×uint32 BE) || salt(16) || nonce(12) || ct
//
// ct is the 32-byte Ed25519 seed sealed with AES-GCM (wrong passphrase →
// authentication failure, no oracle beyond "wrong"). Legacy plaintext
// files (64 hex chars) remain fully supported — detection is by magic.
package securekey

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"

	"golang.org/x/crypto/scrypt"
)

// Magic prefixes v1 encrypted keyfiles.
var Magic = []byte("FREENSK1")

// scrypt work factors (OWASP-recommended 2023 tier for interactive unlock;
// ~50-100 ms on a laptop core).
const (
	scryptN = 1 << 15
	scryptR = 8
	scryptP = 1
	keyLen  = 32 // AES-256
)

// ErrWrongPassphrase reports a failed unlock (GCM auth or malformed input).
var ErrWrongPassphrase = errors.New("wrong passphrase (or corrupted keyfile)")

// IsEncrypted reports whether b carries the encrypted-keyfile envelope.
func IsEncrypted(b []byte) bool {
	return len(b) >= len(Magic) && string(b[:len(Magic)]) == string(Magic)
}

// EncryptSeed seals seed under passphrase.
func EncryptSeed(seed []byte, passphrase string) ([]byte, error) {
	if len(seed) == 0 {
		return nil, fmt.Errorf("securekey: empty seed")
	}
	salt := make([]byte, 16)
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	key, err := scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, keyLen)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(Magic)+12+16+12+len(seed)+16)
	out = append(out, Magic...)
	var p [12]byte
	binary.BigEndian.PutUint32(p[0:4], scryptN)
	binary.BigEndian.PutUint32(p[4:8], scryptR)
	binary.BigEndian.PutUint32(p[8:12], scryptP)
	out = append(out, p[:]...)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = gcm.Seal(out, nonce, seed, nil)
	return out, nil
}

// DecryptSeed opens an EncryptSeed envelope.
func DecryptSeed(b []byte, passphrase string) ([]byte, error) {
	if !IsEncrypted(b) {
		return nil, fmt.Errorf("securekey: not an encrypted keyfile")
	}
	off := len(Magic)
	if len(b) < off+12+16+12+16 {
		return nil, ErrWrongPassphrase
	}
	n := binary.BigEndian.Uint32(b[off : off+4])
	r := binary.BigEndian.Uint32(b[off+4 : off+8])
	p := binary.BigEndian.Uint32(b[off+8 : off+12])
	off += 12
	salt := b[off : off+16]
	off += 16
	nonce := b[off : off+12]
	off += 12
	ct := b[off:]
	// Parameter allowlist: the header is UNTRUSTED input, and the old
	// "bounds" check (N≤2^22, r≤32, p≤8) still admitted ~16 GiB of scrypt
	// state from a tampered keyfile — an OOM bomb on the arm64 box. This
	// build has exactly one writer profile, so only the writer's own
	// parameters are accepted; anything else is refused BEFORE scrypt runs.
	// (The version/magic check above is unchanged: the envelope format is
	// version-stable and every keyfile this code ever wrote carries exactly
	// these parameters, so nothing legitimate is locked out.)
	if n != scryptN || r != scryptR || p != scryptP {
		return nil, fmt.Errorf("securekey: unsupported scrypt parameters N=%s r=%s p=%s (this build supports only N=%d r=%d p=%d; the keyfile header may be corrupted or from an incompatible writer)",
			strconv.FormatUint(uint64(n), 10), strconv.FormatUint(uint64(r), 10), strconv.FormatUint(uint64(p), 10),
			scryptN, scryptR, scryptP)
	}
	key, err := scrypt.Key([]byte(passphrase), salt, int(n), int(r), int(p), keyLen)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	seed, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	if len(seed) != 32 {
		return nil, ErrWrongPassphrase
	}
	return seed, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
