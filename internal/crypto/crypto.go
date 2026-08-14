// Package crypto implements the freens cryptography layer (specifications.md §5):
//
//   - Ed25519 (RFC 8032) signatures and SHA-256 key identities (§5.1, §5.2).
//   - Simple per-purpose hierarchical key derivation
//     SK_purpose = SHA-256(SK_root || "freens:" || purpose) (§5.3).
//   - Hashcash-style proof of work pow_hash = SHA-256(prefix || nonce)
//     with >= D leading zero bits (§7.3), difficulty recorded in nonce[0]
//     per Appendix A.4.
//   - Threshold recovery policy data structure (§5.4).
//   - Canonical witness-attestation signing input (§7.3).
//
// Only the Go standard library is used (crypto/ed25519, crypto/sha256,
// crypto/rand, crypto/hmac).
package crypto

import (
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/laurent/freens/internal/constants"
)

// ErrCrypto is returned for unrecoverable crypto failures (e.g. PoW exhaustion).
var ErrCrypto = errors.New("crypto: error")

// Keypair is an Ed25519 keypair. The private key is the 64-byte
// crypto/ed25519.PrivateKey (seed || public-key); the raw 32-byte seed is
// exposed via Seed().
type Keypair struct {
	priv ed25519.PrivateKey
}

// Generate returns a fresh Ed25519 keypair from the OS CSPRNG.
func Generate() (*Keypair, error) {
	_, priv, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		return nil, err
	}
	return &Keypair{priv: priv}, nil
}

// FromSeed reconstructs a keypair from a 32-byte Ed25519 seed.
func FromSeed(seed []byte) (*Keypair, error) {
	if len(seed) != constants.Ed25519PrivateKeyLen {
		return nil, fmt.Errorf("crypto: seed must be %d bytes", constants.Ed25519PrivateKeyLen)
	}
	return &Keypair{priv: ed25519.NewKeyFromSeed(seed)}, nil
}

// Public returns the 32-byte Ed25519 verifying key.
func (k *Keypair) Public() []byte { return k.priv[32:] }

// Seed returns the 32-byte private seed.
func (k *Keypair) Seed() []byte { return k.priv[:32] }

// Sign returns a 64-byte Ed25519 signature over message.
func (k *Keypair) Sign(message []byte) []byte { return ed25519.Sign(k.priv, message) }

// Verify reports whether sig is a valid Ed25519 signature of message under
// publicKey. It never returns an error for a bad signature — only false.
func Verify(publicKey, signature, message []byte) bool {
	if len(publicKey) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(publicKey, message, signature)
}

// TldID returns TLD_ID = SHA-256(publicKey) — 32 bytes (§3.1, §5.2).
func TldID(publicKey []byte) ([]byte, error) {
	if len(publicKey) != constants.Ed25519PublicKeyLen {
		return nil, fmt.Errorf("crypto: public key must be %d bytes", constants.Ed25519PublicKeyLen)
	}
	h := sha256.Sum256(publicKey)
	return h[:], nil
}

// NodeID returns Node ID = SHA-256(nodePublicKey) — 32 bytes (§6.2). Same
// algorithm as TldID; distinct name documents intent.
func NodeID(publicKey []byte) ([]byte, error) {
	return TldID(publicKey)
}

// DerivePurpose returns SK_purpose = SHA-256(rootSeed || "freens:" || purpose)
// per §5.3's simple per-purpose derivation. The 32-byte digest is a valid
// Ed25519 seed.
func DerivePurpose(rootSeed []byte, purpose string) ([]byte, error) {
	if len(rootSeed) != constants.Ed25519PrivateKeyLen {
		return nil, fmt.Errorf("crypto: root seed must be %d bytes", constants.Ed25519PrivateKeyLen)
	}
	h := sha256.New()
	h.Write(rootSeed)
	h.Write([]byte("freens:"))
	h.Write([]byte(purpose))
	return h.Sum(nil), nil
}

// DerivePurposeKeypair derives a purpose seed and wraps it into a Keypair.
func DerivePurposeKeypair(rootSeed []byte, purpose string) (*Keypair, error) {
	seed, err := DerivePurpose(rootSeed, purpose)
	if err != nil {
		return nil, err
	}
	return FromSeed(seed)
}

// LeadingZeroBits counts the leading zero bits in a big-endian digest.
// Used by the hashcash PoW check (§7.3): a digest meets difficulty D iff it
// has at least D leading zero bits.
//
//	0xff -> 0, 0x7f -> 1, 0x40 -> 1, 0x01 -> 7, 0x10 -> 3,
//	0x00 -> 8, 0x0001 -> 15, 0x0010 -> 11, 32 zero bytes -> 256
func LeadingZeroBits(digest []byte) int {
	bits := 0
	for _, b := range digest {
		if b == 0 {
			bits += 8
			continue
		}
		bits += 8 - bitLenU8(b)
		break
	}
	return bits
}

// bitLenU8 returns the index of the highest set bit + 1 (i.e. the bit-length).
func bitLenU8(b byte) int {
	n := 0
	for b != 0 {
		b >>= 1
		n++
	}
	return n
}

// MeetsDifficulty reports whether digest has at least difficultyBits leading
// zero bits.
func MeetsDifficulty(digest []byte, difficultyBits int) bool {
	return LeadingZeroBits(digest) >= difficultyBits
}

// PoWHash returns SHA-256(prefix || nonce) (§7.3).
func PoWHash(prefix, nonce []byte) []byte {
	h := sha256.New()
	h.Write(prefix)
	h.Write(nonce)
	return h.Sum(nil)
}

// clampDifficultyByte returns min(difficultyBits, 255) as a byte. This is the
// value recorded in nonce[0] per Appendix A.4 (the difficulty byte is capped
// at 255 because a single byte cannot represent more). Matches the Python
// reference (crypto.py:248): nonce[0] = min(difficultyBits, 255).
func clampDifficultyByte(difficultyBits int) byte {
	d := difficultyBits
	if d > 255 {
		d = 255
	}
	return byte(d)
}

// MinePoW searches for a nonce such that SHA-256(prefix || nonce) has at least
// difficultyBits leading zero bits. Returns (nonce, powHash). The first byte
// of the nonce is fixed to min(difficultyBits, 255) per Appendix A.4 (records
// the difficulty used); only the remaining nonceSize-1 bytes are randomized.
//
// Returns ErrCrypto if maxIters is exhausted.
func MinePoW(prefix []byte, difficultyBits, maxIters, nonceSize int) (nonce, powHash []byte, err error) {
	if difficultyBits < 0 {
		return nil, nil, fmt.Errorf("crypto: difficulty must be >= 0")
	}
	if nonceSize < 0 {
		return nil, nil, fmt.Errorf("crypto: nonceSize must be >= 0")
	}
	tailLen := nonceSize - 1
	if tailLen < 0 {
		tailLen = 0
	}
	dByte := byte(0)
	if nonceSize >= 1 {
		dByte = clampDifficultyByte(difficultyBits)
	}
	for i := 0; i < maxIters; i++ {
		tail := make([]byte, tailLen)
		if _, err := crand.Read(tail); err != nil {
			return nil, nil, err
		}
		nonce := append([]byte{dByte}, tail...)
		if nonceSize == 0 {
			nonce = tail
		}
		h := PoWHash(prefix, nonce)
		if MeetsDifficulty(h, difficultyBits) {
			return nonce, h, nil
		}
	}
	return nil, nil, fmt.Errorf("%w: PoW mining exceeded %d iterations at difficulty %d", ErrCrypto, maxIters, difficultyBits)
}

// VerifyPoW reports whether SHA-256(prefix || nonce) meets difficultyBits. It
// verifies the hash only; it does not require nonce[0] == difficulty (that
// byte is informational per Appendix A.4).
func VerifyPoW(prefix, nonce []byte, difficultyBits int) bool {
	return MeetsDifficulty(PoWHash(prefix, nonce), difficultyBits)
}

// RecoveryPolicy is the §5.4 threshold-of-N recovery policy with a timelock.
// Mirrors the CBOR structure {1: threshold, 2: keys, 3: timelock}.
type RecoveryPolicy struct {
	Threshold int
	Keys      [][]byte // 32-byte recovery public keys
	Timelock  int
}

// NewRecoveryPolicy validates and constructs a recovery policy.
func NewRecoveryPolicy(threshold int, keys [][]byte, timelock int) (*RecoveryPolicy, error) {
	if threshold < 1 {
		return nil, errors.New("crypto: threshold must be >= 1")
	}
	for _, k := range keys {
		if len(k) != constants.Ed25519PublicKeyLen {
			return nil, fmt.Errorf("crypto: recovery keys must be %d bytes", constants.Ed25519PublicKeyLen)
		}
	}
	if threshold > len(keys) {
		return nil, errors.New("crypto: threshold > keys count")
	}
	if timelock < 0 {
		return nil, errors.New("crypto: timelock must be >= 0")
	}
	cp := make([][]byte, len(keys))
	for i, k := range keys {
		cp[i] = append([]byte{}, k...)
	}
	return &RecoveryPolicy{Threshold: threshold, Keys: cp, Timelock: timelock}, nil
}

// WitnessSigningTag is the canonical domain-separation tag for witness
// attestations (§7.3).
var WitnessSigningTag = []byte("freens-witness-v1")

// WitnessSigningMessage returns the canonical bytes a witness signs for
// (alias, tldID, claimantPK, ts). Length-prefixed so signing is
// self-contained and unambiguous:
//
//	"freens-witness-v1" || uint32_be(len(alias)) || alias
//	|| tld_id(32) || claimant_pk(32) || uint64_be(ts)
func WitnessSigningMessage(alias string, tldID, claimantPK []byte, ts uint64) ([]byte, error) {
	if len(tldID) != constants.SHA256Len || len(claimantPK) != constants.Ed25519PublicKeyLen {
		return nil, fmt.Errorf("crypto: tld_id/claimant_pk must be %d bytes", constants.SHA256Len)
	}
	ab := []byte(alias)
	var lenBuf [4]byte
	lenBuf[0] = byte(len(ab) >> 24)
	lenBuf[1] = byte(len(ab) >> 16)
	lenBuf[2] = byte(len(ab) >> 8)
	lenBuf[3] = byte(len(ab))
	var tsBuf [8]byte
	for i := 0; i < 8; i++ {
		tsBuf[7-i] = byte(ts >> (8 * i))
	}
	out := make([]byte, 0, len(WitnessSigningTag)+4+len(ab)+32+32+8)
	out = append(out, WitnessSigningTag...)
	out = append(out, lenBuf[:]...)
	out = append(out, ab...)
	out = append(out, tldID...)
	out = append(out, claimantPK...)
	out = append(out, tsBuf[:]...)
	return out, nil
}
