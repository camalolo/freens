package wire

// sigmemo.go — a process-global memo for Ed25519 verification outcomes.
//
// Ed25519 verification is a PURE function of (public key, signature,
// message): the same triple always verifies to the same boolean, so a
// cached outcome is exactly as correct as a fresh verify — this is not
// trust caching. The key is SHA-256(pk || sig || msg): planting a FALSE
// entry that collides with a different triple would require breaking
// SHA-256, and a false entry for an honest triple is impossible (the
// entry was itself produced by a real verify of that exact triple).
//
// Why: the resolver re-verifies every chain hop's envelope signature on
// every cache-miss resolution, and claim verification re-verifies witness
// signatures — all over BYTE-IDENTICAL content that simply arrived through
// a fresh decode (the 2026-09-18 verb audit's finding #8: the per-miss
// crypto is the remaining CPU hotspot). Memoizing turns per-resolution
// crypto into per-distinct-content crypto. Wire MESSAGE verification
// (transport.go's per-packet check) deliberately does NOT route through
// this memo — every packet carries a unique txid, so hits would be zero
// and the key hash would be pure overhead on the hottest path.

import (
	"crypto/sha256"
	"sync"

	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
)

// sigMemoSize bounds the memo. Overflow drops the whole generation: a
// memo miss only costs a fresh verify, so wholesale reset is simpler and
// safer than LRU bookkeeping.
const sigMemoSize = 8192

var (
	sigMemoMu sync.Mutex
	sigMemo   = make(map[[32]byte]bool, sigMemoSize)
)

func sigMemoKey(pk, sig, msg []byte) [32]byte {
	h := sha256.New()
	h.Write(pk)
	h.Write(sig)
	h.Write(msg)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// VerifyMemoized is crypto.Verify with the memo. Malformed inputs bypass
// the memo (they can never verify; crypto.Verify reports the same).
func VerifyMemoized(pk, sig, msg []byte) bool {
	if len(pk) != constants.Ed25519PublicKeyLen || len(sig) != constants.Ed25519SignatureLen {
		return crypto.Verify(pk, sig, msg)
	}
	key := sigMemoKey(pk, sig, msg)
	sigMemoMu.Lock()
	if v, ok := sigMemo[key]; ok {
		sigMemoMu.Unlock()
		return v
	}
	sigMemoMu.Unlock()
	v := crypto.Verify(pk, sig, msg)
	sigMemoMu.Lock()
	if len(sigMemo) >= sigMemoSize {
		sigMemo = make(map[[32]byte]bool, sigMemoSize)
	}
	sigMemo[key] = v
	sigMemoMu.Unlock()
	return v
}
