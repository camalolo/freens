// verify_cache.go — memoization layer for [Verify].
//
// WHY (profiling, Aug 2026): ed25519 verification dominates every hot path —
// ~60% of total CPU in both the resolver and DHT profiles — but the SAME
// (publicKey, signature, message) triples are verified repeatedly:
//
//   - one cold resolve verifies the same claim envelope at the collection
//     boundary (CollectClaims' add()) and again in the resolver's §7.4 filter
//     (IsBasicValid → VerifySignature);
//   - a fetched envelope is verified walk-side (IterativeGetDetailed) and
//     AGAIN by the defensive store.Put(verifySignature=true) cache-back;
//   - popular records are re-fetched and re-verified by many requesters;
//   - contested aliases (§10.4 60 s TTL cap) re-run the full §7.4 filter —
//     including all W witness verifies — every cache expiry.
//
// Ed25519 verification is a PURE function of its inputs, so memoizing it is
// semantics-preserving by construction: the cache key is
// SHA-256(publicKey || signature || message), which covers every input byte —
// an in-place mutation of any argument produces a different key and therefore
// a fresh real verification. Both positive AND negative results are cached
// (invalidity is as deterministic as validity).
//
// Adversarial posture: an attacker flooding distinct inputs only evicts cache
// entries (a perf effect, never a correctness one); a cache hit can never
// assert "valid" for bytes that do not carry a real signature, because the
// entry can only have been created by a successful ed25519.Verify over the
// exact same triple. The table is direct-mapped (index = hash bits) and
// bounded, so memory is a fixed ~8 Ki slots regardless of load.
package crypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"sync/atomic"
)

// verifyCacheSlots is the table size (power of two). 8192 × ~40 B ≈ 320 KiB —
// plenty for the working set of a node's repeatedly-verified envelopes,
// witness attestations, and RPC messages.
const verifyCacheBits = 13 // log2 of the table size
const verifyCacheSlots = 1 << verifyCacheBits

// verifyCacheEntry is one memoized verdict. key is the full SHA-256 over the
// verify inputs, so a slot hit is unambiguous.
type verifyCacheEntry struct {
	key [sha256.Size]byte
	ok  bool
}

// verifyCache is the direct-mapped memo table. Slots hold immutable entries
// (never mutated in place — a overwrite installs a NEW entry), so
// atomic.Pointer loads/stores are race-free without a lock: a stale load
// (pre-overwrite entry) still matches its own key or misses, and an
// in-flight store is simply not yet visible.
var verifyCache [verifyCacheSlots]atomic.Pointer[verifyCacheEntry]

// verifyCacheStats counts memo hits/misses for diagnostics (atomic; read via
// VerifyCacheStats).
var verifyCacheHits, verifyCacheMisses atomic.Uint64

// verifyCacheKey derives the memo key over ALL Verify inputs. publicKey and
// signature have protocol-fixed lengths (32, 64), so the concatenation is
// unambiguous; the final SHA-256 makes collisions negligible.
func verifyCacheKey(publicKey, signature, message []byte) (key [sha256.Size]byte) {
	h := sha256.New()
	h.Write(publicKey)
	h.Write(signature)
	h.Write(message)
	copy(key[:], h.Sum(nil))
	return key
}

// verifyCacheSlot picks the table index for a key. Fibonacci hashing
// (multiply by the 64-bit fractional constant of the golden ratio, then take
// the high bits) spreads keys with low-entropy prefixes evenly.
func verifyCacheSlot(key [sha256.Size]byte) int {
	v := uint64(key[0])<<56 | uint64(key[1])<<48 | uint64(key[2])<<40 | uint64(key[3])<<32 |
		uint64(key[4])<<24 | uint64(key[5])<<16 | uint64(key[6])<<8 | uint64(key[7])
	return int((v * 0x9E3779B97F4A7C15) >> (64 - verifyCacheBits))
}

// VerifyCacheStats reports (hits, misses) since process start — the memo's
// observed effectiveness (exposed for tests and /metrics wiring later).
func VerifyCacheStats() (hits, misses uint64) {
	return verifyCacheHits.Load(), verifyCacheMisses.Load()
}

// verifyMemoized wraps a real ed25519 verification with the memo table.
func verifyMemoized(publicKey, signature, message []byte) bool {
	key := verifyCacheKey(publicKey, signature, message)
	slot := &verifyCache[verifyCacheSlot(key)]
	if e := slot.Load(); e != nil && e.key == key {
		verifyCacheHits.Add(1)
		return e.ok
	}
	verifyCacheMisses.Add(1)
	ok := ed25519.Verify(publicKey, message, signature)
	slot.Store(&verifyCacheEntry{key: key, ok: ok})
	return ok
}
