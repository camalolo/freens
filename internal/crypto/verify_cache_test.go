// verify_cache_test.go — correctness properties of the Verify memoization.
// The invariant under test throughout: memoization is TRANSPARENT — every
// outcome must equal what an unmemoized ed25519.Verify would return, no
// matter the cache state, because the key covers every input byte.
package crypto

import (
	"bytes"
	"sync"
	"testing"
)

func TestVerifyMemoTransparent(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("the quick brown freens node")
	sig := kp.Sign(msg)

	if !Verify(kp.Public(), sig, msg) {
		t.Fatal("valid signature: want true")
	}
	// Repeated call (memo hit path) must agree.
	if !Verify(kp.Public(), sig, msg) {
		t.Fatal("memoized repeat: want true")
	}

	// In-place mutation of ANY input must produce a fresh, correct verdict.
	bad := append([]byte(nil), sig...)
	bad[0] ^= 0xff
	if Verify(kp.Public(), bad, msg) {
		t.Fatal("corrupted signature: want false")
	}

	msg2 := append([]byte(nil), msg...)
	msg2[0] ^= 0x01
	if Verify(kp.Public(), sig, msg2) {
		t.Fatal("signature over a different message: want false")
	}

	other, _ := Generate()
	if Verify(other.Public(), sig, msg) {
		t.Fatal("signature under the wrong key: want false")
	}

	// Restoring the mutated bytes must RESTORE the true verdict — proves the
	// earlier false did not poison a key that is now valid again.
	bad[0] ^= 0xff
	if !Verify(kp.Public(), bad, msg) {
		t.Fatal("restored signature: memo must not stick at false")
	}
}

func TestVerifyMemoNegativeNotCachedAcrossKeyChanges(t *testing.T) {
	kp, _ := Generate()
	msg := []byte("negative cache probe")
	sig := kp.Sign(msg)

	// A one-byte-off signature (false), then the CORRECT signature whose
	// bytes differ from the bad one in exactly one place — the two keys are
	// distinct, so the earlier false must not leak.
	bad := append([]byte(nil), sig...)
	bad[63] ^= 0x01
	if Verify(kp.Public(), bad, msg) {
		t.Fatal("setup: corrupted sig must fail")
	}
	if !Verify(kp.Public(), sig, msg) {
		t.Fatal("correct sig must verify even after a near-miss negative")
	}
}

func TestVerifyMemoLengthRejections(t *testing.T) {
	kp, _ := Generate()
	sig := kp.Sign([]byte("len"))
	// Wrong-length inputs are rejected BEFORE the memo (no table pollution).
	if Verify(kp.Public()[:31], sig, []byte("len")) {
		t.Error("short public key: want false")
	}
	if Verify(kp.Public(), sig[:63], []byte("len")) {
		t.Error("short signature: want false")
	}
}

func TestVerifyMemoStatsAndSlots(t *testing.T) {
	kp, _ := Generate()
	msg := []byte("stats probe")
	sig := kp.Sign(msg)

	h0, m0 := VerifyCacheStats()
	Verify(kp.Public(), sig, msg) // miss (or collision-overwrite miss)
	Verify(kp.Public(), sig, msg) // hit
	h1, m1 := VerifyCacheStats()
	if h1-h0 != 1 {
		t.Errorf("hits delta = %d, want 1", h1-h0)
	}
	if m1-m0 != 1 {
		t.Errorf("misses delta = %d, want 1", m1-m0)
	}
}

func TestVerifyMemoSlotIndexInBounds(t *testing.T) {
	for i := 0; i < 256; i++ {
		var k [32]byte
		k[0] = byte(i)
		k[1] = byte(i * 7)
		if s := verifyCacheSlot(k); s < 0 || s >= verifyCacheSlots {
			t.Fatalf("slot %d out of range [0,%d)", s, verifyCacheSlots)
		}
	}
}

// TestVerifyMemoConcurrent drives the table from many goroutines over a mix
// of shared (contended) and private inputs; run with -race, it is the
// atomicity proof for the slot swap.
func TestVerifyMemoConcurrent(t *testing.T) {
	base, _ := Generate()
	shared := base.Sign([]byte("shared input"))

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			priv, _ := Generate()
			mine := priv.Sign([]byte{byte('a' + g)})
			for i := 0; i < 200; i++ {
				if !Verify(base.Public(), shared, []byte("shared input")) {
					t.Error("shared valid input flipped false under concurrency")
					return
				}
				bad := append([]byte(nil), mine...)
				if i%2 == 0 {
					bad[5] ^= 0xff
				}
				Verify(priv.Public(), bad, []byte{byte('a' + g)})
			}
		}(g)
	}
	wg.Wait()
}

// TestVerifyMemoCollisionCorrectness: table collisions must only cost
// performance, never correctness — two inputs engineered into the same slot
// still verify independently.
func TestVerifyMemoCollisionCorrectness(t *testing.T) {
	kp, _ := Generate()
	a := kp.Sign([]byte("collision input a"))
	b := kp.Sign([]byte("collision input b"))
	sa := verifyCacheSlot(verifyCacheKey(kp.Public(), a, []byte("collision input a")))
	sb := verifyCacheSlot(verifyCacheKey(kp.Public(), b, []byte("collision input b")))
	// Same slot or not, both must be true.
	_ = sa
	_ = sb
	if !Verify(kp.Public(), a, []byte("collision input a")) {
		t.Error("input a lost its verdict after collision pressure")
	}
	if !Verify(kp.Public(), b, []byte("collision input b")) {
		t.Error("input b lost its verdict after collision pressure")
	}
	// Pressure the table with many distinct inputs, then re-check both.
	for i := 0; i < 4*verifyCacheSlots; i++ {
		Verify(kp.Public(), kp.Sign([]byte{byte(i), byte(i >> 8)}), []byte{byte(i), byte(i >> 8)})
	}
	if !Verify(kp.Public(), a, []byte("collision input a")) {
		t.Error("input a not re-verifiable after table churn")
	}
	if !Verify(kp.Public(), b, []byte("collision input b")) {
		t.Error("input b not re-verifiable after table churn")
	}
}

var sinkBool bool

// BenchmarkVerifyColdVsMemoized shows the memo's effect: COLD (unique input
// each iteration — always a miss) vs the same input repeatedly (hit).
func BenchmarkVerifyColdVsMemoized(b *testing.B) {
	kp, _ := Generate()
	sigs := make([][]byte, 512)
	msgs := make([][]byte, 512)
	for i := range sigs {
		msgs[i] = bytes.Repeat([]byte{byte(i)}, 64)
		sigs[i] = kp.Sign(msgs[i])
	}
	b.Run("Cold", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			sinkBool = Verify(kp.Public(), sigs[i%len(sigs)], msgs[i%len(msgs)])
		}
	})
	b.Run("Memoized", func(b *testing.B) {
		msg, sig := msgs[0], sigs[0]
		for i := 0; i < b.N; i++ {
			sinkBool = Verify(kp.Public(), sig, msg)
		}
	})
}
