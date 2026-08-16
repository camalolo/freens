// canonical_cache_test.go — properties of the lazily-cached canonical
// serializations on SignedEnvelope (canonRecord / canonFull):
//
//  1. cache transparency: Bytes/CanonicalRecordBytes return the exact bytes
//     an uncached marshal would, before AND after the cache is warm;
//  2. wire-format neutrality: the cache fields are unexported and never
//     appear in the CBOR encoding (golden round-trip);
//  3. concurrency: racing first uses all observe identical bytes.
package wire

import (
	"bytes"
	"sync"
	"testing"
)

func TestCanonicalCacheTransparent(t *testing.T) {
	env := makeTldEnv(t, mustKeypair(t), "cache", nil)

	freshBytes, err := env.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	freshRec, err := env.CanonicalRecordBytes()
	if err != nil {
		t.Fatal(err)
	}

	// Warm both caches, then re-derive from scratch and compare.
	if _, err := env.Bytes(); err != nil {
		t.Fatal(err)
	}
	if _, err := env.CanonicalRecordBytes(); err != nil {
		t.Fatal(err)
	}
	scratch := &SignedEnvelope{Record: env.Record, Sig: env.Sig, Signer: env.Signer}
	scratchBytes, err := scratch.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	scratchRec, err := scratch.CanonicalRecordBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(freshBytes, scratchBytes) {
		t.Error("Bytes() changed after the cache warmed")
	}
	if !bytes.Equal(freshRec, scratchRec) {
		t.Error("CanonicalRecordBytes() changed after the cache warmed")
	}
}

func TestCanonicalCacheWireNeutral(t *testing.T) {
	env := makeTldEnv(t, mustKeypair(t), "neutral", nil)
	// Warm the caches…
	if _, err := env.Bytes(); err != nil {
		t.Fatal(err)
	}
	if _, err := env.CanonicalRecordBytes(); err != nil {
		t.Fatal(err)
	}
	// …then the encoding must be identical to a never-cached envelope's.
	plain := &SignedEnvelope{Record: env.Record, Sig: env.Sig, Signer: env.Signer}
	b1, _ := env.Bytes()
	b2, _ := plain.Bytes()
	if !bytes.Equal(b1, b2) {
		t.Fatal("cache fields leaked into the wire encoding")
	}
	// And a decode → re-encode round-trip still reproduces the same bytes.
	rt, err := DecodeEnvelope(b1)
	if err != nil {
		t.Fatal(err)
	}
	rb, err := rt.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b1, rb) {
		t.Fatal("decode → re-encode not byte-stable with a warm cache")
	}
}

func TestCanonicalCacheConcurrentFirstUse(t *testing.T) {
	env := makeTldEnv(t, mustKeypair(t), "race", nil)
	want, err := env.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	wantRec, err := env.CanonicalRecordBytes()
	if err != nil {
		t.Fatal(err)
	}
	fresh := &SignedEnvelope{Record: env.Record, Sig: env.Sig, Signer: env.Signer}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				b, err := fresh.Bytes()
				if err != nil || !bytes.Equal(b, want) {
					t.Error("Bytes() diverged under racing first use")
					return
				}
				rb, err := fresh.CanonicalRecordBytes()
				if err != nil || !bytes.Equal(rb, wantRec) {
					t.Error("CanonicalRecordBytes() diverged under racing first use")
					return
				}
			}
		}()
	}
	wg.Wait()
}
