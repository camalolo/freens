package dht

import (
	"bytes"
	"testing"

	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/wire"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// makeEnv builds a self-certifying TLD SignedEnvelope (0 labels, alias "foo")
// owned and signed by ownerKP, with the given sequence/created/expires. Its
// VerifySignature() is true by construction. Mirrors the makeTldEnv helper in
// package wire's own test suite.
func makeEnv(t *testing.T, sequence, created, expires uint64, ownerKP *crypto.Keypair) *wire.SignedEnvelope {
	t.Helper()
	tldID, err := crypto.TldID(ownerKP.Public())
	if err != nil {
		t.Fatalf("TldID: %v", err)
	}
	name, err := naming.EncodeWireName(nil, "foo", tldID)
	if err != nil {
		t.Fatalf("EncodeWireName: %v", err)
	}
	rec, err := wire.NewRecord(name, ownerKP.Public(), sequence, created, expires)
	if err != nil {
		t.Fatalf("NewRecord: %v", err)
	}
	env, err := wire.SignRecord(rec, ownerKP)
	if err != nil {
		t.Fatalf("SignRecord: %v", err)
	}
	return env
}

func mustKeypair(t *testing.T) *crypto.Keypair {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return kp
}

// keyN returns the n-th distinct 32-byte DHT key (0x00..0x00, 0x00..0x01, ...).
func keyN(n byte) []byte {
	k := make([]byte, constants.SHA256Len)
	k[constants.SHA256Len-1] = n
	return k
}

// envBytes returns len(env.Bytes()) or fails the test.
func envBytes(t *testing.T, env *wire.SignedEnvelope) int {
	t.Helper()
	b, err := env.Bytes()
	if err != nil {
		t.Fatalf("env.Bytes: %v", err)
	}
	return len(b)
}

// ---------------------------------------------------------------------------
// Basic Put / Get / Has / Count / SizeBytes
// ---------------------------------------------------------------------------

func TestEnvelopeStoreBasicPutGet(t *testing.T) {
	kp := mustKeypair(t)
	env := makeEnv(t, 1, 1000, 2000, kp)
	key := keyN(1)
	s := NewEnvelopeStore(0, func() int64 { return 1500 })

	ok, err := s.Put(key, env, 1500, true)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if !ok {
		t.Fatal("Put should accept a fresh valid envelope")
	}
	if c := s.Count(); c != 1 {
		t.Errorf("Count = %d, want 1", c)
	}
	if !s.Has(key, 1500) {
		t.Error("Has should be true after Put")
	}

	got, err := s.Get(key, 1500)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Fatal("Get should return the stored envelope")
	}
	rhNew, _ := env.RecordHash()
	rhGot, _ := got.RecordHash()
	if !bytes.Equal(rhNew, rhGot) {
		t.Error("Get returned an envelope with a different RecordHash")
	}
	if want := envBytes(t, env); s.SizeBytes() != want {
		t.Errorf("SizeBytes = %d, want %d", s.SizeBytes(), want)
	}
}

func TestEnvelopeStoreEmptyStore(t *testing.T) {
	s := NewEnvelopeStore(0, nil)
	if s.Count() != 0 {
		t.Errorf("Count = %d, want 0", s.Count())
	}
	if s.SizeBytes() != 0 {
		t.Errorf("SizeBytes = %d, want 0", s.SizeBytes())
	}
	if got, _ := s.Get(keyN(0), 1000); got != nil {
		t.Error("Get on empty store should return nil")
	}
	if s.Has(keyN(0), 1000) {
		t.Error("Has on empty store should be false")
	}
	if s.Remove(keyN(0)) {
		t.Error("Remove on empty store should return false")
	}
	if n := len(s.Keys()); n != 0 {
		t.Errorf("Keys len = %d, want 0", n)
	}
}

// ---------------------------------------------------------------------------
// §6.4 step 3 — winner rule (higher sequence wins; lower rejected)
// ---------------------------------------------------------------------------

func TestEnvelopeStoreWinnerRule(t *testing.T) {
	kp := mustKeypair(t)
	e4 := makeEnv(t, 4, 1000, 2000, kp)
	e5 := makeEnv(t, 5, 1000, 2000, kp)
	key := keyN(7)
	s := NewEnvelopeStore(0, func() int64 { return 1500 })

	// Put seq4, then seq5: both accepted (5 strictly wins over 4).
	if ok, _ := s.Put(key, e4, 1500, true); !ok {
		t.Fatal("Put(e4) should be accepted")
	}
	if ok, _ := s.Put(key, e5, 1600, true); !ok {
		t.Fatal("Put(e5) should be accepted (strict win)")
	}
	got, _ := s.Get(key, 1600)
	if got == nil || got.Record.Sequence != 5 {
		t.Fatalf("Get.Sequence = %v, want 5", seqOf(got))
	}

	// Re-put seq4 (older): rejected; winner unchanged.
	if ok, _ := s.Put(key, e4, 1700, true); ok {
		t.Error("Put(e4) after e5 should be rejected (older)")
	}
	got, _ = s.Get(key, 1700)
	if got == nil || got.Record.Sequence != 5 {
		t.Fatalf("Get.Sequence = %v, want still 5", seqOf(got))
	}
	if c := s.Count(); c != 1 {
		t.Errorf("Count = %d, want 1 (one winner per key)", c)
	}
}

// seqOf returns the record sequence or 0 for a nil envelope (test helper).
func seqOf(env *wire.SignedEnvelope) uint64 {
	if env == nil || env.Record == nil {
		return 0
	}
	return env.Record.Sequence
}

// Same-sequence tie-break: bytewise-greater H_record wins (wire.EnvelopeWins).
func TestEnvelopeStoreWinnerRuleSameSequenceTieBreak(t *testing.T) {
	// Two TLDs owned by distinct keys -> distinct names -> distinct record
	// hashes, same sequence.
	kpA := mustKeypair(t)
	kpB := mustKeypair(t)
	envA := makeEnv(t, 1, 1000, 2000, kpA)
	envB := makeEnv(t, 1, 1000, 2000, kpB)
	hA, _ := envA.RecordHash()
	hB, _ := envB.RecordHash()
	if bytes.Equal(hA, hB) {
		t.Fatal("test setup: envA and envB must have distinct record hashes")
	}
	key := keyN(9)
	s := NewEnvelopeStore(0, func() int64 { return 1500 })

	// The bytewise-greater hash wins. Put the smaller first, then the larger.
	var first, second *wire.SignedEnvelope
	if bytes.Compare(hA, hB) < 0 {
		first, second = envA, envB
	} else {
		first, second = envB, envA
	}
	if ok, _ := s.Put(key, first, 1500, true); !ok {
		t.Fatal("Put(first) should be accepted")
	}
	if ok, _ := s.Put(key, second, 1600, true); !ok {
		t.Fatal("Put(second) should be accepted (bytewise-greater hash wins)")
	}
	got, _ := s.Get(key, 1600)
	if got != second {
		t.Error("winner should be the bytewise-greater-hash envelope")
	}
	// Putting the smaller back is rejected.
	if ok, _ := s.Put(key, first, 1700, true); ok {
		t.Error("Put(first) after second should be rejected")
	}
}

// ---------------------------------------------------------------------------
// §4.4 rule 4 / §8.3 — prev_hash chain-link enforcement on Put
// ---------------------------------------------------------------------------

// makeChainedEnv builds a self-certifying TLD envelope (alias "foo") with the
// given sequence and prev_hash, signed by ownerKP so Put(verifySignature=true)
// accepts its signature. prevHash may be nil.
func makeChainedEnv(t *testing.T, sequence uint64, prevHash []byte, ownerKP *crypto.Keypair) *wire.SignedEnvelope {
	t.Helper()
	tldID, err := crypto.TldID(ownerKP.Public())
	if err != nil {
		t.Fatalf("TldID: %v", err)
	}
	name, err := naming.EncodeWireName(nil, "foo", tldID)
	if err != nil {
		t.Fatalf("EncodeWireName: %v", err)
	}
	rec, err := wire.NewRecord(name, ownerKP.Public(), sequence, 1000, 2000)
	if err != nil {
		t.Fatalf("NewRecord: %v", err)
	}
	rec.PrevHash = prevHash
	env, err := wire.SignRecord(rec, ownerKP)
	if err != nil {
		t.Fatalf("SignRecord: %v", err)
	}
	return env
}

func TestEnvelopeStoreChainLinkPrevHash(t *testing.T) {
	kp := mustKeypair(t)
	key := keyN(11)
	s := NewEnvelopeStore(0, func() int64 { return 1500 })

	first := makeChainedEnv(t, 1, nil, kp)
	firstHash, err := first.RecordHash()
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.Put(key, first, 1500, true); !ok {
		t.Fatal("Put(first) should be accepted (fresh slot)")
	}

	wrongHash := append([]byte(nil), firstHash...)
	wrongHash[0] ^= 0xFF

	// Higher sequence + CORRECT prev_hash → accepted.
	good := makeChainedEnv(t, 2, firstHash, kp)
	if ok, _ := s.Put(key, good, 1600, true); !ok {
		t.Fatal("Put(seq2, correct prev_hash) should be accepted")
	}
	goodHash, err := good.RecordHash()
	if err != nil {
		t.Fatal(err)
	}

	// Higher sequence + WRONG prev_hash → rejected, winner unchanged.
	bad := makeChainedEnv(t, 3, wrongHash, kp)
	ok, err := s.Put(key, bad, 1700, true)
	if err != nil {
		t.Fatalf("Put(bad prev_hash): %v", err)
	}
	if ok {
		t.Error("Put(seq3, wrong prev_hash) should be rejected (chain link fails)")
	}
	got, _ := s.Get(key, 1700)
	if got == nil || got.Record.Sequence != 2 {
		t.Fatalf("winner sequence = %v, want 2 (unchanged)", seqOf(got))
	}

	// Equal sequence with CORRECT prev_hash but a bytewise-GREATER record
	// hash: EnvelopeWins(newer, older) is true (§6.4 step 3 same-sequence
	// tie-break), so only the chain-link gate (sequence must strictly
	// increase, §4.4 rule 4) can reject it. Search for a Created value whose
	// resulting hash beats the incumbent's so the winner rule alone would
	// accept.
	var sneaky *wire.SignedEnvelope
	for created := uint64(1001); created < 1200; created++ {
		r2, err := wire.NewRecord(good.Record.Name, good.Record.Owner, 2, created, 2000)
		if err != nil {
			t.Fatal(err)
		}
		r2.PrevHash = goodHash
		cand, err := wire.SignRecord(r2, kp)
		if err != nil {
			t.Fatal(err)
		}
		ch, err := cand.RecordHash()
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Compare(ch, goodHash) > 0 {
			sneaky = cand
			break
		}
	}
	if sneaky == nil {
		t.Fatal("test setup: could not build a same-sequence bigger-hash envelope")
	}
	if !wire.EnvelopeWins(sneaky, good) {
		t.Fatal("test setup: sneaky must strictly win the §6.4 tie-break")
	}
	if ok, _ := s.Put(key, sneaky, 1700, true); ok {
		t.Error("Put(seq2-equal, correct prev_hash, bigger hash) should be rejected: sequence does not strictly increase (§4.4 rule 4)")
	}

	// prev_hash set but the slot is empty (fresh name) → accepted only if it
	// strictly wins; VerifyChainLink against a nil predecessor would fail, but
	// an empty slot has no incumbent to chain to, so the plain winner rule
	// applies (§6.4 step 4: dead/absent incumbent = empty slot).
	other := keyN(12)
	if ok, _ := s.Put(other, makeChainedEnv(t, 5, wrongHash, kp), 1500, true); !ok {
		t.Error("Put into an EMPTY slot with arbitrary prev_hash should be accepted")
	}
}

// Backward compatibility: a nil prev_hash newcomer is judged by the plain
// winner rule alone (§6.4 step 3); the chain-link gate never fires.
func TestEnvelopeStoreNilPrevHashBackwardCompat(t *testing.T) {
	kp := mustKeypair(t)
	key := keyN(13)
	s := NewEnvelopeStore(0, func() int64 { return 1500 })

	e1 := makeChainedEnv(t, 1, nil, kp)
	e4 := makeChainedEnv(t, 4, nil, kp)
	if ok, _ := s.Put(key, e1, 1500, true); !ok {
		t.Fatal("Put(seq1) should be accepted")
	}
	// seq4 with NO prev_hash (a gap under §8.2's plain winner rule): still
	// accepted — pre-prev_hash publishers must not break.
	if ok, _ := s.Put(key, e4, 1600, true); !ok {
		t.Error("Put(seq4, nil prev_hash) should be accepted (plain winner rule)")
	}
	got, _ := s.Get(key, 1600)
	if seqOf(got) != 4 {
		t.Errorf("winner sequence = %v, want 4", seqOf(got))
	}
	// Older nil-prev_hash newcomer still rejected by the winner rule.
	if ok, _ := s.Put(key, e1, 1700, true); ok {
		t.Error("Put(seq1 after seq4) should be rejected (older)")
	}
}

// ---------------------------------------------------------------------------
// Signature verification toggle
// ---------------------------------------------------------------------------

func TestEnvelopeStoreBadSignature(t *testing.T) {
	owner := mustKeypair(t)
	good := makeEnv(t, 1, 1000, 2000, owner)

	// Forge: copy the good envelope but claim a different signer.
	other := mustKeypair(t)
	forged := &wire.SignedEnvelope{
		Record: good.Record,
		Sig:    good.Sig, // signature is over the record, still valid for `owner`
		Signer: other.Public(),
	}
	if forged.VerifySignature() {
		t.Fatal("test setup: forged envelope must fail VerifySignature")
	}

	key := keyN(2)
	s := NewEnvelopeStore(0, func() int64 { return 1500 })

	// verifySignature=true -> rejected, count unchanged.
	ok, err := s.Put(key, forged, 1500, true)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if ok {
		t.Error("Put(forged, verify=true) should be false")
	}
	if c := s.Count(); c != 0 {
		t.Errorf("Count = %d, want 0 after rejected put", c)
	}

	// verifySignature=false -> accepted.
	if ok, _ := s.Put(key, forged, 1500, false); !ok {
		t.Error("Put(forged, verify=false) should be true")
	}
	if c := s.Count(); c != 1 {
		t.Errorf("Count = %d, want 1", c)
	}
}

// ---------------------------------------------------------------------------
// Expiry / lazy eviction (§6.4 step 4)
// ---------------------------------------------------------------------------

func TestEnvelopeStoreExpiryLazyEvict(t *testing.T) {
	kp := mustKeypair(t)
	// expires=2000; alive iff now < 2000 + ExpiryGrace (86400) == 88400.
	env := makeEnv(t, 1, 1000, 2000, kp)
	key := keyN(3)
	s := NewEnvelopeStore(0, func() int64 { return 1500 })

	if ok, _ := s.Put(key, env, 1500, true); !ok {
		t.Fatal("Put should accept")
	}

	// One second before the grace boundary: present.
	justBefore := int64(2000 + constants.ExpiryGrace - 1) // 88399
	if got, _ := s.Get(key, justBefore); got == nil {
		t.Error("Get at grace-1 should return the envelope")
	}
	if !s.Has(key, justBefore) {
		t.Error("Has at grace-1 should be true")
	}

	// Exactly at the grace boundary: dead (now == expires + grace is NOT <).
	if s.Has(key, int64(2000+constants.ExpiryGrace)) {
		t.Error("Has at grace boundary should be false (now == expires+grace)")
	}

	// One second past the grace boundary: lazily evicted on Get.
	justAfter := int64(2000 + constants.ExpiryGrace + 1) // 88401
	got, _ := s.Get(key, justAfter)
	if got != nil {
		t.Error("Get at grace+1 should return nil (dead)")
	}
	if c := s.Count(); c != 0 {
		t.Errorf("Count = %d, want 0 after lazy eviction", c)
	}
}

func TestEnvelopeStoreEvictExpiredSweep(t *testing.T) {
	kp := mustKeypair(t)
	env := makeEnv(t, 1, 1000, 2000, kp)
	key := keyN(4)
	s := NewEnvelopeStore(0, func() int64 { return 1500 })

	if ok, _ := s.Put(key, env, 1500, true); !ok {
		t.Fatal("Put should accept")
	}
	if c := s.Count(); c != 1 {
		t.Fatalf("Count = %d, want 1", c)
	}

	// Advance well past grace and sweep.
	farFuture := int64(2000 + constants.ExpiryGrace + 1000)
	n := s.EvictExpired(farFuture)
	if n != 1 {
		t.Errorf("EvictExpired = %d, want 1", n)
	}
	if c := s.Count(); c != 0 {
		t.Errorf("Count after sweep = %d, want 0", c)
	}
	// A second sweep on an empty store is a no-op returning 0.
	if n := s.EvictExpired(farFuture); n != 0 {
		t.Errorf("EvictExpired on empty = %d, want 0", n)
	}
}

// ---------------------------------------------------------------------------
// §12 — byte cap + LRU eviction (just-put survives)
// ---------------------------------------------------------------------------

func TestEnvelopeStoreByteCapLRU(t *testing.T) {
	kp := mustKeypair(t)
	env := makeEnv(t, 1, 1000, 20000, kp) // alive across the test window
	sz := envBytes(t, env)
	if sz <= 64 {
		t.Fatalf("test envelope too small (%d bytes) for cap math", sz)
	}
	// Cap fits exactly two envelopes plus 64 bytes of slack.
	cap := 2*sz + 64
	s := NewEnvelopeStore(cap, func() int64 { return 1000 })

	k1, k2, k3 := keyN(1), keyN(2), keyN(3)
	// Distinct lastAccess times so LRU order is deterministic: k1 oldest.
	if ok, _ := s.Put(k1, env, 1000, true); !ok {
		t.Fatal("Put(k1) should accept")
	}
	if ok, _ := s.Put(k2, env, 1001, true); !ok {
		t.Fatal("Put(k2) should accept")
	}
	if s.SizeBytes() > cap {
		t.Fatalf("after k1,k2 SizeBytes=%d > cap=%d", s.SizeBytes(), cap)
	}

	// Third put overflows; LRU (k1) is evicted; the just-put k3 survives.
	if ok, _ := s.Put(k3, env, 1002, true); !ok {
		t.Fatal("Put(k3) should accept (protected)")
	}
	if s.Has(k1, 1002) {
		t.Error("k1 (oldest / LRU) should have been evicted")
	}
	if !s.Has(k2, 1002) {
		t.Error("k2 should still be present")
	}
	if !s.Has(k3, 1002) {
		t.Error("k3 (just-put, protected) should survive")
	}
	if c := s.Count(); c != 2 {
		t.Errorf("Count = %d, want 2", c)
	}
	if s.SizeBytes() > cap {
		t.Errorf("SizeBytes = %d > cap %d after LRU eviction", s.SizeBytes(), cap)
	}
}

// A single oversized entry that alone exceeds the cap is retained (no infinite
// eviction loop).
func TestEnvelopeStoreSingleOversizedSurvives(t *testing.T) {
	kp := mustKeypair(t)
	env := makeEnv(t, 1, 1000, 20000, kp)
	key := keyN(5)
	// Cap smaller than one envelope.
	s := NewEnvelopeStore(8, func() int64 { return 1000 })

	if ok, _ := s.Put(key, env, 1000, true); !ok {
		t.Fatal("Put of a single oversized envelope should still be accepted")
	}
	if !s.Has(key, 1000) {
		t.Error("single oversized entry should be retained")
	}
	if c := s.Count(); c != 1 {
		t.Errorf("Count = %d, want 1", c)
	}
}

// ---------------------------------------------------------------------------
// Remove / Keys
// ---------------------------------------------------------------------------

func TestEnvelopeStoreRemoveAndKeys(t *testing.T) {
	kp := mustKeypair(t)
	env := makeEnv(t, 1, 1000, 2000, kp)
	s := NewEnvelopeStore(0, func() int64 { return 1500 })
	keys := [][]byte{keyN(1), keyN(2), keyN(3)}
	for _, k := range keys {
		if ok, _ := s.Put(k, env, 1500, true); !ok {
			t.Fatalf("Put(%x): not accepted", k)
		}
	}
	if c := s.Count(); c != 3 {
		t.Fatalf("Count = %d, want 3", c)
	}

	// Keys snapshot contains all three.
	snap := s.Keys()
	if len(snap) != 3 {
		t.Fatalf("Keys len = %d, want 3", len(snap))
	}
	// Mutating the snapshot must not affect the store.
	snap[0][0] = 0xff

	// Remove the middle one.
	if !s.Remove(keys[1]) {
		t.Error("Remove of present key should return true")
	}
	if s.Has(keys[1], 1500) {
		t.Error("Has after Remove should be false")
	}
	if c := s.Count(); c != 2 {
		t.Errorf("Count = %d, want 2", c)
	}
	// Removing again is a no-op returning false.
	if s.Remove(keys[1]) {
		t.Error("Remove of absent key should return false")
	}
	// The other two are untouched.
	if !s.Has(keys[0], 1500) || !s.Has(keys[2], 1500) {
		t.Error("unrelated keys must remain after Remove")
	}
}

// ---------------------------------------------------------------------------
// Invalid key handling
// ---------------------------------------------------------------------------

func TestEnvelopeStoreInvalidKey(t *testing.T) {
	kp := mustKeypair(t)
	env := makeEnv(t, 1, 1000, 2000, kp)
	s := NewEnvelopeStore(0, func() int64 { return 1500 })

	tooShort := make([]byte, constants.SHA256Len-1) // 31 bytes
	if _, err := s.Put(tooShort, env, 1500, true); err == nil {
		t.Error("Put with 31-byte key should return an error")
	}
	tooLong := make([]byte, constants.SHA256Len+1) // 33 bytes
	if _, err := s.Put(tooLong, env, 1500, true); err == nil {
		t.Error("Put with 33-byte key should return an error")
	}
	if c := s.Count(); c != 0 {
		t.Errorf("Count after invalid puts = %d, want 0", c)
	}

	// Get / Has with wrong-length keys.
	if _, err := s.Get(tooShort, 1500); err == nil {
		t.Error("Get with 31-byte key should return an error")
	}
	if s.Has(tooLong, 1500) {
		t.Error("Has with 33-byte key should be false")
	}
	if s.Remove(tooShort) {
		t.Error("Remove with 31-byte key should be false")
	}
}

// ---------------------------------------------------------------------------
// Sanity: a Put whose incumbent is past grace is accepted (slot treated empty)
// ---------------------------------------------------------------------------

func TestEnvelopeStoreDeadIncumbentIsOverwritten(t *testing.T) {
	kp := mustKeypair(t)
	// envOld is already far past grace at the put time.
	envOld := makeEnv(t, 1, 1000, 2000, kp)
	// envNew has a LOWER sequence; normally it would lose, but the incumbent
	// is dead so the slot is treated as empty.
	envNew := makeEnv(t, 1, 5000, 6000, kp)
	key := keyN(6)
	s := NewEnvelopeStore(0, func() int64 { return 1500 })

	// Seed envOld and jump past its grace.
	if ok, _ := s.Put(key, envOld, 1500, true); !ok {
		t.Fatal("seed Put should accept")
	}
	pastGrace := int64(2000 + constants.ExpiryGrace + 1)

	// Newcomer has equal sequence; would lose to an ALIVE incumbent via the
	// tie-break, but the dead incumbent means unconditional accept.
	if ok, _ := s.Put(key, envNew, pastGrace, true); !ok {
		t.Error("Put over a dead incumbent should be accepted")
	}
	got, _ := s.Get(key, pastGrace)
	if got == nil || !bytes.Equal(mustHash(t, got), mustHash(t, envNew)) {
		t.Error("Get should return envNew after overwriting the dead incumbent")
	}
}

func mustHash(t *testing.T, env *wire.SignedEnvelope) []byte {
	t.Helper()
	h, err := env.RecordHash()
	if err != nil {
		t.Fatalf("RecordHash: %v", err)
	}
	return h
}
