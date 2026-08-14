package dht

// store_history_test.go pins the §8.3 (specifications.md lines 666-688)
// superseded-envelope history of EnvelopeStore: a displaced incumbent (Put of
// a winning successor), a swept entry (expired / LRU / lazy eviction), and
// the historyMax bound with oldest-first eviction. The live-map winner
// semantics themselves are pinned by store_test.go / eviction_test.go and
// must be unaffected — TestEnvelopeStoreHistoryDoesNotChangeWinnerSemantics
// re-runs a few canonical winner-rule cases with the history in place.

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/laurent/freens/internal/constants"
	"github.com/laurent/freens/internal/crypto"
	"github.com/laurent/freens/internal/naming"
	"github.com/laurent/freens/internal/wire"
)

// histHash returns H_record(env) or fails the test.
func histHash(t *testing.T, env *wire.SignedEnvelope) []byte {
	t.Helper()
	h, err := env.RecordHash()
	if err != nil {
		t.Fatalf("RecordHash: %v", err)
	}
	return h
}

// putOK puts env under key at now with signature verification and fails the
// test unless it is accepted.
func putOK(t *testing.T, s *EnvelopeStore, key []byte, env *wire.SignedEnvelope, now int64) {
	t.Helper()
	ok, err := s.Put(key, env, now, true)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if !ok {
		t.Fatal("Put should accept")
	}
}

// TestEnvelopeStoreHistoryOnDisplacement: a Put that replaces an ALIVE
// winner sends the incumbent to history keyed by ITS H_record; the new
// winner is live, not history (§8.3).
func TestEnvelopeStoreHistoryOnDisplacement(t *testing.T) {
	kp := mustKeypair(t)
	v1 := makeEnv(t, 1, 1000, 5000, kp)
	v2 := makeEnv(t, 2, 1100, 5000, kp)
	v3 := makeEnv(t, 3, 1200, 5000, kp)
	key := keyN(7)
	s := NewEnvelopeStore(0, nil)

	putOK(t, s, key, v1, 1500)
	if s.HistoryCount() != 0 {
		t.Fatalf("HistoryCount after first put = %d, want 0", s.HistoryCount())
	}

	putOK(t, s, key, v2, 1500)
	if got := s.HistoryCount(); got != 1 {
		t.Fatalf("HistoryCount = %d, want 1 (v1 displaced)", got)
	}
	if got := s.GetHistory(histHash(t, v1)); got != v1 {
		t.Fatalf("GetHistory(H(v1)) should return the displaced v1, got %+v", got)
	}
	if got := s.GetHistory(histHash(t, v2)); got != nil {
		t.Fatal("GetHistory(H(v2)) should be nil: v2 is the LIVE winner, not history")
	}
	if got, _ := s.Get(key, 1500); got != v2 {
		t.Fatal("Get should still return the live winner v2")
	}

	putOK(t, s, key, v3, 1500)
	if got := s.HistoryCount(); got != 2 {
		t.Fatalf("HistoryCount = %d, want 2", got)
	}
	if got := s.GetHistory(histHash(t, v2)); got != v2 {
		t.Fatal("GetHistory(H(v2)) should return the displaced v2")
	}
	if got := s.GetHistory(histHash(t, v3)); got != nil {
		t.Fatal("GetHistory(H(v3)) should be nil: v3 is live")
	}
}

// TestEnvelopeStoreHistoryWrongLengthHash: GetHistory with a non-32-byte
// hash is a nil miss, not a panic.
func TestEnvelopeStoreHistoryWrongLengthHash(t *testing.T) {
	s := NewEnvelopeStore(0, nil)
	if got := s.GetHistory(nil); got != nil {
		t.Error("GetHistory(nil) should be nil")
	}
	if got := s.GetHistory([]byte("short")); got != nil {
		t.Error("GetHistory(short) should be nil")
	}
	long := make([]byte, constants.SHA256Len+1)
	if got := s.GetHistory(long); got != nil {
		t.Error("GetHistory(33 bytes) should be nil")
	}
}

// TestEnvelopeStoreHistoryOnExpirySweep: an envelope dropped by
// EvictExpired is retained in history — the §8.3 case: an EXPIRED
// predecessor must stay fetchable for transfer-chain verification
// (predecessors are audit history, not live records).
func TestEnvelopeStoreHistoryOnExpirySweep(t *testing.T) {
	kp := mustKeypair(t)
	env := makeEnv(t, 1, 1000, 2000, kp) // expires at 2000
	key := keyN(9)
	s := NewEnvelopeStore(0, nil)
	putOK(t, s, key, env, 1500)

	dead := int64(2000) + int64(constants.ExpiryGrace) + 1
	if n := s.EvictExpired(dead); n != 1 {
		t.Fatalf("EvictExpired = %d, want 1", n)
	}
	if s.Count() != 0 {
		t.Fatalf("Count after sweep = %d, want 0", s.Count())
	}
	if got := s.HistoryCount(); got != 1 {
		t.Fatalf("HistoryCount = %d, want 1 (swept entry retained)", got)
	}
	if got := s.GetHistory(histHash(t, env)); got != env {
		t.Fatal("GetHistory should return the expired-and-swept envelope")
	}
	// History never expires by record time: far past expiry, still there.
	if got := s.GetHistory(histHash(t, env)); got == nil {
		t.Fatal("history entries must not expire by record time (§8.3 audit trail)")
	}
}

// TestEnvelopeStoreHistoryOnLazyEviction: Get's lazy eviction of a dead
// entry (§6.4 step 4) retains it in history too.
func TestEnvelopeStoreHistoryOnLazyEviction(t *testing.T) {
	kp := mustKeypair(t)
	env := makeEnv(t, 1, 1000, 2000, kp)
	key := keyN(11)
	s := NewEnvelopeStore(0, nil)
	putOK(t, s, key, env, 1500)

	dead := int64(2000) + int64(constants.ExpiryGrace) + 1
	if got, _ := s.Get(key, dead); got != nil {
		t.Fatal("Get past grace should return nil (lazy eviction)")
	}
	if s.Count() != 0 {
		t.Fatalf("Count after lazy eviction = %d, want 0", s.Count())
	}
	if got := s.GetHistory(histHash(t, env)); got != env {
		t.Fatal("lazily evicted entry should be retained in history")
	}
}

// TestEnvelopeStoreHistoryOnLRUCapEviction: an entry dropped by the §12 LRU
// cap enforcement is retained in history.
func TestEnvelopeStoreHistoryOnLRUCapEviction(t *testing.T) {
	kp := mustKeypair(t)
	// Distinct sequences: identical records under the same key sign to the
	// SAME envelope bytes (Ed25519 is deterministic), hence one H_record.
	e1 := makeEnv(t, 1, 1000, 9000, kp)
	e2 := makeEnv(t, 2, 1000, 9000, kp)
	s := NewEnvelopeStore(64, nil) // tiny cap: two envelopes never fit
	putOK(t, s, keyN(1), e1, 1500)
	putOK(t, s, keyN(2), e2, 1501)
	if s.Count() != 1 {
		t.Fatalf("Count after cap sweep = %d, want 1 (LRU evicted e1)", s.Count())
	}
	if got := s.HistoryCount(); got != 1 {
		t.Fatalf("HistoryCount = %d, want 1 (LRU-evicted e1 retained)", got)
	}
	if got := s.GetHistory(histHash(t, e1)); got != e1 {
		t.Fatal("GetHistory should return the LRU-evicted e1")
	}
	if got := s.GetHistory(histHash(t, e2)); got != nil {
		t.Fatal("GetHistory(H(e2)) should be nil: e2 is live")
	}
}

// TestEnvelopeStoreHistoryBoundKeepsNewest: overflowing historyMax evicts
// the oldest-retained envelope first and keeps the newest. Repeated winning
// puts over one key displace one incumbent each, in order.
func TestEnvelopeStoreHistoryBoundKeepsNewest(t *testing.T) {
	kp := mustKeypair(t)
	extra := 8
	s := NewEnvelopeStore(0, nil)
	key := keyN(3)
	envs := make([]*wire.SignedEnvelope, 0, historyMax+extra)
	for i := 0; i < historyMax+extra; i++ {
		envs = append(envs, makeEnv(t, uint64(i+1), 1000, 99999999, kp))
		putOK(t, s, key, envs[i], int64(1500+i)) // distinct lastAccess order
	}
	// Live map holds the last put; history is exactly at the bound.
	if got, _ := s.Get(key, 99999998); got != envs[len(envs)-1] {
		t.Fatal("live winner should be the final put")
	}
	if got := s.HistoryCount(); got != historyMax {
		t.Fatalf("HistoryCount = %d, want %d", got, historyMax)
	}
	// Displaced incumbents are envs[0..historyMax+extra-2]; the newest
	// historyMax of them survive: indices extra-1 .. historyMax+extra-2.
	// Everything older was evicted.
	for i := 0; i < extra-1; i++ {
		if got := s.GetHistory(histHash(t, envs[i])); got != nil {
			t.Errorf("H(envs[%d]) should have been evicted from history (oldest)", i)
		}
	}
	for i := extra - 1; i < historyMax+extra-1; i++ {
		if got := s.GetHistory(histHash(t, envs[i])); got != envs[i] {
			t.Errorf("H(envs[%d]) should be retained (newest %d)", i, historyMax)
		}
	}
}

// TestEnvelopeStoreHistoryDoesNotChangeWinnerSemantics: with retention in
// place, the §6.4 winner rule still rejects a loser (lower sequence, and
// same sequence with smaller H_record) WITHOUT touching history.
func TestEnvelopeStoreHistoryDoesNotChangeWinnerSemantics(t *testing.T) {
	kp := mustKeypair(t)
	kp2 := mustKeypair(t)
	v1 := makeEnv(t, 5, 1000, 9000, kp)
	loser := makeEnv(t, 4, 1000, 9000, kp2) // lower sequence: loses
	key := keyN(21)
	s := NewEnvelopeStore(0, nil)
	putOK(t, s, key, v1, 1500)

	ok, err := s.Put(key, loser, 1500, true)
	if err != nil {
		t.Fatalf("Put loser: %v", err)
	}
	if ok {
		t.Fatal("lower-sequence Put must be rejected (§6.4 step 3)")
	}
	if s.HistoryCount() != 0 {
		t.Fatalf("HistoryCount = %d, want 0 (nothing displaced)", s.HistoryCount())
	}
	if got, _ := s.Get(key, 1500); got != v1 {
		t.Fatal("v1 must remain the live winner")
	}

	// Same-sequence tie-break: exactly one of the two envelopes wins; the
	// winner's identity is the plain §6.4 rule, unaffected by history. (The
	// two envelopes come from DIFFERENT owner keys: Ed25519 is deterministic,
	// so same key + same record bytes would be one and the same envelope.)
	a := makeEnv(t, 7, 1000, 9000, kp)
	b := makeEnv(t, 7, 1000, 9000, kp2) // same sequence, different content
	ha, hb := histHash(t, a), histHash(t, b)
	wantA := bytes.Compare(ha, hb) > 0
	putOK(t, s, key, a, 1600)
	ok, _ = s.Put(key, b, 1600, true)
	if wantA && ok {
		t.Fatal("b has the smaller H_record: must lose the tie-break")
	}
	if !wantA && !ok {
		t.Fatal("b has the greater H_record: must win the tie-break")
	}
}

// TestEnvelopeStoreRemoveDoesNotRetain: Remove is an explicit administrative
// drop — the envelope does NOT enter the §8.3 history (documented on Remove).
func TestEnvelopeStoreRemoveDoesNotRetain(t *testing.T) {
	kp := mustKeypair(t)
	env := makeEnv(t, 1, 1000, 9000, kp)
	key := keyN(23)
	s := NewEnvelopeStore(0, nil)
	putOK(t, s, key, env, 1500)
	if !s.Remove(key) {
		t.Fatal("Remove should return true")
	}
	if s.HistoryCount() != 0 {
		t.Fatalf("HistoryCount after Remove = %d, want 0", s.HistoryCount())
	}
	if got := s.GetHistory(histHash(t, env)); got != nil {
		t.Fatal("Remove must not retain the envelope in history")
	}
}

// TestRetainHistoryAndPersistRoundTrip: force-retained history survives
// PersistHistoryTo → RetainHistory (the daemon restart path for §8.3 audit
// chains): the retained predecessor is fetchable by H_record after reload,
// without ever becoming the live winner.
func TestRetainHistoryAndPersistRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s1 := NewEnvelopeStore(0, nil)
	now := s1.Now()
	kp := mustKeypair(t)
	tldID, err := crypto.TldID(kp.Public())
	if err != nil {
		t.Fatal(err)
	}
	name, err := naming.EncodeWireName(nil, "retainme", tldID)
	if err != nil {
		t.Fatal(err)
	}
	mk := func(seq uint64) *wire.SignedEnvelope {
		rec, err := wire.NewRecord(name, kp.Public(), seq, uint64(now), uint64(now+3600))
		if err != nil {
			t.Fatal(err)
		}
		env, err := wire.SignRecord(rec, kp)
		if err != nil {
			t.Fatal(err)
		}
		return env
	}
	env1, env2 := mk(1), mk(2)
	key := tldID // K_tld
	putOK(t, s1, key, env1, now)
	putOK(t, s1, key, env2, now)
	h1 := histHash(t, env1)
	if s1.GetHistory(h1) == nil {
		t.Fatal("displacement did not retain v1")
	}
	if _, err := s1.PersistHistoryTo(filepath.Join(dir, "history")); err != nil {
		t.Fatal(err)
	}
	// Reload into a fresh store: v2 live, v1 force-retained from file.
	s2 := NewEnvelopeStore(0, nil)
	putOK(t, s2, key, env2, now)
	hfiles, err := filepath.Glob(filepath.Join(dir, "history", "*.cbor"))
	if err != nil || len(hfiles) != 1 {
		t.Fatalf("history files: %v %v", hfiles, err)
	}
	data, err := os.ReadFile(hfiles[0])
	if err != nil {
		t.Fatal(err)
	}
	henv, err := wire.DecodeEnvelope(data)
	if err != nil {
		t.Fatal(err)
	}
	s2.RetainHistory(henv)
	if s2.GetHistory(h1) == nil {
		t.Error("reloaded history missing v1 (transfer-chain predecessors lost)")
	}
	if got, _ := s2.Get(key, now); got == nil {
		t.Fatal("live winner missing")
	} else {
		gh, _ := got.RecordHash()
		h2, _ := env2.RecordHash()
		if !bytes.Equal(gh, h2) {
			t.Error("live winner changed — history retention must not touch the live map")
		}
	}
}
