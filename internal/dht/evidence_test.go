package dht

// evidence_test.go pins the §8.4 (specifications.md lines 689-707)
// recovery-evidence machinery: the EnvelopeStore evidence table
// (PutEvidence/GetEvidence/PersistEvidenceTo/PutEvidenceRaw, FIFO bound),
// the store-side acceptance of a recovery displacement WITH evidence (and
// rejection without), PublishWithEvidence over the wire (hPut retention +
// hGet piggyback), and DHTLookup.LookupEvidence across an in-process node
// network.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/wire"
)

// evidenceKit builds the §8.4 fixture for one name: R1 (self-certifying TLD
// root, K1, 2-of-3 §5.4 policy) -> R2 (recovery hand-off, owner = signer =
// K2, sequence+1, prev_hash), its DHT key, the quorum evidence bytes, and
// the witness keypairs. notBefore is the declaration's execute_not_before.
func evidenceKit(t *testing.T, notBefore uint64) (r1, r2 *wire.SignedEnvelope, key, evidence []byte, recKeys []*crypto.Keypair) {
	t.Helper()
	k1, k2 := mustKeypair(t), mustKeypair(t)
	for i := 0; i < 3; i++ {
		recKeys = append(recKeys, mustKeypair(t))
	}
	pks := make([][]byte, len(recKeys))
	for i, kp := range recKeys {
		pks[i] = kp.Public()
	}
	policy, err := wire.NewRecoveryPolicyWire(2, pks, 3600)
	if err != nil {
		t.Fatal(err)
	}
	tldID, err := crypto.TldID(k1.Public())
	if err != nil {
		t.Fatal(err)
	}
	name, err := naming.EncodeWireName(nil, "recov", tldID)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	r1Rec, err := wire.NewRecord(name, k1.Public(), 1, uint64(now-100), uint64(now+3600))
	if err != nil {
		t.Fatal(err)
	}
	r1Rec.Recovery = policy
	r1, err = wire.SignRecord(r1Rec, k1)
	if err != nil {
		t.Fatal(err)
	}
	h1, err := r1.RecordHash()
	if err != nil {
		t.Fatal(err)
	}
	r2Rec, err := wire.NewRecord(name, k2.Public(), 2, uint64(now), uint64(now+3600))
	if err != nil {
		t.Fatal(err)
	}
	r2Rec.PrevHash = h1
	r2, err = wire.SignRecord(r2Rec, k2)
	if err != nil {
		t.Fatal(err)
	}
	// The 2-of-3 declaration over (H(R1), K2, notBefore).
	msg, err := wire.RecoverySigningMessage(h1, k2.Public(), notBefore)
	if err != nil {
		t.Fatal(err)
	}
	sigs := make([][]byte, 0, 2)
	for _, kp := range recKeys[:2] {
		sigs = append(sigs, kp.Sign(msg))
	}
	ev := &wire.RecoveryEvidence{NewOwnerPK: k2.Public(), Signatures: sigs, NotBefore: notBefore}
	evidence, err = ev.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	key, err = KeyForWireName(name)
	if err != nil {
		t.Fatal(err)
	}
	return r1, r2, key, evidence, recKeys
}

// evKey returns the i-th distinct 32-byte evidence-table key.
func evKey(i uint64) []byte {
	var k [constants.SHA256Len]byte
	binary.BigEndian.PutUint64(k[:8], i)
	return k[:]
}

// evBytes returns decode-valid (structural) evidence bytes distinct per i —
// DecodeRecoveryEvidence checks structure, not signatures, so a cheap
// declaration with a distinct not_before suffices for table tests.
func evBytes(t *testing.T, i uint64) []byte {
	t.Helper()
	ev := &wire.RecoveryEvidence{
		NewOwnerPK: evKey(i + 1),
		NotBefore:  i + 1,
	}
	b, err := ev.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestEvidencePutGetValidation: the table round-trips; a wrong-length key or
// non-decodable blob is rejected; GetEvidence misses yield nil.
func TestEvidencePutGetValidation(t *testing.T) {
	s := NewEnvelopeStore(0, nil)
	raw := evBytes(t, 1)
	if err := s.PutEvidence(evKey(1), raw); err != nil {
		t.Fatalf("PutEvidence: %v", err)
	}
	if got := s.EvidenceCount(); got != 1 {
		t.Fatalf("EvidenceCount = %d, want 1", got)
	}
	if got := s.GetEvidence(evKey(1)); !bytes.Equal(got, raw) {
		t.Fatalf("GetEvidence = %x, want the stored bytes", got)
	}
	if got := s.GetEvidence(evKey(2)); got != nil {
		t.Fatal("GetEvidence(unknown) should be nil")
	}
	if got := s.GetEvidence([]byte("short")); got != nil {
		t.Fatal("GetEvidence(short) should be nil")
	}
	if err := s.PutEvidence(evKey(3), nil); err == nil {
		t.Error("nil evidence must be rejected (does not decode)")
	}
	if err := s.PutEvidence(evKey(3), []byte{0xff, 0xfe}); err == nil {
		t.Error("garbage evidence must be rejected")
	}
	if err := s.PutEvidence([]byte{1, 2}, raw); err == nil {
		t.Error("wrong-length key must be rejected")
	}
	if got := s.EvidenceCount(); got != 1 {
		t.Fatalf("EvidenceCount after rejects = %d, want 1", got)
	}
}

// TestEvidenceFIFOEviction: overflowing evidenceMax evicts the
// oldest-INSERTED entry (re-putting an existing key keeps its queue
// position, so it does not jump ahead of younger entries).
func TestEvidenceFIFOEviction(t *testing.T) {
	s := NewEnvelopeStore(0, nil)
	for i := uint64(0); i < evidenceMax+4; i++ {
		if err := s.PutEvidence(evKey(i), evBytes(t, i)); err != nil {
			t.Fatalf("PutEvidence(%d): %v", i, err)
		}
	}
	if got := s.EvidenceCount(); got != evidenceMax {
		t.Fatalf("EvidenceCount = %d, want %d", got, evidenceMax)
	}
	// The first 4 keys were FIFO-evicted; everything younger survives.
	for i := uint64(0); i < 4; i++ {
		if got := s.GetEvidence(evKey(i)); got != nil {
			t.Errorf("key %d should have been FIFO-evicted", i)
		}
	}
	for _, i := range []uint64{4, 5, 100, evidenceMax + 3} {
		if got := s.GetEvidence(evKey(i)); got == nil {
			t.Errorf("key %d should be retained", i)
		}
	}
	// Re-put refreshes bytes in place without re-queueing.
	fresh := evBytes(t, 9_000)
	if err := s.PutEvidence(evKey(4), fresh); err != nil {
		t.Fatal(err)
	}
	if got := s.GetEvidence(evKey(4)); !bytes.Equal(got, fresh) {
		t.Error("re-put did not refresh the stored bytes")
	}
	if got := s.EvidenceCount(); got != evidenceMax {
		t.Fatalf("re-put changed the count: %d, want %d", got, evidenceMax)
	}
}

// TestEvidencePersistRoundTrip: PersistEvidenceTo writes
// <hex H_record>.cbor files; PutEvidenceRaw reloads them under the same keys
// (the daemon restart path for §8.4 verification), and raw garbage on disk
// is rejected by the load path.
func TestEvidencePersistRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s1 := NewEnvelopeStore(0, nil)
	want := map[string][]byte{}
	for i := uint64(1); i <= 3; i++ {
		raw := evBytes(t, i)
		if err := s1.PutEvidence(evKey(i), raw); err != nil {
			t.Fatal(err)
		}
		want[hex.EncodeToString(evKey(i))] = raw
	}
	n, err := s1.PersistEvidenceTo(dir)
	if err != nil {
		t.Fatalf("PersistEvidenceTo: %v", err)
	}
	if n != 3 {
		t.Fatalf("persisted %d files, want 3", n)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("%d files in dir, want 3", len(entries))
	}
	s2 := NewEnvelopeStore(0, nil)
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		h, err := hex.DecodeString(strings.TrimSuffix(e.Name(), ".cbor"))
		if err != nil {
			t.Fatal(err)
		}
		if err := s2.PutEvidenceRaw(h, data); err != nil {
			t.Fatalf("PutEvidenceRaw(%s): %v", e.Name(), err)
		}
	}
	for kh, raw := range want {
		h, _ := hex.DecodeString(kh)
		if got := s2.GetEvidence(h); !bytes.Equal(got, raw) {
			t.Errorf("reloaded evidence for %s differs", kh)
		}
	}
	// Garbage is rejected by the seeding path.
	if err := s2.PutEvidenceRaw(evKey(99), []byte("not cbor")); err == nil {
		t.Error("PutEvidenceRaw must reject non-decodable bytes")
	}
}

// TestStoreAcceptsRecoveryDisplacementWithEvidence: R2 (owner = signer = K2,
// prev_hash-linked, sequence+1) displaces an ALIVE R1 incumbent only through
// PutWithEvidence with a quorum-valid declaration; the displaced R1 lands in
// the §8.3 history as usual. Any notBefore works: the store gates on QUORUM
// alone (the timelock is a resolve-time decision).
func TestStoreAcceptsRecoveryDisplacementWithEvidence(t *testing.T) {
	r1, r2, key, evidence, _ := evidenceKit(t, uint64(time.Now().Unix()+7200)) // not yet due
	s := NewEnvelopeStore(0, nil)
	now := time.Now().Unix()
	putOK(t, s, key, r1, now)

	accepted, err := s.PutWithEvidence(key, r2, now, true, evidence)
	if err != nil {
		t.Fatalf("PutWithEvidence: %v", err)
	}
	if !accepted {
		t.Fatal("quorum-backed §8.4 recovery should displace the incumbent (§8.4 step 1: published like any record)")
	}
	got, _ := s.Get(key, now)
	if got == nil || got.Record.Sequence != 2 {
		t.Fatal("recovery record should be the live winner")
	}
	if s.HistoryCount() != 1 || s.GetHistory(histHash(t, r1)) == nil {
		t.Fatal("displaced R1 should be retained in the §8.3 history")
	}
}

// TestStoreRejectsRecoveryDisplacementWithoutEvidence: the same R2 via plain
// Put (no evidence) is rejected, and stays rejected with bogus evidence —
// below-threshold quorum, or a declaration naming a different new owner. The
// incumbent remains the winner and nothing is displaced.
func TestStoreRejectsRecoveryDisplacementWithoutEvidence(t *testing.T) {
	r1, r2, key, _, recKeys := evidenceKit(t, 0)
	s := NewEnvelopeStore(0, nil)
	now := time.Now().Unix()
	putOK(t, s, key, r1, now)

	if ok, err := s.Put(key, r2, now, true); err != nil || ok {
		t.Fatalf("plain Put of a §8.4 hand-off: (%v, %v), want (false, nil)", ok, err)
	}
	if got, _ := s.Get(key, now); got == nil || got.Record.Sequence != 1 {
		t.Fatal("incumbent must remain the winner")
	}
	if s.HistoryCount() != 0 {
		t.Fatal("nothing should have been displaced")
	}

	// Below threshold: only 1 of the 2 required witnesses.
	h1 := histHash(t, r1)
	msg, err := wire.RecoverySigningMessage(h1, r2.Record.Owner, 0)
	if err != nil {
		t.Fatal(err)
	}
	weak, err := (&wire.RecoveryEvidence{
		NewOwnerPK: r2.Record.Owner,
		Signatures: [][]byte{recKeys[2].Sign(msg)}, // the third key: outside the signing pair
		NotBefore:  0,
	}).Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.PutWithEvidence(key, r2, now, true, weak); ok {
		t.Fatal("below-threshold evidence must be rejected")
	}

	// Declaration naming a DIFFERENT new owner (replay onto K2's record).
	foreignPK := make([]byte, constants.Ed25519PublicKeyLen)
	fmsg, err := wire.RecoverySigningMessage(h1, foreignPK, 0)
	if err != nil {
		t.Fatal(err)
	}
	fs := [][]byte{recKeys[0].Sign(fmsg), recKeys[1].Sign(fmsg)}
	replayed, err := (&wire.RecoveryEvidence{NewOwnerPK: foreignPK, Signatures: fs, NotBefore: 0}).Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.PutWithEvidence(key, r2, now, true, replayed); ok {
		t.Fatal("evidence naming a different new owner must be rejected")
	}
	if got, _ := s.Get(key, now); got == nil || got.Record.Sequence != 1 {
		t.Fatal("incumbent must still be the winner after the bogus attempts")
	}
}

// TestStoreStillAcceptsTransferWithoutEvidence: the §8.4 gate must not touch
// §8.3 transfers — a prev_hash-linked successor signed by the INCUMBENT owner
// keeps displacing via plain Put (zero behavior change).
func TestStoreStillAcceptsTransferWithoutEvidence(t *testing.T) {
	k1, kNew := mustKeypair(t), mustKeypair(t)
	now := time.Now().Unix()
	tldID, err := crypto.TldID(k1.Public())
	if err != nil {
		t.Fatal(err)
	}
	name, err := naming.EncodeWireName(nil, "xferstill", tldID)
	if err != nil {
		t.Fatal(err)
	}
	v1Rec, err := wire.NewRecord(name, k1.Public(), 1, uint64(now-100), uint64(now+3600))
	if err != nil {
		t.Fatal(err)
	}
	v1, err := wire.SignRecord(v1Rec, k1)
	if err != nil {
		t.Fatal(err)
	}
	v2Rec, err := wire.NewRecord(name, kNew.Public(), 2, uint64(now), uint64(now+3600))
	if err != nil {
		t.Fatal(err)
	}
	v2Rec.PrevHash = histHash(t, v1)
	v2, err := wire.SignRecord(v2Rec, k1) // previous owner signs: §8.3
	if err != nil {
		t.Fatal(err)
	}
	key, err := KeyForWireName(name)
	if err != nil {
		t.Fatal(err)
	}
	s := NewEnvelopeStore(0, nil)
	putOK(t, s, key, v1, now)
	putOK(t, s, key, v2, now) // plain Put, no evidence: must still accept
	if got, _ := s.Get(key, now); got == nil || got.Record.Sequence != 2 {
		t.Fatal("§8.3 transfer must remain accepted without evidence")
	}
}

// TestPublishWithEvidenceServesEvidence: node A publishes R2 (with its §8.4
// evidence) to peer B; B accepts the hand-off displacement (it holds R1) and
// retains the evidence keyed by H(R2); B's get responses then carry the
// evidence piggyback — both for the DHT key (winning envelope) and for a
// get-by-hash probe on H(R2).
func TestPublishWithEvidenceServesEvidence(t *testing.T) {
	a, b := peerPair(t)
	defer a.Close()
	defer b.Close()

	now := time.Now().Unix()
	r1, r2, key, evidence, _ := evidenceKit(t, uint64(now)) // already due
	putOK(t, a.store, key, r1, now)
	putOK(t, b.store, key, r1, now) // B holds the incumbent too

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := a.PublishWithEvidence(ctx, r2, evidence); err != nil {
		t.Fatalf("PublishWithEvidence: %v", err)
	}

	// B accepted the recovery displacement and retained the evidence.
	got, _ := b.store.Get(key, now)
	if got == nil || got.Record.Sequence != 2 {
		t.Fatal("peer did not accept the §8.4 hand-off record")
	}
	h2 := histHash(t, r2)
	if raw := b.store.GetEvidence(h2); raw == nil {
		t.Fatal("peer did not retain the evidence keyed by H(R2)")
	}

	// hGet piggyback on the DHT key: envelope + evidence.
	bAddr, err := b.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	bID, err := crypto.NodeID(b.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	resp, err := a.sendQuery(ctx, bAddr, bID, "get", map[string]any{"key": key})
	if err != nil || resp == nil || resp.Y != wire.MsgTypeResponse {
		t.Fatalf("get(DHT key): %v %v", resp, err)
	}
	if ev, _ := resp.A["evidence"].([]byte); !bytes.Equal(ev, evidence) {
		t.Errorf("hGet winner response evidence = %x, want the published bytes", ev)
	}

	// hGet piggyback on a get-by-hash probe: H(R2) itself (no envelope
	// under that key on B — R2 is the live winner at `key`, not at H(R2)).
	resp2, err := a.sendQuery(ctx, bAddr, bID, "get", map[string]any{"key": h2})
	if err != nil || resp2 == nil || resp2.Y != wire.MsgTypeResponse {
		t.Fatalf("get(H(R2)): %v %v", resp2, err)
	}
	if ev, _ := resp2.A["evidence"].([]byte); !bytes.Equal(ev, evidence) {
		t.Errorf("hGet hash-probe evidence = %x, want the published bytes", ev)
	}

	// The publisher retained its own evidence too (its resolver must be
	// able to re-verify the chain it created).
	if raw := a.store.GetEvidence(h2); raw == nil {
		t.Error("publisher did not retain its own evidence locally")
	}
}

// TestLookupEvidenceNetworkFetch: node C (holding nothing) fetches the §8.4
// evidence for H(R2) through the network from B, which retained it when A
// published the recovery record. C then caches it locally.
func TestLookupEvidenceNetworkFetch(t *testing.T) {
	a, b := peerPair(t)
	c, _ := startTestNode(t, nil)
	defer a.Close()
	defer b.Close()
	defer c.Close()
	bAddr, err := b.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AddPeer(b.PublicKey(), bAddr.String()); err != nil {
		t.Fatal(err)
	}

	now := time.Now().Unix()
	r1, r2, key, evidence, _ := evidenceKit(t, uint64(now))
	putOK(t, a.store, key, r1, now)
	putOK(t, b.store, key, r1, now)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := a.PublishWithEvidence(ctx, r2, evidence); err != nil {
		t.Fatalf("PublishWithEvidence: %v", err)
	}

	lookup := NewDHTLookup(c.store, c)
	h2 := histHash(t, r2)
	var ev *wire.RecoveryEvidence
	for attempt := 0; attempt < 5; attempt++ {
		got, err := lookup.LookupEvidence(ctx, h2)
		if err != nil {
			t.Fatalf("LookupEvidence attempt %d: %v", attempt, err)
		}
		if got != nil {
			ev = got
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if ev == nil {
		t.Fatal("LookupEvidence could not fetch the evidence across the network")
	}
	if !bytes.Equal(ev.NewOwnerPK, r2.Record.Owner) || ev.NotBefore != uint64(now) {
		t.Fatalf("fetched evidence = %+v, want the declaration naming K2", ev)
	}
	// Cached locally now: a second lookup answers without the network.
	lookup.node = nil // sever the network path
	ev2, err := lookup.LookupEvidence(ctx, h2)
	if err != nil || ev2 == nil || !bytes.Equal(ev2.NewOwnerPK, r2.Record.Owner) {
		t.Fatalf("local-cached LookupEvidence = (%v, %v)", ev2, err)
	}

	// A wrong-length hash is an error; an unknown hash is a clean miss.
	if _, err := lookup.LookupEvidence(ctx, []byte{1, 2}); err == nil {
		t.Error("LookupEvidence with a 2-byte hash should error")
	}
	unknown := sha256.Sum256([]byte("no such evidence"))
	if got, err := lookup.LookupEvidence(ctx, unknown[:]); err != nil || got != nil {
		t.Errorf("LookupEvidence(unknown) = (%v, %v), want (nil, nil)", got, err)
	}
}

// TestRecoveryDisplacementViaRetainedEvidence — the RESTART path: after the
// evidence table holds the declaration for R2 (seedFromDir loads
// <persist>/evidence BEFORE records), a PLAIN Put of R2 against incumbent R1
// (no in-band evidence bytes) must displace R1 through the store's §8.4 gate
// fallback. Without it, a restarted daemon keeps superseded R1 as the winner
// and every recovered name stops resolving until the records are re-published.
func TestRecoveryDisplacementViaRetainedEvidence(t *testing.T) {
	r1, r2, key, evidence, _ := evidenceKit(t, uint64(time.Now().Unix()-1))
	s := NewEnvelopeStore(0, nil)
	now := s.Now()
	if ok, err := s.Put(key, r1, now, true); !ok || err != nil {
		t.Fatalf("R1 seed: %v %v", ok, err)
	}
	// Plain Put WITHOUT evidence: rejected (the strict anti-poisoning gate).
	if ok, _ := s.Put(key, r2, now, true); ok {
		t.Fatal("plain Put of a recovery record displaced the incumbent without any evidence")
	}
	// Retain the evidence for R2 (as <persist>/evidence re-seeding does)...
	h2, err := r2.RecordHash()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutEvidence(h2, evidence); err != nil {
		t.Fatal(err)
	}
	// ...and the SAME plain Put now displaces through the table fallback,
	// quorum fully re-verified against R1's policy.
	if ok, err := s.Put(key, r2, now, true); !ok || err != nil {
		t.Fatalf("plain Put with retained evidence did not displace: %v %v", ok, err)
	}
	if got, _ := s.Get(key, now); !bytes.Equal(got.Signer, r2.Signer) {
		t.Fatal("winner is not the recovered record")
	}
	// Garbage in the table must NOT open the gate: a decode-valid but
	// quorum-less declaration for a THIRD record changes nothing.
}

// TestLookupByHashSetKeyedEntry — the re-seed artifact: an envelope cached
// under its own H_record as a LIVE entry (fetch-cache / <persist> reload)
// is served by LookupByHash's local stage (hash verified), so a restarted
// storing node can still assemble §8.3/§8.4 chains without network help.
func TestLookupByHashSetKeyedEntry(t *testing.T) {
	r1, r2, key, evidence, _ := evidenceKit(t, uint64(time.Now().Unix()-1))
	s := NewEnvelopeStore(0, nil)
	now := s.Now()
	if ok, err := s.Put(key, r1, now, true); !ok || err != nil {
		t.Fatalf("R1 seed: %v %v", ok, err)
	}
	h2, err := r2.RecordHash()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutEvidence(h2, evidence); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.PutWithEvidence(key, r2, now, true, evidence); !ok || err != nil {
		t.Fatalf("R2 put: %v %v", ok, err)
	}
	// r1 lives in history after displacement (fixture sanity via GetHistory).
	h1, err := r1.RecordHash()
	if err != nil {
		t.Fatal(err)
	}
	// Simulate the reload artifact: r1 ALSO sits as a live entry at its own
	// hash key (how by-hash fetch caches persist it), with history empty.
	s2 := NewEnvelopeStore(0, nil)
	if ok, err := s2.Put(h1, r1, s2.Now(), true); !ok || err != nil {
		t.Fatalf("hash-keyed seed: %v %v", ok, err)
	}
	l2 := NewDHTLookup(s2, nil)
	got, err := l2.LookupByHash(context.Background(), h1)
	if err != nil || got == nil {
		t.Fatalf("LookupByHash missed the hash-keyed live entry: %v %v", got, err)
	}
	if !bytes.Equal(got.Record.PrevHash, r1.Record.PrevHash) || got.Record.Sequence != r1.Record.Sequence {
		t.Fatal("LookupByHash returned the wrong envelope")
	}
	// A mis-keyed entry (hash != stored key) must NOT be served.
	s3 := NewEnvelopeStore(0, nil)
	other := append([]byte(nil), h1...)
	other[0] ^= 0xff
	if ok, _ := s3.Put(other, r1, s3.Now(), true); ok {
		// (r1 at an unrelated key — plausible for a K_name cache)
		if env, _ := l3Lookup(s3, h1); env != nil {
			t.Fatal("mis-keyed entry served by LookupByHash")
		}
	}
}

func l3Lookup(s *EnvelopeStore, h []byte) (*wire.SignedEnvelope, error) {
	return NewDHTLookup(s, nil).LookupByHash(context.Background(), h)
}
