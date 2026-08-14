package dht

// store_persist_test.go covers the store enumeration helper (Entries) and the
// PersistTo snapshot added for daemon restart survival: envelopes fetched over
// the DHT live only in the in-process EnvelopeStore, so PersistTo writes them
// out as <keyhex>.cbor (the same format -load / freens-cli make-record
// produce) and the next start can re-seed from the same directory.

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/laurent/freens/internal/wire"
)

// TestEntriesLiveOnlySorted verifies that Entries(now) snapshots only ALIVE
// entries (past expires+grace entries are excluded, mirroring Get's lazy
// eviction) in bytewise-ascending key order.
func TestEntriesLiveOnlySorted(t *testing.T) {
	const t0 = int64(10_000)
	live, liveKey := makeEnvAt(t, "live", t0-100, t0+50_000)
	dying, dyingKey := makeEnvAt(t, "dying", t0-100, t0+50) // dead after grace

	store := NewEnvelopeStore(0, nil)
	for _, e := range []struct {
		env *wire.SignedEnvelope
		key []byte
	}{{live, liveKey}, {dying, dyingKey}} {
		if ok, err := store.Put(e.key, e.env, t0, true); err != nil || !ok {
			t.Fatalf("seed: accepted=%v err=%v", ok, err)
		}
	}

	ents := store.Entries(t0)
	if len(ents) != 2 {
		t.Fatalf("Entries at t0: want 2, got %d", len(ents))
	}
	if !sort.SliceIsSorted(ents, func(i, j int) bool { return bytes.Compare(ents[i].Key, ents[j].Key) < 0 }) {
		t.Error("Entries not sorted by key")
	}

	// Far future: the dying entry is past expires + ExpiryGrace (24h); only
	// the live one remains.
	ents = store.Entries(t0 + 100_000)
	if len(ents) != 1 || !bytes.Equal(ents[0].Key, liveKey) {
		t.Fatalf("Entries after grace: want only the live key, got %d entries", len(ents))
	}
	if ents[0].Env != live {
		t.Error("Entries returned the wrong envelope")
	}
}

// TestPersistToRoundTrip puts live + dying envelopes, persists to a
// non-existent (nested) directory, reads the files back, decodes them, and
// verifies byte equality with the originals; then re-seeds a fresh store from
// the directory exactly as the daemon's -load path does.
func TestPersistToRoundTrip(t *testing.T) {
	var clock atomic.Int64
	const t0 = int64(20_000)
	clock.Store(t0)
	store := NewEnvelopeStore(0, func() int64 { return clock.Load() })

	alpha, alphaKey := makeEnvAt(t, "alpha", t0-100, t0+3600)
	beta, betaKey := makeEnvAt(t, "beta", t0-1000, t0+3500)
	doomed, doomedKey := makeEnvAt(t, "doomed", t0-100, t0+10) // dead once the clock advances
	for _, e := range []struct {
		env *wire.SignedEnvelope
		key []byte
	}{{alpha, alphaKey}, {beta, betaKey}, {doomed, doomedKey}} {
		if ok, err := store.Put(e.key, e.env, t0, true); err != nil || !ok {
			t.Fatalf("seed: accepted=%v err=%v", ok, err)
		}
	}

	dir := filepath.Join(t.TempDir(), "nested", "store") // must be created
	// Past doomed's expires + ExpiryGrace (t0+10+86400) but before the live
	// envelopes' (t0+3600+86400): exactly the dead one is filtered out.
	clock.Store(t0 + 86_500)
	n, err := store.PersistTo(dir)
	if err != nil {
		t.Fatalf("PersistTo: %v", err)
	}
	if n != 2 {
		t.Fatalf("PersistTo wrote %d files, want 2 (dead entry must be skipped)", n)
	}

	// Exactly the two live files, each decoding to the original bytes.
	live := map[string]*wire.SignedEnvelope{
		hex.EncodeToString(alphaKey) + ".cbor": alpha,
		hex.EncodeToString(betaKey) + ".cbor":  beta,
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != len(live) {
		t.Fatalf("dir has %d files, want %d", len(files), len(live))
	}
	for _, f := range files {
		want, ok := live[f.Name()]
		if !ok {
			t.Fatalf("unexpected file %q (want one of %v)", f.Name(), keysOf(live))
		}
		data, err := os.ReadFile(filepath.Join(dir, f.Name()))
		if err != nil {
			t.Fatal(err)
		}
		got, err := wire.DecodeEnvelope(data)
		if err != nil {
			t.Fatalf("decode %q: %v", f.Name(), err)
		}
		gb, _ := got.Bytes()
		wb, _ := want.Bytes()
		if !bytes.Equal(gb, wb) {
			t.Errorf("%q: decoded bytes differ from the original envelope", f.Name())
		}
	}

	// Re-seed a fresh store from the dir (the daemon -load path): each file
	// decodes and lands at its canonical key; the winner rule makes the
	// reload idempotent.
	seeded := NewEnvelopeStore(0, nil)
	now := clock.Load()
	for name := range live {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		env, err := wire.DecodeEnvelope(data)
		if err != nil {
			t.Fatal(err)
		}
		key, err := KeyForWireName(env.Record.Name)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(key) != strings.TrimSuffix(name, ".cbor") {
			t.Errorf("file %q is not keyed by its canonical DHT key", name)
		}
		if ok, err := seeded.Put(key, env, now, true); err != nil || !ok {
			t.Fatalf("re-seed %q: accepted=%v err=%v", name, ok, err)
		}
	}
	if got := seeded.Count(); got != 2 {
		t.Errorf("re-seeded store holds %d entries, want 2", got)
	}

	// An empty store persists trivially.
	empty := filepath.Join(t.TempDir(), "empty")
	if n, err := (NewEnvelopeStore(0, nil)).PersistTo(empty); err != nil || n != 0 {
		t.Errorf("empty PersistTo: count=%d err=%v, want 0/<nil>", n, err)
	}
}

func keysOf(m map[string]*wire.SignedEnvelope) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
