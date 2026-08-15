package dht

// lookup_freshness_test.go pins the §6.4 cache-freshness semantics of
// DHTLookup.Lookup: a FETCHED envelope is served from the local store only
// for one record-TTL window; after that the lookup re-validates against the
// network and picks up updates (higher sequence), while a fetch failure falls
// back to the stale copy (offline resilience). Seeded/authoritative envelopes
// (never fetched by this lookup) are always served locally.

import (
	"context"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/wire"
)

// TestDHTLookupFreshnessRevalidates: B fetches v1 from A; A publishes v2
// (seq+1, new IP); B still serves v1 within the TTL window; after the window
// B re-validates and serves v2.
func TestDHTLookupFreshnessRevalidates(t *testing.T) {
	a, b := peerPair(t)
	defer a.Close()
	defer b.Close()

	owner, _ := crypto.Generate()
	env1, key := makeTLDRecord(t, owner, "freshness")
	// Shrink the record TTL so the test's clock jump crosses the window
	// (makeTLDRecord uses TTL 300; keep it — we jump 301s).
	if ok, err := a.store.Put(key, env1, time.Now().Unix(), true); err != nil || !ok {
		t.Fatalf("seed v1: %v %v", ok, err)
	}

	lookup := NewDHTLookup(b.store, b)
	now := time.Now().Unix()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	got, err := lookup.Lookup(ctx, env1.Record.Name, now)
	if err != nil || got == nil {
		t.Fatalf("first lookup: %v %v", got, err)
	}
	h1, _ := env1.RecordHash()
	gh, _ := got.RecordHash()
	if string(gh) != string(h1) {
		t.Fatal("first lookup did not return v1")
	}

	// Within the TTL window: serve the cached copy even though A already has
	// a newer sequence (simulate by publishing v2 to A immediately).
	ttl := int(env1.Record.RRset[0].TTL)
	env2 := bumpSequence(t, env1, owner)
	if ok, err := a.store.Put(key, env2, now, true); err != nil || !ok {
		t.Fatalf("publish v2 on A: %v %v", ok, err)
	}
	got, err = lookup.Lookup(ctx, env1.Record.Name, now+1)
	if err != nil || got == nil {
		t.Fatalf("fresh-window lookup: %v %v", got, err)
	}
	gh, _ = got.RecordHash()
	if string(gh) != string(h1) {
		t.Error("fresh window must serve the cached v1 (no network re-validation)")
	}

	// After the TTL window: re-validate and converge to v2.
	got, err = lookup.Lookup(ctx, env1.Record.Name, now+int64(ttl)+1)
	if err != nil || got == nil {
		t.Fatalf("post-window lookup: %v %v", got, err)
	}
	h2, _ := env2.RecordHash()
	gh, _ = got.RecordHash()
	if string(gh) != string(h2) {
		t.Error("stale cache was not re-validated to v2 after the TTL window")
	}
}

// TestDHTLookupStaleFallbackOnDeadNetwork: after the window, with the source
// node closed, the lookup still serves the stale cached copy rather than
// failing.
func TestDHTLookupStaleFallbackOnDeadNetwork(t *testing.T) {
	a, b := peerPair(t)
	defer b.Close()

	owner, _ := crypto.Generate()
	env1, key := makeTLDRecord(t, owner, "stalefall")
	now := time.Now().Unix()
	if ok, err := a.store.Put(key, env1, now, true); err != nil || !ok {
		t.Fatalf("seed: %v %v", ok, err)
	}
	lookup := NewDHTLookup(b.store, b)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if _, err := lookup.Lookup(ctx, env1.Record.Name, now); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil { // source gone
		t.Fatal(err)
	}
	ttl := int(env1.Record.RRset[0].TTL)
	got, err := lookup.Lookup(ctx, env1.Record.Name, now+int64(ttl)+10)
	if err != nil {
		t.Fatalf("post-window lookup with dead network: %v", err)
	}
	if got == nil {
		t.Error("stale fallback lost the cached envelope on a dead network")
	}
}

// TestDHTLookupSeededAlwaysFresh: an envelope seeded locally (never fetched
// by this lookup) is served without network re-validation even past its TTL.
func TestDHTLookupSeededAlwaysFresh(t *testing.T) {
	a, _ := startTestNode(t, nil)
	defer a.Close()
	owner, _ := crypto.Generate()
	env1, key := makeTLDRecord(t, owner, "seeded")
	now := time.Now().Unix()
	if ok, err := a.store.Put(key, env1, now, true); err != nil || !ok {
		t.Fatal(err)
	}
	lookup := NewDHTLookup(a.store, a) // same store: seeded, not fetched
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// Past the record TTL but inside its validity window: a seeded
	// (authoritative-local) envelope is served without re-validation. (A jump
	// past expires would evict it via §6.4 expiry, which is a different rule.)
	got, err := lookup.Lookup(ctx, env1.Record.Name, now+301)
	if err != nil || got == nil {
		t.Fatalf("seeded lookup: %v %v", got, err)
	}
}

// TestFetchMetaRoundTrip: the fetched-keys metadata survives JSON and marks
// exactly the fetched keys as caches.
func TestFetchMetaRoundTrip(t *testing.T) {
	a, b := peerPair(t)
	defer a.Close()
	defer b.Close()
	owner, _ := crypto.Generate()
	env1, key := makeTLDRecord(t, owner, "meta")
	now := time.Now().Unix()
	if ok, err := a.store.Put(key, env1, now, true); err != nil || !ok {
		t.Fatal(err)
	}
	lookup := NewDHTLookup(b.store, b)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if _, err := lookup.Lookup(ctx, env1.Record.Name, now); err != nil {
		t.Fatal(err)
	}
	meta, err := lookup.FetchMetaJSON()
	if err != nil {
		t.Fatal(err)
	}
	fresh := NewDHTLookup(b.store, nil)
	if err := fresh.LoadFetchMetaJSON(meta); err != nil {
		t.Fatal(err)
	}
	// The restored map must mark the fetched key as a cache (not fresh far in
	// the future).
	if fresh.freshLocked(key, env1, now+10*365*86400) {
		t.Error("restored metadata did not mark the fetched key as a network cache")
	}
	if !fresh.freshLocked(key, env1, now) {
		t.Error("metadata lost the fetch timestamp (key should be fresh at fetch time)")
	}
}

// bumpSequence returns a successor of env signed by the same owner: sequence+1,
// fresh timestamps, new A record IP, prev_hash chaining to env.
func bumpSequence(t *testing.T, env *wire.SignedEnvelope, kp *crypto.Keypair) *wire.SignedEnvelope {
	t.Helper()
	prevH, err := env.RecordHash()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	rec, err := wire.NewRecord(env.Record.Name, env.Record.Owner, env.Record.Sequence+1,
		uint64(now), uint64(now+3600))
	if err != nil {
		t.Fatal(err)
	}
	rr, err := wire.A([]byte{203, 0, 113, 5}, 300)
	if err != nil {
		t.Fatal(err)
	}
	rec.RRset = []*wire.RR{rr}
	rec.PrevHash = prevH
	out, err := wire.SignRecord(rec, kp)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
