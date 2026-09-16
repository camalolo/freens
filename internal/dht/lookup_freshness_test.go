package dht

// lookup_freshness_test.go pins the §6.4 cache-freshness semantics of
// DHTLookup.Lookup: a FETCHED envelope is served from the local store only
// for one record-TTL window; after that the lookup re-validates against the
// network and picks up updates (higher sequence), while a fetch failure falls
// back to the stale copy (offline resilience). Seeded/authoritative envelopes
// (never fetched by this lookup) are always served locally — and so are
// PUSHED cache copies (peer puts), BUT never past the record's own expires:
// the expired-local-hit revalidation (v0.18.1, the www.camalolo incident).

import (
	"context"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/naming"
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
	// past its expires would NOT be served either — freshLocked now refuses
	// expired records regardless of the cache stamp — while §6.4 lazy
	// eviction from the store itself only happens past expires+ExpiryGrace.
	// See the expired-local-hit tests below.)
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

// tldRecordAt is makeTLDRecord with a caller-chosen sequence, created/expires
// and RR TTL — the expired-local-hit tests need a record whose SIGNED lease is
// shorter than its cache TTL (the live-incident shape: expires passed while
// the cache stamp still read fresh).
func tldRecordAt(t *testing.T, kp *crypto.Keypair, alias string, seq uint64, created, expires int64, ttl uint32) (*wire.SignedEnvelope, []byte) {
	t.Helper()
	tid, err := crypto.TldID(kp.Public())
	if err != nil {
		t.Fatal(err)
	}
	wn, err := naming.EncodeWireName(nil, alias, tid)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := wire.NewRecord(wn, kp.Public(), seq, uint64(created), uint64(expires))
	if err != nil {
		t.Fatal(err)
	}
	rr, err := wire.A([]byte{203, 0, 113, 77}, uint64(ttl))
	if err != nil {
		t.Fatal(err)
	}
	rec.RRset = []*wire.RR{rr}
	env, err := wire.SignRecord(rec, kp)
	if err != nil {
		t.Fatal(err)
	}
	key, err := KeyForWireName(wn)
	if err != nil {
		t.Fatal(err)
	}
	return env, key
}

// TestLookupExpiredPushedCopyRewalks (v0.18.1, the www.camalolo incident):
// a PUSHED cache copy (a peer put the envelope straight into B's store) has
// no fetchedAt stamp, so freshLocked used to treat it as fresh FOREVER — when
// the record expired, the lookup served it anyway, the §7.4 checklist
// NXDOMAINed it, and the box never re-walked while the network held a newer
// generation. The expired local hit must fall through to the walk.
func TestLookupExpiredPushedCopyRewalks(t *testing.T) {
	a, b := peerPair(t)
	defer a.Close()
	defer b.Close()

	owner, _ := crypto.Generate()
	now := time.Now().Unix()
	// v1: a short lease that is already expired at the lookup time (the
	// pushed copy the owner renewed elsewhere).
	env1, key := tldRecordAt(t, owner, "pushedvict", 1, now-100, now+10, 300)
	if ok, err := a.store.Put(key, env1, now, true); err != nil || !ok {
		t.Fatalf("seed v1 on A: %v %v", ok, err)
	}
	// PUSH into B's store (the peer-put shape): no DHTLookup fetch, no stamp.
	if ok, err := b.store.Put(key, env1, now, true); err != nil || !ok {
		t.Fatalf("push v1 into B: %v %v", ok, err)
	}
	lookup := NewDHTLookup(b.store, b)
	var kArr [32]byte
	copy(kArr[:], key)
	lookup.mu.Lock()
	_, stamped := lookup.fetchedAt[kArr]
	lookup.mu.Unlock()
	if stamped {
		t.Fatal("precondition: a pushed copy must carry no fetch stamp")
	}

	// The owner renewed to seq 2 while B's pushed copy aged past its expires.
	env2 := bumpSequence(t, env1, owner)
	if ok, err := a.store.Put(key, env2, now, true); err != nil || !ok {
		t.Fatalf("publish v2 on A: %v %v", ok, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	got, err := lookup.Lookup(ctx, env1.Record.Name, now+11) // v1 expired at now+10
	if err != nil || got == nil {
		t.Fatalf("post-expiry lookup: %v %v", got, err)
	}
	h2, _ := env2.RecordHash()
	gh, _ := got.RecordHash()
	if string(gh) != string(h2) {
		t.Fatal("the expired pushed copy was served instead of re-walking to the newer generation (the www.camalolo NXDOMAIN bug)")
	}
}

// TestLookupExpiredStampedCopyInsideGraceRewalks: a FETCHED copy whose cache
// stamp is still inside its freshness window but whose record lease has
// lapsed (expires ≪ fetchedAt+TTL) must not be served — the store's §6.4
// lazy eviction only fires past expires+ExpiryGrace, so the fresh-hit path is
// the only line of defense. The lookup re-walks and adopts the newer
// envelope.
func TestLookupExpiredStampedCopyInsideGraceRewalks(t *testing.T) {
	a, b := peerPair(t)
	defer a.Close()
	defer b.Close()

	owner, _ := crypto.Generate()
	now := time.Now().Unix()
	// v1: TTL 300 but a 10 s lease — past expires while the cache stamp is
	// still fresh (the exact gap the lazy store eviction never covers).
	env1, key := tldRecordAt(t, owner, "stampedvict", 1, now-100, now+10, 300)
	if ok, err := a.store.Put(key, env1, now, true); err != nil || !ok {
		t.Fatalf("seed v1 on A: %v %v", ok, err)
	}

	lookup := NewDHTLookup(b.store, b)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if got, err := lookup.Lookup(ctx, env1.Record.Name, now); err != nil || got == nil {
		t.Fatalf("initial fetch: %v %v", got, err)
	}

	env2 := bumpSequence(t, env1, owner)
	if ok, err := a.store.Put(key, env2, now, true); err != nil || !ok {
		t.Fatalf("publish v2 on A: %v %v", ok, err)
	}

	got, err := lookup.Lookup(ctx, env1.Record.Name, now+11) // v1 expired; stamp (now) still fresh
	if err != nil || got == nil {
		t.Fatalf("post-expiry lookup: %v %v", got, err)
	}
	h2, _ := env2.RecordHash()
	gh, _ := got.RecordHash()
	if string(gh) != string(h2) {
		t.Fatal("the lapsed-but-fresh-stamped copy was served instead of revalidating")
	}
}

// TestLookupFreshUnexpiredCopyServedWithoutWalk: the other side of the fix —
// a fresh, UNEXPIRED local hit (pushed, hence no stamp) is still served
// without any network walk even when a newer generation already exists on
// the network (the TestDHTLookupFreshnessRevalidates contract, pinned here
// for the no-stamp shape the expiry gate now also sees).
func TestLookupFreshUnexpiredCopyServedWithoutWalk(t *testing.T) {
	a, b := peerPair(t)
	defer a.Close()
	defer b.Close()

	owner, _ := crypto.Generate()
	now := time.Now().Unix()
	env1, key := tldRecordAt(t, owner, "unexpired", 1, now-100, now+3600, 300)
	if ok, err := a.store.Put(key, env1, now, true); err != nil || !ok {
		t.Fatalf("seed v1 on A: %v %v", ok, err)
	}
	if ok, err := b.store.Put(key, env1, now, true); err != nil || !ok {
		t.Fatalf("push v1 into B: %v %v", ok, err)
	}
	// A newer generation exists network-side BEFORE the local hit is served.
	env2 := bumpSequence(t, env1, owner)
	if ok, err := a.store.Put(key, env2, now, true); err != nil || !ok {
		t.Fatalf("publish v2 on A: %v %v", ok, err)
	}

	lookup := NewDHTLookup(b.store, b)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	got, err := lookup.Lookup(ctx, env1.Record.Name, now+1) // unexpired, fresh
	if err != nil || got == nil {
		t.Fatalf("fresh lookup: %v %v", got, err)
	}
	h1, _ := env1.RecordHash()
	gh, _ := got.RecordHash()
	if string(gh) != string(h1) {
		t.Fatal("a fresh unexpired local copy must be served without a walk")
	}
}
