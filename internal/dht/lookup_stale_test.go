package dht

// lookup_stale_test.go — the phantom-freshness fixes (found live 2026-09-04,
// the minipc incident):
//
//   1. DHTLookup.LookupClaim must REVALIDATE a fetched claim cache past its
//      freshness window (mirroring DHTLookup.Lookup). Without it, a node
//      that cached a claim envelope which then LAPSED served the dead copy
//      for the whole §6.4 ExpiryGrace day while the network moved on — the
//      resolver's §7.4 checklist rightly rejected the expired envelope, so
//      the name NXDOMAINed locally while every fresher vantage resolved it.
//   2. On a DEGRADED walk (probes failed) with a LAPSED cached copy,
//      LookupClaim returns ErrDegradedMiss — SERVFAIL upstream, never
//      negative-cached — instead of an authoritative-looking NXDOMAIN for a
//      name whose holders may be alive (issue #1's contract).
//   3. Sequence discovery behind a stale bootstrap peer: a get answered from
//      a peer's store omits {nodes}, so a one-shot node bootstrapped from
//      that peer alone never learns the true closest-set and bases sequence
//      discovery on the stale copy ("phantom 21"). IterativeFindNode first —
//      find_node responses always carry {nodes} — then the get races the
//      real storers and EnvelopeWins picks the max sequence.

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/wire"
)

// connectTwo cross-seeds two nodes' routing tables (the peerPair pattern,
// for pairs built from startTestNode).
func connectTwo(t *testing.T, a, b *Node) {
	t.Helper()
	aAddr, err := a.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	bAddr, err := b.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.AddPeer(b.PublicKey(), bAddr.String()); err != nil {
		t.Fatal(err)
	}
	if err := b.AddPeer(a.PublicKey(), aAddr.String()); err != nil {
		t.Fatal(err)
	}
}

// claimEnvelopeAt builds a self-signed TLD-record envelope for alias with an
// explicit sequence and expiry (no embedded claim — LookupClaim fetches the
// envelope at K_claim; the §7.4 claim screening is the resolver's business,
// not the lookup's).
func claimEnvelopeAt(t *testing.T, kp *crypto.Keypair, alias string, seq int, created, expires int64) (*wire.SignedEnvelope, []byte) {
	t.Helper()
	tid, err := crypto.TldID(kp.Public())
	if err != nil {
		t.Fatal(err)
	}
	wn, err := naming.EncodeWireName(nil, alias, tid)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := wire.NewRecord(wn, kp.Public(), uint64(seq), uint64(created), uint64(expires))
	if err != nil {
		t.Fatal(err)
	}
	env, err := wire.SignRecord(rec, kp)
	if err != nil {
		t.Fatal(err)
	}
	kClaim, err := KeyForClaim(alias)
	if err != nil {
		t.Fatal(err)
	}
	return env, kClaim
}

func TestLookupClaimStaleCacheRevalidates(t *testing.T) {
	a, b := peerPair(t)
	defer a.Close()
	defer b.Close()

	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	lapsedEnv, kClaim := claimEnvelopeAt(t, kp, "staleclaim", 1, now-7200, now-3600)
	liveEnv, _ := claimEnvelopeAt(t, kp, "staleclaim", 2, now-100, now+3600)

	// The network (A) holds the LIVE envelope at K_claim.
	if accepted, err := a.store.Put(kClaim, liveEnv, now, true); err != nil || !accepted {
		t.Fatalf("seed A (live): accepted=%v err=%v", accepted, err)
	}
	// B cached the LAPSED envelope earlier (fetched, so fetchedAt is stamped)
	// and its freshness window has passed.
	if accepted, err := b.store.Put(kClaim, lapsedEnv, now, true); err != nil || !accepted {
		t.Fatalf("seed B (lapsed): accepted=%v err=%v", accepted, err)
	}
	lookup := NewDHTLookup(b.store, b)
	var kArr [constants.SHA256Len]byte
	copy(kArr[:], kClaim)
	lookup.mu.Lock()
	lookup.fetchedAt[kArr] = now - 100000 // far past cacheFreshness (empty RRset → RecordDefaultTTL = 24 h)
	lookup.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	got, err := lookup.LookupClaim(ctx, "staleclaim", now)
	if err != nil {
		t.Fatalf("LookupClaim: %v", err)
	}
	gh, _ := got.RecordHash()
	lh, _ := liveEnv.RecordHash()
	if !bytes.Equal(gh, lh) {
		t.Fatal("LookupClaim served the lapsed cached copy instead of revalidating against the network (the nanopi-stale-cache bug)")
	}
	// The live copy was adopted into the local store and is fresh now.
	if cached, _ := b.store.Get(kClaim, now); cached != nil {
		ch, _ := cached.RecordHash()
		if !bytes.Equal(ch, lh) {
			t.Error("fetched live envelope was not cached locally")
		}
	}
	lookup.mu.Lock()
	fa := lookup.fetchedAt[kArr]
	lookup.mu.Unlock()
	if fa != now {
		t.Errorf("fetchedAt not restamped (%d), stale caches would re-walk every query", fa)
	}
}

func TestLookupClaimDegradedWithLapsedCacheIsNotNXDOMAIN(t *testing.T) {
	a, b := peerPair(t)
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	lapsedEnv, kClaim := claimEnvelopeAt(t, kp, "deadclaim", 1, now-7200, now-3600)
	if accepted, err := b.store.Put(kClaim, lapsedEnv, now, true); err != nil || !accepted {
		t.Fatalf("seed B (lapsed): accepted=%v err=%v", accepted, err)
	}
	lookup := NewDHTLookup(b.store, b)
	var kArr [constants.SHA256Len]byte
	copy(kArr[:], kClaim)
	lookup.mu.Lock()
	lookup.fetchedAt[kArr] = now - 100000
	lookup.mu.Unlock()

	// Kill the only peer AFTER the table knows it: every probe now fails —
	// a DEGRADED walk, not a clean miss.
	a.Close()
	time.Sleep(100 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	got, err := lookup.LookupClaim(ctx, "deadclaim", now)
	if got != nil {
		t.Fatal("LookupClaim served a LAPSED cached copy off a degraded walk — the resolver would NXDOMAIN (and negative-cache) a name whose holders may be alive")
	}
	if !errors.Is(err, ErrDegradedMiss) {
		t.Fatalf("err = %v, want ErrDegradedMiss (SERVFAIL upstream, never cached)", err)
	}
}

func TestStandaloneDiscoverySeesTrueClosestSet(t *testing.T) {
	stale, _ := startTestNode(t, nil)
	live, _ := startTestNode(t, nil)
	client, _ := startTestNode(t, nil)
	defer stale.Close()
	defer live.Close()
	defer client.Close()

	// Topology: client ↔ stale only (the phantom-21 shape: a one-shot node
	// bootstrapped from a single stale peer). stale ↔ live so the
	// find_node walk can learn the true storer.
	connectTwo(t, client, stale)
	connectTwo(t, stale, live)

	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	lapsedEnv, kTld := claimEnvelopeAt(t, kp, "phantom", 1, now-7200, now-3600)
	liveEnv, _ := claimEnvelopeAt(t, kp, "phantom", 5, now-100, now+3600)
	if accepted, err := stale.store.Put(kTld, lapsedEnv, now, true); err != nil || !accepted {
		t.Fatalf("seed stale store: accepted=%v err=%v", accepted, err)
	}
	if accepted, err := live.store.Put(kTld, liveEnv, now, true); err != nil || !accepted {
		t.Fatalf("seed live store: accepted=%v err=%v", accepted, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	// The blindness, documented: with only the stale peer known, the get is
	// answered from its store (no {nodes} on a store hit) and returns the
	// lapsed copy — exactly what sequence discovery used to base on.
	blind, err := client.IterativeGet(ctx, kTld)
	if err != nil {
		t.Fatalf("pre-fix get: %v", err)
	}
	if blind == nil || blind.Record.Sequence != 1 {
		t.Fatalf("precondition: blind get = %v, want the stale peer's seq-1 copy", blind)
	}

	// The fix's shape: find_node first (always carries {nodes} — the table
	// learns the true storer), THEN the get races both and EnvelopeWins
	// picks the max sequence.
	client.IterativeFindNode(ctx, kTld, constants.RReplication)
	got, err := client.IterativeGet(ctx, kTld)
	if err != nil {
		t.Fatalf("post-warmup get: %v", err)
	}
	if got == nil || got.Record.Sequence != 5 {
		t.Fatalf("post-warmup get = seq %v, want the live storer's seq 5 — discovery must never trust a lone stale store hit", got)
	}
}
