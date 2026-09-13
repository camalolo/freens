package dht

// keyspace_split_test.go — regressions for the 2026-09-13 camalolo
// keyspace split (found live during the v0.16.6-dev fleet roll): a box
// whose walk landed on stale-replica holders kept serving a LAPSED
// predecessor while warm tables reached the fresh holders. Defenses
// under test:
//
//  1. hGet carries {nodes} on a store HIT too (pre-amendment a hit answered
//     the envelope alone, so a walker landing in a stale pocket never
//     learned the true closest set — the pocket-blind walk).
//  2. A lookup whose best envelope is already expired warms the table with
//     one real node-walk toward the key and re-GETs once (expiredWinner).
//  3. The publish walk-rescue fires on strict-minority acceptance too, not
//     just zero (a 4/8 renewal is what split the keyspace in the first
//     place).

import (
	"context"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/claims"
	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/wire"
)

// TestGetReplyCarriesNodesOnStoreHit: a get that HITS the store must still
// carry {nodes} — a walker probing a stale-replica holder has to learn the
// closer contacts from that very reply or it can never escape the pocket.
func TestGetReplyCarriesNodesOnStoreHit(t *testing.T) {
	a, _ := startTestNode(t, nil)
	defer a.Close()
	b, _ := startTestNode(t, nil)
	defer b.Close()
	bAddr, err := b.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}

	env, key := makeEnvAt(t, "hithere", time.Now().Unix(), time.Now().Unix()+3600)
	if ok, err := b.store.Put(key, env, time.Now().Unix(), true); err != nil || !ok {
		t.Fatalf("seed store: ok=%v err=%v", ok, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := a.sendQuery(ctx, bAddr, b.ID(), "get", map[string]any{"key": key})
	if err != nil || resp == nil || resp.Y == wire.MsgTypeError {
		t.Fatalf("get: resp=%v err=%v", resp, err)
	}
	if resp.A["envelope"] == nil {
		t.Fatal("hit reply carries no envelope")
	}
	entries, _ := resp.A["nodes"].([]any)
	if len(entries) == 0 {
		t.Fatal("hit reply carries no {nodes} — the pocket-blind reply shape is back")
	}
}

// splitGenerations mints TWO generations of one identity's claim envelope:
// seq 1 with an EXPIRED window and seq 2 with a live one — same owner key,
// same claim, so both live at the same K_claim and the §6.4 winner rule
// picks by sequence.
func splitGenerations(t *testing.T, alias string, now int64) (stale, fresh *wire.SignedEnvelope) {
	t.Helper()
	withFastWitnessPoW(t)
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	tid, err := crypto.TldID(kp.Public())
	if err != nil {
		t.Fatal(err)
	}
	claim, err := claims.MineAliasClaim(alias, kp, uint64(now-4000), 8, 2_000_000, 16)
	if err != nil {
		t.Fatalf("MineAliasClaim: %v", err)
	}
	cb, err := claim.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	wn, err := naming.EncodeWireName(nil, alias, tid)
	if err != nil {
		t.Fatal(err)
	}
	mk := func(seq uint64, created, expires int64) *wire.SignedEnvelope {
		t.Helper()
		rec, err := wire.NewRecord(wn, kp.Public(), seq, uint64(created), uint64(expires))
		if err != nil {
			t.Fatal(err)
		}
		rec.Claim = cb
		env, err := wire.SignRecord(rec, kp)
		if err != nil {
			t.Fatal(err)
		}
		return env
	}
	return mk(1, now-4000, now-3600), mk(2, now-100, now+3600)
}

// TestLookupSelfHealsOffStaleReplicaPocket: a's only reachable holder (b)
// serves an EXPIRED envelope (still within the holders' 24 h ExpiryGrace,
// so b's store keeps answering it); the FRESH generation lives on c, which
// a does not know. A lookup from a must come back with the fresh
// envelope — via {nodes}-on-hit teaching the walk about c, and/or the
// expired-winner warm-and-retry — never with the expired one.
func TestLookupSelfHealsOffStaleReplicaPocket(t *testing.T) {
	const alias = "splitfoo"
	now := time.Now().Unix()
	staleEnv, freshEnv := splitGenerations(t, alias, now)
	key, err := KeyForClaim(alias)
	if err != nil {
		t.Fatal(err)
	}

	// c: the fresh generation, unknown to a.
	c, _ := startTestNode(t, nil)
	defer c.Close()
	cAddr, err := c.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := c.store.Put(key, freshEnv, now, true); err != nil || !ok {
		t.Fatalf("seed fresh: ok=%v err=%v", ok, err)
	}

	// b: the stale replica — and the ONLY contact a knows. b knows c, so
	// its (now mandatory) {nodes} on the hit is how the walk escapes.
	b, _ := startTestNode(t, nil)
	defer b.Close()
	bAddr, err := b.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := b.store.Put(key, staleEnv, now, true); err != nil || !ok {
		t.Fatalf("seed stale: ok=%v err=%v", ok, err)
	}
	if err := b.AddPeer(c.PublicKey(), cAddr.String()); err != nil {
		t.Fatal(err)
	}

	// a: the divergent box.
	a, _ := startTestNode(t, nil)
	defer a.Close()
	if err := a.AddPeer(b.PublicKey(), bAddr.String()); err != nil {
		t.Fatal(err)
	}

	lookup := NewDHTLookup(NewEnvelopeStore(0, nil), a)
	env, err := lookup.LookupClaim(context.Background(), alias, now)
	if err != nil {
		t.Fatalf("LookupClaim: %v", err)
	}
	if env == nil {
		t.Fatal("LookupClaim returned nil — the walk settled for nothing")
	}
	if env.Record.Sequence != 2 {
		t.Fatalf("LookupClaim served seq %d from the stale pocket, want the fresh seq 2", env.Record.Sequence)
	}
}

// TestExpiredWinnerReturnsUnchangedWithoutHelp: expiredWinner with no
// fresher copy reachable must return the original envelope and error
// unchanged (the heal is best-effort; the honest answer stays honest).
func TestExpiredWinnerReturnsUnchangedWithoutHelp(t *testing.T) {
	const alias = "splitbar"
	now := time.Now().Unix()
	staleEnv, _ := splitGenerations(t, alias, now)
	key, err := KeyForClaim(alias)
	if err != nil {
		t.Fatal(err)
	}

	b, _ := startTestNode(t, nil)
	defer b.Close()
	bAddr, err := b.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := b.store.Put(key, staleEnv, now, true); err != nil || !ok {
		t.Fatalf("seed stale: ok=%v err=%v", ok, err)
	}
	a, _ := startTestNode(t, nil)
	defer a.Close()
	if err := a.AddPeer(b.PublicKey(), bAddr.String()); err != nil {
		t.Fatal(err)
	}

	lookup := NewDHTLookup(NewEnvelopeStore(0, nil), a)
	env, gerr := lookup.expiredWinner(context.Background(), key, staleEnv, nil)
	if env != staleEnv || gerr != nil {
		t.Fatalf("expiredWinner changed the answer without a fresher copy: env=%v err=%v", env != nil, gerr)
	}
}

// TestPublishRescueOnMinorityAcceptance: a publish accepted by a MINORITY
// of its closest set (here 3 of 8 — the rest ghosts, the 2026-09-13 shape)
// must fire the walk-rescue too, and the walk's newly reached contacts must
// be put to. Fixture: a's closest-8 = 5 ghosts (b's real address behind
// fabricated IDs — puts silently dropped) + 3 live peers; a 4th live peer
// (e) is reachable ONLY through the rescue walk (b advertises it).
func TestPublishRescueOnMinorityAcceptance(t *testing.T) {
	alias := "minorityrescue"
	env, _, _ := tombstoneFixture(t, alias, uint64(time.Now().Unix()), time.Now().Unix(), time.Now().Unix()+3600, true, false)
	key, err := KeyForClaim(alias)
	if err != nil {
		t.Fatal(err)
	}

	// The live set: b, c, d in a's table; e only in b's.
	live := make([]*Node, 0, 4)
	for i := 0; i < 4; i++ {
		n, _ := startTestNode(t, nil)
		defer n.Close()
		live = append(live, n)
	}
	bAddr, err := live[0].LocalAddr()
	if err != nil {
		t.Fatal(err)
	}

	a, _ := startTestNode(t, nil)
	defer a.Close()

	// 5 ghosts inside the closest cluster (see publish_rescue_test.go for
	// the shape and the LastSeen caveat).
	now := time.Now().Unix()
	for i := 0; i < 5; i++ {
		ghostID := append([]byte(nil), key...)
		ghostID[31] = key[31] ^ byte(i+10) // clear of the live peers' distances
		if _, err := a.rt.Add(&NodeContact{
			NodeID:   ghostID,
			Addr:     bAddr.String(),
			LastSeen: now,
		}); err != nil {
			t.Fatalf("ghost %d: %v", i, err)
		}
	}
	// 3 live peers join a's table (generically farther than the ghosts).
	for _, n := range live[:3] {
		addr, err := n.LocalAddr()
		if err != nil {
			t.Fatal(err)
		}
		if err := a.AddPeer(n.PublicKey(), addr.String()); err != nil {
			t.Fatal(err)
		}
	}
	// b advertises e for the rescue walk to discover.
	eAddr, err := live[3].LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	if err := live[0].AddPeer(live[3].PublicKey(), eAddr.String()); err != nil {
		t.Fatal(err)
	}

	closest := a.rt.Closest(key, constants.RReplication)
	if len(closest) != constants.RReplication {
		t.Fatalf("fixture: closest(key,8) = %d contacts", len(closest))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	stats, err := a.publishKeyedStats(ctx, key, env, nil)
	if err != nil {
		t.Fatalf("publish = %v (stats %+v)", err, stats)
	}
	// 3 accepted locally → minority (6 < 8) → rescue must have run and put
	// to e (the walk's discovery), lifting targets past the local table.
	if stats.Targets <= constants.RReplication {
		t.Errorf("targets = %d, want > %d — the minority rescue did not run (stats %+v)",
			stats.Targets, constants.RReplication, stats)
	}
	if stats.Accepted < 4 {
		t.Errorf("accepted = %d, want ≥ 4 (the walk-reached 4th peer) (stats %+v)", stats.Accepted, stats)
	}
}
