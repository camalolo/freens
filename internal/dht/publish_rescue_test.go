package dht

// publish_rescue_test.go — the walk-rescue regression (v0.15.5, found live
// on the fleet): a publish whose local-table round accepts NOTHING must
// rescue itself with a real walk before reporting "accepted by 0 of N". The
// live case: a cold standalone node's bootstrap table around K_claim is
// polluted with ghost one-shot contacts, every put to them times out, the
// command reported "accepted by 0 of 8" — while the fleet was healthy and
// resolving. The rescue walk must find the REAL closest set (here: through
// the live bootstrap relay) and land the put.

import (
	"context"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/constants"
)

func TestPublishRescuesGhostTableWithWalk(t *testing.T) {
	// c: the live storing peer the rescue walk must discover (it is NOT in
	// a's table — only the relay B knows it).
	c, _ := startTestNode(t, nil)
	defer c.Close()
	cAddr, err := c.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}

	// B: the live bootstrap relay — a's only real contact. Its answer
	// ({nodes}) is how the walk learns c.
	b, _ := startTestNode(t, nil)
	defer b.Close()
	bAddr, err := b.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	if err := b.AddPeer(c.PublicKey(), cAddr.String()); err != nil {
		t.Fatal(err)
	}

	alias := "rescuefoo"
	env, _, _ := tombstoneFixture(t, alias, uint64(time.Now().Unix()), time.Now().Unix(), time.Now().Unix()+3600, true, false)
	key, err := KeyForClaim(alias)
	if err != nil {
		t.Fatal(err)
	}

	a, _ := startTestNode(t, nil)
	defer a.Close()
	// The pollution: 16 ghost contacts clustered INSIDE distance 15 of the
	// publish key — B's real address with fabricated node IDs (the ghost
	// one-shot shape: a real node's bytes behind someone else's identity,
	// every exchange rejected instantly on the recipient-ID check). With 16
	// ghosts nearer than ANY random-ID peer, the closest-8 round-1 targets
	// are all ghosts.
	//
	// LastSeen MUST be stamped: the idle sweep (issue #2) treats a
	// never-confirmed contact's learn time as its probation start, and a
	// zero stamp reads as the epoch — instantly sweep-eligible. The 1-minute
	// sweep tick landing before the publish's Closest deleted the whole
	// cluster mid-test and turned this into a coin-flip CI failure (found
	// 2026-09-04: alternating PASS/FAIL in CI on both v0.15.5 and v0.16.0;
	// a real learnContact always stamps LastSeen, so only the fixture lied).
	now := time.Now().Unix()
	for i := 0; i < 2*constants.RReplication; i++ {
		ghostID := append([]byte(nil), key...)
		ghostID[31] = key[31] ^ byte(i) // XOR-distance exactly i from key
		if _, err := a.rt.Add(&NodeContact{
			NodeID:   ghostID,
			Addr:     bAddr.String(),
			LastSeen: now,
		}); err != nil {
			t.Fatalf("ghost %d: %v", i, err)
		}
	}
	// B joins the table as the only live contact — generically FAR outside
	// the ghost cluster, so the local-table round never reaches it.
	if err := a.AddPeer(b.PublicKey(), bAddr.String()); err != nil {
		t.Fatal(err)
	}
	closest := a.rt.Closest(key, constants.RReplication)
	if len(closest) != constants.RReplication {
		t.Fatalf("fixture: closest(key,8) = %d contacts", len(closest))
	}
	for _, ct := range closest {
		if string(ct.NodeID) == string(b.ID()) || string(ct.NodeID) == string(c.ID()) {
			t.Fatal("fixture: a live peer sits inside the closest-8 — round 1 would succeed without the rescue")
		}
	}

	// The ghost round-1 puts cost one honest RPCTimeout each (messages
	// addressed to a fabricated ID are silently dropped by design —
	// anti-amplification), so the budget covers 8×5 s plus the walk.
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	stats, err := a.publishKeyedStats(ctx, key, env, nil)
	if err != nil {
		t.Fatalf("publish = %v (stats %+v) — the walk-rescue did not engage", err, stats)
	}
	if stats.Accepted == 0 {
		t.Fatalf("accepted = 0 after rescue (stats %+v)", stats)
	}
	if stats.Targets <= constants.RReplication {
		t.Errorf("targets = %d, want > the %d local-table contacts (the walk added candidates)", stats.Targets, constants.RReplication)
	}
}
