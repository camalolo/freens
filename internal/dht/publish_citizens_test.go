package dht

import (
	"bytes"
	"context"
	"testing"
	"time"
)

// citizenFixture builds a table fixture with explicit longevity stamps,
// derived from the node's own ID so that fixture idx lands in a DISTINCT
// Kademlia bucket (first differing bit at position idx) — bucket-capacity
// interactions can't shadow the fixture set.
func citizenFixture(t *testing.T, n *Node, idx int, addr string, lastSeen, confirmedAt, firstSeen int64) *NodeContact {
	t.Helper()
	id := append([]byte(nil), n.id...)
	g, b := idx/8, idx%8
	if g >= 32 {
		t.Fatalf("fixture idx %d out of bucket range", idx)
	}
	id[g] ^= 1 << (7 - b)
	c, err := NewNodeContact(id, id, addr, lastSeen)
	if err != nil {
		t.Fatal(err)
	}
	c.ConfirmedAt = confirmedAt
	c.FirstSeen = firstSeen
	return c
}

// TestCitizensSelection pins the v0.19 replica-target gate: only contacts
// that are directly confirmed, fresh on both confirmation and last-seen, and
// either long-known or birth-stamp-less (legacy/peerbook) qualify. Young
// one-shot ghosts and stale corpses are routable but voteless.
func TestCitizensSelection(t *testing.T) {
	rtNode, _ := startTestNode(t, nil)
	defer rtNode.Close()
	rt := rtNode.rt
	now := time.Now().Unix()

	add := func(c *NodeContact, what string) {
		t.Helper()
		if _, err := rt.Add(c); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	}

	// legacy citizen: pre-v0.19 entry (no birth stamp), confirmed 1 min ago.
	add(citizenFixture(t, rtNode, 1, "127.0.0.1:20001", now-60, now-60, 0), "legacy")
	// aged citizen: known for an hour, confirmed 2 min ago.
	add(citizenFixture(t, rtNode, 2, "127.0.0.1:20002", now-120, now-120, now-3600), "aged")
	// young ghost: born 2 min ago, confirmed once at birth (the one-shot
	// shape) — routable, but never a put target.
	add(citizenFixture(t, rtNode, 3, "127.0.0.1:20003", now-120, now-120, now-120), "young-ghost")
	// corpse: known for hours but its confirmation aged out (dead peer,
	// stale NAT self-address) — excluded by the freshness gate.
	add(citizenFixture(t, rtNode, 4, "127.0.0.1:20004", now-7200, now-7200, now-7200), "corpse")
	// never-confirmed: advertisement-only knowledge — not a put target.
	add(citizenFixture(t, rtNode, 5, "127.0.0.1:20005", now-60, 0, now-3600), "never-confirmed")

	got := rt.Citizens(now)
	if len(got) != 2 {
		t.Fatalf("Citizens returned %d contacts, want 2 (legacy + aged): %+v", len(got), got)
	}
	for _, c := range got {
		if c.Addr != "127.0.0.1:20001" && c.Addr != "127.0.0.1:20002" {
			t.Fatalf("unexpected citizen %s", c.Addr)
		}
	}
}

// TestPublishTargetsCitizensNotGhosts is the regression test for the
// 2026-09-17 pocket class: with a table flooded by one-shot ghosts, a keyed
// publish must target the citizen daemons — not run a hash-proximity
// election that the corpses win. The whole fleet was on one LAN and the
// renewal still reported accepted=1/11 because 10 of its 11 elected targets
// were dead ephemeral ports.
func TestPublishTargetsCitizensNotGhosts(t *testing.T) {
	a, _ := startTestNode(t, nil)
	defer a.Close()

	now := time.Now().Unix()

	// The flood: 24 ghosts (they would win any closest-8 election),
	// confirmed once at birth — 20 inside the min-age gate, 4 aged past it
	// but stale (dead corpses). Addresses are black-hole loopback ports: if
	// a ghost ever gets targeted, the put fails loudly (and fast, on
	// loopback) instead of silently succeeding.
	for i := 0; i < 20; i++ {
		if _, err := a.rt.Add(citizenFixture(t, a, i+1, "127.0.0.1:1", now-120, now-120, now-120)); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 4; i++ {
		if _, err := a.rt.Add(citizenFixture(t, a, i+30, "127.0.0.1:1", now-7200, now-7200, now-7200)); err != nil {
			t.Fatal(err)
		}
	}

	// Three citizen daemons (born an hour ago, confirmed a minute ago) —
	// distance-irrelevant on purpose: the rule is longevity, not proximity.
	citizenIDs := make([][]byte, 0, 3)
	for i := 0; i < 3; i++ {
		c := citizenFixture(t, a, 100+i, "127.0.0.1:2100"+string(rune('0'+i)), now-60, now-60, now-3600)
		if _, err := a.rt.Add(c); err != nil {
			t.Fatal(err)
		}
		citizenIDs = append(citizenIDs, c.NodeID)
	}

	targets := a.publishTargets(context.Background(), []byte("publishkeypublishkeypublishkey00"), now)
	if len(targets) != 3 {
		t.Fatalf("publishTargets returned %d targets, want exactly the 3 citizens", len(targets))
	}
	for _, tc := range targets {
		found := false
		for _, want := range citizenIDs {
			if bytes.Equal(tc.NodeID, want) {
				found = true
			}
		}
		if !found {
			t.Fatalf("put target %x is not a citizen", tc.NodeID)
		}
		if tc.Addr == "127.0.0.1:1" {
			t.Fatalf("ghost address %s got a put slot", tc.Addr)
		}
	}
}

// TestPublishTargetsSparseTableFallsBackToWalk pins the bootstrap path: with
// no citizens at all (fresh node), targeting falls back to the v0.17
// discovery walk so a young network can still replicate.
func TestPublishTargetsSparseTableFallsBackToWalk(t *testing.T) {
	b, _ := startTestNode(t, nil)
	defer b.Close()
	bAddr, err := b.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	if err := b.AddPeer(b.PublicKey(), bAddr.String()); err != nil {
		t.Fatal(err)
	}

	a, _ := startTestNode(t, nil)
	defer a.Close()
	if err := a.AddPeer(b.PublicKey(), bAddr.String()); err != nil {
		t.Fatal(err)
	}

	targets := a.publishTargets(context.Background(), []byte("sparsekeysparsekeysparsekeyspar00"), a.now())
	if len(targets) == 0 {
		t.Fatal("sparse table: publishTargets reached nothing (walk + fallback both empty)")
	}
	sawB := false
	for _, tc := range targets {
		if bytes.Equal(tc.PublicKey, b.PublicKey()) {
			sawB = true
		}
	}
	if !sawB {
		t.Fatal("sparse table: the only live peer did not make the target set")
	}
}

// TestWalkBatchPrefersCitizens pins the walk-round ordering (the fast-walk
// half of the 2026-09-17 ghost-flood fix): probe slots go to long-confirmed
// citizens before unproven contacts regardless of hash distance, penalized
// corpses are skipped outright, and the width caps the batch.
func TestWalkBatchPrefersCitizens(t *testing.T) {
	a, _ := startTestNode(t, nil)
	defer a.Close()

	now := time.Now().Unix()
	key := []byte("walkbatchwalkbatchwalkbatchwalkb00")

	// six young ghosts, closest to the key (the old picker took these first)
	for i := 0; i < 6; i++ {
		if _, err := a.rt.Add(citizenFixture(t, a, i+1, "127.0.0.1:1", now-120, now-120, now-120)); err != nil {
			t.Fatal(err)
		}
	}
	// two citizens, far from the key by every measure that matters
	citizenIDs := make([][]byte, 0, 2)
	for i := 0; i < 2; i++ {
		c := citizenFixture(t, a, 60+i, "127.0.0.1:2200"+string(rune('0'+i)), now-60, now-60, now-3600)
		if _, err := a.rt.Add(c); err != nil {
			t.Fatal(err)
		}
		citizenIDs = append(citizenIDs, c.NodeID)
	}

	shortlist := a.rt.Closest(key, 16)
	queried := make(map[string]bool)

	batch := a.walkBatch(shortlist, queried, key, now, lookupRoundWidth)
	if len(batch) != lookupRoundWidth {
		t.Fatalf("batch = %d, want width %d", len(batch), lookupRoundWidth)
	}
	if !bytes.Equal(batch[0].NodeID, citizenIDs[0]) || !bytes.Equal(batch[1].NodeID, citizenIDs[1]) {
		t.Fatal("citizens did not lead the batch")
	}
	for _, c := range batch[2:] {
		if c.Addr == "127.0.0.1:2200"+string(rune('0'+0)) || c.Addr == "127.0.0.1:2201" {
			t.Fatalf("citizen %s duplicated in filler", c.Addr)
		}
	}

	// citizens queried: the next round is the young filler — discovery
	// still happens, just after the proven peers.
	for _, id := range citizenIDs {
		queried[string(id)] = true
	}
	batch2 := a.walkBatch(shortlist, queried, key, now, lookupRoundWidth)
	if len(batch2) == 0 {
		t.Fatal("filler round empty")
	}
	for _, c := range batch2 {
		if bytes.Equal(c.NodeID, citizenIDs[0]) || bytes.Equal(c.NodeID, citizenIDs[1]) {
			t.Fatal("queried citizen re-probed")
		}
	}

	// a penalized corpse is skipped outright (the retry-last tier: its
	// retry schedule is the deadUntil window, not the next round)
	corpse := citizenFixture(t, a, 90, "127.0.0.1:1", now-120, now-120, now-120)
	if _, err := a.rt.Add(corpse); err != nil {
		t.Fatal(err)
	}
	shortlist = append(shortlist, corpse)
	a.markDeadUnlessPromoted(corpse, now)
	for _, c := range shortlist {
		queried[string(c.NodeID)] = false
	}
	for _, id := range citizenIDs {
		queried[string(id)] = false
	}
	batch3 := a.walkBatch(shortlist, queried, key, now, lookupRoundWidth)
	for _, c := range batch3 {
		if bytes.Equal(c.NodeID, corpse.NodeID) {
			t.Fatal("penalized corpse got a probe slot")
		}
	}
}
