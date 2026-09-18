package dht

// altaging_test.go — the "never-listening mappings" half of the ghost fix:
// never-confirmed alternate addresses age out of the routing table
// (PruneStaleAlts, called from the idle sweep at twice the contact TTL).
// Before this, a NAT rotation left every old mapping listed forever and
// walks burned filler-probe timeouts on them in exactly the keyspaces the
// debris dominated.

import (
	"testing"
	"time"

	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
)

func testTable(t *testing.T) *RoutingTable {
	t.Helper()
	self, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	selfID, err := crypto.NodeID(self.Public())
	if err != nil {
		t.Fatal(err)
	}
	rt, err := NewRoutingTable(selfID, constants.K)
	if err != nil {
		t.Fatal(err)
	}
	return rt
}

func TestPruneStaleAlts(t *testing.T) {
	rt := testTable(t)
	now := time.Now().Unix()

	mk := func(seed byte, alts ...AddrState) *NodeContact {
		id := make([]byte, 32)
		id[0] = seed
		pk := make([]byte, 32)
		pk[0] = seed
		c, err := NewNodeContact(id, pk, "192.0.2.1:15353", now)
		if err != nil {
			t.Fatal(err)
		}
		c.ConfirmedAt = now // a citizen: the contact itself stays fresh
		c.Alts = alts
		return c
	}

	stale := mk(1, AddrState{Addr: "192.0.2.2:15353", LastSeen: now - 4*3600})                                   // never confirmed, old → prune
	fresh := mk(2, AddrState{Addr: "192.0.2.3:15353", LastSeen: now - 5*60})                                     // never confirmed, fresh → keep
	confirmedAlt := mk(3, AddrState{Addr: "192.0.2.4:15353", LastSeen: now - 4*3600, ConfirmedAt: now - 4*3600}) // confirmed once → keep
	noAlts := mk(4)

	for _, c := range []*NodeContact{stale, fresh, confirmedAlt, noAlts} {
		if _, err := rt.Add(c); err != nil {
			t.Fatal(err)
		}
	}

	if dropped := rt.PruneStaleAlts(now, 2*3600); dropped != 1 {
		t.Fatalf("PruneStaleAlts = %d, want exactly 1", dropped)
	}

	get := func(seed byte) *NodeContact {
		id := make([]byte, 32)
		id[0] = seed
		return rt.Get(id)
	}
	if c := get(1); len(c.Alts) != 0 {
		t.Fatalf("stale never-confirmed alt survived: %+v", c.Alts)
	}
	if c := get(2); len(c.Alts) != 1 {
		t.Fatalf("fresh never-confirmed alt was pruned: %+v", c.Alts)
	}
	if c := get(3); len(c.Alts) != 1 {
		// A once-confirmed alt is the cheap retry path after a NAT change:
		// only the contact-level idle sweep may retire it, never this.
		t.Fatalf("confirmed alt was pruned: %+v", c.Alts)
	}
	if c := get(4); c == nil || len(c.Alts) != 0 {
		t.Fatalf("contact without alts disturbed: %+v", c)
	}
}

func TestPruneStaleAltsEmptyTable(t *testing.T) {
	rt := testTable(t)
	if dropped := rt.PruneStaleAlts(time.Now().Unix(), 3600); dropped != 0 {
		t.Fatalf("empty table dropped %d", dropped)
	}
}
