// ghost_contacts_test.go — issue #2: advertisement re-teaching must not
// launder dead contacts into liveness. ConfirmedAt is the only thing a
// direct exchange advances; the idle sweep converges ghosts to evicted;
// the peerbook persists only confirmed contacts.
package dht

import (
	"testing"
	"time"

	"github.com/camalolo/freens/internal/crypto"
)

func mkContact(t *testing.T, n *Node, confirmed bool) *NodeContact {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	id, err := crypto.NodeID(kp.Public())
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewNodeContact(id, kp.Public(), "192.0.2.10:15353", n.now())
	if err != nil {
		t.Fatal(err)
	}
	if confirmed {
		c.ConfirmedAt = n.now()
	}
	return c
}

// reteach returns a FRESH contact object carrying the same identity as c —
// production advertisements are freshly parsed per response, never the same
// pointer (the bucket stores the caller's object, so re-using it would
// mutate the stored entry directly and mask the merge semantics under test).
func reteach(t *testing.T, n *Node, c *NodeContact) *NodeContact {
	t.Helper()
	cp, err := NewNodeContact(c.NodeID, c.PublicKey, c.Addr, n.now())
	if err != nil {
		t.Fatal(err)
	}
	return cp
}

// TestAdvertisedContactNotRefreshedByReteach: learning the same contact
// via {nodes} advertisement twice must keep the ORIGINAL LastSeen — recency
// is only earned by direct exchange (issue #2 anti-laundering invariant).
func TestAdvertisedContactNotRefreshedByReteach(t *testing.T) {
	n, _ := startTestNode(t, nil)
	defer n.Close()
	c := mkContact(t, n, false)
	n.learnContact(c) // advertisement: learn

	got := n.RoutingTable().Get(c.NodeID)
	if got == nil {
		t.Fatal("contact not learned")
	}
	firstSeen := got.LastSeen
	if got.ConfirmedAt != 0 {
		t.Fatalf("advertised contact has ConfirmedAt=%d, want 0", got.ConfirmedAt)
	}

	time.Sleep(1100 * time.Millisecond) // cross a second boundary
	n.learnContact(reteach(t, n, c))    // re-teach: must NOT refresh
	got = n.RoutingTable().Get(c.NodeID)
	if got.LastSeen != firstSeen {
		t.Errorf("re-teach refreshed LastSeen (%d -> %d): advertisement must not launder liveness", firstSeen, got.LastSeen)
	}
	if got.ConfirmedAt != 0 {
		t.Errorf("re-teach set ConfirmedAt=%d, want 0", got.ConfirmedAt)
	}

	// A direct exchange DOES refresh both.
	time.Sleep(1100 * time.Millisecond)
	direct := reteach(t, n, c)
	direct.ConfirmedAt = n.now()
	n.learn(direct)
	got = n.RoutingTable().Get(c.NodeID)
	if got.ConfirmedAt == 0 || got.LastSeen == firstSeen {
		t.Errorf("direct exchange did not confirm: LastSeen=%d ConfirmedAt=%d", got.LastSeen, got.ConfirmedAt)
	}
}

// TestIdleSweepEvictsGhosts: with a short ContactIdleTTL, an advertised
// never-confirmed contact and a confirmed-then-vanished contact are both
// evicted; a recently confirmed contact survives.
func TestIdleSweepEvictsGhosts(t *testing.T) {
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	n, err := NewNode(NodeConfig{
		Keypair:        kp,
		ListenAddr:     "127.0.0.1:0",
		Store:          NewEnvelopeStore(0, nil),
		ContactIdleTTL: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(); err != nil {
		t.Fatal(err)
	}
	defer n.Close()

	ghost := mkContact(t, n, false) // advertised only
	n.learnContact(ghost)
	stale := mkContact(t, n, true) // confirmed once, then silence
	n.learn(stale)
	live := mkContact(t, n, true)
	n.learn(live)

	// Age everything past the TTL except `live`, which we keep confirming
	// by re-learning it as a direct exchange right before the sweep.
	time.Sleep(3 * time.Second)
	fresh := reteach(t, n, live)
	fresh.ConfirmedAt = n.now()
	n.learn(fresh)

	n.sweepIdleContacts(n.now())
	if got := n.RoutingTable().Get(ghost.NodeID); got != nil {
		t.Error("advertised ghost survived the idle sweep")
	}
	if got := n.RoutingTable().Get(stale.NodeID); got != nil {
		t.Error("confirmed-then-silent contact survived the idle sweep")
	}
	if got := n.RoutingTable().Get(live.NodeID); got == nil {
		t.Error("recently confirmed contact was swept")
	}
}
