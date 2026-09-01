package dht

import (
	"testing"
	"time"

	"github.com/camalolo/freens/internal/crypto"
)

// probeFailed is the §6.2 failure handler shared by every walk (lookup,
// claims, evidence). Its contract, found live on the desktop box
// 2026-09-01: a contact we exchanged with DIRECTLY moments ago must keep
// its routing-table slot through a single missed probe — the desktop's
// only non-LAN anchor (the community seed, reachable solely via a NAT'd
// public path) was being hard-evicted whenever one 2s probe tripped, and
// the peers table showed the seed gone until a walk re-learned it. A
// never-confirmed (or already-demoted) contact is still removed exactly
// as before, so genuinely dead peers converge within a probe round.

func mkWalkProbeNode(t *testing.T) *Node {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	n, err := NewNode(NodeConfig{
		Keypair:    kp,
		ListenAddr: "127.0.0.1:0",
		Store:      NewEnvelopeStore(0, nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	return n
}

func TestProbeFailedDemotesConfirmedContact(t *testing.T) {
	n := mkWalkProbeNode(t)
	c := mkContact(t, n, true) // confirmed directly
	n.learn(c)

	n.probeFailed(c)

	live := n.rt.Get(c.NodeID)
	if live == nil {
		t.Fatal("confirmed contact was hard-evicted by one missed probe")
	}
	if live.ConfirmedAt != 0 {
		t.Fatalf("demoted contact still stamped ConfirmedAt=%d, want 0", live.ConfirmedAt)
	}
}

func TestProbeFailedStillEvictsNeverConfirmedContact(t *testing.T) {
	n := mkWalkProbeNode(t)
	ghost := mkContact(t, n, false) // advertised only, never exchanged
	n.learnContact(ghost)

	n.probeFailed(ghost)

	if live := n.rt.Get(ghost.NodeID); live != nil {
		t.Fatalf("never-confirmed contact survived a failed probe: %+v", live)
	}
}

func TestProbeFailedSecondMissEvictsDemotedContact(t *testing.T) {
	n := mkWalkProbeNode(t)
	c := mkContact(t, n, true)
	n.learn(c)

	n.probeFailed(c) // first miss: demote, keep the slot
	if live := n.rt.Get(c.NodeID); live == nil {
		t.Fatal("first miss evicted a confirmed contact")
	}

	n.probeFailed(c) // second miss with no confirmation left: evict
	if live := n.rt.Get(c.NodeID); live != nil {
		t.Fatalf("repeatedly failing contact not evicted: %+v", live)
	}
}

func TestReconfirmAfterDemotion(t *testing.T) {
	n := mkWalkProbeNode(t)
	c := mkContact(t, n, true)
	n.learn(c)

	n.probeFailed(c)
	if live := n.rt.Get(c.NodeID); live == nil || live.ConfirmedAt != 0 {
		t.Fatal("precondition: contact should be present and demoted")
	}

	// The peer was merely slow: its next direct exchange re-stamps it.
	back := reteach(t, n, c)
	back.ConfirmedAt = n.now()
	n.learn(back)

	live := n.rt.Get(c.NodeID)
	if live == nil || live.ConfirmedAt == 0 {
		t.Fatalf("re-learn after demotion did not re-confirm: %+v", live)
	}
	if time.Since(time.Unix(live.ConfirmedAt, 0)) > time.Minute {
		t.Fatalf("re-confirmation stamp is stale: %d", live.ConfirmedAt)
	}
}

func TestRoutingTableDemote(t *testing.T) {
	n := mkWalkProbeNode(t)
	c := mkContact(t, n, true)
	n.learn(c)

	if !n.rt.Demote(c.NodeID) {
		t.Fatal("Demote returned false for a present contact")
	}
	if live := n.rt.Get(c.NodeID); live == nil || live.ConfirmedAt != 0 || live.Addr != c.Addr {
		t.Fatalf("Demote lost fields: %+v", live)
	}
	if n.rt.Demote(c.NodeID) != true {
		t.Fatal("Demote of a present (already-demoted) contact should still return true")
	}
	if n.rt.Demote([]byte{0xAA}) {
		t.Fatal("Demote returned true for an absent contact")
	}
}
