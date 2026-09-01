package dht

import (
	"bytes"
	"context"
	"fmt"
	"sync/atomic"
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

// ---- multi-homed contacts (2026-09-01) ----
// A node reachable at more than one address (the seed: WAN + LAN) must
// accumulate both instead of flip-flopping the single Addr field, prefer
// the freshest-confirmed one, and survive a probe miss against one of its
// addresses by failing over to the other.

func TestMultiHomedContactAccumulatesAddresses(t *testing.T) {
	n := mkWalkProbeNode(t)
	c := mkContact(t, n, true) // preferred: 192.0.2.10:15353, confirmed
	n.learn(c)

	// The same node re-learned at its other address (unconfirmed walk find).
	other := mkContact(t, n, false)
	other.NodeID = c.NodeID
	other.PublicKey = c.PublicKey
	other.Addr = "192.0.2.11:15353"
	n.learnContact(other)

	live := n.rt.Get(c.NodeID)
	if live == nil {
		t.Fatal("contact lost on re-learn at a second address")
	}
	if live.Addr != "192.0.2.10:15353" {
		t.Fatalf("preferred changed to %s without any confirmation", live.Addr)
	}
	if len(live.Alts) != 1 || live.Alts[0].Addr != "192.0.2.11:15353" {
		t.Fatalf("second address not accumulated: %+v", live.Alts)
	}
}

func TestMultiHomedPreferenceFollowsConfirmation(t *testing.T) {
	// Second-granularity timestamps make same-second confirmations a TIE
	// (strict-> ranking keeps the incumbent — no ping-pong); advance the
	// clock so the second confirmation genuinely outranks.
	var clock atomic.Int64
	const T = int64(1_000_000)
	clock.Store(T)
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	n, err := NewNode(NodeConfig{
		Keypair:    kp,
		ListenAddr: "127.0.0.1:0",
		Store:      NewEnvelopeStore(0, nil),
		Now:        func() int64 { return clock.Load() },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(); err != nil {
		t.Fatal(err)
	}
	defer n.Close()

	c := mkContact(t, n, true) // 192.0.2.10 confirmed at T
	n.learn(c)

	alt := mkContact(t, n, false)
	alt.NodeID, alt.PublicKey = c.NodeID, c.PublicKey
	alt.Addr = "192.0.2.11:15353"
	alt.LastSeen = n.now()
	n.learnContact(alt)
	if live := n.rt.Get(c.NodeID); live.Addr != "192.0.2.10:15353" {
		t.Fatalf("unconfirmed learn stole preference: %s", live.Addr)
	}

	// A direct exchange at the other address, LATER: THAT address now leads.
	clock.Store(T + 10)
	alt.ConfirmedAt = n.now()
	n.learn(alt)
	live := n.rt.Get(c.NodeID)
	if live.Addr != "192.0.2.11:15353" {
		t.Fatalf("freshly-confirmed address did not win preference: %s", live.Addr)
	}
	if len(live.Alts) != 1 || live.Alts[0].Addr != "192.0.2.10:15353" {
		t.Fatalf("previous preferred not demoted into Alts: %+v", live.Alts)
	}
	if live.Alts[0].ConfirmedAt == 0 {
		t.Fatal("demoted preferred lost its confirmation history")
	}
}

func TestProbeFailedFailsOverToAlternate(t *testing.T) {
	n := mkWalkProbeNode(t)
	c := mkContact(t, n, true) // preferred 192.0.2.10 (WAN), confirmed
	n.learn(c)

	alt := mkContact(t, n, false)
	alt.NodeID, alt.PublicKey = c.NodeID, c.PublicKey
	alt.Addr = "192.0.2.11:15353" // LAN, learned moments ago
	alt.LastSeen = n.now()
	n.learnContact(alt)

	// The WAN probe missed. The node must survive, preferred at the alt.
	n.probeFailed(c)

	live := n.rt.Get(c.NodeID)
	if live == nil {
		t.Fatal("probe miss evicted a multi-homed node with a live alternate")
	}
	if live.Addr != "192.0.2.11:15353" {
		t.Fatalf("failover did not switch preferred to the alternate: %s", live.Addr)
	}
	// The failed address sits in Alts with its confirmation cleared.
	for _, a := range live.Alts {
		if a.Addr == "192.0.2.10:15353" && a.ConfirmedAt != 0 {
			t.Fatalf("failed address kept its confirmation stamp: %+v", a)
		}
	}
}

func TestMultiHomedAltCapTrimsLRU(t *testing.T) {
	n := mkWalkProbeNode(t)
	c := mkContact(t, n, true)
	n.learn(c)

	base := n.now()
	for i := 0; i < 6; i++ {
		alt := mkContact(t, n, false)
		alt.NodeID, alt.PublicKey = c.NodeID, c.PublicKey
		alt.Addr = fmt.Sprintf("192.0.2.%d:15353", 20+i)
		alt.LastSeen = base + int64(i)
		n.learnContact(alt)
	}

	live := n.rt.Get(c.NodeID)
	if got := len(live.Alts); got != maxAddrsPerContact-1 {
		t.Fatalf("alt list not capped: %d entries, want %d", got, maxAddrsPerContact-1)
	}
	// The newest alt must have survived the trim.
	found := false
	for _, a := range live.Alts {
		if a.Addr == "192.0.2.25:15353" {
			found = true
		}
	}
	if !found {
		t.Fatalf("newest alt trimmed instead of the oldest: %+v", live.Alts)
	}
}

// ---- multi-addr advertisement (operator idea: "all the peers known should
// be returned by the seed") ----
// {nodes} entries are emitted PER KNOWN ADDRESS: a newcomer's first
// exchange with the seed hands it the whole fleet at LAN+WAN, so no single
// node's death strands it. Receivers with v0.13.3+ merge same-NodeID
// entries into one multi-homed contact; the wire format itself is
// unchanged (older peers just re-learn, their classic overwrite behavior).

func TestEncodeNodesEmitsEveryKnownAddress(t *testing.T) {
	n := mkWalkProbeNode(t)
	c := mkContact(t, n, true)
	n.learn(c)
	alt := mkContact(t, n, false)
	alt.NodeID, alt.PublicKey = c.NodeID, c.PublicKey
	alt.Addr = "192.0.2.11:15353"
	n.learnContact(alt)

	live := n.rt.Get(c.NodeID)
	entries := encodeNodes([]*NodeContact{live})
	if len(entries) != 2 {
		t.Fatalf("multi-homed contact encoded %d entries, want 2", len(entries))
	}
	seen := map[string]bool{}
	for _, e := range entries {
		parsed := parseNodes([]any{e})
		if len(parsed) != 1 {
			t.Fatalf("entry did not round-trip: %v", e)
		}
		seen[parsed[0].Addr] = true
		if !bytes.Equal(parsed[0].NodeID, c.NodeID) {
			t.Fatal("round-tripped entry lost its NodeID")
		}
	}
	if !seen["192.0.2.10:15353"] || !seen["192.0.2.11:15353"] {
		t.Fatalf("addresses missing from advertisement: %v", seen)
	}
}

func TestNewcomerAccumulatesFleetAddressesFromSeed(t *testing.T) {
	// The seed S knows peer P at two addresses (LAN+WAN). A newcomer N
	// running one find_node against S must end up with P as ONE
	// multi-homed contact carrying both.
	seed := mkWalkProbeNode(t)
	p := mkContact(t, seed, true)
	seed.learn(p)
	pAlt := mkContact(t, seed, false)
	pAlt.NodeID, pAlt.PublicKey = p.NodeID, p.PublicKey
	pAlt.Addr = "192.0.2.11:15353"
	seed.learnContact(pAlt)

	newcomer := mkWalkProbeNode(t)
	target := make([]byte, 32)
	for i := range target {
		target[i] = 0x7f // some target; the response carries S's closest
	}
	seedAddr, _ := seed.LocalAddr()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resp, err := newcomer.sendQuery(ctx, seedAddr, seed.ID(), "find_node", map[string]any{"target": target})
	if err != nil {
		t.Fatalf("find_node: %v", err)
	}
	// The walk's response handling: parse + learn every returned contact.
	for _, nc := range parseNodes(resp.A["nodes"]) {
		newcomer.learnContact(nc)
	}

	live := newcomer.rt.Get(p.NodeID)
	if live == nil {
		t.Fatal("newcomer did not learn the peer from the seed's response")
	}
	if len(live.Alts) != 1 || live.Alts[0].Addr != "192.0.2.11:15353" {
		t.Fatalf("newcomer did not accumulate both addresses: %+v", live)
	}
	if live.ConfirmedAt != 0 {
		t.Fatal("advertisement must not confirm (anti-ghost invariant)")
	}
}
