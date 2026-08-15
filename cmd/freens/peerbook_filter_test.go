// peerbook_filter_test.go — only DIRECTLY CONFIRMED contacts persist to
// the peerbook (issue #2: advertisement-learned ghosts must not survive a
// restart).
package main

import (
	"testing"

	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/dht"
)

func contactWithConfirmation(t *testing.T, confirmed bool) *dht.NodeContact {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	id, err := crypto.NodeID(kp.Public())
	if err != nil {
		t.Fatal(err)
	}
	c, err := dht.NewNodeContact(id, kp.Public(), "192.0.2.1:15353", 1000)
	if err != nil {
		t.Fatal(err)
	}
	if confirmed {
		c.ConfirmedAt = 1000
	}
	return c
}

func TestConfirmedPeersFiltersGhosts(t *testing.T) {
	confirmed := []*dht.NodeContact{
		contactWithConfirmation(t, true),
		contactWithConfirmation(t, true),
	}
	ghost := contactWithConfirmation(t, false) // advertised, never confirmed

	got := confirmedPeers(append(append([]*dht.NodeContact{}, confirmed...), ghost), 2000)
	if len(got) != 2 {
		t.Fatalf("confirmedPeers kept %d, want 2 (ghost filtered)", len(got))
	}
	for i, p := range got {
		if p.Addr != confirmed[i].Addr || string(p.PublicKey) != string(confirmed[i].PublicKey) {
			t.Errorf("peer %d mangled in conversion", i)
		}
	}
}
