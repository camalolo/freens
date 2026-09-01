// peers_confirmed_test.go — regression (found live 2026-09-01 on the
// desktop box): the /peers handler has carried each contact's confirmed
// timestamp since the issue-#2 machinery, but the admin client decoded
// only addr+pk — every admin-socket consumer (the webui peers table)
// rendered "never confirmed" for live, ping-verified peers, forever.
package admin

import (
	"context"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/dht"
)

// TestClientPeersCarriesConfirmed: after a confirmed ping, the client
// must surface the confirmed timestamp (not a permanent zero).
func TestClientPeersCarriesConfirmed(t *testing.T) {
	a, b, _, c := adminPair(t, "test")

	pa, err := a.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	if err := b.AddPeer(a.PublicKey(), pa.String()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := b.Ping(ctx, dht.Peer{Addr: pa.String(), PublicKey: a.PublicKey()}); err != nil {
		t.Fatalf("confirming ping: %v", err)
	}

	peers, err := c.Peers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	confirmed := 0
	for _, p := range peers {
		if p.Confirmed > 0 {
			confirmed++
		}
	}
	// The regression: the client used to decode only addr+pk, leaving
	// Confirmed permanently 0 even for ping-verified contacts.
	if confirmed == 0 {
		t.Fatalf("no peer carries a confirmed timestamp — the client dropped the field again: %+v", peers)
	}
}
