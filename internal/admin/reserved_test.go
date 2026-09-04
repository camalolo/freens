package admin

// reserved_test.go — the §7.6 reserved-alias gate on the admin face
// (claimTLDID): without this daemon's -allow-reserved override (mirrored via
// SetAllowReserved), /resolve treats a reserved-TLD alias as claim-less —
// "a node running without -allow-reserved never accepts a freens .com" holds
// for the CLI verbs that ride the admin socket, not just the DNS face.

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/dht"
)

func TestResolveReservedAliasGate(t *testing.T) {
	a := startDHTNode(t)
	b := startDHTNode(t)
	connectPeers(t, a, b)
	lookup := dht.NewDHTLookup(dht.NewEnvelopeStore(0, nil), a)
	srv := New(a, lookup, "v-res7", slog.Default())
	sock := startAdmin(t, srv)
	c := &Client{Sock: sock, Timeout: 10 * time.Second}

	owner, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	// A fully valid claim-carrying TLD record for "com" — exactly what a
	// rogue-witnessed claim would look like once published.
	tldEnv, _, _ := makeClaimTLDRecord(t, owner, "com")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if accepted, err := c.Publish(ctx, tldEnv); err != nil || accepted != 2 {
		t.Fatalf("Publish(com): accepted=%d err=%v, want 2", accepted, err)
	}

	// Default policy: the claim exists in the store, but /resolve refuses to
	// accept it — Found=false, the established no-claim answer.
	res, err := c.Resolve(ctx, "com")
	if err != nil {
		t.Fatalf("Resolve(com): %v", err)
	}
	if res.Found {
		t.Fatal("Resolve(com).Found = true under the default policy — the §7.6 gate failed")
	}

	// The override accepts the same record.
	srv.SetAllowReserved(true)
	res, err = c.Resolve(ctx, "com")
	if err != nil {
		t.Fatalf("Resolve(com) after override: %v", err)
	}
	if !res.Found {
		t.Fatal("Resolve(com).Found = false with SetAllowReserved — the override must accept")
	}
}
