package cli

// renew_standalone_test.go — the phantom-sequence regression (found live
// 2026-09-04): a standalone `renew -force -peers <stale-peer>` used to base
// its new sequence on the bootstrap peer's possibly-lapsed STORE copy — the
// store-hit get omits {nodes}, so the one-shot node never learned the true
// closest-set — and minted a globally-losing sequence (§6.4 max-sequence).
// The fix warms the table with IterativeFindNode (find_node always carries
// {nodes}) toward BOTH keys before the discovery get, so EnvelopeWins picks
// the max-sequence copy the network actually holds.

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/dht"
	"github.com/camalolo/freens/internal/keychain"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/wire"
)

// cliNode starts one bare dht node with its own store (no background
// chatter) and returns it, the store (for direct seeding — Node.store is
// unexported), and its addr#pk peer line.
func cliNode(t *testing.T) (*dht.Node, *dht.EnvelopeStore, string) {
	t.Helper()
	store := dht.NewEnvelopeStore(0, nil)
	node, err := dht.NewNode(dht.NodeConfig{
		Keypair:               mustTestKeypair(t),
		ListenAddr:            "127.0.0.1:0",
		Store:                 store,
		BucketRefreshInterval: -1,
		RepublishInterval:     -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := node.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = node.Close() })
	la, err := node.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	return node, store, la.String() + "#" + hexPK(node.PublicKey())
}

func connectCliNodes(t *testing.T, a, b *dht.Node) {
	t.Helper()
	bAddr, err := b.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.AddPeer(b.PublicKey(), bAddr.String()); err != nil {
		t.Fatal(err)
	}
	aAddr, err := a.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	if err := b.AddPeer(a.PublicKey(), aAddr.String()); err != nil {
		t.Fatal(err)
	}
}

func TestRenewStandaloneIgnoresStaleBootstrapCopy(t *testing.T) {
	if testing.Short() {
		t.Skip("starts real dht nodes")
	}
	tempHome(t)

	// The network: a live storer the bootstrap peer knows about.
	stale, staleStore, _ := cliNode(t)
	live, liveStore, _ := cliNode(t)
	defer stale.Close()
	defer live.Close()
	connectCliNodes(t, stale, live)

	owner, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	const alias = "renewstand"
	tid, err := crypto.TldID(owner.Public())
	if err != nil {
		t.Fatal(err)
	}
	wn, err := naming.EncodeWireName(nil, alias, tid)
	if err != nil {
		t.Fatal(err)
	}
	kTld, err := dht.KeyForWireName(wn)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	mkEnv := func(seq int, created, expires int64) *wire.SignedEnvelope {
		t.Helper()
		rec, err := wire.NewRecord(wn, owner.Public(), uint64(seq), uint64(created), uint64(expires))
		if err != nil {
			t.Fatal(err)
		}
		env, err := wire.SignRecord(rec, owner)
		if err != nil {
			t.Fatal(err)
		}
		return env
	}
	liveEnv := mkEnv(5, now-100, now+3600)
	lapsedEnv := mkEnv(1, now-7200, now-3600) // lapsed, inside the §6.4 ExpiryGrace day
	if accepted, err := liveStore.Put(kTld, liveEnv, now, true); err != nil || !accepted {
		t.Fatalf("seed live store: accepted=%v err=%v", accepted, err)
	}
	if accepted, err := staleStore.Put(kTld, lapsedEnv, now, true); err != nil || !accepted {
		t.Fatalf("seed stale store: accepted=%v err=%v", accepted, err)
	}

	// Owner key in the keychain so renew can sign.
	if err := keychain.Save(ownerKeyPath(alias), owner, ""); err != nil {
		t.Fatalf("save owner key: %v", err)
	}

	// Bootstrap ONLY from the stale peer (the phantom-21 shape).
	staleAddr, err := stale.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	peers := staleAddr.String() + "#" + hex.EncodeToString(stale.PublicKey())
	if err := cmdRenew([]string{"-force", "-peers", peers, alias}); err != nil {
		t.Fatalf("renew: %v", err)
	}

	// The renewed sequence must base on the LIVE copy (5 → 6), never on the
	// lapsed bootstrap copy (1 → 2, a global loser).
	got, _ := liveStore.Get(kTld, time.Now().Unix())
	if got == nil {
		t.Fatal("renewed envelope never landed on the live storer")
	}
	if got.Record.Sequence != 6 {
		t.Fatalf("renewed sequence = %d, want 6 (base must be the network's max-sequence copy, not the stale bootstrap copy)", got.Record.Sequence)
	}
}
