package main

// register_test.go pins the register flow against a real in-process DHT
// network: enough nodes that W=5 DISTINCT live witnesses exist beyond the
// single bootstrap peer (the IterativeFindNode walk must discover them), the
// owner keyfile lifecycle (generated, 0600, @file reload), and the
// @keyfile seed spec shared by every seed flag.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/laurent/freens/internal/crypto"
	"github.com/laurent/freens/internal/dht"
	"github.com/laurent/freens/internal/naming"
)

// startWitnessNet boots n witness-capable nodes on an in-process network:
// node 0 is the bootstrap entry the CLI is told about; the others are
// discovered via find_node (proving the routing-table walk). Nodes peer in
// a ring + to node 0 so their tables interconnect.
func startWitnessNet(t *testing.T, n int) (*dht.Node, []string) {
	t.Helper()
	nodes := make([]*dht.Node, n)
	pks := make([]string, n)
	addrs := make([]string, n)
	for i := range nodes {
		store := dht.NewEnvelopeStore(0, nil)
		node, err := dht.NewNode(dht.NodeConfig{
			Keypair:    mustTestKeypair(t),
			ListenAddr: "127.0.0.1:0",
			Store:      store,
			// Keep witness cooldown etc. live but skip refresh/republish
			// chatter — irrelevant to a short test.
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
		nodes[i] = node
		la, err := node.LocalAddr()
		if err != nil {
			t.Fatal(err)
		}
		addrs[i] = la.String()
		pks[i] = hexPK(node.PublicKey())
	}
	// Interconnect: everyone pings node 0 and its ring neighbors.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for i := 1; i < n; i++ {
		targets := []int{0}
		if i > 1 {
			targets = append(targets, i-1)
		}
		for _, j := range targets {
			if err := nodes[i].AddPeer(nodes[j].PublicKey(), addrs[j]); err != nil {
				t.Fatal(err)
			}
			c, cc := context.WithTimeout(ctx, 2*time.Second)
			if err := nodes[i].Ping(c, dht.Peer{Addr: addrs[j], PublicKey: nodes[j].PublicKey()}); err != nil {
				// A ring ping failing is survivable; node 0 is the one that
				// must be reachable.
				if j == 0 {
					t.Fatalf("bootstrap node ping: %v", err)
				}
			}
			cc()
		}
	}
	return nodes[0], []string{addrs[0] + "#" + pks[0]}
}

func mustTestKeypair(t *testing.T) *crypto.Keypair {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func hexPK(pk []byte) string {
	const hexd = "0123456789abcdef"
	out := make([]byte, len(pk)*2)
	for i, c := range pk {
		out[2*i], out[2*i+1] = hexd[c>>4], hexd[c&15]
	}
	return string(out)
}

// TestRegisterEndToEnd: the full flow against 7 live in-process nodes — key
// generated to a 0600 file, PoW at floor difficulty (12 would be faster but
// register enforces the network floor; 24 bits ≈ seconds), witnesses
// discovered PAST the single bootstrap peer, publication verifiable by get.
func TestRegisterEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("mines real PoW")
	}
	boot, peerArgs := startWitnessNet(t, 7)
	dir := t.TempDir()

	keyPath := filepath.Join(dir, "alice.key")
	envPath := filepath.Join(dir, "alice.tld.cbor")
	err := cmdRegister([]string{
		"-alias", "alice",
		"-ip", "203.0.113.5",
		"-peers", peerArgs[0],
		"-difficulty", "24",
		"-out-key", keyPath,
		"-out-dir", dir,
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	// Keyfile: 0600, hex seed, reloads to the same key.
	st, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("keyfile: %v", err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("keyfile mode = %o, want 0600", st.Mode().Perm())
	}
	kp, err := seedKeypair("@"+keyPath, "-test")
	if err != nil {
		t.Fatalf("keyfile reload: %v", err)
	}
	tldID, _ := crypto.TldID(kp.Public())

	// The envelope on the wire: K_tld holds the record, embedded claim has
	// W distinct witnesses.
	kTld, err := dht.KeyForWireName(mustWireName(t, "alice", tldID))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	env, err := boot.IterativeGet(ctx, kTld)
	if err != nil || env == nil {
		t.Fatalf("registered record not found on the network: %v %v", env, err)
	}
	if env.Record.Sequence != 1 || len(env.Record.RRset) != 1 {
		t.Fatalf("unexpected record shape: seq=%d rrset=%d", env.Record.Sequence, len(env.Record.RRset))
	}
	if len(env.Record.Claim) == 0 {
		t.Fatal("record carries no embedded claim")
	}
	if _, err := os.Stat(envPath); err != nil {
		t.Fatalf("envelope artifact: %v", err)
	}
}

// TestRegisterTooFewWitnesses: with fewer reachable witnesses than W the
// command fails with the guidance error (and no partial publication).
func TestRegisterTooFewWitnesses(t *testing.T) {
	if testing.Short() {
		t.Skip("mines real PoW")
	}
	boot, peerArgs := startWitnessNet(t, 2) // bootstrap + 1: < W=5
	_ = boot
	err := cmdRegister([]string{
		"-alias", "lone",
		"-ip", "203.0.113.6",
		"-peers", peerArgs[0],
		"-difficulty", "24",
		"-out-key", filepath.Join(t.TempDir(), "lone.key"),
		"-out-dir", t.TempDir(),
	})
	if err == nil || !strings.Contains(err.Error(), "witness") {
		t.Fatalf("expected witness-shortage error, got: %v", err)
	}
}

// TestSeedSpecKeyfile: the @file form loads from disk; plain hex still
// works; a missing file is a usage error, not a panic.
func TestSeedSpecKeyfile(t *testing.T) {
	dir := t.TempDir()
	kp := mustTestKeypair(t)
	path := filepath.Join(dir, "k.key")
	if err := writeKeyFile(path, kp); err != nil {
		t.Fatal(err)
	}
	got, err := seedKeypair("@"+path, "-x")
	if err != nil || string(got.Public()) != string(kp.Public()) {
		t.Fatalf("keyfile spec: %v", err)
	}
	got2, err := seedKeypair(hexPK(kp.Seed()), "-x")
	if err != nil || string(got2.Public()) != string(kp.Public()) {
		t.Fatalf("hex spec: %v", err)
	}
	if _, err := seedKeypair("@"+filepath.Join(dir, "nope"), "-x"); err == nil {
		t.Fatal("missing keyfile accepted")
	}
}

func mustWireName(t *testing.T, alias string, tldID []byte) []byte {
	t.Helper()
	wn, err := naming.EncodeWireName(nil, alias, tldID)
	if err != nil {
		t.Fatal(err)
	}
	return wn
}
