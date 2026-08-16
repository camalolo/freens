// helpers_test.go — shared test plumbing for the cli package tests:
// stdout capture, deterministic keypairs, envelope writers, and the
// in-process witness network (moved from cmd/freens-cli's tests).
package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/dht"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/wire"
)

// tempHome points FREENS_HOME at a fresh temp dir (every test that touches
// home/keychain/admin state MUST run against one — never the real home).
func tempHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("FREENS_HOME", dir)
	return dir
}

// lifecycleKeypair returns a deterministic keypair from a single-byte seed.
func lifecycleKeypair(t *testing.T, seed byte) *crypto.Keypair {
	t.Helper()
	kp, err := crypto.FromSeed(bytes.Repeat([]byte{seed}, constants.Ed25519PrivateKeyLen))
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

// captureStdout runs fn with os.Stdout redirected to a pipe and returns what
// it printed (keeps the CLI subcommand tests' output clean).
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	saved := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	fnErr := fn()
	w.Close()
	os.Stdout = saved
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatal(err)
	}
	return buf.String(), fnErr
}

// writeEnvelope signs rec with kp, writes the canonical .cbor to dir, and
// returns the envelope plus its path (the make-record/publish file format).
func writeEnvelope(t *testing.T, dir string, name string, rec *wire.Record, kp *crypto.Keypair) (*wire.SignedEnvelope, string) {
	t.Helper()
	env, err := wire.SignRecord(rec, kp)
	if err != nil {
		t.Fatal(err)
	}
	b, err := env.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name+".cbor")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return env, path
}

// newSubNameRecord builds a §4.1 record for labels under the "foo" alias of
// tldOwner with an A RR, in the fresh validity window around now.
func newSubNameRecord(t *testing.T, labels []string, owner *crypto.Keypair, tldID []byte, seq uint64, now int64) *wire.Record {
	t.Helper()
	wireName, err := naming.EncodeWireName(labels, "foo", tldID)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := wire.NewRecord(wireName, owner.Public(), seq, uint64(now), uint64(now+constants.RecordDefaultTTL))
	if err != nil {
		t.Fatal(err)
	}
	aRR, err := wire.A([]byte{203, 0, 113, 42}, 300)
	if err != nil {
		t.Fatal(err)
	}
	rec.RRset = []*wire.RR{aRR}
	return rec
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
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

func mustWireName(t *testing.T, alias string, tldID []byte) []byte {
	t.Helper()
	wn, err := naming.EncodeWireName(nil, alias, tldID)
	if err != nil {
		t.Fatal(err)
	}
	return wn
}

// mustTestEnvelope signs a minimal record over wireName at the given
// sequence (no RRset — sequence discovery only reads Record.Sequence).
func mustTestEnvelope(t *testing.T, kp *crypto.Keypair, wireName []byte, seq uint64) *wire.SignedEnvelope {
	t.Helper()
	now := uint64(2_000_000)
	rec, err := wire.NewRecord(wireName, kp.Public(), seq, now, now+3600)
	if err != nil {
		t.Fatal(err)
	}
	env, err := wire.SignRecord(rec, kp)
	if err != nil {
		t.Fatal(err)
	}
	return env
}
