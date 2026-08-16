// transport_bench_test.go: benchmarks isolating the §6.3 UDP RPC transport so
// `go test -cpuprofile` attributes cycles per hop — the signed ping
// round-trip (one RPC) and the cold iterative GET (one full walk). All
// sockets are loopback 127.0.0.1:0 with background loops disabled.
package dht

import (
	"context"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/wire"
)

// startBenchNode is startTestNode for *testing.B, with the §12 get-rate
// bucket disabled (GetRateLimit < 0): the tight refetch loops below far
// exceed the default 50/s per-source limit, and a throttled 301 answer maps
// to a clean miss on the client side, which would fail the benchmarks.
func startBenchNode(b *testing.B) (*Node, *crypto.Keypair) {
	b.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		b.Fatalf("gen keypair: %v", err)
	}
	n, err := NewNode(NodeConfig{
		Keypair:      kp,
		ListenAddr:   "127.0.0.1:0",
		Store:        NewEnvelopeStore(0, nil),
		GetRateLimit: -1,
	})
	if err != nil {
		b.Fatalf("NewNode: %v", err)
	}
	if err := n.Start(); err != nil {
		b.Fatalf("Start: %v", err)
	}
	b.Cleanup(func() { _ = n.Close() })
	return n, kp
}

// benchSeedRecord is makeTLDRecord for *testing.B (a signed TLD envelope).
func benchSeedRecord(b *testing.B, kp *crypto.Keypair, alias string) (*wire.SignedEnvelope, []byte) {
	b.Helper()
	tid, err := crypto.TldID(kp.Public())
	if err != nil {
		b.Fatal(err)
	}
	wn, err := naming.EncodeWireName(nil, alias, tid)
	if err != nil {
		b.Fatal(err)
	}
	now := time.Now().Unix()
	rec, err := wire.NewRecord(wn, kp.Public(), 1, uint64(now), uint64(now+3600))
	if err != nil {
		b.Fatal(err)
	}
	rr, err := wire.A([]byte{203, 0, 113, 99}, 300)
	if err != nil {
		b.Fatal(err)
	}
	rec.RRset = []*wire.RR{rr}
	env, err := wire.SignRecord(rec, kp)
	if err != nil {
		b.Fatal(err)
	}
	key, err := KeyForWireName(wn)
	if err != nil {
		b.Fatal(err)
	}
	return env, key
}

// BenchmarkPingRoundTrip: one signed UDP RPC each direction — CBOR
// encode/decode, ed25519 sign+verify, routing-table touch.
func BenchmarkPingRoundTrip(b *testing.B) {
	a, _ := startBenchNode(b)
	tgt, _ := startBenchNode(b)
	tgtAddr, err := tgt.LocalAddr()
	if err != nil {
		b.Fatal(err)
	}
	if err := a.AddPeer(tgt.PublicKey(), tgtAddr.String()); err != nil {
		b.Fatal(err)
	}
	peer := Peer{Addr: tgtAddr.String(), PublicKey: tgt.PublicKey()}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := a.Ping(ctx, peer); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkIterativeGetCold: one full iterative walk — B holds nothing, so
// each iteration removes its cached copy and re-fetches from A over UDP.
func BenchmarkIterativeGetCold(b *testing.B) {
	a, akp := startBenchNode(b)
	env, key := benchSeedRecord(b, akp, "benchseed")
	now := time.Now().Unix()
	if _, err := a.store.Put(key, env, now, true); err != nil {
		b.Fatal(err)
	}
	q, _ := startBenchNode(b)
	aAddr, err := a.LocalAddr()
	if err != nil {
		b.Fatal(err)
	}
	if err := q.AddPeer(a.PublicKey(), aAddr.String()); err != nil {
		b.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		q.store.Remove(key) // force the network walk
		got, err := q.IterativeGet(ctx, key)
		if err != nil || got == nil {
			b.Fatalf("IterativeGet: env=%v err=%v", got, err)
		}
	}
}
