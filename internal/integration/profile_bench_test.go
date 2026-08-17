// Package integration — profile_bench_test.go: benchmarks backing the
// profiling workflow. They drive the daemon's real per-query hot paths
// end-to-end so `go test -cpuprofile` attributes cycles to production code:
//
//	go test -run '^$' -bench . -benchtime 2s \
//	    -cpuprofile cpu.out -memprofile mem.out ./internal/integration
//
// Paths covered (heaviest first):
//
//   - BenchmarkServeDNSNetworkCold     full §9.2+§7.4 resolve where every
//     envelope is fetched over UDP from a peer
//   - BenchmarkServeDNSColdInMemory    authoritative local resolve with the
//     ResponseCache disabled (full claim
//     quorum verification per query)
//   - BenchmarkServeDNSResponseCacheHit steady-state cached answer
//   - BenchmarkEnvelopeDecodeVerify    inbound DHT envelope path (CBOR decode
//   - ed25519 verify + basic validity)
//   - BenchmarkStorePutGet             envelope-store hot operations
//
// All nodes bind 127.0.0.1:0 (loopback, ephemeral), background loops are
// disabled, and log output is discarded — no LAN contact, per AGENTS.md.
package integration

import (
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/claims"
	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/dht"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/resolver"
	"github.com/camalolo/freens/internal/wire"
	"github.com/miekg/dns"
)

// ---------------------------------------------------------------------------
// Bench-local node/world helpers (the *testing.T variants in
// claim_resolution_test.go take a concrete T, so they are re-derived here).
// ---------------------------------------------------------------------------

// benchNode is a loopback DHT node with a fixed clock and background loops
// disabled, for benchmarks.
type benchNode struct {
	node  *dht.Node
	store *dht.EnvelopeStore
	kp    *crypto.Keypair
}

// newBenchNode is the shared constructor: nowFn drives the node and store
// clocks; getRate < 0 disables the §12 get token bucket (a tight
// remove-and-refetch loop would otherwise exhaust the burst and the walk
// would read as a miss — the bucket refills on wall-clock time).
func newBenchNode(b testing.TB, nowFn func() int64, getRate float64) *benchNode {
	b.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		b.Fatal(err)
	}
	store := dht.NewEnvelopeStore(0, nowFn)
	node, err := dht.NewNode(dht.NodeConfig{
		Keypair:               kp,
		ListenAddr:            "127.0.0.1:0",
		Store:                 store,
		Logger:                slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:                   nowFn,
		BucketRefreshInterval: -1,
		RepublishInterval:     -1,
		GetRateLimit:          getRate,
	})
	if err != nil {
		b.Fatalf("NewNode: %v", err)
	}
	if err := node.Start(); err != nil {
		b.Fatalf("Start: %v", err)
	}
	b.Cleanup(func() { _ = node.Close() })
	return &benchNode{node: node, store: store, kp: kp}
}

// startBenchNode: fixed clock (deterministic, for the in-memory benches).
func startBenchNode(b testing.TB, now int64) *benchNode {
	return newBenchNode(b, func() int64 { return now }, 0)
}

// startBenchNetNode: wall clock, §12 get-rate limiting disabled (for the
// network benches — see newBenchNode).
func startBenchNetNode(b testing.TB) *benchNode {
	return newBenchNode(b, nil, -1)
}

// peerBenchNodes cross-seeds two nodes' routing tables, both directions.
func peerBenchNodes(b testing.TB, a, c *benchNode) {
	b.Helper()
	aAddr, err := a.node.LocalAddr()
	if err != nil {
		b.Fatal(err)
	}
	cAddr, err := c.node.LocalAddr()
	if err != nil {
		b.Fatal(err)
	}
	if err := a.node.AddPeer(c.node.PublicKey(), cAddr.String()); err != nil {
		b.Fatal(err)
	}
	if err := c.node.AddPeer(a.node.PublicKey(), aAddr.String()); err != nil {
		b.Fatal(err)
	}
}

// benchWorld is a fully-registered alias: TLD envelope (claim embedded) at
// K_tld and K_claim, plus a www A record at K_name, stored LOCALLY on the
// publishing node (the -load pattern), exactly like publishClaimWorld.
type benchWorld struct {
	tldEnv *wire.SignedEnvelope
	wwwEnv *wire.SignedEnvelope
	kClaim []byte
	kTld   []byte
	kName  []byte
}

func publishBenchWorld(b testing.TB, n *benchNode, alias string, now int64) *benchWorld {
	b.Helper()
	claimant, err := crypto.Generate()
	if err != nil {
		b.Fatal(err)
	}
	tldID, err := crypto.TldID(claimant.Public())
	if err != nil {
		b.Fatal(err)
	}
	claim, err := claims.MineAliasClaim(alias, claimant, uint64(now), 8, 2_000_000, 16)
	if err != nil {
		b.Fatalf("MineAliasClaim: %v", err)
	}
	witnessKPs := []*crypto.Keypair{n.kp}
	for len(witnessKPs) < constants.W {
		wkp, err := crypto.Generate()
		if err != nil {
			b.Fatal(err)
		}
		witnessKPs = append(witnessKPs, wkp)
	}
	ph, err := claim.PrefixHash()
	if err != nil {
		b.Fatal(err)
	}
	atts := make([]*claims.WitnessAttestation, 0, len(witnessKPs))
	for i, wkp := range witnessKPs {
		w, err := claims.NewWitnessAttestation(wkp, uint64(now)+uint64(i), ph)
		if err != nil {
			b.Fatalf("NewWitnessAttestation: %v", err)
		}
		atts = append(atts, w)
	}
	claim.Witnesses = atts

	tldWire, err := naming.EncodeWireName(nil, alias, tldID)
	if err != nil {
		b.Fatal(err)
	}
	tldRec, err := wire.NewRecord(tldWire, claimant.Public(), 1, uint64(now), uint64(now+constants.RecordDefaultTTL))
	if err != nil {
		b.Fatal(err)
	}
	cb, err := claim.CanonicalBytes()
	if err != nil {
		b.Fatal(err)
	}
	tldRec.Claim = cb
	tldEnv, err := wire.SignRecord(tldRec, claimant)
	if err != nil {
		b.Fatal(err)
	}

	wwwWire, err := naming.EncodeWireName([]string{"www"}, alias, tldID)
	if err != nil {
		b.Fatal(err)
	}
	wwwRec, err := wire.NewRecord(wwwWire, claimant.Public(), 1, uint64(now), uint64(now+constants.RecordDefaultTTL))
	if err != nil {
		b.Fatal(err)
	}
	rr, err := wire.A([]byte{203, 0, 113, 77}, 300)
	if err != nil {
		b.Fatal(err)
	}
	wwwRec.RRset = []*wire.RR{rr}
	wwwEnv, err := wire.SignRecord(wwwRec, claimant)
	if err != nil {
		b.Fatal(err)
	}

	kTld, err := dht.KeyForWireName(tldWire)
	if err != nil {
		b.Fatal(err)
	}
	kName, err := dht.KeyForWireName(wwwWire)
	if err != nil {
		b.Fatal(err)
	}
	kClaim, err := dht.KeyForClaim(alias)
	if err != nil {
		b.Fatal(err)
	}
	for _, kv := range []struct {
		k   []byte
		env *wire.SignedEnvelope
	}{{kTld, tldEnv}, {kClaim, tldEnv}, {kName, wwwEnv}} {
		if _, err := n.store.Put(kv.k, kv.env, now, true); err != nil {
			b.Fatalf("seed store: %v", err)
		}
	}
	return &benchWorld{tldEnv: tldEnv, wwwEnv: wwwEnv, kClaim: kClaim, kTld: kTld, kName: kName}
}

// benchConfig routes <alias> into freens with no alias pins (the network
// claim layer carries the alias), mirroring the resolver-test claimConfig.
func benchConfig(alias string) *resolver.Config {
	cfg, err := resolver.ParseConfig("[tld-routes]\n* = dns-first\n")
	if err != nil {
		panic(err)
	}
	cfg.TLDRoutes[alias] = resolver.RouteFREENS
	return cfg
}

// packingWriter is a dns.ResponseWriter whose WriteMsg PACKS the reply into a
// scratch buffer — unlike captureWriter it includes the full server-side wire
// encoding (the daemon's actual per-reply cost) without socket I/O.
type packingWriter struct {
	buf   []byte
	packs int
}

func (w *packingWriter) WriteMsg(m *dns.Msg) error {
	buf, err := m.Pack()
	if err != nil {
		return err
	}
	w.buf = append(w.buf[:0], buf...)
	w.packs++
	return nil
}
func (w *packingWriter) LocalAddr() net.Addr       { return nil }
func (w *packingWriter) RemoteAddr() net.Addr      { return nil }
func (w *packingWriter) Write([]byte) (int, error) { return 0, nil }
func (w *packingWriter) Close() error              { return nil }
func (w *packingWriter) TsigStatus() error         { return nil }
func (w *packingWriter) TsigTimersOnly(bool)       {}
func (w *packingWriter) TsigGenerate([]byte, bool) {}
func (w *packingWriter) Hijack()                   {}

// withBenchPoW lowers the mining difficulty so setup stays fast (restored on
// return), matching withFastPoW in the test files.
func withBenchPoW(b testing.TB) {
	saved := claims.PoWDifficultyInit.Load()
	claims.PoWDifficultyInit.Store(8)
	b.Cleanup(func() { claims.PoWDifficultyInit.Store(saved) })
}

// assertBenchReply unpacks the writer's last packed reply and fails the
// benchmark unless it is a NOERROR answer carrying exactly one A record —
// guards against silently benchmarking a REFUSED/NXDOMAIN fast path.
func assertBenchReply(b testing.TB, w *packingWriter) {
	b.Helper()
	m := new(dns.Msg)
	if err := m.Unpack(w.buf); err != nil {
		b.Fatalf("unpack reply: %v", err)
	}
	if m.Rcode != dns.RcodeSuccess {
		b.Fatalf("reply rcode = %d (%s), want NOERROR", m.Rcode, dns.RcodeToString[m.Rcode])
	}
	if len(m.Answer) != 1 {
		b.Fatalf("reply has %d answers, want 1: %v", len(m.Answer), m.Answer)
	}
	if _, ok := m.Answer[0].(*dns.A); !ok {
		b.Fatalf("first answer is %T, want *dns.A", m.Answer[0])
	}
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

// BenchmarkServeDNSColdInMemory: the authoritative path — records live in the
// node's own store, no ResponseCache, so EVERY query re-runs the full §7.4
// claim verification (PoW + witness quorum) and signature checks.
func BenchmarkServeDNSColdInMemory(b *testing.B) {
	withBenchPoW(b)
	const now int64 = 2_000_000
	pub := startBenchNode(b, now)
	publishBenchWorld(b, pub, "bench", now)

	// The daemon's own adapter: DHTLookup over the node's own store (all
	// records local ⇒ no network; claim set readable from K_claim).
	r := resolver.New(benchConfig("bench"), dht.NewDHTLookup(pub.store, pub.node), nil)
	r.Now = func() int64 { return now }

	q := new(dns.Msg).SetQuestion("www.bench.", dns.TypeA)
	pw := &packingWriter{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.ServeDNS(pw, q)
	}
	b.StopTimer()
	assertBenchReply(b, pw)
}

// BenchmarkServeDNSResponseCacheHit: the steady state — the §10.4 response
// cache answers before any namespace work runs.
func BenchmarkServeDNSResponseCacheHit(b *testing.B) {
	withBenchPoW(b)
	const now int64 = 2_000_000
	pub := startBenchNode(b, now)
	publishBenchWorld(b, pub, "bench", now)

	r := resolver.New(benchConfig("bench"), dht.NewDHTLookup(pub.store, pub.node), nil)
	r.Now = func() int64 { return now }
	r.Cache = resolver.NewResponseCache(1024, func() int64 { return now })
	q := new(dns.Msg).SetQuestion("www.bench.", dns.TypeA)
	pw := &packingWriter{}
	// Warm the cache (one full resolve).
	r.ServeDNS(pw, q)
	if pw.packs == 0 {
		b.Fatal("warm-up query produced no reply")
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.ServeDNS(pw, q)
	}
	b.StopTimer()
	assertBenchReply(b, pw)
}

// BenchmarkServeDNSNetworkCold: the §9.2 step-3a path — node B holds NOTHING
// locally; each query collects the claim set and fetches K_tld/K_name over
// UDP from peer A (B's cached copies are dropped per iteration to force the
// network walk, the first-resolve experience of a fresh node). Wall clock +
// §12 get-limit off so the tight refetch loop is not throttled (see
// newBenchNode).
func BenchmarkServeDNSNetworkCold(b *testing.B) {
	withBenchPoW(b)
	a := startBenchNetNode(b)
	now := time.Now().Unix()
	w := publishBenchWorld(b, a, "bench", now)
	qn := startBenchNetNode(b)
	peerBenchNodes(b, a, qn)

	r := resolver.New(benchConfig("bench"), dht.NewDHTLookup(qn.store, qn.node), nil)

	q := new(dns.Msg).SetQuestion("www.bench.", dns.TypeA)
	pw := &packingWriter{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Drop B's cached copies so the query must walk to A again.
		qn.store.Remove(w.kClaim)
		qn.store.Remove(w.kTld)
		qn.store.Remove(w.kName)
		r.ServeDNS(pw, q)
	}
	b.StopTimer()
	assertBenchReply(b, pw)
}

// BenchmarkEnvelopeDecodeVerify: the inbound-DHT path per envelope — CBOR
// decode, signature verify, basic validity (the work a peer does for every
// record it receives).
func BenchmarkEnvelopeDecodeVerify(b *testing.B) {
	withBenchPoW(b)
	const now int64 = 2_000_000
	pub := startBenchNode(b, now)
	w := publishBenchWorld(b, pub, "bench", now)
	data, err := w.tldEnv.Bytes()
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		env, err := wire.DecodeEnvelope(data)
		if err != nil {
			b.Fatal(err)
		}
		if !env.VerifySignature() {
			b.Fatal("VerifySignature: want true")
		}
		if !wire.IsBasicValid(env, uint64(now)) {
			b.Fatal("IsBasicValid: want true")
		}
	}
}

// BenchmarkStorePutGet: envelope-store operations at the per-RPC hot end —
// Put re-verifies the signature (the defensive inbound path) and Get is the
// lookup-path read.
func BenchmarkStorePutGet(b *testing.B) {
	withBenchPoW(b)
	const now int64 = 2_000_000
	pub := startBenchNode(b, now)
	w := publishBenchWorld(b, pub, "bench", now)
	store := dht.NewEnvelopeStore(0, func() int64 { return now })

	b.Run("Get", func(b *testing.B) {
		if _, err := store.Put(w.kName, w.wwwEnv, now, true); err != nil {
			b.Fatal(err)
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := store.Get(w.kName, now); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("PutVerified", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := store.Put(w.kName, w.wwwEnv, now, true); err != nil {
				b.Fatal(err)
			}
		}
	})
}
