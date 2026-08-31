package dht

// flood_hardening_test.go pins the v0.9.2 distributed-flood hardening:
//
//   - packetBudget: the GLOBAL pre-verify inbound packet budget bounds the
//     aggregate decode+verify CPU a distributed (or spoofed-source) flood
//     can induce — per-source-IP buckets cannot, every distinct source
//     drawing a fresh bucket.
//   - handle's stray-response filter: a y="r"/"e" message for a txid no
//     in-flight sendQuery owns is dropped BEFORE the Ed25519 verify (one map
//     lookup instead of one signature check).
//   - WalkConcurrency: the outbound walk semaphore caps the work
//     amplification of a distinct-name query flood; a refused walk fails
//     fast with ErrWalkBusy (never queues), and the slot is released when
//     the walk ends.
//   - DHTLookup.CollectClaimsWithWitnesses serves a LOCAL claim under
//     ErrWalkBusy (overload must not hide data this node holds).

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/wire"
)

// startFloodNode starts a node with the given extra NodeConfig mutations —
// the flood tests need knobs the plain startTestNode helper does not expose.
func startFloodNode(t *testing.T, mutate func(*NodeConfig)) *Node {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	cfg := NodeConfig{
		Keypair:    kp,
		ListenAddr: "127.0.0.1:0",
		Store:      NewEnvelopeStore(0, nil),
	}
	if mutate != nil {
		mutate(&cfg)
	}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(); err != nil {
		t.Fatal(err)
	}
	return n
}

// rawClient is a bare UDP socket speaking the §6.3 wire protocol directly,
// so the tests control exactly what the node receives (and can count what
// it answers) without a second full Node in the way.
type rawClient struct {
	t  *testing.T
	kp *crypto.Keypair
	c  *net.UDPConn
}

func newRawClient(t *testing.T) *rawClient {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = uc.Close() })
	return &rawClient{t: t, kp: kp, c: uc}
}

// send writes one signed message to the node.
func (r *rawClient) send(n *Node, m *wire.Message) {
	r.t.Helper()
	data, err := m.Bytes()
	if err != nil {
		r.t.Fatal(err)
	}
	addr, err := n.LocalAddr()
	if err != nil {
		r.t.Fatal(err)
	}
	if _, err := r.c.WriteToUDP(data, addr); err != nil {
		r.t.Fatal(err)
	}
}

// ping builds a signed ping query from the client keypair.
func (r *rawClient) ping(n *Node, txid []byte) *wire.Message {
	r.t.Helper()
	m, err := wire.NewQuery("ping", map[string]any{}, r.kp, n.ID(), txid)
	if err != nil {
		r.t.Fatal(err)
	}
	return m
}

// countReplies reads until the deadline and returns how many datagrams the
// node sent back.
func (r *rawClient) countReplies(d time.Duration) int {
	r.t.Helper()
	_ = r.c.SetReadDeadline(time.Now().Add(d))
	n := 0
	buf := make([]byte, 65535)
	for {
		if _, _, err := r.c.ReadFromUDP(buf); err != nil {
			return n
		}
		n++
	}
}

// ---------------------------------------------------------------------------
// Global packet budget
// ---------------------------------------------------------------------------

// TestPacketBudgetCapsAggregateFlood: with a tiny global budget (rate 1/s,
// burst 2) a flood of VALID signed pings from one source is answered exactly
// burst times — the excess dies in handle() before decode/verify, whatever
// the per-source-IP read buckets would allow (ping is not even read-
// throttled). The rate is 1 token/s so no refill interferes inside the
// read window.
func TestPacketBudgetCapsAggregateFlood(t *testing.T) {
	n := startFloodNode(t, func(c *NodeConfig) {
		c.PacketRateLimit = 1
		c.PacketBurst = 2
	})
	defer n.Close()
	cl := newRawClient(t)

	for i := 0; i < 10; i++ {
		cl.send(n, cl.ping(n, []byte{byte(i)}))
	}
	if got := cl.countReplies(500 * time.Millisecond); got != 2 {
		t.Errorf("node answered %d of 10 flooded pings, want exactly 2 (burst; excess dropped pre-verify)", got)
	}
}

// TestPacketBudgetBoundsDistributedFlood: the budget is GLOBAL — 5 sources ×
// 2 packets each still see only the one shared burst, unlike the per-IP
// buckets (this is the botnet shape the budget exists for).
func TestPacketBudgetBoundsDistributedFlood(t *testing.T) {
	n := startFloodNode(t, func(c *NodeConfig) {
		c.PacketRateLimit = 1
		c.PacketBurst = 3
	})
	defer n.Close()

	clients := make([]*rawClient, 5)
	for i := range clients {
		clients[i] = newRawClient(t)
	}
	// Each client sends 2 pings: 10 packets total against a shared burst of 3.
	total := 0
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i, cl := range clients {
		wg.Add(1)
		go func(i int, cl *rawClient) {
			defer wg.Done()
			cl.send(n, cl.ping(n, []byte{byte(i), 0}))
			cl.send(n, cl.ping(n, []byte{byte(i), 1}))
			got := cl.countReplies(600 * time.Millisecond)
			mu.Lock()
			total += got
			mu.Unlock()
		}(i, cl)
	}
	wg.Wait()
	if total != 3 {
		t.Errorf("node answered %d of 10 distributed pings, want exactly 3 (one GLOBAL burst)", total)
	}
}

// TestPacketBudgetDisabled: PacketRateLimit < 0 turns the budget off — the
// flood gets through (guards the knob's negative-disables contract).
func TestPacketBudgetDisabled(t *testing.T) {
	n := startFloodNode(t, func(c *NodeConfig) {
		c.PacketRateLimit = -1
	})
	defer n.Close()
	cl := newRawClient(t)
	for i := 0; i < 10; i++ {
		cl.send(n, cl.ping(n, []byte{byte(i)}))
	}
	if got := cl.countReplies(2 * time.Second); got != 10 {
		t.Errorf("disabled budget: node answered %d of 10 pings, want 10", got)
	}
}

// TestPacketBudgetRefills: after the burst is spent the bucket refills at
// the configured rate — a following quiet second admits new packets (the
// budget sheds load, it does not brick the node).
func TestPacketBudgetRefills(t *testing.T) {
	n := startFloodNode(t, func(c *NodeConfig) {
		c.PacketRateLimit = 10
		c.PacketBurst = 2
	})
	defer n.Close()
	cl := newRawClient(t)
	for i := 0; i < 4; i++ { // burst 2 spent, 2 dropped
		cl.send(n, cl.ping(n, []byte{byte(i)}))
	}
	if got := cl.countReplies(300 * time.Millisecond); got != 2 {
		t.Fatalf("pre-idle: %d replies, want 2", got)
	}
	time.Sleep(300 * time.Millisecond) // ≥ 3 tokens refill at 10/s
	cl.send(n, cl.ping(n, []byte{0x42}))
	if got := cl.countReplies(1 * time.Second); got != 1 {
		t.Errorf("post-refill: %d replies, want 1 (budget must refill)", got)
	}
}

// ---------------------------------------------------------------------------
// Stray-response pre-verify filter
// ---------------------------------------------------------------------------

// TestHasPendingReportedInFlightTxids pins the filter's predicate directly:
// a registered txid (sendQuery inserts it before its query leaves) is
// pending; anything else is not.
func TestHasPendingReportedInFlightTxids(t *testing.T) {
	n := startFloodNode(t, nil)
	defer n.Close()
	n.mu.Lock()
	n.pending["abc"] = make(chan *wire.Message, 1)
	n.mu.Unlock()
	if !n.hasPending([]byte("abc")) {
		t.Error("hasPending(in-flight txid) = false, want true")
	}
	if n.hasPending([]byte("zzz")) {
		t.Error("hasPending(unknown txid) = true, want false")
	}
}

// TestStrayResponseIgnoredAndNodeHealthy: a WELL-SIGNED response for a txid
// the node never issued is ignored (no reply — responses are never answered
// — and no protocol state disturbed: a real ping right after still works).
func TestStrayResponseIgnoredAndNodeHealthy(t *testing.T) {
	n := startFloodNode(t, nil)
	defer n.Close()
	cl := newRawClient(t)

	stray, err := wire.NewResponse(map[string]any{}, cl.kp, n.ID(), []byte("stray-txid"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ { // a little flood of them
		cl.send(n, stray)
	}
	if got := cl.countReplies(300 * time.Millisecond); got != 0 {
		t.Errorf("node sent %d replies to stray responses, want 0", got)
	}
	cl.send(n, cl.ping(n, []byte{9}))
	if got := cl.countReplies(2 * time.Second); got != 1 {
		t.Errorf("post-stray ping: %d replies, want 1 (node must stay healthy)", got)
	}
}

// ---------------------------------------------------------------------------
// Walk concurrency cap
// ---------------------------------------------------------------------------

// fakePeer is a bare UDP socket posing as one DHT contact: it answers get
// probes with a signed (empty) response, holding the FIRST answer until a
// release signal so a walk stays in flight.
type fakePeer struct {
	t       *testing.T
	kp      *crypto.Keypair
	c       *net.UDPConn
	addr    *net.UDPAddr
	got     chan struct{} // signals each received query
	release chan struct{} // first answer waits for this
	once    sync.Once
}

func newFakePeer(t *testing.T) *fakePeer {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	fp := &fakePeer{
		t:       t,
		kp:      kp,
		c:       uc,
		got:     make(chan struct{}, 16),
		release: make(chan struct{}),
	}
	addr, err := net.ResolveUDPAddr("udp", uc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	fp.addr = addr
	t.Cleanup(func() { _ = uc.Close() })
	go fp.serve()
	return fp
}

func (f *fakePeer) serve() {
	buf := make([]byte, 65535)
	for {
		nread, from, err := f.c.ReadFromUDP(buf)
		if err != nil {
			return // socket closed by cleanup
		}
		m, err := wire.DecodeMessage(buf[:nread])
		if err != nil {
			continue
		}
		// Answer in a goroutine: the held FIRST answer must not stop the
		// read loop from receiving (and signalling) the later queries.
		go func(m *wire.Message, from *net.UDPAddr) {
			f.got <- struct{}{}
			f.once.Do(func() { <-f.release })
			resp, err := wire.NewResponse(map[string]any{}, f.kp, m.ID, m.T)
			if err != nil {
				return
			}
			data, err := resp.Bytes()
			if err != nil {
				return
			}
			_, _ = f.c.WriteToUDP(data, from)
		}(m, from)
	}
}

// waitGot blocks until the peer has received a query (or times out).
func (f *fakePeer) waitGot(t *testing.T) {
	t.Helper()
	select {
	case <-f.got:
	case <-time.After(3 * time.Second):
		t.Fatal("fake peer never received the walk's probe")
	}
}

// startWalkCapped starts a node with capVal WalkConcurrency that knows one
// contact: the fake peer.
func startWalkCapped(t *testing.T, capVal int, fp *fakePeer) *Node {
	t.Helper()
	n := startFloodNode(t, func(c *NodeConfig) {
		c.WalkConcurrency = capVal
	})
	if err := n.AddPeer(fp.kp.Public(), fp.addr.String()); err != nil {
		t.Fatal(err)
	}
	return n
}

func randKey(i byte) []byte {
	k := make([]byte, 32)
	for j := range k {
		k[j] = byte(i) + byte(j)
	}
	return k
}

// TestWalkCapRefusesSecondWalk: with capacity 1 and one walk in flight
// (pinned: the fake peer HAS the probe and is holding it), a second walk
// for a different key fails FAST with ErrWalkBusy instead of queueing.
func TestWalkCapRefusesSecondWalk(t *testing.T) {
	fp := newFakePeer(t)
	n := startWalkCapped(t, 1, fp)
	defer n.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	type res struct {
		env *wire.SignedEnvelope
		err error
	}
	w1 := make(chan res, 1)
	go func() {
		env, err := n.IterativeGet(ctx, randKey(1))
		w1 <- res{env, err}
	}()
	fp.waitGot(t) // walk 1 is provably in flight

	start := time.Now()
	_, err := n.IterativeGet(ctx, randKey(2))
	if !errors.Is(err, ErrWalkBusy) {
		t.Fatalf("second concurrent walk: err = %v, want ErrWalkBusy", err)
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Errorf("refusal took %v, want immediate (never queue)", d)
	}

	close(fp.release) // let walk 1 finish
	select {
	case r := <-w1:
		if r.err != nil || r.env != nil {
			t.Errorf("walk 1: env=%v err=%v, want (nil, nil) clean miss", r.env, r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("walk 1 never finished after release")
	}

	// The slot was released: a fresh walk runs again.
	go func() { _, _ = n.IterativeGet(ctx, randKey(3)) }()
	fp.waitGot(t)
}

// TestWalkCapCollectClaimsRefused: the §7.4 collect walk shares the same
// budget — with the one slot held, CollectClaims returns ErrWalkBusy.
func TestWalkCapCollectClaimsRefused(t *testing.T) {
	fp := newFakePeer(t)
	n := startWalkCapped(t, 1, fp)
	defer n.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	w1 := make(chan error, 1)
	go func() {
		_, err := n.IterativeGet(ctx, randKey(1))
		w1 <- err
	}()
	fp.waitGot(t)

	if _, _, err := n.CollectClaims(ctx, "busyalias"); !errors.Is(err, ErrWalkBusy) {
		t.Fatalf("CollectClaims with the budget spent: err = %v, want ErrWalkBusy", err)
	}
	close(fp.release)
	if err := <-w1; err != nil {
		t.Fatalf("walk 1: %v", err)
	}
}

// TestWalkCapDisabled: WalkConcurrency < 0 means uncapped — two walks run
// concurrently, neither is refused.
func TestWalkCapDisabled(t *testing.T) {
	fp := newFakePeer(t)
	n := startWalkCapped(t, -1, fp)
	defer n.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var busy atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, err := n.IterativeGetDetailed(ctx, randKey(byte(i)))
			if errors.Is(err, ErrWalkBusy) {
				busy.Add(1)
			}
		}(i)
	}
	// All three probes must arrive while... (capacity: all 3 walks run at
	// once — three got-signals before any release).
	for i := 0; i < 3; i++ {
		fp.waitGot(t)
	}
	close(fp.release)
	wg.Wait()
	if busy.Load() != 0 {
		t.Errorf("%d walks refused under a disabled cap, want 0", busy.Load())
	}
}

// TestCollectClaimsServesLocalUnderWalkBusy: DHTLookup.CollectClaimsWith-
// Witnesses treats ErrWalkBusy like ErrDegradedMiss — a LOCAL K_claim
// envelope still serves; only an empty-everywhere overload propagates the
// refusal (the resolver then SERVFAILs instead of NXDOMAINing).
func TestCollectClaimsServesLocalUnderWalkBusy(t *testing.T) {
	fp := newFakePeer(t)
	n := startWalkCapped(t, 1, fp) // table non-empty: the walk gate is reached
	defer n.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Hold the one walk slot.
	w1 := make(chan error, 1)
	go func() {
		_, err := n.IterativeGet(ctx, randKey(1))
		w1 <- err
	}()
	fp.waitGot(t)
	defer func() {
		close(fp.release)
		if err := <-w1; err != nil {
			t.Fatalf("walk 1: %v", err)
		}
	}()

	env, k := contestedClaimEnv(t, "localbusy", uint64(time.Now().Unix()))
	if _, err := n.store.Put(k, env, n.now(), true); err != nil {
		t.Fatal(err)
	}
	l := NewDHTLookup(n.store, n)

	envs, _, err := l.CollectClaimsWithWitnesses(ctx, "localbusy", n.now())
	if err != nil {
		t.Fatalf("local claim under ErrWalkBusy: err = %v, want nil (local view serves)", err)
	}
	if len(envs) != 1 {
		t.Fatalf("collected %d envelopes under ErrWalkBusy, want the 1 local claim", len(envs))
	}

	// With NOTHING local, the same overload propagates ErrWalkBusy.
	if _, _, err := l.CollectClaimsWithWitnesses(ctx, "nothinglocal", n.now()); !errors.Is(err, ErrWalkBusy) {
		t.Fatalf("empty overload: err = %v, want ErrWalkBusy", err)
	}
}
