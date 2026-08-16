package dht

// throttle_test.go exercises the per-source-IP read throttle (§12 line 914:
// "Implementations MAY throttle passive clients' get rates"): get and
// find_node draw from a token bucket keyed on the OBSERVED source IP
// (normIP, like the write-token defense); excess queries get a signed error
// 301 "throttled"; ping (and put) are unaffected; other source IPs are
// unaffected.
//
// Distinct source IPs are obtained by binding the querying nodes to different
// loopback addresses (the whole 127/8 range is loopback on Linux), so A on
// 127.0.0.2 and C on 127.0.0.3 present different observed IPs to B on
// 127.0.0.1.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/wire"
)

// startThrottleNode starts a node bound to a specific loopback address with a
// given get rate limit (background loops disabled).
func startThrottleNode(t *testing.T, addr string, rate float64, burst int) *Node {
	t.Helper()
	return startCfgNode(t, NodeConfig{
		ListenAddr:   addr,
		GetRateLimit: rate,
		GetBurst:     burst,
	})
}

// mustKP mints a throwaway keypair for Node-only (unstarted) constructions.
func mustKP(t *testing.T) *crypto.Keypair {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

// TestGetThrottledPerSourceIP: rate ~0 (no meaningful refill) with burst 3 ⇒
// exactly the first 3 gets from A pass, every later one gets 301
// "throttled"; ping still answers; find_node shares the bucket; a different
// source IP is unaffected; put bypasses the read throttle (it hits its own
// 302 token defense instead).
func TestGetThrottledPerSourceIP(t *testing.T) {
	b := startThrottleNode(t, "127.0.0.1:0", 0.001, 3)
	defer b.Close()
	a := startThrottleNode(t, "127.0.0.2:0", 0, 0) // throttle config only matters on B
	defer a.Close()
	c := startThrottleNode(t, "127.0.0.3:0", 0, 0)
	defer c.Close()

	bAddr, err := b.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	key := make([]byte, constants.SHA256Len)

	get := func(n *Node) (*wire.Message, error) {
		return n.sendQuery(ctx, bAddr, b.ID(), "get", map[string]any{"key": key})
	}

	// Burst of 3 passes (refill 0.001/s refills ~nothing during the test).
	for i := 0; i < 3; i++ {
		resp, err := get(a)
		if err != nil {
			t.Fatalf("get %d: %v", i, err)
		}
		if resp.Y != wire.MsgTypeResponse {
			t.Fatalf("get %d inside burst was throttled (y=%q)", i, resp.Y)
		}
	}
	// Everything past the burst is answered with 301 "throttled".
	for i := 3; i < 8; i++ {
		resp, err := get(a)
		if err != nil {
			t.Fatalf("get %d: %v", i, err)
		}
		if resp.Y != wire.MsgTypeError {
			t.Fatalf("get %d past burst: expected error, got y=%q", i, resp.Y)
		}
		if code, _ := asUint64(resp.A["code"]); code != 301 {
			t.Fatalf("get %d past burst: expected code 301, got %v", i, resp.A["code"])
		}
	}

	// ping is NOT throttled (liveness/learning stays cheap and unconditional).
	if err := a.Ping(ctx, Peer{Addr: bAddr.String(), PublicKey: b.PublicKey()}); err != nil {
		t.Fatalf("ping after throttle: %v", err)
	}

	// find_node shares the read bucket: throttled with the same 301.
	resp, err := a.sendQuery(ctx, bAddr, b.ID(), "find_node", map[string]any{"target": b.ID()})
	if err != nil {
		t.Fatalf("find_node: %v", err)
	}
	if resp.Y != wire.MsgTypeError {
		t.Fatalf("find_node past burst: expected error, got y=%q", resp.Y)
	}
	if code, _ := asUint64(resp.A["code"]); code != 301 {
		t.Fatalf("find_node past burst: expected code 301, got %v", resp.A["code"])
	}

	// put is not a read: it proceeds to its own defense and fails there (302
	// invalid token), proving the throttle did not swallow it.
	putResp, err := a.sendQuery(ctx, bAddr, b.ID(), "put", map[string]any{
		"token":    make([]byte, 32),
		"envelope": []byte("garbage"),
	})
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if putResp.Y != wire.MsgTypeError {
		t.Fatalf("put past burst: expected error, got y=%q", putResp.Y)
	}
	if code, _ := asUint64(putResp.A["code"]); code != 302 {
		t.Fatalf("put past burst: expected 302 (token defense), got %v", putResp.A["code"])
	}

	// A different source IP has its own full bucket: unaffected.
	cResp, err := get(c)
	if err != nil {
		t.Fatalf("get from other IP: %v", err)
	}
	if cResp.Y != wire.MsgTypeResponse {
		t.Fatalf("get from other IP was throttled: y=%q", cResp.Y)
	}
}

// TestThrottleDisabled: GetRateLimit < 0 disables the limiter entirely — an
// unbounded hammer of gets is fully answered.
func TestThrottleDisabled(t *testing.T) {
	b := startThrottleNode(t, "127.0.0.1:0", -1, 0)
	defer b.Close()
	a := startThrottleNode(t, "127.0.0.2:0", 0, 0)
	defer a.Close()

	bAddr, err := b.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	key := make([]byte, constants.SHA256Len)
	for i := 0; i < 30; i++ {
		resp, err := a.sendQuery(ctx, bAddr, b.ID(), "get", map[string]any{"key": key})
		if err != nil {
			t.Fatalf("get %d: %v", i, err)
		}
		if resp.Y != wire.MsgTypeResponse {
			t.Fatalf("get %d throttled despite disabled limiter (y=%q)", i, resp.Y)
		}
	}
}

// TestThrottleDefaultsResolved: NodeConfig zero values resolve to the
// documented defaults (50/s, burst 100); negative rate resolves to a nil
// (disabled) limiter.
func TestThrottleDefaultsResolved(t *testing.T) {
	n, err := NewNode(NodeConfig{
		Keypair:    mustKP(t),
		ListenAddr: "127.0.0.1:0",
		Store:      NewEnvelopeStore(0, nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	if n.getLim == nil {
		t.Fatal("default config should enable the read throttle")
	}
	if n.getLim.rate != defaultGetRateLimit || n.getLim.burst != float64(defaultGetBurst) {
		t.Errorf("defaults = %v/%v, want %v/%v",
			n.getLim.rate, n.getLim.burst, defaultGetRateLimit, defaultGetBurst)
	}

	off, err := NewNode(NodeConfig{
		Keypair:      mustKP(t),
		ListenAddr:   "127.0.0.1:0",
		Store:        NewEnvelopeStore(0, nil),
		GetRateLimit: -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if off.getLim != nil {
		t.Error("GetRateLimit < 0 should disable the limiter (nil)")
	}
}

// TestRateLimiterRefill: the bucket refills over wall time (a fast rate
// restores a spent token within the test's patience) — proving the mechanism
// is a leaky token bucket, not a fixed counter.
func TestRateLimiterRefill(t *testing.T) {
	l := newRateLimiter(10_000, 1) // 10k tokens/s: 1ms refills a whole token
	ip := []byte{127, 0, 0, 4}
	if !l.allow(ip) {
		t.Fatal("first request should pass")
	}
	if l.allow(ip) {
		t.Fatal("second request within a burst-1 bucket should be throttled")
	}
	deadline := time.Now().Add(2 * time.Second)
	for !l.allow(ip) {
		if time.Now().After(deadline) {
			t.Fatal("bucket never refilled")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestRateLimiterSweepIdle: once the map exceeds limiterMaxEntries, idle
// entries are dropped (lazy expiry) while active ones survive.
func TestRateLimiterSweepIdle(t *testing.T) {
	l := newRateLimiter(1, 1)
	active := []byte{9, 9, 9, 9}
	l.allow(active) // active entry, recently used
	for i := 0; i < limiterMaxEntries; i++ {
		ip := []byte{1, 0, 0, 0, byte(i >> 8), byte(i)} // 10k distinct stale keys
		l.buckets[string(ip)] = &tokenBucket{tokens: 1, last: time.Now().Add(-2 * limiterIdle)}
	}
	// The next new key triggers the sweep.
	fresh := []byte{8, 8, 8, 8}
	if !l.allow(fresh) {
		t.Fatal("fresh request should pass")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.buckets[string(active)]; !ok {
		t.Error("active entry was swept")
	}
	if _, ok := l.buckets[string(fresh)]; !ok {
		t.Error("fresh entry missing after sweep")
	}
	if len(l.buckets) > 10 {
		t.Errorf("sweep left %d entries; idle ones should be gone", len(l.buckets))
	}
}

// ---------------------------------------------------------------------------
// Walk-side classification (found live while profiling, Aug 2026): a get
// answered with error 301 "throttled" must surface as ErrThrottled inside the
// iterative walks → a DEGRADED miss (retryable, never negative-cached), and
// must NOT evict or penalize the (alive) throttling peer. The tests above
// cover the RESPONDER; these cover the CLIENT.
// ---------------------------------------------------------------------------

// startThrottlePair builds A (rate-limited: burst 1, refill 0.5/s) holding a
// test envelope at K_tld AND K_claim, and B (unlimited) peered with it.
func startThrottlePair(t *testing.T) (a, b *Node, key []byte) {
	t.Helper()
	akp := mustKP(t)
	var err error
	a, err = NewNode(NodeConfig{
		Keypair:      akp,
		ListenAddr:   "127.0.0.1:0",
		Store:        NewEnvelopeStore(0, nil),
		GetRateLimit: 0.5, // one token every 2 s
		GetBurst:     1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })

	bkp := mustKP(t)
	b, err = NewNode(NodeConfig{
		Keypair:      bkp,
		ListenAddr:   "127.0.0.1:0",
		Store:        NewEnvelopeStore(0, nil),
		GetRateLimit: -1, // B is never the bottleneck
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })

	tid, err := crypto.TldID(akp.Public())
	if err != nil {
		t.Fatal(err)
	}
	wn, err := naming.EncodeWireName(nil, "throttled", tid)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	rec, err := wire.NewRecord(wn, akp.Public(), 1, uint64(now), uint64(now+3600))
	if err != nil {
		t.Fatal(err)
	}
	rr, _ := wire.A([]byte{203, 0, 113, 5}, 300)
	rec.RRset = []*wire.RR{rr}
	env, err := wire.SignRecord(rec, akp)
	if err != nil {
		t.Fatal(err)
	}
	key, err = KeyForWireName(wn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.store.Put(key, env, now, true); err != nil {
		t.Fatal(err)
	}
	// Also store at K_claim (§7.4: a claim-carrying TLD envelope lives at BOTH
	// keys) so the CollectClaims walk — which probes K_claim — finds it.
	kClaim, err := KeyForClaim("throttled")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.store.Put(kClaim, env, now, true); err != nil {
		t.Fatal(err)
	}

	aAddr, err := a.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	if err := b.AddPeer(a.PublicKey(), aAddr.String()); err != nil {
		t.Fatal(err)
	}
	return a, b, key
}

// TestThrottledGetIsDegradedMiss: after exhausting A's burst, B's cold
// IterativeGet must return ErrDegradedMiss — NOT a clean (nil, nil) miss that
// the resolver would negative-cache as NXDOMAIN (the issue #1 failure mode).
func TestThrottledGetIsDegradedMiss(t *testing.T) {
	a, b, key := startThrottlePair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// 1st get consumes the single burst token and fetches the envelope.
	env, err := b.IterativeGet(ctx, key)
	if err != nil || env == nil {
		t.Fatalf("first IterativeGet: env=%v err=%v", env, err)
	}

	// 2nd get: A throttles (301) — must classify as a degraded miss.
	b.store.Remove(key)
	env2, _, err2 := b.IterativeGetDetailed(ctx, key)
	if env2 != nil {
		t.Fatal("throttled IterativeGet returned an envelope; want nil")
	}
	if !errors.Is(err2, ErrDegradedMiss) {
		t.Fatalf("throttled IterativeGet err = %v, want ErrDegradedMiss", err2)
	}

	// The throttling peer must NOT have been evicted from B's table.
	if got := b.RoutingTable().Size(); got < 1 {
		t.Fatalf("throttled peer evicted from routing table (size %d); §12 throttling is not a §6.2 failure", got)
	}

	// After the bucket refills (2 s at 0.5 tokens/s), the same contact must
	// serve the record again — proving no eviction AND no dead-penalty.
	time.Sleep(2200 * time.Millisecond)
	env3, err3 := b.IterativeGet(ctx, key)
	if err3 != nil || env3 == nil {
		t.Fatalf("post-refill IterativeGet: env=%v err=%v (peer wrongly penalized/evicted?)", env3, err3)
	}
	_ = a
}

// TestThrottledCollectClaimsIsDegradedMiss: the §7.4 claim-collection walk
// shares the classification — an all-throttled collection with no local copy
// returns ErrDegradedMiss instead of an empty (authoritative) set.
func TestThrottledCollectClaimsIsDegradedMiss(t *testing.T) {
	_, b, _ := startThrottlePair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	alias := "throttled"
	// First collection consumes the burst token and collects the envelope.
	set, err := b.CollectClaims(ctx, alias)
	if err != nil || len(set) != 1 {
		t.Fatalf("first CollectClaims: n=%d err=%v", len(set), err)
	}

	// Second collection: B holds no local copy (no cache-back happened — the
	// node-level walk does not write the store), A throttles → degraded.
	set2, err2 := b.CollectClaims(ctx, alias)
	if len(set2) != 0 {
		t.Fatalf("throttled CollectClaims returned %d envelopes; want 0", len(set2))
	}
	if !errors.Is(err2, ErrDegradedMiss) {
		t.Fatalf("throttled CollectClaims err = %v, want ErrDegradedMiss", err2)
	}
}
