package dht

// hardening_test.go pins the v0.7.1 security-hardening behaviors found in the
// application audit:
//
//   - ClaimPool: the §7.4 claim screen (claimant consistency + PoW) gates
//     OFFERED claims (the collect path could previously pool zero-PoW claims
//     from any peer), and the pool is bounded by key count and total bytes
//     (FIFO whole-key eviction).
//   - hPut: per-source-IP put throttling (the write token authorizes, the
//     bucket bounds CPU).
//   - hWitness: the claim-timestamp sanity gates survive attacker-controlled
//     uint64 values ≥ 2^63 (the pre-fix int64 conversions wrapped both gates
//     negative and the node co-signed year-292-billion claims).
//   - rateLimiter: the per-IP bucket map is hard-capped (a >10k-distinct-
//     source flood used to grow it without bound).
//   - EnvelopeStore: the §8.3 history and §8.4 evidence tables are bounded
//     by TOTAL BYTES, not just entry count; evidence blobs over
//     maxEvidenceBlobLen are rejected outright.

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/claims"
	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/wire"
)

// ---------------------------------------------------------------------------
// ClaimPool hardening
// ---------------------------------------------------------------------------

// unminedClaimEnv builds a well-formed, well-SIGNED claim envelope whose PoW
// does NOT recompute (the nonce was salted after mining): exactly the shape a
// malicious peer offers along the collect path at zero PoW cost.
func unminedClaimEnv(t *testing.T, alias string, ts uint64) (*wire.SignedEnvelope, []byte) {
	t.Helper()
	env, kClaim := contestedClaimEnv(t, alias, ts)
	// Rebuild the claim with a corrupted nonce and re-embed + re-sign: the
	// envelope signature stays valid, the claim PoW does not.
	claim, err := claims.DecodeAliasClaim(env.Record.Claim)
	if err != nil {
		t.Fatal(err)
	}
	claim.Nonce[len(claim.Nonce)-1] ^= 0xff // PoW no longer recomputes
	cb, err := claim.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	rec := *env.Record // shallow copy; the other fields are shared deliberately
	rec.Claim = cb
	reSigned, err := wire.SignRecord(&rec, mustGenKP(t))
	if err != nil {
		t.Fatal(err)
	}
	return reSigned, kClaim
}

// TestClaimPoolRejectsUnminedClaim: Offer refuses a claim whose PoW does not
// recompute — the collect-path memory-exhaustion vector (pool zero-PoW
// envelopes for unlimited distinct aliases).
func TestClaimPoolRejectsUnminedClaim(t *testing.T) {
	p := NewClaimPool()
	env, kClaim := unminedClaimEnv(t, "powless", uint64(time.Now().Unix()))
	if !env.VerifySignature() {
		t.Fatal("fixture envelope must be well-signed (isolating the PoW gate)")
	}
	if p.Offer(kClaim, env) {
		t.Error("Offer must refuse a claim whose PoW does not recompute")
	}
	if got := p.Top2(kClaim); len(got) != 0 {
		t.Errorf("pool holds %d envelopes for an unmined claim, want 0", len(got))
	}
	// The mined twin (same fixture, untampered) IS pooled.
	good, kGood := contestedClaimEnv(t, "powless", uint64(time.Now().Unix()))
	if !p.Offer(kGood, good) {
		t.Error("mined claim fixture should be pooled")
	}
}

// TestClaimPoolKeyCountBudget: whole-key FIFO eviction at the key-count
// budget (oldest-inserted key leaves; the just-inserted key survives).
func TestClaimPoolKeyCountBudget(t *testing.T) {
	p := NewClaimPool()
	p.maxKeys = 3
	ts := uint64(time.Now().Unix())
	var firstKey [constants.SHA256Len]byte
	for i := 0; i < 4; i++ {
		env, k := contestedClaimEnv(t, fmt.Sprintf("capkey%d", i), ts)
		if i == 0 {
			copy(firstKey[:], k)
		}
		if !p.Offer(k, env) {
			t.Fatalf("offer %d not stored", i)
		}
	}
	if got := len(p.byKey); got != 3 {
		t.Fatalf("pool holds %d keys, want 3 (key budget)", got)
	}
	if _, ok := p.byKey[firstKey]; ok {
		t.Error("oldest-inserted key must be evicted at the key budget")
	}
}

// TestClaimPoolByteBudget: total pooled bytes stay under the byte budget
// (FIFO key eviction), independent of the key count.
func TestClaimPoolByteBudget(t *testing.T) {
	p := NewClaimPool()
	p.maxBytes = 6000 // ~2 typical claim envelopes
	ts := uint64(time.Now().Unix())
	var firstKey [constants.SHA256Len]byte
	for i := 0; i < 4; i++ {
		env, k := contestedClaimEnv(t, fmt.Sprintf("capbyte%d", i), ts)
		if i == 0 {
			copy(firstKey[:], k)
		}
		p.Offer(k, env)
	}
	if p.bytes > p.maxBytes && len(p.byKey) > 1 {
		t.Errorf("pool bytes %d exceed budget %d with %d keys held", p.bytes, p.maxBytes, len(p.byKey))
	}
	if _, ok := p.byKey[firstKey]; ok && p.bytes > p.maxBytes {
		t.Error("oldest key must be evicted to bring the byte budget down")
	}
}

// ---------------------------------------------------------------------------
// hPut put-throttle
// ---------------------------------------------------------------------------

// TestPutThrottlePerSource: with a tiny put bucket, puts past the burst are
// answered 301 "throttled" BEFORE the token defense (302) — the read bucket
// is untouched (gets keep flowing).
func TestPutThrottlePerSource(t *testing.T) {
	store := NewEnvelopeStore(0, nil)
	n, err := NewNode(NodeConfig{
		Keypair:      mustGenKP(t),
		ListenAddr:   "127.0.0.1:0",
		Store:        store,
		GetRateLimit: -1, // reads off: isolate the put bucket
		PutRateLimit: 1,
		PutBurst:     2,
	})
	if err != nil {
		t.Fatal(err)
	}
	raddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 54321}
	mkPut := func() *wire.Message {
		return &wire.Message{Y: "q", Q: "put", ID: make([]byte, 32), T: []byte("t"), A: map[string]any{
			"token":    make([]byte, 32),
			"envelope": []byte("garbage"),
		}}
	}
	// Fill the burst: each passes the put bucket and dies at the token
	// defense (302), proving ordering.
	for i := 0; i < 2; i++ {
		resp := n.hPut(mkPut(), raddr)
		if resp == nil || resp.Y != wire.MsgTypeError {
			t.Fatalf("put %d: expected error response", i)
		}
		if code, _ := asUint64(resp.A["code"]); code != 302 {
			t.Fatalf("put %d within burst: code = %v, want 302 (token defense)", i, resp.A["code"])
		}
	}
	// Past the burst: 301 throttled.
	resp := n.hPut(mkPut(), raddr)
	if resp == nil || resp.Y != wire.MsgTypeError {
		t.Fatal("expected error response past put burst")
	}
	if code, _ := asUint64(resp.A["code"]); code != 301 {
		t.Fatalf("put past burst: code = %v, want 301 (throttled)", resp.A["code"])
	}
	// Reads unaffected (read limiter disabled; and separate regardless).
	if !n.allowRead(raddr) {
		t.Error("read bucket must be independent of the put bucket")
	}
}

func mustGenKP(t *testing.T) *crypto.Keypair {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

// ---------------------------------------------------------------------------
// hWitness claim-ts sanity vs huge uint64
// ---------------------------------------------------------------------------

// TestWitnessRejectsHugeTimestamp: ts >= 2^63 used to wrap BOTH sanity gates
// negative (int64 conversions) and get co-signed. It must be refused with 305.
func TestWitnessRejectsHugeTimestamp(t *testing.T) {
	a, b := peerPair(t)
	defer a.Close()
	defer b.Close()

	withFastWitnessPoW(t)
	id := newWitnessIdentity(t, 1<<63) // year ~292 billion when read as uint64
	args := witnessArgs(t, "hugets", id)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err := a.sendQuery(ctx, bAddr(t, b), b.ID(), "witness", args)
	if err != nil {
		t.Fatalf("witness rpc: %v", err)
	}
	if resp == nil || resp.Y != wire.MsgTypeError {
		t.Fatal("huge-ts witness request must be refused with an error")
	}
	if code, _ := asUint64(resp.A["code"]); code != 305 {
		t.Fatalf("huge-ts witness: code = %v, want 305", resp.A["code"])
	}
}

// TestWitnessAcceptsHugeTimestampPreFixPins is deliberately absent: the
// pre-fix behavior (co-signing) was the vulnerability.

// bAddr resolves the node's local address for sendQuery.
func bAddr(t *testing.T, n *Node) *net.UDPAddr {
	t.Helper()
	a, err := n.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// ---------------------------------------------------------------------------
// rateLimiter hard cap
// ---------------------------------------------------------------------------

// TestRateLimiterHardCap: a flood of DISTINCT source keys cannot grow the
// bucket map past limiterMaxEntries (the idle sweep alone did not bound it
// when every entry was recently touched).
func TestRateLimiterHardCap(t *testing.T) {
	l := newRateLimiter(1000, 5) // generous per-key: never the bottleneck
	for i := 0; i < limiterMaxEntries+2000; i++ {
		var k [4]byte
		binary.BigEndian.PutUint32(k[:], uint32(i))
		l.allow(k[:])
	}
	l.mu.Lock()
	got := len(l.buckets)
	l.mu.Unlock()
	if got > limiterMaxEntries {
		t.Errorf("bucket map holds %d entries, cap is %d", got, limiterMaxEntries)
	}
}

// ---------------------------------------------------------------------------
// EnvelopeStore history/evidence byte budgets
// ---------------------------------------------------------------------------

// TestHistoryByteBudget: the §8.3 history obeys a TOTAL-BYTES budget with
// oldest-first eviction — not just the entry count.
func TestHistoryByteBudget(t *testing.T) {
	s := NewEnvelopeStore(0, nil)
	now := time.Now().Unix()
	key := make([]byte, constants.SHA256Len)

	owner := mustGenKP(t) // one owner, sequence-increasing updates: each Put displaces
	tid, err := crypto.TldID(owner.Public())
	if err != nil {
		t.Fatal(err)
	}
	name, err := naming.EncodeWireName(nil, "histbudget", tid)
	if err != nil {
		t.Fatal(err)
	}
	var firstHash []byte
	var unit int
	for i := 0; i < 5; i++ {
		rec, err := wire.NewRecord(name, owner.Public(), uint64(i+1), uint64(now-100), uint64(now+3600))
		if err != nil {
			t.Fatal(err)
		}
		env, err := wire.SignRecord(rec, owner)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			firstHash, err = env.RecordHash()
			if err != nil {
				t.Fatal(err)
			}
			if b, berr := env.Bytes(); berr == nil {
				unit = len(b)
			}
			// Budget for ~2 fixture envelopes: 4 displaced entries MUST
			// force eviction of the oldest.
			s.histMaxBytes = 2*unit + unit/2
		}
		ok, err := s.Put(key, env, now+int64(i), false)
		if err != nil || !ok {
			t.Fatalf("put %d: (%v, %v)", i, ok, err)
		}
	}
	if s.historyBytes > s.histMaxBytes && s.HistoryCount() > 1 {
		t.Errorf("history bytes %d exceed budget %d with %d entries", s.historyBytes, s.histMaxBytes, s.HistoryCount())
	}
	// 4 displaced envelopes against a ~2.5-envelope budget: the oldest
	// must have been evicted to bring the total under the budget.
	if s.GetHistory(firstHash) != nil {
		t.Error("oldest history entry must be evicted first under the byte budget")
	}
	if s.HistoryCount() >= 4 {
		t.Errorf("history still holds %d of 4 displaced entries against a %d-entry budget", s.HistoryCount(), s.histMaxBytes/unit)
	}
}

// bigEvidence builds a decode-valid RecoveryEvidence blob of roughly n bytes
// (n/threshold 64-byte signatures; each signature must be exactly 64 bytes).
func bigEvidence(t *testing.T, n int) []byte {
	t.Helper()
	sigs := make([][]byte, 0, n/64+1)
	one := bytes.Repeat([]byte{0x5a}, 64)
	for len(sigs)*64 < n {
		sigs = append(sigs, one)
	}
	ev := &wire.RecoveryEvidence{
		NewOwnerPK: bytes.Repeat([]byte{0x99}, 32),
		Signatures: sigs,
		NotBefore:  uint64(time.Now().Unix()),
	}
	b, err := ev.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestEvidenceByteBudget: the §8.4 evidence table obeys a total-bytes budget
// with FIFO eviction.
func TestEvidenceByteBudget(t *testing.T) {
	s := NewEnvelopeStore(0, nil)
	s.evidMaxBytes = 2000
	k1 := evKey(1)
	k2 := evKey(2)
	k3 := evKey(3)
	if err := s.PutEvidence(k1, bigEvidence(t, 1200)); err != nil {
		t.Fatalf("put k1: %v", err)
	}
	if err := s.PutEvidence(k2, bigEvidence(t, 1200)); err != nil {
		t.Fatalf("put k2: %v", err)
	}
	if err := s.PutEvidence(k3, bigEvidence(t, 1200)); err != nil {
		t.Fatalf("put k3: %v", err)
	}
	if s.evidenceBytes > s.evidMaxBytes && s.EvidenceCount() > 1 {
		t.Errorf("evidence bytes %d exceed budget %d with %d blobs", s.evidenceBytes, s.evidMaxBytes, s.EvidenceCount())
	}
	if s.GetEvidence(k1) != nil && s.evidenceBytes > s.evidMaxBytes {
		t.Error("oldest evidence blob must be evicted to satisfy the byte budget")
	}
}

// TestEvidenceBlobSizeCap: a blob over maxEvidenceBlobLen is rejected
// outright (the datagram ceiling was the only per-blob bound before).
func TestEvidenceBlobSizeCap(t *testing.T) {
	s := NewEnvelopeStore(0, nil)
	if err := s.PutEvidence(evKey(9), bigEvidence(t, maxEvidenceBlobLen+1024)); err == nil {
		t.Error("oversized evidence blob must be rejected")
	}
	if s.EvidenceCount() != 0 {
		t.Error("nothing may be retained for a rejected blob")
	}
}
