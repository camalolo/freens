// Package dht — claims_pool.go implements the §7.4 STORING-NODE side of the
// verifier's step 1 (spec lines 600-604):
//
//	"1. get(K_claim); collect all competing claims nodes offer (storing nodes
//	 keep the top 2 by ordering; clients SHOULD probe GET_CLOSEST nodes and
//	 merge)."
//
// The single-slot EnvelopeStore (§6.4) keeps ONE winner per key by
// (sequence, H_record) — a rule that cannot express "the top 2 by ordering":
// when two DIFFERENT claims for one alias arrive at the same node (each with
// sequence 1, so the H_record tie-break decides the store slot), the loser of
// the tie-break is silently dropped and the merged set a later verifier
// collects collapses to one claim (verified live in claims_lookup_test.go).
// §7.4 explicitly requires more: a storing node must be able to offer BOTH
// competing claims so verifiers can run the (timestamp, pow_hash, tld_id)
// ordering themselves (§6.5: the DHT does not adjudicate alias races).
//
// ClaimPool is that second, claim-key-space-only store: a mutex-guarded map
// K_claim → up to 2 envelopes ordered BEST-FIRST by the §7.4 step-3 tuple
// (timestamp, pow_hash, tld_id) ascending — earliest asserted time wins, ties
// by lower PoW hash, then lower TLD ID (computed from the decoded AliasClaim
// via the claims package's exported OrderKey; the ordering is the same total
// order claims.OrderClaims applies, reproduced here without modifying
// internal/claims). It is filled by hPut's explicit-K_claim branch (§7.4
// registration step 5) and by collecting nodes (DHTLookup.CollectClaims
// offering every merged claim back into their pool), and served by hGet as the
// documented `envelopes` extension (see Node.hGet). Signature and structural
// validity of offered envelopes are the CALLER's job (hPut has already
// verified the envelope signature; CollectClaims verifies before merging).
package dht

import (
	"bytes"
	"sync"

	"github.com/camalolo/freens/internal/claims"
	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/wire"
)

// ClaimPool is the §7.4 "storing nodes keep the top 2 by ordering" store: for
// each K_claim it holds at most 2 claim envelopes, best-first by the §7.4
// step-3 ordering tuple. All methods are safe for concurrent use.
//
// Boundedness (v0.7.1 hardening): the pool is capped BOTH by key count
// (claimPoolMaxKeys, FIFO whole-key eviction of the oldest-inserted key) and
// by total pooled bytes (claimPoolMaxBytes, counting each pooled envelope's
// canonical size). Before the caps the byKey map grew without bound — one
// entry (up to 2 × ~64 KB envelopes + decoded claims) per DISTINCT alias
// ever pooled, forever, which a malicious peer could drive via the collect
// path (claims_lookup offers every collected envelope into the local pool)
// at zero PoW cost. Offer additionally enforces the §7.4 step-2 claim screen
// (claimant consistency + recomputed PoW) so only claims a STORING node would
// have accepted at hPut can occupy pool memory.
type ClaimPool struct {
	mu sync.Mutex
	// byKey maps K_claim → the 1-or-2 pooled claims, ordered best-first.
	byKey map[[constants.SHA256Len]byte][]pooledClaim
	// order records first-insertion order of byKey's keys (FIFO eviction
	// source); a key re-Offered keeps its original position.
	order [][constants.SHA256Len]byte
	// bytes is the sum of every pooled envelope's canonical size (the
	// byte budget). maxKeys/maxBytes are fields (defaults from the consts
	// below) so tests can shrink the budgets.
	bytes    int
	maxKeys  int
	maxBytes int
}

// Pool bounds. 4096 keys × 2 × ~4 KB typical claim envelopes ≈ 32 MB worst
// case at the byte cap alone; the key cap keeps map/index overhead bounded
// for tiny envelopes, the byte cap keeps memory bounded for maximal (~64 KB)
// ones. Both are defense-in-depth ceilings far above honest fleet scale.
const (
	claimPoolMaxKeys  = 4096
	claimPoolMaxBytes = 16 << 20 // 16 MiB
)

// pooledClaim is one pool member: the envelope, its decoded AliasClaim (the
// ordering input, decoded once at Offer), its H_record (the dedupe key), and
// its canonical byte size (the byte-budget accounting unit).
type pooledClaim struct {
	env   *wire.SignedEnvelope
	claim *claims.AliasClaim
	h     []byte // H_record = SHA-256(canonical envelope)
	size  int    // len(env.Bytes()), cached for the byte budget
}

// NewClaimPool returns an empty ClaimPool.
func NewClaimPool() *ClaimPool {
	return &ClaimPool{
		byKey:    make(map[[constants.SHA256Len]byte][]pooledClaim),
		maxKeys:  claimPoolMaxKeys,
		maxBytes: claimPoolMaxBytes,
	}
}

// claimOrderLess is the §7.4 step-3 ascending total order on AliasClaims,
// built from the exported claims.OrderKey: (timestamp, pow_hash, tld_id),
// earliest/lower wins. It matches the unexported claims.lessOrderKey used by
// claims.OrderClaims / claims.SelectWinner (same tuple, same bytes.Compare
// semantics) without reaching into internal/claims.
func claimOrderLess(a, b *claims.AliasClaim) bool {
	if a.Timestamp != b.Timestamp {
		return a.Timestamp < b.Timestamp
	}
	if cmp := bytes.Compare(a.PowHash, b.PowHash); cmp != 0 {
		return cmp < 0
	}
	return bytes.Compare(a.TldID, b.TldID) < 0
}

// Offer inserts env under key if it belongs in the top 2: it is stored when
// the pool holds fewer than 2 claims for key, or when it orders STRICTLY
// better (§7.4 tuple) than the current worst member, evicting that member.
// An envelope whose H_record is already pooled is a no-op. It returns whether
// the pool contents changed (a new envelope was stored). A wrong-length key,
// an undecodable envelope, or an envelope without a decodable AliasClaim
// (field 11) returns false — the pool is claim-key-space-only by construction.
//
// Claim screen (v0.7.1): the decoded claim must pass the §7.4 step-2
// PoW-side filter — claimant consistency (TldID == SHA-256(ClaimantPK)) and
// a recomputed PoW at the inferred difficulty — BEFORE it may occupy pool
// memory. hPut already runs the full VerifyFull screen (PoW + quorum) before
// offering; the pool-side gate exists for the OTHER caller, the collect path
// (claims_lookup.go), whose remote-sourced envelopes previously entered the
// pool on envelope-signature alone — a zero-PoW memory-exhaustion vector.
// Quorum is NOT re-checked here (the resolver applies it per query; pooled
// storage mirrors what hPut would have retained).
//
// Signature validity remains the caller's job (hPut verifies before offering;
// CollectClaims verifies before merging).
func (p *ClaimPool) Offer(key []byte, env *wire.SignedEnvelope) bool {
	if p == nil || len(key) != constants.SHA256Len || env == nil || env.Record == nil {
		return false
	}
	claim, err := claims.DecodeAliasClaim(env.Record.Claim)
	if err != nil {
		return false
	}
	// §7.4 claim screen: no PoW, no pool slot.
	if !claim.VerifyClaimantConsistency() || !claim.VerifyPoW(claims.InferDifficulty) {
		return false
	}
	h, err := env.RecordHash()
	if err != nil {
		return false
	}
	envBytes, err := env.Bytes()
	if err != nil {
		return false
	}
	pc := pooledClaim{env: env, claim: claim, h: h, size: len(envBytes)}
	var k [constants.SHA256Len]byte
	copy(k[:], key)

	p.mu.Lock()
	defer p.mu.Unlock()
	cur, ok := p.byKey[k]
	for _, m := range cur {
		if bytes.Equal(m.h, h) {
			return false // already pooled (H_record dedupe)
		}
	}
	newKey := !ok
	if len(cur) >= 2 {
		// Full: keep the newcomer only if it beats the worst member strictly;
		// an equal tuple (same claim contents in a different envelope) loses
		// to the incumbent, keeping the pool stable under republication.
		if !claimOrderLess(pc.claim, cur[1].claim) {
			return false
		}
		p.bytes -= cur[1].size // the evicted worst leaves the byte budget
		cur = cur[:1]          // drop the worst
	}
	cur = append(cur, pc)
	p.bytes += pc.size
	// Maintain best-first order (<= 2 members; stable for equal tuples).
	if len(cur) == 2 && claimOrderLess(cur[1].claim, cur[0].claim) {
		cur[0], cur[1] = cur[1], cur[0]
	}
	p.byKey[k] = cur
	if newKey {
		p.order = append(p.order, k)
		p.evictOverBudgetLocked(k)
	}
	return true
}

// evictOverBudgetLocked enforces the pool bounds, evicting whole keys
// oldest-inserted-first (FIFO) until both the key-count and byte budgets
// hold. The just-inserted key protect is only dropped when it is the sole
// remaining key (a single key cannot evict itself into a livelock; the
// budgets are ceilings, not hard invariants for pathological singles).
// Caller must hold p.mu.
func (p *ClaimPool) evictOverBudgetLocked(protected [constants.SHA256Len]byte) {
	for (len(p.byKey) > p.maxKeys || p.bytes > p.maxBytes) && len(p.order) > 0 {
		oldest := p.order[0]
		if oldest == protected && len(p.order) == 1 {
			return // never evict the only (newest) key: the budget is soft for one entry
		}
		p.order = p.order[1:]
		for _, m := range p.byKey[oldest] {
			p.bytes -= m.size
		}
		delete(p.byKey, oldest)
	}
}

// Contains reports whether the envelope with H_record h is currently pooled
// under key. hPut uses it to answer a claim put that lost the single-slot
// §6.4 winner race but was retained by the top-2 pool with success (the node
// DID retain the claim — §7.4 — so 304 "stale record" would be a lie).
func (p *ClaimPool) Contains(key []byte, h []byte) bool {
	if p == nil || len(key) != constants.SHA256Len || len(h) != constants.SHA256Len {
		return false
	}
	var k [constants.SHA256Len]byte
	copy(k[:], key)
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, m := range p.byKey[k] {
		if bytes.Equal(m.h, h) {
			return true
		}
	}
	return false
}

// Top2 returns a copy of the (at most 2) envelopes pooled for key, BEST-FIRST
// by the §7.4 ordering. The slice (and its envelope pointers) may be retained
// freely; envelopes are never mutated in place. An unknown key yields nil.
func (p *ClaimPool) Top2(key []byte) []*wire.SignedEnvelope {
	if p == nil || len(key) != constants.SHA256Len {
		return nil
	}
	var k [constants.SHA256Len]byte
	copy(k[:], key)
	p.mu.Lock()
	defer p.mu.Unlock()
	cur := p.byKey[k]
	if len(cur) == 0 {
		return nil
	}
	out := make([]*wire.SignedEnvelope, len(cur))
	for i, m := range cur {
		out[i] = m.env
	}
	return out
}
