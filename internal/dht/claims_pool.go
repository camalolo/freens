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

	"github.com/laurent/freens/internal/claims"
	"github.com/laurent/freens/internal/constants"
	"github.com/laurent/freens/internal/wire"
)

// ClaimPool is the §7.4 "storing nodes keep the top 2 by ordering" store: for
// each K_claim it holds at most 2 claim envelopes, best-first by the §7.4
// step-3 ordering tuple. All methods are safe for concurrent use.
type ClaimPool struct {
	mu sync.Mutex
	// byKey maps K_claim → the 1-or-2 pooled claims, ordered best-first.
	byKey map[[constants.SHA256Len]byte][]pooledClaim
}

// pooledClaim is one pool member: the envelope, its decoded AliasClaim (the
// ordering input, decoded once at Offer), and its H_record (the dedupe key).
type pooledClaim struct {
	env   *wire.SignedEnvelope
	claim *claims.AliasClaim
	h     []byte // H_record = SHA-256(canonical envelope)
}

// NewClaimPool returns an empty ClaimPool.
func NewClaimPool() *ClaimPool {
	return &ClaimPool{byKey: make(map[[constants.SHA256Len]byte][]pooledClaim)}
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
// Signature validity is the caller's job (hPut verifies before offering;
// CollectClaims verifies before merging).
func (p *ClaimPool) Offer(key []byte, env *wire.SignedEnvelope) bool {
	if p == nil || len(key) != constants.SHA256Len || env == nil || env.Record == nil {
		return false
	}
	claim, err := claims.DecodeAliasClaim(env.Record.Claim)
	if err != nil {
		return false
	}
	h, err := env.RecordHash()
	if err != nil {
		return false
	}
	pc := pooledClaim{env: env, claim: claim, h: h}
	var k [constants.SHA256Len]byte
	copy(k[:], key)

	p.mu.Lock()
	defer p.mu.Unlock()
	cur := p.byKey[k]
	for _, m := range cur {
		if bytes.Equal(m.h, h) {
			return false // already pooled (H_record dedupe)
		}
	}
	if len(cur) >= 2 {
		// Full: keep the newcomer only if it beats the worst member strictly;
		// an equal tuple (same claim contents in a different envelope) loses
		// to the incumbent, keeping the pool stable under republication.
		if !claimOrderLess(pc.claim, cur[1].claim) {
			return false
		}
		cur = cur[:1] // drop the worst
	}
	cur = append(cur, pc)
	// Maintain best-first order (<= 2 members; stable for equal tuples).
	if len(cur) == 2 && claimOrderLess(cur[1].claim, cur[0].claim) {
		cur[0], cur[1] = cur[1], cur[0]
	}
	p.byKey[k] = cur
	return true
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
