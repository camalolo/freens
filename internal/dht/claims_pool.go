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
// via the claims package's exported LessOrderKey; the ordering is the same total
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
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
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

// PersistClaimPoolDir persists the node's claim pool (Node wrapper for the
// daemon's persist loop). Returns the number of envelopes written.
func (n *Node) PersistClaimPoolDir(dir string) (int, error) {
	if n == nil || n.claims == nil {
		return 0, nil
	}
	return n.claims.PersistClaimPoolTo(dir, n.now())
}

// LoadClaimPoolDir restores a persisted claim pool (Node wrapper for the
// daemon's startup path). Returns the number of envelopes pooled.
func (n *Node) LoadClaimPoolDir(dir string) (int, error) {
	if n == nil || n.claims == nil {
		return 0, nil
	}
	return n.claims.RetainClaimPool(dir, n.now())
}

// SweepClaimPool drops pool entries past their §8.4 reuse window (Node
// wrapper; see ClaimPool.Sweep). Returns the number dropped.
func (n *Node) SweepClaimPool(now int64) int {
	if n == nil || n.claims == nil {
		return 0
	}
	return n.claims.Sweep(now)
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
		if !claims.LessOrderKey(pc.claim, cur[1].claim) {
			return false
		}
		p.bytes -= cur[1].size // the evicted worst leaves the byte budget
		cur = cur[:1]          // drop the worst
	}
	cur = append(cur, pc)
	p.bytes += pc.size
	// Maintain best-first order (<= 2 members; stable for equal tuples).
	if len(cur) == 2 && claims.LessOrderKey(cur[1].claim, cur[0].claim) {
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

// ---------------------------------------------------------------------------
// §8.4 reuse-window retention (v0.8.0) + persistence
// ---------------------------------------------------------------------------

// Sweep drops every pooled entry whose carrier is expired MORE THAN
// AliasReuseDelay ago — past that point the envelope can neither win (dead)
// nor open the §8.4 reuse window (closed), so retaining it is pure memory.
// Live entries and dead-but-in-window entries (the §8.4 tombstones) are
// kept. It returns the number of entries dropped. Callers: the daemon's
// persist loop (once a minute) and PersistTo's write path, so the pool
// self-cleans without a timer.
func (p *ClaimPool) Sweep(now int64) int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	dropped := 0
	var deadKeys [][constants.SHA256Len]byte
	for k, members := range p.byKey {
		keep := members[:0]
		for _, m := range members {
			if now >= int64(m.env.Record.Expires)+int64(constants.AliasReuseDelay) {
				p.bytes -= m.size
				dropped++
				continue
			}
			keep = append(keep, m)
		}
		if len(keep) == 0 {
			delete(p.byKey, k)
			deadKeys = append(deadKeys, k)
			continue
		}
		p.byKey[k] = keep
	}
	if len(deadKeys) > 0 {
		dead := make(map[[constants.SHA256Len]byte]struct{}, len(deadKeys))
		for _, k := range deadKeys {
			dead[k] = struct{}{}
		}
		order := p.order[:0]
		for _, k := range p.order {
			if _, ok := dead[k]; ok {
				continue
			}
			order = append(order, k)
		}
		p.order = order
	}
	return dropped
}

// PoolEntry is one pooled claim envelope plus the K_claim it is pooled under
// (the ClaimPool persistence unit).
type PoolEntry struct {
	Key []byte
	Env *wire.SignedEnvelope
}

// Entries returns a snapshot of every pooled (key, envelope) pair, ordered
// deterministically by key then H_record — the PersistTo source.
func (p *ClaimPool) Entries() []PoolEntry {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]PoolEntry, 0, len(p.byKey))
	for k, members := range p.byKey {
		key := make([]byte, constants.SHA256Len)
		copy(key, k[:])
		for _, m := range members {
			out = append(out, PoolEntry{Key: key, Env: m.env})
		}
	}
	sort.Slice(out, func(i, j int) bool { return poolEntryLess(out[i], out[j]) })
	return out
}

// poolEntryLess orders pool entries by (key, H_record) for a deterministic
// persistence order; on a hash error it degrades to false (sort tolerates).
func poolEntryLess(a, b PoolEntry) bool {
	if c := bytes.Compare(a.Key, b.Key); c != 0 {
		return c < 0
	}
	ha, e1 := a.Env.RecordHash()
	hb, e2 := b.Env.RecordHash()
	if e1 != nil || e2 != nil {
		return false
	}
	return bytes.Compare(ha, hb) < 0
}

// PersistClaimPoolTo writes every pooled claim envelope as
// <H_record hex>.cbor into dir (created if missing), after a Sweep so only
// live claims and in-window §8.4 tombstones are written. Same
// temp-file-then-rename write as EnvelopeStore.PersistTo. Returns the number
// written.
func (p *ClaimPool) PersistClaimPoolTo(dir string, now int64) (int, error) {
	if p == nil {
		return 0, nil
	}
	p.Sweep(now)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, fmt.Errorf("dht: persist-claim-pool mkdir %q: %w", dir, err)
	}
	written := 0
	for _, e := range p.Entries() {
		b, err := e.Env.Bytes()
		if err != nil {
			continue
		}
		h, err := e.Env.RecordHash()
		if err != nil {
			continue
		}
		name := hex.EncodeToString(h)
		final := filepath.Join(dir, name+".cbor")
		tmp, err := os.CreateTemp(dir, "."+name+".tmp-*")
		if err != nil {
			return written, fmt.Errorf("dht: persist-claim-pool temp file in %q: %w", dir, err)
		}
		if _, err := tmp.Write(b); err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
			return written, fmt.Errorf("dht: persist-claim-pool write %q: %w", tmp.Name(), err)
		}
		if err := tmp.Close(); err != nil {
			os.Remove(tmp.Name())
			return written, fmt.Errorf("dht: persist-claim-pool close %q: %w", tmp.Name(), err)
		}
		if err := os.Rename(tmp.Name(), final); err != nil {
			os.Remove(tmp.Name())
			return written, fmt.Errorf("dht: persist-claim-pool rename %q: %w", final, err)
		}
		written++
	}
	return written, nil
}

// RetainClaimPool loads persisted claim envelopes (written by
// PersistClaimPoolTo) back into the pool: each file is decoded, its K_claim
// re-derived from the embedded claim (the same canonical rule as
// StorageKeys), and — only while still worth pooling (alive or inside its
// §8.4 reuse window) — Offered. Envelopes past their window are skipped
// (silently; the next persist rewrites the directory without them).
// Signatures are re-verified here since these envelopes come from disk, not
// from a network peer that already checked them.
func (p *ClaimPool) RetainClaimPool(dir string, now int64) (int, error) {
	if p == nil {
		return 0, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("dht: retain-claim-pool read %q: %w", dir, err)
	}
	count := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".cbor") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return count, err
		}
		env, err := wire.DecodeEnvelope(data)
		if err != nil || env.Record == nil || len(env.Record.Claim) == 0 || !env.VerifySignature() {
			continue
		}
		claim, cerr := claims.DecodeAliasClaim(env.Record.Claim)
		if cerr != nil {
			continue
		}
		kClaim, kerr := KeyForClaim(claim.Alias)
		if kerr != nil {
			continue
		}
		if now >= int64(env.Record.Expires)+int64(constants.AliasReuseDelay) {
			continue // window closed: not worth a pool slot
		}
		if p.Offer(kClaim, env) {
			count++
		}
	}
	return count, nil
}
