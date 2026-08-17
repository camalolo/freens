// Package dht — claims_lookup.go implements the §7.4 verifier-side step-1
// multi-claim collection (spec lines 600-604):
//
//	"1. get(K_claim); collect all competing claims nodes offer (storing nodes
//	 keep the top 2 by ordering; clients SHOULD probe GET_CLOSEST nodes and
//	 merge)."
//
// The single-winner [Node.IterativeGet] / [DHTLookup.LookupClaim] paths
// (transport.go) return ONE envelope — the §6.4 (sequence, H_record) DHT store
// winner — which is the wrong selection rule for contested aliases: §6.5 says
// the DHT "does not adjudicate alias races (that is Section 7)", and §7.4 puts
// the burden on verifiers to merge the SET of competing claims different
// storing nodes temporarily hold and apply the (timestamp, pow_hash, tld_id)
// ordering themselves. CollectClaims is that merge: an iterative Kademlia walk
// on K_claim that returns every distinct, signature-valid claim envelope the
// reachable network offers (deduplicated by H_record), instead of one winner.
package dht

import (
	"context"
	"encoding/hex"
	"errors"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/camalolo/freens/internal/claims"
	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/wire"
)

// CollectClaims performs the §7.4 verifier-side step 1 (with the §6.4 GET step
// 2 merge) for alias: an iterative Kademlia lookup on
// K_claim = SHA-256(0x03 || "claim:" || alias) that queries GET_CLOSEST
// (constants.GetClosest) of the closest reachable nodes and returns the SET of
// distinct claim envelopes they offer — not a single winner. Per §7.4 lines
// 602-604, "collect all competing claims nodes offer ... clients SHOULD probe
// GET_CLOSEST nodes and merge": different storing nodes may temporarily hold
// different §6.4 winners for the same K_claim, and only the merged set lets a
// verifier run the §7.4 step-3 ordering.
//
// Semantics:
//
//   - The local offer set is the union of the store's single §6.4 winner at
//     K_claim AND this node's §7.4 top-2 claim pool (claims_pool.go) — this
//     node may itself be one of the storing nodes, and the pool may hold a
//     competitor the single-slot store dropped.
//   - Every envelope offered by a probed peer must decode and pass
//     env.VerifySignature (§6.4: caching nodes never mutate envelopes; a
//     signature-failing envelope is dropped, not fatal).
//   - Deduplication is by H_record (SHA-256 of the canonical envelope), so the
//     same claim republished by several nodes counts once.
//   - The iterative walk probes ALPHA contacts per round with the same
//     lookupProbeTimeout budget and §6.2 dead-contact eviction as
//     IterativeGet; per-peer failures are swallowed (the set simply lacks that
//     peer's offer). On convergence a final §6.4-step-2 merge re-probes the
//     GET_CLOSEST closest REACHABLE nodes — idempotent under dedupe, but it is
//     the letter of the spec and guards the case where late-discovered close
//     contacts were not yet queried.
//   - The returned slice is sorted by H_record so callers see a stable order;
//     §7.4 selection must be order-independent regardless (and is — the
//     (timestamp, pow_hash, tld_id) tuple is a total order).
//
// It returns (nil, nil, nil) when neither the local store nor any reachable peer
// offers a claim envelope; a non-nil error only for caller-input problems
// (invalid alias) — network failures degrade to a (possibly empty) set.
//
// The SECOND return value is the CONVERGED WITNESS SET for the alias (v0.7.0,
// the §7.3 WITNESS_SET membership enforcement): when the walk heard from at
// least constants.WitnessSet (8) distinct reachable nodes, it is the
// hex(NodeID) set of the 8 closest REACHED contacts to K_claim — the same set
// a converged Kademlia walk names on any honest node, and what a verifier
// restricts the §7.3 quorum to (claims.HasQuorum). A sparse view (< 8
// reachable nodes — e.g. the small beta fleet) yields nil: the membership
// check is silently NOT enforced rather than enforced against a set an
// eclipse or a young table would skew. See DHTLookup.CollectClaimsWithWitnesses
// for the resolver-side plumbing.
//
// Full §7.4 filtering (structural validity, PoW, witness quorum, ordering,
// winner selection) is the RESOLVER's job (§6.5: the DHT does not adjudicate);
// this method only collects and signature-checks.
func (n *Node) CollectClaims(ctx context.Context, alias string) ([]*wire.SignedEnvelope, map[string]bool, error) {
	aliasN, err := naming.ValidateAlias(alias)
	if err != nil {
		return nil, nil, err
	}
	key, err := KeyForClaim(aliasN)
	if err != nil {
		return nil, nil, err
	}

	collected := make(map[string]*wire.SignedEnvelope) // H_record → envelope
	add := func(env *wire.SignedEnvelope) {
		if env == nil || env.Record == nil || !env.VerifySignature() {
			return
		}
		h, herr := env.RecordHash()
		if herr != nil {
			return
		}
		collected[string(h)] = env
	}

	// The local offer set joins the merge (this node may be a K_claim
	// storer): the store's §6.4 winner AND the §7.4 top-2 claim pool (which
	// may hold the competitor the single-slot store dropped). Pass n.now()
	// so a claim past expires+grace is not offered (§6.4 eviction).
	if env, _ := n.store.Get(key, n.now()); env != nil {
		add(env)
	}
	for _, env := range n.claims.Top2(key) {
		add(env)
	}

	shortlist := append([]*NodeContact(nil), n.rt.Closest(key, constants.K)...)
	if len(shortlist) == 0 {
		return sortedByRecordHash(collected), nil, nil // island: local copy only.
	}
	queried := make(map[string]bool, len(shortlist))
	answered := make(map[string]*NodeContact, len(shortlist)) // reachable nodes
	probesFailed := 0
	probesThrottled := 0
	batchSize := constants.Alpha

	for round := 0; round < maxLookupRounds; round++ {
		// Nearest-first so the ALPHA un-queried we pick are the closest.
		sort.SliceStable(shortlist, func(i, j int) bool {
			return CompareDistance(key, shortlist[i].NodeID, shortlist[j].NodeID) < 0
		})
		now := n.now()
		var batch []*NodeContact
		for _, c := range shortlist {
			if queried[string(c.NodeID)] {
				continue
			}
			if n.penalized(c.NodeID, now) {
				continue // recently-failed corpse: skip (issue #1 churn)
			}
			batch = append(batch, c)
			if len(batch) >= batchSize {
				break
			}
		}
		if len(batch) == 0 {
			break // every known contact queried or penalized: converged.
		}

		type res struct {
			envs  []*wire.SignedEnvelope // every offer (§7.4 `envelopes` + legacy `envelope`)
			nodes []*NodeContact
			err   error // probe failure (drives §6.2 eviction)
		}
		results := make([]res, len(batch))
		var wg sync.WaitGroup
		for i, c := range batch {
			queried[string(c.NodeID)] = true
			wg.Add(1)
			go func(i int, c *NodeContact) {
				defer wg.Done()
				// Same probe budget as IterativeGet: a peer that cannot
				// answer a tiny UDP get within lookupProbeTimeout is
				// effectively unavailable.
				pctx, cancel := context.WithTimeout(ctx, lookupProbeTimeout)
				defer cancel()
				es, ns, err := n.getFromPeer(pctx, key, c)
				results[i] = res{es, ns, err}
			}(i, c)
		}
		wg.Wait()

		roundAnswered := 0
		for i, r := range results {
			// §12 throttle: alive but withholding (see getFromPeer) — not a
			// §6.2 failure, no eviction, counts as answered; the empty-result
			// classification below treats it as non-authoritative.
			if errors.Is(r.err, ErrThrottled) {
				probesThrottled++
				answered[string(batch[i].NodeID)] = batch[i]
				roundAnswered++
				continue
			}
			// §6.2 failure handling, identical to IterativeGet: evict a
			// contact whose probe failed (unless the caller cancelled) and
			// penalize it for deadPenaltyWindow so later walks skip it.
			if r.err != nil && !errors.Is(r.err, context.Canceled) && ctx.Err() == nil {
				probesFailed++
				n.rt.Remove(batch[i].NodeID)
				n.markDead(batch[i].NodeID, n.now())
				n.log.Debug("dht: claims lookup evicted unresponsive contact", "addr", batch[i].Addr, "err", r.err)
				continue
			}
			if r.err == nil {
				answered[string(batch[i].NodeID)] = batch[i]
				roundAnswered++
			}
			for _, nc := range r.nodes {
				n.learnContact(nc)
				if !contactIn(shortlist, nc.NodeID) {
					shortlist = append(shortlist, nc)
				}
			}
			for _, e := range r.envs {
				add(e)
			}
		}
		// Adaptive batch, same rationale as IterativeGet (issue #1).
		if roundAnswered == 0 {
			batchSize *= 2
			if batchSize > constants.K {
				batchSize = constants.K
			}
		}
	}

	// §6.4 GET step 2 / §7.4 step 1 final merge: "the client queries
	// GET_CLOSEST = 4 of the closest reachable nodes for their envelopes".
	// The walk above already asked each of them once; the re-probe is
	// idempotent under H_record dedupe and keeps this path literally on-spec.
	reachable := make([]*NodeContact, 0, len(answered))
	for _, c := range answered {
		reachable = append(reachable, c)
	}
	sort.SliceStable(reachable, func(i, j int) bool {
		return CompareDistance(key, reachable[i].NodeID, reachable[j].NodeID) < 0
	})
	if len(reachable) > constants.GetClosest {
		reachable = reachable[:constants.GetClosest]
	}
	var finalsThrottled, finalsFailed int32 // atomic; merged after fwg.Wait
	finals := make([][]*wire.SignedEnvelope, len(reachable))
	var fwg sync.WaitGroup
	for i, c := range reachable {
		fwg.Add(1)
		go func(i int, c *NodeContact) {
			defer fwg.Done()
			pctx, cancel := context.WithTimeout(ctx, lookupProbeTimeout)
			defer cancel()
			envs, _, err := n.getFromPeer(pctx, key, c)
			switch {
			case err == nil:
				finals[i] = envs
			case errors.Is(err, ErrThrottled):
				// §12: answer withheld — the final merge did not interrogate
				// this holder (counted for the classification below).
				atomic.AddInt32(&finalsThrottled, 1)
			default:
				// Probe failure in the final merge: same non-authoritative
				// consequence as a walk failure below.
				atomic.AddInt32(&finalsFailed, 1)
			}
		}(i, c)
	}
	fwg.Wait()
	probesThrottled += int(atomic.LoadInt32(&finalsThrottled))
	probesFailed += int(atomic.LoadInt32(&finalsFailed))
	for _, envs := range finals {
		for _, e := range envs {
			add(e)
		}
	}

	// Degraded-miss classification (issue #1): an EMPTY collected set with
	// probe failures — or §12-throttled holders whose "held or not" answer
	// was withheld — is not an authoritative "nobody claims this alias": the
	// resolver must retry (SERVFAIL) rather than negative-cache an NXDOMAIN
	// for an alias whose claim holders were alive all along.
	if len(collected) == 0 && (probesFailed > 0 || probesThrottled > 0) {
		return nil, nil, ErrDegradedMiss
	}
	return sortedByRecordHash(collected), convergedWitnessSet(answered, key), nil
}

// convergedWitnessSet names the §7.3 WITNESS_SET (the WitnessSet = 8 closest
// nodes to K_claim) as this converged walk saw it: answered is every REACHED
// contact (replies + §12-throttled-but-alive), key is K_claim. Fewer than
// WitnessSet reachable contacts yields nil — the set would say more about
// table sparsity (or an eclipse) than about the network, and the resolver
// treats nil as "membership unenforced" rather than rejecting everything.
func convergedWitnessSet(answered map[string]*NodeContact, key []byte) map[string]bool {
	if len(answered) < constants.WitnessSet {
		return nil
	}
	reached := make([]*NodeContact, 0, len(answered))
	for _, c := range answered {
		reached = append(reached, c)
	}
	sort.SliceStable(reached, func(i, j int) bool {
		return CompareDistance(key, reached[i].NodeID, reached[j].NodeID) < 0
	})
	set := make(map[string]bool, constants.WitnessSet)
	for _, c := range reached[:constants.WitnessSet] {
		set[hex.EncodeToString(c.NodeID)] = true
	}
	return set
}

// StorageKeys returns every DHT key an envelope legitimately lives at:
//
//   - the record's own key (K_tld for a TLD-root name, K_name otherwise);
//   - AND, for a claim-bearing TLD record (field 11 non-empty), K_claim of the
//     embedded claim's alias (§7.4 / C.1: the envelope is published at BOTH
//     K_tld and K_claim).
//
// It is the single canonical seeding rule: cmd/freens' -load seeder uses it so
// a persisted store (whose files are named <key>.cbor by PersistTo) reloads
// every key — deriving the key from the record name alone would drop K_claim
// and break alias resolution after every restart (the claim envelope is a
// TLD-root record, so its name-derived key is K_tld).
func StorageKeys(env *wire.SignedEnvelope) ([][]byte, error) {
	if env == nil || env.Record == nil {
		return nil, errors.New("dht: nil envelope")
	}
	nameKey, err := KeyForWireName(env.Record.Name)
	if err != nil {
		return nil, err
	}
	keys := [][]byte{nameKey}
	if len(env.Record.Claim) > 0 {
		if claim, aerr := claims.DecodeAliasClaim(env.Record.Claim); aerr == nil {
			if ck, kerr := KeyForClaim(claim.Alias); kerr == nil {
				keys = append(keys, ck)
			}
		}
	}
	return keys, nil
}

// sortedByRecordHash flattens a H_record-keyed set into a slice ordered by
// H_record, giving CollectClaims a stable output order (§7.4 selection must
// not depend on it, but tests and logs may).
func sortedByRecordHash(set map[string]*wire.SignedEnvelope) []*wire.SignedEnvelope {
	out := make([]*wire.SignedEnvelope, 0, len(set))
	for _, env := range set {
		out = append(out, env)
	}
	sort.Slice(out, func(i, j int) bool { return setKeyLess(out[i], out[j]) })
	return out
}

// setKeyLess orders two envelopes by their H_record (both assumed computable;
// on a hash error the comparison degrades to false, which sort tolerates).
func setKeyLess(a, b *wire.SignedEnvelope) bool {
	ha, err1 := a.RecordHash()
	hb, err2 := b.RecordHash()
	if err1 != nil || err2 != nil {
		return false
	}
	return string(ha) < string(hb)
}

// CollectClaims is the ClaimSetResolver side of [DHTLookup]: it merges the
// local K_claim envelope with the network-collected set (§7.4 verifier step 1,
// "collect all competing claims nodes offer ... probe GET_CLOSEST nodes and
// merge") so the resolver can apply the full §7.4 ordering. It structurally
// satisfies the resolver's optional resolver.ClaimSetResolver interface (the
// import would cycle, so the satisfaction is structural — same as LookupClaim
// vs resolver.ClaimResolver).
//
// Local-first, like [DHTLookup.Lookup]: the local store's copy is always
// included, then the network walk runs under the same dhtLookupTimeout budget.
//
// Cache-back is EMPTY-SLOT-ONLY on the single-slot EnvelopeStore: if this
// node holds no envelope at K_claim, the first collected envelope is cached
// (offline replay / island resilience); if the slot is occupied — by this
// node's own published offer or a previous cache — nothing is written. A
// blind cache-back Put at equal sequence resolves by the H_record tie-break
// and DISPLACES the storer's own offer, collapsing the network-wide set the
// next collector merges (verified live: a two-node split converged to one
// envelope after the first resolver pass).
//
// The multi-claim home is the ClaimPool instead (§7.4 line 602-604: "storing
// nodes keep the top 2 by ordering"): EVERY collected envelope is Offered
// into the node's pool. Because the pool holds TWO claims per K_claim, a
// collector-side cache-back cannot collapse a contested split — the second
// claim has its own slot and is re-offered to the next verifier via the
// `envelopes` extension of hGet.
//
// A network-collection error is propagated — with only a local view the §7.4
// merge would silently degrade to the single-claim behavior, which is exactly
// what ClaimSetResolver exists to avoid.
//
// Resolvers wanting full §7.4 contested-alias semantics use this method;
// LookupClaim remains the single-winner legacy path (§6.4 selection only).
//
// This is the SET-ONLY projection of [DHTLookup.CollectClaimsWithWitnesses]
// (it drops the converged witness set); see that method for the v0.7.0
// §7.3 witness-set membership enforcement the resolver can layer on top.
func (l *DHTLookup) CollectClaims(ctx context.Context, alias string, now int64) ([]*wire.SignedEnvelope, error) {
	envs, _, err := l.CollectClaimsWithWitnesses(ctx, alias, now)
	return envs, err
}

// CollectClaimsWithWitnesses is [DHTLookup.CollectClaims] plus the CONVERGED
// WITNESS SET of the same walk: the hex(NodeID) set of the WitnessSet = 8
// closest REACHED nodes to K_claim, or nil when the reachable view is too
// sparse to name a set (small fleets, partitions, eclipses — nil means the
// resolver must NOT enforce §7.3 membership, not that it must reject).
//
// It structurally satisfies the resolver's optional
// resolver.ClaimSetWithWitnesses interface (same structural-satisfaction
// trick as CollectClaims vs resolver.ClaimSetResolver — the import would
// cycle). A resolver that has the set passes it to claims.VerifyFull, which
// then counts only witnesses among the WITNESS_SET — closing the
// fabricated-quorum hole (v0.7.0): five keys minted out of thin air are not
// among the network's actual closest nodes, so their attestations no longer
// count toward the quorum, whatever their timestamps claim.
//
// Residual, documented: an adversary that BOTH grinds NodeIDs into the true
// witness set AND forges a self-consistent (backdated) quorum still wins the
// §7.4 ordering — that is the protocol's fundamental Sybil bound (§12),
// priced by the grinding cost, not eliminated.
func (l *DHTLookup) CollectClaimsWithWitnesses(ctx context.Context, alias string, now int64) ([]*wire.SignedEnvelope, map[string]bool, error) {
	key, err := KeyForClaim(alias)
	if err != nil {
		return nil, nil, err
	}
	collected := make(map[string]*wire.SignedEnvelope)
	add := func(env *wire.SignedEnvelope) {
		if env == nil || env.Record == nil || !env.VerifySignature() {
			return
		}
		h, herr := env.RecordHash()
		if herr != nil {
			return
		}
		collected[string(h)] = env
	}

	// Local store first (§7.4: this node's own offer joins the merge).
	if env, _ := l.store.Get(key, now); env != nil {
		add(env)
	}
	if l.node == nil {
		return sortedByRecordHash(collected), nil, nil
	}

	c, cancel := context.WithTimeout(ctx, dhtLookupTimeout)
	defer cancel()
	envs, witnessSet, err := l.node.CollectClaims(c, alias)
	if err != nil && !errors.Is(err, ErrDegradedMiss) {
		return nil, nil, err
	}
	for _, env := range envs {
		add(env)
	}
	// A degraded walk (ErrDegradedMiss) with a LOCAL claim still serves
	// the local view; only an empty-everywhere degrade propagates the
	// sentinel (the resolver retries instead of negative-caching). A
	// degraded walk also yields no witness set (it could not interrogate
	// the holders, so it cannot honestly name the WITNESS_SET).
	if errors.Is(err, ErrDegradedMiss) && len(collected) == 0 {
		return nil, nil, err
	}
	if errors.Is(err, ErrDegradedMiss) {
		witnessSet = nil
	}
	set := sortedByRecordHash(collected)
	// §7.4 "storing nodes keep the top 2 by ordering": every collected claim
	// is Offered into the node's ClaimPool (the multi-claim home — see the
	// doc comment for why the single-slot store cache-back below stays
	// empty-slot-only).
	if l.node != nil {
		for _, env := range set {
			l.node.claims.Offer(key, env)
		}
	}
	// Empty-slot-only cache-back (see doc comment): an occupied slot is never
	// displaced — that is what collapses a contested split.
	if len(set) > 0 && !l.store.Has(key, now) {
		_, _ = l.store.Put(key, set[0], now, true)
	}
	return set, witnessSet, nil
}
