// Package dht — claims_tombstone.go implements the §8.4 ALIAS_REUSE_DELAY
// enforcement (v0.8.0; the constant existed since the spec draft but nothing
// could enforce it — every claim carrier dies at expires+grace and nothing
// alias-keyed survived).
//
// # The tombstone is the expired claim envelope itself
//
// A claim carrier published at K_claim is self-contained evidence: the
// envelope signature (claimant-bound), the embedded AliasClaim's PoW, and
// the ≥ W witness attestations are all TIMELESS — they verify identically
// the day the record expires and 29 days later. So "this alias was held and
// its lease died at T" needs no new wire format: it is the envelope, with
// its signed `expires` playing the role of the death date. During
//
//	expires <= now < expires + ALIAS_REUSE_DELAY
//
// the alias is in its REUSE WINDOW and new claims for it are refused (§8.4:
// "the alias becomes claimable again after ALIAS_REUSE_DELAY (30 days past
// the claim's own expiry)").
//
// # Why this cannot be forged (the rigged-node bar)
//
// Every check in reuseWindowEnd is content verification over signed data:
// to manufacture a tombstone for an alias, an attacker must produce a
// PoW-valid claim for THAT alias carrying ≥ W=5 distinct in-band witness
// attestations inside the corroboration band — i.e. it must actually have
// registered the alias. A rogue node can pool, serve, and re-serve whatever
// it wants; nothing it asserts extends or fabricates a window. (The pool's
// collect-path screen checks PoW only, which is why EVERY consumer of a
// pooled envelope as tombstone evidence must run the full VerifyFull here —
// a quorum-less PoW-valid fabrication pooled into a witness must not lock
// the alias: that would be the denial-of-registration attack the window
// itself must not enable.)
//
// # Renewal vs re-claim (v0.9.1: same identity is always continuity)
//
// A fresh carrier of a STILL-LIVE claim is a renewal (overlap: created
// before the predecessor's expires). v0.8.0 additionally refused a
// same-identity carrier created AFTER the predecessor expired — a
// "resurrection" — on the theory that re-wrapping the old identity
// without a new witness round was a back door. Found live on the LAN
// fleet (2026-08-22) that the opposite is true: only the claimant key
// can sign a same-identity carrier, and it carries the exact claim
// (same PoW, same attestations) that registered the alias, so a
// resurrection IS ownership continuity — while refusing it locked every
// alias whose auto-renewal arrived one tick late (the pools retain every
// dead generation, so after the first generation's death even perfectly
// overlapping later renewals were refused against the OLDER tombstone,
// deadlocking the whole namespace into ALIAS_REUSE_DELAY). The window
// now refuses only DIFFERENT-identity claims; the witness path is
// unchanged (the §6.3 claim-ts gate already refuses re-presentations
// that old).
//
// A carrier with revoke = true (§8.5) is NOT a tombstone: revocation is a
// deliberate death, not an abandoned one, and must not freeze the alias for
// 30 days against the owner who revoked-and-renames.
//
// # Availability (best-effort, like everything DHT)
//
// Enforcement runs on the envelopes storing and collecting nodes still
// offer: the ClaimPool retains dead-in-window claims (Sweep drops them only
// past the window; PersistClaimPoolTo/RetainClaimPool survive restarts) and
// hGet's `envelopes` extension re-serves them to collectors. A network that
// retains no copy of the dead claim cannot distinguish the window — the
// same R-replication availability argument as record storage, and the
// reason the resolver-side lock also verifies everything itself instead of
// trusting the pool's screen.
package dht

import (
	"bytes"
	"errors"

	"github.com/camalolo/freens/internal/claims"
	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/wire"
)

// ErrAliasReuseWindow is returned by CollectWitnesses when every candidate
// witness refused to co-sign because the alias is inside its §8.4 reuse
// window (an expired claim's tombstone is still in force). Registrants
// surface it as "retry after the window", not as "network too small".
var ErrAliasReuseWindow = errors.New("dht: alias is inside its §8.4 reuse window (expired claim, ALIAS_REUSE_DELAY not elapsed)")

// reuseWindowEnd returns the §8.4 reuse-window end time (expires +
// AliasReuseDelay) when env is a DEAD-but-content-valid claim envelope for
// alias whose window is still open at now, and 0 otherwise. "Content-valid"
// is the full §7.4 step-2 filter minus liveness: envelope signature, claim
// decode + alias match, claim-timestamp sanity, claimant binding (signer ==
// claimant pk, TLD-record shape, tld_id match), PoW, and the ≥ W DISTINCT
// CORROBORATING witness quorum (witnessSet nil: the WITNESS_SET membership
// restriction is deliberately not applied to tombstones — the converged set
// names today's closest nodes, which churns over a 30-day window and would
// un-evidence honestly-witnessed old claims; binding, distinctness, and the
// corroboration band all still apply).
func reuseWindowEnd(env *wire.SignedEnvelope, alias string, now int64) int64 {
	if env == nil || env.Record == nil || !env.VerifySignature() || env.IsRevoked() {
		return 0 // §8.5: deliberate death is not a tombstone
	}
	claim, cerr := claims.DecodeAliasClaim(env.Record.Claim)
	if cerr != nil {
		return 0
	}
	aliasN, aerr := naming.ValidateAlias(alias)
	if aerr != nil || claim.Alias != aliasN {
		return 0
	}
	// §7.4 anti-forgery: a future-dated claim is garbage today too.
	if int64(claim.Timestamp) > now+int64(constants.SkewTolerance) {
		return 0
	}
	// Claimant binding: the carrier is the claimant's own TLD record.
	if !bytes.Equal(env.Signer, claim.ClaimantPK) {
		return 0
	}
	labels, tldID, derr := naming.DecodeWireName(env.Record.Name)
	if derr != nil || len(labels) != 0 || !bytes.Equal(tldID, claim.TldID) {
		return 0
	}
	// Full §7.4 content screen (PoW + quorum, historical difficulty per
	// A.4's "any historically valid D" letter — no oracle floor applies to
	// a claim mined days ago).
	if !claims.VerifyFull(claim, claims.InferDifficulty, nil, constants.W) {
		return 0
	}
	exp := int64(env.Record.Expires)
	if now < exp {
		return 0 // still alive: an ordinary competing claim, not a tombstone
	}
	if now >= exp+int64(constants.AliasReuseDelay) {
		return 0 // window closed: the alias is claimable again
	}
	return exp + int64(constants.AliasReuseDelay)
}

// claimReuseRefusal answers whether a claim presentation for alias must be
// refused under the §8.4 reuse window, given the incoming claim's identity
// (its prefix hash) and — when the presentation carries an envelope, the
// hPut path — the envelope itself. It scans this node's ClaimPool for the
// alias's K_claim and consults every candidate as potential tombstone
// evidence (fully re-verified; see reuseWindowEnd):
//
//   - a candidate with a DIFFERENT claim identity inside an open window
//     refuses the presentation (a new claim while the alias is cooling off);
//
//   - a candidate with the SAME identity is the incoming claim's own dead
//     predecessor: NEVER a refusal (v0.9.1). A same-identity carrier can
//     only be signed by the claimant key itself, and it carries the exact
//     claim — same PoW, same attestations — that registered the alias:
//     whether it overlaps the dead lease (a renewal) or post-dates it (a
//     resurrection after a lapse) is ownership continuity either way, not
//     a re-claim. Refusing it (v0.8.0's "resurrection hole" rule) locked
//     every alias whose owner's renewal arrived one tick late — found live
//     on the LAN fleet (2026-08-22: whole-namespace NXDOMAIN after the
//     first in-place renewal generation died in the pools).
// It returns the refusing window's end time (> 0 ⇒ refuse), or 0.
func (n *Node) claimReuseRefusal(alias string, incomingPrefixHash []byte, now int64) int64 {
	if n == nil || n.claims == nil {
		return 0
	}
	aliasN, err := naming.ValidateAlias(alias)
	if err != nil {
		return 0
	}
	kClaim, err := KeyForClaim(aliasN)
	if err != nil {
		return 0
	}
	for _, cand := range n.claims.Top2(kClaim) {
		end := reuseWindowEnd(cand, aliasN, now)
		if end == 0 {
			continue // not (valid, dead, in-window) evidence
		}
		candClaim, cerr := claims.DecodeAliasClaim(cand.Record.Claim)
		if cerr != nil {
			continue
		}
		candPH, perr := candClaim.PrefixHash()
		if perr != nil {
			continue
		}
		if bytes.Equal(candPH, incomingPrefixHash) {
			// Same claim identity: the tombstone's own claim, re-carried
			// by its claimant (v0.9.1) — renewal or resurrection, both
			// are ownership continuity. Never refused.
			continue
		}
		// Different identity inside an open window: §8.4 refuses.
		return end
	}
	return 0
}
