// Package wire — recovery_walk.go implements the §8.4-recovery-aware variant
// of the §8.3 transfer walk (specifications.md lines 689-707): the authority
// chain verifier that accepts a chain[0] hand-off which is a §8.3 TRANSFER, a
// §8.4 RECOVERY, or any MIX of the two along the prev_hash lineage.
//
// §8.4 (lines 691-701): "If the primary key is lost but a `recovery` policy
// exists: 1. Any `threshold`-of-`keys` sign a recovery declaration ...
// published like any record (sequence +1, `recovery` fields updated) ...
// 3. After the timelock elapses with no cancellation, the recovery record
// takes effect and the new primary key owns the name." The recovery record R2
// therefore has Owner = Signer = K2 (the NEW primary signs — the opposite of
// §8.3, where the PREVIOUS owner signs), Sequence = R1.Sequence+1, PrevHash =
// H_record(R1), and its validity is decided by off-record EVIDENCE
// (recovery.go's RecoveryEvidence): VerifyRecovery(R1.Record.Recovery, E,
// H_record(R1), now >= E.NotBefore).
//
// Consequence for §3.4: a recovery root has Signer == Owner, so it takes the
// plain verifier's "ordinary" branch — and FAILS it, because the name still
// carries the ORIGINAL tld_id (crypto.TldID(K2) != tld_id): the root is not
// self-certifying for its new owner. Proving it requires walking prev_hash
// links back to the self-certifying origin, dispatching per hop on the
// signer/owner relationships:
//
//   - TRANSFER hop (§8.3): cur.Signer == prev.Record.Owner — the previous
//     owner signed the hand-off; no evidence required.
//   - RECOVERY hop (§8.4): cur.Signer == cur.Record.Owner (the new primary
//     signs) AND prev.Record.Owner != cur.Signer (and it IS a key change) —
//     requires fetchEvidence(H_record(cur)) to yield evidence satisfying
//     VerifyRecovery(prev.Record.Recovery, ev, H_record(prev), now), where
//     `now` is the CALLER's clock: the §8.4 timelock (now >= NotBefore) is a
//     resolve-time decision, so the cancellation race (§8.4 step 2 — the
//     current primary cancels by publishing a higher-sequence record) is
//     settled by the sequence rule before any of this is consulted.
package wire

import (
	"bytes"

	"github.com/laurent/freens/internal/constants"
)

// VerifyAuthorityChainWithHandoffs verifies chain[0] authority when it is a
// §8.3 transfer OR §8.4 recovery hand-off (or a MIX along the walk), by
// walking PrevHash links back to a self-certifying root.
//
// When chain[0] already satisfies the §3.4 root rule (signer == owner of a
// self-certifying TLD record) the behaviour is byte-identical to
// [VerifyAuthorityChain] / [VerifyAuthorityChainWithTransfers] and neither
// fetch callback is invoked — so every plain and pure-transfer chain that the
// older verifiers accept is accepted here unchanged (backward compatibility).
// A §8.3 transfer root (Signer != Owner) walks exactly as in
// VerifyAuthorityChainWithTransfers; fetchEvidence is simply never needed for
// its hops. When chain[0] is signer==owner but NOT self-certifying (a recovery
// hand-off: the name carries the original tld_id), ONLY this walker can prove
// the chain, via the §8.4 per-hop evidence check.
//
// Per hop, walking cur -> prev = fetchPredecessor(cur.Record.PrevHash):
//
//   - link checks (shared with the §8.3 walk): cur.Record.PrevHash is a
//     32-byte H_record; prev is non-nil with a valid signature; prev.Record
//     .Sequence+1 == cur.Record.Sequence (§8.2/§8.3 "sequence: prev + 1",
//     exact); prev.Record.Name bytewise-equals cur.Record.Name (§4.4 rule 6);
//     VerifyChainLink(cur, prev) holds (PrevHash == H_record(prev));
//     predecessors are exempt from the liveness window (audit history, same
//     as transfers — only chain[0] must be live, via the caller's
//     [IsBasicValid]);
//   - transfer-or-recovery dispatch (see the package comment), with recovery
//     hops additionally requiring fetchEvidence(H_record(cur)) to return
//     evidence whose NewOwnerPK == cur.Record.Owner (the declaration names
//     THIS hand-off's new primary) and VerifyRecovery(prev.Record.Recovery,
//     ev, H_record(prev), now) to hold — quorum over the predecessor's §5.4
//     policy AND the §8.4 timelock gate against the caller's `now`.
//
// The walk is capped at transferMaxDepth (16) hops. The terminal predecessor
// must satisfy the self-certifying root rule (signer == owner, zero labels,
// crypto.TldID(owner) == tld_id in the name — the shared checks from
// transfer.go). fetchPredecessor / fetchEvidence returning (nil, nil) or an
// error means the link is unavailable: the chain is unverifiable. A nil
// fetchEvidence makes every recovery hop unverifiable (transfers still
// verify). Non-raising: every failure path yields false.
func VerifyAuthorityChainWithHandoffs(chain []*SignedEnvelope, fetchPredecessor func([]byte) (*SignedEnvelope, error), fetchEvidence func([]byte) (*RecoveryEvidence, error), now uint64) bool {
	if !chainWellFormed(chain) {
		return false
	}
	root := chain[0]
	if !selfCertifiedTldRoot(root) {
		// A hand-off root (§8.3 transfer: signer != owner, or §8.4 recovery:
		// signer == owner but tld_id != H(signer)): walk the prev_hash lineage
		// back to the self-certifying origin.
		if !verifyHandoffWalk(root, fetchPredecessor, fetchEvidence, now) {
			return false
		}
	}
	return verifyDescents(chain)
}

// verifyHandoffWalk walks the §8.3/§8.4 hand-off chain backwards from tip via
// fetchPredecessor until a record satisfying the self-certifying TLD-root rule
// is reached, dispatching each hop to the transfer or recovery authorization
// check. Unlike verifyTransferWalk (which stops at the first signer == owner
// record), the walk continues THROUGH recovery records — a §8.4 root has
// signer == owner yet is not self-certifying — so the loop condition is the
// root rule itself. See VerifyAuthorityChainWithHandoffs for the per-hop
// rules.
func verifyHandoffWalk(tip *SignedEnvelope, fetchPredecessor func([]byte) (*SignedEnvelope, error), fetchEvidence func([]byte) (*RecoveryEvidence, error), now uint64) bool {
	cur := tip
	for depth := 0; !selfCertifiedTldRoot(cur); depth++ {
		if depth >= transferMaxDepth {
			return false // hand-off lineage longer than the walk budget.
		}
		// (a) prev_hash must name a predecessor (32-byte H_record, §4.2).
		if len(cur.Record.PrevHash) != constants.SHA256Len {
			return false
		}
		prev, err := fetchPredecessor(cur.Record.PrevHash)
		if err != nil || prev == nil || prev.Record == nil {
			return false // missing predecessor: unverifiable.
		}
		// (b) the predecessor must be authentic and chain-linked (the same
		// shared checks as the §8.3 walk).
		if !prev.VerifySignature() {
			return false
		}
		if prev.Record.Sequence+1 != cur.Record.Sequence {
			return false // §8.2/§8.3: sequence = prev + 1, exactly.
		}
		if !bytes.Equal(prev.Record.Name, cur.Record.Name) {
			return false // same name, bytewise (§4.4 rule 6).
		}
		if !VerifyChainLink(cur, prev) {
			return false // prev_hash != H_record(prev).
		}
		// (c) authorization: transfer OR recovery hop.
		if bytes.Equal(cur.Signer, prev.Record.Owner) {
			// §8.3 transfer hop: signed by the CURRENT owner at hand-off time
			// (the previous record's owner); nothing more is required.
		} else if bytes.Equal(cur.Signer, cur.Record.Owner) && !bytes.Equal(prev.Record.Owner, cur.Signer) {
			// §8.4 recovery hop: the NEW primary key signs its own record and
			// the owner actually changed — quorum evidence required.
			if !verifyRecoveryHop(cur, prev, fetchEvidence, now) {
				return false
			}
		} else {
			// Signed neither by the previous owner (§8.3) nor — as the new
			// owner — by a quorum-backed key (§8.4): unauthorized.
			return false
		}
		cur = prev
	}
	// (d) termination: the loop only exits on the §3.4 root rule.
	return true
}

// verifyRecoveryHop checks the §8.4 evidence for one recovery hop cur <- prev:
// fetchEvidence(H_record(cur)) must produce evidence (the evidence table is
// keyed by the PUBLISHED record it accompanied, i.e. the recovery record
// itself), whose NewOwnerPK names cur's owner/signer, and whose quorum
// satisfies prev's §5.4 policy over the message anchored at H_record(prev) —
// the record being recovered — with the §8.4 timelock gated on the caller's
// now. Non-raising.
func verifyRecoveryHop(cur, prev *SignedEnvelope, fetchEvidence func([]byte) (*RecoveryEvidence, error), now uint64) bool {
	if fetchEvidence == nil {
		return false // no evidence source: a recovery hop is unprovable.
	}
	hCur, err := cur.RecordHash()
	if err != nil {
		return false
	}
	ev, err := fetchEvidence(hCur)
	if err != nil || ev == nil {
		return false // evidence unavailable: unverifiable.
	}
	// The declaration must hand the name to THIS record's new primary key
	// (replaying another declaration onto an unrelated record must fail).
	if !bytes.Equal(ev.NewOwnerPK, cur.Record.Owner) {
		return false
	}
	hPrev, err := prev.RecordHash()
	if err != nil {
		return false
	}
	// Quorum over prev's policy + §8.4 timelock at the caller's clock.
	return VerifyRecovery(prev.Record.Recovery, ev, hPrev, now)
}
