// Package wire — transfer.go implements the §8.3 transfer-aware variant of
// the §3.4 authority-chain verifier (specifications.md lines 666-688).
//
// §8.3: "Transferring alice.foo means re-pointing its authority": the
// transfer record has owner = the NEW key, prev_hash = H_record(previous
// signed envelope), sequence = prev + 1, and is signed by the CURRENT owner
// (the previous record's owner). "The network accepts the new record because
// the previous owner — whose key the current authority chain names — signed
// it. ... prev_hash links the transfer into an auditable chain so third
// parties can verify the hand-off history offline."
//
// Consequence for §3.4: VerifyAuthorityChain requires the TLD root of every
// chain to be self-certifying (signer == owner). After a whole-TLD transfer
// (§8.3 lines 686-688) the live TLD root's signer is by construction DIFFERENT
// from its owner (the new owner) — the root was signed by the PREVIOUS owner.
// The chain is still valid, but proving it requires walking prev_hash links
// back through superseded envelopes to the self-certifying origin. That walk
// is what this file adds; the predecessors come from a caller-supplied fetch
// (the DHT superseded-envelope history, see internal/dht history.go).
package wire

import (
	"bytes"

	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/naming"
)

// transferMaxDepth caps how many prev_hash links VerifyAuthorityChainWithTransfers
// will walk from chain[0] towards the self-certifying origin (§8.3 "auditable
// chain"). It bounds the fetch loop against maliciously cyclic or
// unboundedly long synthetic histories; 16 hand-offs far exceeds any
// realistic transfer lineage while keeping verification O(depth) fetches.
const transferMaxDepth = 16

// VerifyAuthorityChainWithTransfers is identical to [VerifyAuthorityChain]
// (§3.4) EXCEPT for the chain[0] root check: when chain[0].Signer !=
// chain[0].Record.Owner — a §8.3 transfer — the root need not be
// self-certifying; instead its prev_hash chain is walked (see below) back to
// a self-certifying TLD root for the ORIGINAL owner. When chain[0].Signer ==
// chain[0].Record.Owner the normal self-certification applies and the
// behaviour is byte-identical to VerifyAuthorityChain (fetchPredecessor is
// never called).
//
// Transfer walk (§8.3 lines 671-684), starting at cur = chain[0], repeated
// while cur.Signer != cur.Record.Owner (at most transferMaxDepth = 16 hops):
//
//   - cur.Record.PrevHash must be present and exactly 32 bytes;
//   - prev := fetchPredecessor(cur.Record.PrevHash) must be non-nil with a
//     valid signature (prev.VerifySignature);
//   - prev.Record.Sequence+1 == cur.Record.Sequence (§8.3 "sequence: prev + 1");
//   - prev.Record.Name bytewise-equals cur.Record.Name (§4.4 rule 6: the
//     chain never changes names — prev_hash is per-name history);
//   - [VerifyChainLink](cur, prev) holds (cur.PrevHash == H_record(prev),
//     §4.4 rule 4);
//   - prev.Record.Owner == cur.Signer — the transfer was signed by the
//     CURRENT owner at that hop, i.e. the previous record's owner (§8.3
//     lines 677-681: "signature: by A7C91... (current owner key)"; "the
//     network accepts the new record because the previous owner ... signed
//     it");
//   - cur = prev, and the walk continues.
//
// Termination success: a record with Signer == Owner that is the
// self-certifying TLD root for its Owner (zero labels, crypto.TldID(owner)
// == tld_id embedded in the name — the same §3.4 root rule as
// VerifyAuthorityChain).
//
// Validity window: historical predecessors are NOT required to be inside
// their created..expires window. §8.3 makes prev_hash an AUDIT chain ("third
// parties can verify the hand-off history offline"); a predecessor is
// evidence of who owned the name at hand-off time, not a live record, and
// superseded envelopes are in any case evicted from live storage on their
// expiry. Only chain[0] must be live — the caller checks it via
// [IsBasicValid] before consulting this verifier.
//
// fetchPredecessor returning (nil, nil) or an error means the predecessor is
// unavailable: the chain is unverifiable and the function returns false.
// Non-raising: every failure path yields false.
func VerifyAuthorityChainWithTransfers(chain []*SignedEnvelope, fetchPredecessor func(prevHash []byte) (*SignedEnvelope, error)) bool {
	if !chainWellFormed(chain) {
		return false
	}
	root := chain[0]
	if bytes.Equal(root.Signer, root.Record.Owner) {
		// Normal case: the root must self-certify exactly as in §3.4.
		if !selfCertifiedTldRoot(root) {
			return false
		}
	} else if !verifyTransferWalk(root, fetchPredecessor) {
		return false
	}
	return verifyDescents(chain)
}

// verifyTransferWalk walks the §8.3 transfer chain backwards from tip via
// fetchPredecessor until a record with Signer == Owner is reached, and
// reports whether that terminal record is the self-certifying TLD root for
// its Owner. See VerifyAuthorityChainWithTransfers for the per-hop rules.
func verifyTransferWalk(tip *SignedEnvelope, fetchPredecessor func(prevHash []byte) (*SignedEnvelope, error)) bool {
	cur := tip
	for depth := 0; !bytes.Equal(cur.Signer, cur.Record.Owner); depth++ {
		if depth >= transferMaxDepth {
			return false // §8.3 audit chain longer than the walk budget.
		}
		// (a) prev_hash must name a predecessor (32-byte H_record, §4.2).
		if len(cur.Record.PrevHash) != constants.SHA256Len {
			return false
		}
		prev, err := fetchPredecessor(cur.Record.PrevHash)
		if err != nil || prev == nil || prev.Record == nil {
			return false // missing predecessor: unverifiable.
		}
		// (b) the predecessor must be authentic and chain-linked.
		if !prev.VerifySignature() {
			return false
		}
		if prev.Record.Sequence+1 != cur.Record.Sequence {
			return false // §8.3: sequence = prev + 1, exactly.
		}
		if !bytes.Equal(prev.Record.Name, cur.Record.Name) {
			return false // same name, bytewise (§4.4 rule 6).
		}
		if !VerifyChainLink(cur, prev) {
			return false // prev_hash != H_record(prev) / sequence not increasing.
		}
		// (c) authorization: the transfer was signed by the previous owner
		// (§8.3 lines 677-681).
		if !bytes.Equal(prev.Record.Owner, cur.Signer) {
			return false
		}
		cur = prev
	}
	// (d) termination: the origin must self-certify (§3.4 root rule).
	return selfCertifiedTldRoot(cur)
}

// chainWellFormed mirrors the structural prefix of [VerifyAuthorityChain]:
// chain length in [1, MaxLabels+1], no nil envelope/record, and every
// signature verifying. Kept in this file (duplicated from wire.go rather
// than shared) so VerifyAuthorityChain itself stays byte-identical.
func chainWellFormed(chain []*SignedEnvelope) bool {
	if len(chain) == 0 {
		return false
	}
	if len(chain) > constants.MaxLabels+1 {
		return false
	}
	for _, env := range chain {
		if env == nil || env.Record == nil {
			return false
		}
		if !env.VerifySignature() {
			return false
		}
	}
	return true
}

// selfCertifiedTldRoot mirrors the chain[0] checks of [VerifyAuthorityChain]:
// signer == owner, the name decodes to ZERO labels, and crypto.TldID(owner)
// equals the tld_id embedded in the name (§3.4 rule 1 — the TLD record is
// signed by PK_tld, and the alias is self-certified by it).
func selfCertifiedTldRoot(env *SignedEnvelope) bool {
	if !bytes.Equal(env.Signer, env.Record.Owner) {
		return false
	}
	rootLabels, rootTldID, err := naming.DecodeWireName(env.Record.Name)
	if err != nil {
		return false
	}
	if len(rootLabels) != 0 {
		return false
	}
	ownerTldID, err := crypto.TldID(env.Record.Owner)
	if err != nil {
		return false
	}
	return bytes.Equal(ownerTldID, rootTldID)
}

// verifyDescents mirrors the i >= 1 hop loop of [VerifyAuthorityChain]
// (§3.4): every child is authorized by its parent — parent.Delegation ==
// child.Signer OR parent.Owner == child.Signer — and the child name is a
// STRICT DESCENDANT of the parent name (same tld_id, more labels, parent's
// display-order labels are the suffix of the child's).
func verifyDescents(chain []*SignedEnvelope) bool {
	for i := 1; i < len(chain); i++ {
		parent := chain[i-1]
		child := chain[i]

		authorized := false
		if len(parent.Record.Delegation) > 0 && bytes.Equal(parent.Record.Delegation, child.Signer) {
			authorized = true
		} else if bytes.Equal(parent.Record.Owner, child.Signer) {
			authorized = true
		}
		if !authorized {
			return false
		}

		pLabels, pTldID, err := naming.DecodeWireName(parent.Record.Name)
		if err != nil {
			return false
		}
		cLabels, cTldID, err := naming.DecodeWireName(child.Record.Name)
		if err != nil {
			return false
		}
		if !bytes.Equal(cTldID, pTldID) {
			return false
		}
		if len(cLabels) <= len(pLabels) {
			return false
		}
		if len(pLabels) > 0 {
			off := len(cLabels) - len(pLabels)
			for j := 0; j < len(pLabels); j++ {
				if cLabels[off+j] != pLabels[j] {
					return false
				}
			}
		}
	}
	return true
}
