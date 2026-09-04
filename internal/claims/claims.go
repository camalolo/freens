// Package claims implements freens alias claims, witness attestations,
// proof-of-work binding, and deterministic collision ordering (specifications.md
// §7, "Registration and Collision Resolution", lines 501-642; AliasClaim and
// WitnessAttestation CBOR records of §7.3 lines 544-578; the registration /
// resolution procedure of §7.4 lines 588-623; and the worked example of
// Appendix C.1 lines 1054-1066).
//
// # PoW prefix — nonce EXCLUDED (authoritative interpretation)
//
// §7.3 line 566-567 calls the PoW "prefix" the canonical CBOR of fields {1..5}
// of AliasClaim. Taken literally that would include field 4 (nonce), which is
// nonsensical — the nonce is precisely the value being searched and cannot be
// part of its own hash input. Appendix C.1 line 1057-1058 is the authoritative
// worked example and resolves the ambiguity:
//
//	SHA-256(cbor{alias, tld_id, ts, claimant_pk} || nonce) < 2^232
//
// i.e. the prefix is the canonical CBOR of the *identity* fields
// {1:alias, 2:tld_id, 3:timestamp, 5:claimant_pk} — field 4 (nonce) is
// intentionally EXCLUDED. The literal {1..5} in §7.3 is loose prose; C.1 is
// normative. (*AliasClaim).Prefix documents the field-4 skip.
//
// # Deterministic ordering (§7.4 step 3)
//
// Surviving claims are ordered ascending by the lexicographic tuple
// (timestamp, pow_hash, tld_id): earliest asserted time wins; ties are broken
// by the lower PoW hash (a public lottery), then by the lower TLD ID. This
// total order is computable by any client from claim contents alone, yielding
// convergence without consensus. Ties on (timestamp, pow_hash) are impossible
// between distinct claimants because tld_id = SHA-256(claimant_pk) differs.
//
// This package is a leaf: it imports only internal/constants, internal/crypto,
// internal/naming and github.com/fxamacker/cbor/v2. It deliberately does NOT
// import internal/wire (wire carries a claim as an opaque cbor.RawMessage in
// its field 11 precisely to avoid a cycle).
package claims

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync/atomic"

	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/naming"
	"github.com/fxamacker/cbor/v2"
)

// canonicalEM is the RFC 8949 §4.2 "core deterministic" CBOR encoding mode:
// map keys sorted in canonical order (length-first then bytewise; ascending
// numeric for this schema's integer keys), minimum-length integers, no
// indefinite-length, no duplicates. It is the mode used for every canonical
// byte string this package emits (Prefix, CanonicalBytes).
//
// NilContainers is set to NilContainerAsEmpty (overriding the default
// NilContainerAsNull) so a nil AliasClaim.Witnesses slice emits CBOR `[]`
// (empty array) rather than `null`, matching the Python reference (which
// always emits `[]`). MineAliasClaim defensively sets Witnesses to a non-nil
// empty slice, but a directly-constructed or decoded claim may carry nil;
// this encoder guarantees wire-stable output in both cases.
var canonicalEM = func() cbor.EncMode {
	opts := cbor.CoreDetEncOptions()
	opts.NilContainers = cbor.NilContainerAsEmpty
	em, _ := opts.EncMode()
	return em
}()

// PoWDifficultyInit is the default PoW difficulty (bits) used by VerifyPoW /
// VerifyFull / SelectWinner / OrderClaims when the difficulty cannot be
// inferred from Nonce[0]. It is an ATOMIC VARIABLE (shadowing the const
// constants.PoWDifficultyInit) so tests — and cmd/freens-cli's demo — may
// retune it WHILE NODE GOROUTINES ARE VERIFYING PoWS (the race detector
// flags a plain-var swap against a live hWitness/VerifyPoW reader); the
// atomics establish the happens-before the plain var lacked. Production
// code never writes it after init and leaves it at
// constants.PoWDifficultyInit.
var PoWDifficultyInit atomic.Int32

func init() { PoWDifficultyInit.Store(int32(constants.PoWDifficultyInit)) }

// InferDifficulty, passed as the difficultyBits argument to VerifyPoW or
// VerifyFull, requests inferring the difficulty: if Nonce is non-empty and
// Nonce[0] >= PoWDifficultyInit the inferred difficulty is Nonce[0] (the
// Appendix A.4 convention); otherwise it is PoWDifficultyInit.
const InferDifficulty = -1

// ErrClaim is the sentinel for a structurally invalid claim or attestation
// (missing keys, wrong field lengths, bad alias). It mirrors the Python
// ClaimError.
var ErrClaim = errors.New("claims: invalid claim or attestation")

// maxNonceLen is the spec bound on the PoW nonce (§7.3: bstr(<=128)).
const maxNonceLen = 128

// maxWitnessEvaluations caps how many witness attestations ValidWitnesses
// will Ed25519-verify for ONE claim: 2× the §7.3 WITNESS_SET (8) = 16. A
// legitimate claim carries ≤ WitnessSet-ish attestations (registration asks
// the 8 closest nodes; redundancy adds a few), while the CBOR packet bound
// alone admits ~400 — each costing an Ed25519 verify on the verifying node.
// The cap bounds a claim's verification cost to a constant regardless of the
// carrier's size (DoS hardening; the witness list order is claimant-chosen
// and signature-covered, so truncation cannot hide a legitimate quorum from
// its own claimant).
const maxWitnessEvaluations = 2 * constants.WitnessSet

// ---------------------------------------------------------------------------
// §7.3 — WitnessAttestation
// ---------------------------------------------------------------------------

// WitnessAttestation is a single witness node's co-signature of an alias claim
// (§7.3). CBOR:
//
//	WitnessAttestation = {
//	  1 : node_id   ; bstr(32) = SHA-256(node_pk)
//	  2 : node_pk   ; bstr(32), Ed25519 verifying key
//	  3 : ts        ; uint, the witness's own timestamp (seconds)
//	  4 : sig       ; bstr(64): node_pk signs canonical
//	               ;   ("freens-witness-v2", claim_prefix_hash, ts)
//	}
//
// The signed message is built by crypto.WitnessSigningMessage — the v2
// claim-bound form: a fixed-size, self-contained byte string (no CBOR on the
// verify path), so verification is deterministic and dependency-free. The
// claim_prefix_hash (NOT carried in the attestation — verifiers recompute it
// from the claim's identity fields via AliasClaim.PrefixHash) commits to
// {alias, tld_id, timestamp, claimant_pk}, binding each attestation to the
// exact claim identity it was issued for.
type WitnessAttestation struct {
	NodeID []byte `cbor:"1,keyasint"` // 32 = SHA-256(NodePK)
	NodePK []byte `cbor:"2,keyasint"` // 32, Ed25519 verifying key
	TS     uint64 `cbor:"3,keyasint"` // witness's own timestamp (unix seconds)
	Sig    []byte `cbor:"4,keyasint"` // 64, Ed25519 signature
}

// NewWitnessAttestation builds a fully-signed v2 attestation from a witness
// keypair. It computes NodePK from the keypair, NodeID = SHA-256(NodePK), and
// signs the canonical witness message for (claimPrefixHash, ts) — the v2
// binding (see crypto.WitnessSigningMessage): the signature commits to the
// claim's full identity {alias, tld_id, timestamp, claimant_pk} via the
// SHA-256 of its PoW prefix, so the attestation verifies only against that
// exact claim. The returned attestation Verify()s true under the same
// prefix hash.
func NewWitnessAttestation(nodeKP *crypto.Keypair, ts uint64, claimPrefixHash []byte) (*WitnessAttestation, error) {
	if nodeKP == nil {
		return nil, fmt.Errorf("%w: nil keypair", ErrClaim)
	}
	if len(claimPrefixHash) != constants.SHA256Len {
		return nil, fmt.Errorf("%w: claim_prefix_hash must be %d bytes", ErrClaim, constants.SHA256Len)
	}
	nodePK := nodeKP.Public()
	nodeID, err := crypto.NodeID(nodePK)
	if err != nil {
		return nil, err
	}
	msg, err := crypto.WitnessSigningMessage(claimPrefixHash, ts)
	if err != nil {
		return nil, err
	}
	sig := nodeKP.Sign(msg)
	return &WitnessAttestation{
		NodeID: nodeID,
		NodePK: nodePK,
		TS:     ts,
		Sig:    sig,
	}, nil
}

// Verify reports whether the attestation is valid for the claim whose PoW
// prefix hashes to claimPrefixHash. It returns true iff BOTH hold:
//
//   - NodeID == SHA-256(NodePK) (binds the node_id to the signing key, so a
//     claimant cannot forge an attestation under an unrelated node_id), AND
//   - Sig verifies under NodePK against the canonical v2 signing input
//     ("freens-witness-v2" || claimPrefixHash || TS).
//
// Because claimPrefixHash commits to (alias, tld_id, claimant-asserted
// timestamp, claimant_pk), an attestation gathered for one claim identity
// cannot be replayed against a different claim for the same alias — in
// particular not against a re-mined backdated claim (different timestamp →
// different prefix hash → signature fails).
//
// It never returns an error; a bad signature, a node_id/pubkey mismatch, or a
// wrong-length prefix hash simply returns false (matching crypto.Verify's
// no-raise contract). Tampering ANY of (NodeID, NodePK, TS, Sig) or the claim
// identity makes this return false.
func (w *WitnessAttestation) Verify(claimPrefixHash []byte) bool {
	if w == nil {
		return false
	}
	// (a) node_id must bind to node_pk.
	nid, err := crypto.NodeID(w.NodePK)
	if err != nil || !bytes.Equal(nid, w.NodeID) {
		return false
	}
	// (b) signature must verify under node_pk over the v2 claim-bound message.
	msg, err := crypto.WitnessSigningMessage(claimPrefixHash, w.TS)
	if err != nil {
		return false
	}
	return crypto.Verify(w.NodePK, w.Sig, msg)
}

// CanonicalBytes returns the canonical CBOR encoding of this attestation.
func (w *WitnessAttestation) CanonicalBytes() ([]byte, error) {
	return canonicalEM.Marshal(w)
}

// validate enforces the §7.3 field lengths. Used by DecodeWitnessAttestation.
func (w *WitnessAttestation) validate() error {
	if len(w.NodeID) != constants.NodeIDLen {
		return fmt.Errorf("%w: node_id must be %d bytes, got %d", ErrClaim, constants.NodeIDLen, len(w.NodeID))
	}
	if len(w.NodePK) != constants.Ed25519PublicKeyLen {
		return fmt.Errorf("%w: node_pk must be %d bytes, got %d", ErrClaim, constants.Ed25519PublicKeyLen, len(w.NodePK))
	}
	if len(w.Sig) != constants.Ed25519SignatureLen {
		return fmt.Errorf("%w: sig must be %d bytes, got %d", ErrClaim, constants.Ed25519SignatureLen, len(w.Sig))
	}
	return nil
}

// DecodeWitnessAttestation decodes canonical CBOR into a WitnessAttestation and
// validates its field lengths.
func DecodeWitnessAttestation(data []byte) (*WitnessAttestation, error) {
	var w WitnessAttestation
	if err := cbor.Unmarshal(data, &w); err != nil {
		return nil, fmt.Errorf("%w: decode WitnessAttestation: %v", ErrClaim, err)
	}
	if err := w.validate(); err != nil {
		return nil, err
	}
	return &w, nil
}

// ---------------------------------------------------------------------------
// §7.3 — AliasClaim
// ---------------------------------------------------------------------------

// AliasClaim is an alias-claim record (§7.3): PoW-bound identity + witness
// quorum. CBOR:
//
//	AliasClaim = {
//	  1 : alias       ; text, normalized per §3.2
//	  2 : tld_id      ; bstr(32), claimant's TLD = SHA-256(claimant_pk)
//	  3 : timestamp   ; uint, unix seconds, claimant-asserted
//	  4 : nonce       ; bstr(<=128), PoW nonce (nonce[0] conventionally == difficulty)
//	  5 : claimant_pk ; bstr(32), Ed25519 TLD verifying key
//	  6 : pow_hash    ; bstr(32), SHA-256(prefix || nonce)
//	  7 : witnesses   ; array of WitnessAttestation (MAY be empty)
//	}
type AliasClaim struct {
	Alias      string                `cbor:"1,keyasint"` // normalized per §3.2
	TldID      []byte                `cbor:"2,keyasint"` // 32; MUST == SHA-256(ClaimantPK)
	Timestamp  uint64                `cbor:"3,keyasint"` // unix seconds, claimant-asserted
	Nonce      []byte                `cbor:"4,keyasint"` // <=128 bytes; Nonce[0] conventionally == difficulty
	ClaimantPK []byte                `cbor:"5,keyasint"` // 32, Ed25519 TLD verifying key
	PowHash    []byte                `cbor:"6,keyasint"` // 32, SHA-256(Prefix || Nonce)
	Witnesses  []*WitnessAttestation `cbor:"7,keyasint"` // MAY be empty
}

// OrderKey is the §7.4 step-3 ordering tuple (timestamp, pow_hash, tld_id),
// ascending. It holds the raw slice fields for inspection; ordering itself is
// performed by LessOrderKey / OrderClaims / SelectWinner using bytes.Compare.
type OrderKey struct {
	TS      uint64
	PowHash []byte
	TldID   []byte
}

// OrderKey returns the §7.4 lexicographic ascending ordering tuple
// (timestamp, pow_hash, tld_id). Earliest asserted time wins; ties are broken
// by the lower PoW hash (a public lottery), then by the lower TLD ID. Ties on
// (timestamp, pow_hash) are impossible between distinct claimants because
// tld_id = SHA-256(claimant_pk) differs.
func (c *AliasClaim) OrderKey() OrderKey {
	return OrderKey{TS: c.Timestamp, PowHash: c.PowHash, TldID: c.TldID}
}

// buildPrefix is the shared identity-fields encoder used by both Prefix and
// MineAliasClaim, guaranteeing the mined PoW prefix and the verified prefix are
// byte-identical. Field 4 (nonce) is intentionally OMITTED (Appendix C.1).
// canonicalEM sorts the map keys canonically (1, 2, 3, 5).
func buildPrefix(alias string, tldID []byte, ts uint64, claimantPK []byte) ([]byte, error) {
	m := map[int]any{
		1: alias,
		2: tldID,
		3: ts,
		5: claimantPK,
		// NOTE: field 4 (nonce) deliberately OMITTED — see Appendix C.1.
	}
	return canonicalEM.Marshal(m)
}

// Prefix returns the canonical CBOR of the claim's identity fields
// {1:alias, 2:tld_id, 3:timestamp, 5:claimant_pk}.
//
// Field 4 (nonce) is intentionally EXCLUDED: Appendix C.1 line 1057-1058 is
// authoritative and hashes cbor{alias, tld_id, ts, claimant_pk} || nonce. The
// literal {1..5} in §7.3 line 567 is loose prose that would otherwise be
// self-referential (the nonce cannot be part of its own hash input). The alias
// is re-normalized via naming.ValidateAlias for defensiveness; in normal use
// Alias is already stored normalized.
func (c *AliasClaim) Prefix() ([]byte, error) {
	aliasN, err := naming.ValidateAlias(c.Alias)
	if err != nil {
		return nil, err
	}
	return buildPrefix(aliasN, c.TldID, c.Timestamp, c.ClaimantPK)
}

// VerifyPoW recomputes the PoW hash from Prefix || Nonce and checks it.
// Returns true iff BOTH hold:
//
//   - SHA-256(Prefix(), Nonce) == PowHash (never trusts the stored PowHash —
//     always recomputes), AND
//   - the recomputed digest has at least difficultyBits leading zero bits.
//
// If difficultyBits < 0 (use InferDifficulty) the difficulty is inferred: if
// Nonce is non-empty and Nonce[0] >= PoWDifficultyInit the inferred difficulty
// is Nonce[0] (Appendix A.4); otherwise PoWDifficultyInit. It never returns an
// error; a malformed claim simply returns false.
func (c *AliasClaim) VerifyPoW(difficultyBits int) bool {
	d := difficultyBits
	if d < 0 {
		if len(c.Nonce) >= 1 && int(c.Nonce[0]) >= int(PoWDifficultyInit.Load()) {
			d = int(c.Nonce[0])
		} else {
			d = int(PoWDifficultyInit.Load())
		}
	}
	prefix, err := c.Prefix()
	if err != nil {
		return false
	}
	return c.verifyPoWFromPrefix(prefix, d)
}

// verifyPoWFromPrefix is the PoW check with the (allocating) canonical
// prefix already built: SHA-256(prefix, nonce) must equal PowHash AND have
// at least d leading zero bits. VerifyFull shares one prefix build between
// the PoW check and the witness check instead of rebuilding it per stage.
func (c *AliasClaim) verifyPoWFromPrefix(prefix []byte, d int) bool {
	recomputed := crypto.PoWHash(prefix, c.Nonce)
	if !bytes.Equal(recomputed, c.PowHash) {
		return false
	}
	return crypto.MeetsDifficulty(recomputed, d)
}

// VerifyClaimantConsistency reports whether TldID == SHA-256(ClaimantPK)
// (self-certifying TLD, §3.1/§5.2). It never returns an error.
func (c *AliasClaim) VerifyClaimantConsistency() bool {
	got, err := crypto.TldID(c.ClaimantPK)
	if err != nil {
		return false
	}
	return bytes.Equal(got, c.TldID)
}

// PrefixHash returns SHA-256(Prefix()) — the claim-prefix hash a witness
// signs over (v2 attestation binding) and that the §6.3 witness RPC carries
// as claim_prefix_hash. It commits to the claim's identity fields
// {alias, tld_id, timestamp, claimant_pk}.
func (c *AliasClaim) PrefixHash() ([]byte, error) {
	prefix, err := c.Prefix()
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(prefix)
	return h[:], nil
}

// ValidWitnesses returns the subset of Witnesses that Verify() against this
// claim's prefix hash (v2 binding: NodeID == SHA-256(NodePK) AND the
// signature covers the claim identity via its prefix hash). The subset is
// deduplicated by NodeID keeping the FIRST occurrence: a verifier must not
// let an attacker substitute a fresh valid signature for a NodeID already
// present — the first one wins. At most maxWitnessEvaluations deduplicated
// attestations are cryptographically evaluated (see its comment).
//
// This is the CRYPTOGRAPHIC filter only. Quorum counting (HasQuorum,
// VerifyFull) additionally applies the §7.3/§7.4 corroboration band — see
// corroboratingWitnesses.
func (c *AliasClaim) ValidWitnesses() []*WitnessAttestation {
	prefixHash, err := c.PrefixHash()
	if err != nil {
		return nil // an unhashable claim identity attests nothing
	}
	return c.validWitnessesFromPrefixHash(prefixHash)
}

// validWitnessesFromPrefixHash is ValidWitnesses with the claim's prefix
// hash already computed (VerifyFull builds it once and shares it between the
// PoW check and the witness check — Prefix()/PrefixHash are pure allocation
// + SHA-256 work that must not be repeated per stage).
func (c *AliasClaim) validWitnessesFromPrefixHash(prefixHash []byte) []*WitnessAttestation {
	seen := make(map[string]struct{})
	deduped := make([]*WitnessAttestation, 0, len(c.Witnesses))
	for _, w := range c.Witnesses {
		key := hex.EncodeToString(w.NodeID)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		deduped = append(deduped, w)
		if len(deduped) >= maxWitnessEvaluations {
			break // evaluation cap reached (see maxWitnessEvaluations)
		}
	}
	out := make([]*WitnessAttestation, 0, len(deduped))
	for _, w := range deduped {
		if w.Verify(prefixHash) {
			out = append(out, w)
		}
	}
	return out
}

// corroboratingWitnessesFromPrefixHash is corroboratingWitnesses with the
// claim's prefix hash precomputed (VerifyFull's shared-prefix path).
func (c *AliasClaim) corroboratingWitnessesFromPrefixHash(prefixHash []byte) []*WitnessAttestation {
	lo := int64(c.Timestamp) - int64(constants.SkewTolerance)
	hi := int64(c.Timestamp) + int64(constants.WitnessPresentWindow) + int64(constants.SkewTolerance)
	out := make([]*WitnessAttestation, 0, len(c.Witnesses))
	for _, w := range c.validWitnessesFromPrefixHash(prefixHash) {
		if ts := int64(w.TS); ts >= lo && ts <= hi {
			out = append(out, w)
		}
	}
	return out
}

// HasQuorum reports whether there are at least quorum DISTINCT
// CORROBORATING witnesses: valid v2 attestations (see ValidWitnesses) whose
// own timestamps fall inside the corroboration band around the claim's
// asserted timestamp. If witnessSetIDs is non-nil, only witnesses whose
// hex(NodeID) is in the set are counted — this is the §7.3/§7.4 restriction
// to the WITNESS_SET (=8) closest nodes to
// K_claim = SHA-256(0x03 || "claim:" || alias), which the RESOLVER enforces
// when its lookup converged on a routing view dense enough to name that set
// (nil = view too sparse; see the DHTLookup witness-set plumbing).
func (c *AliasClaim) HasQuorum(witnessSetIDs map[string]bool, quorum int) bool {
	ph, err := c.PrefixHash()
	if err != nil {
		return false
	}
	return c.hasQuorumFromPrefixHash(ph, witnessSetIDs, quorum)
}

// hasQuorumFromPrefixHash is HasQuorum with the claim's prefix hash
// precomputed (VerifyFull's shared-prefix path).
func (c *AliasClaim) hasQuorumFromPrefixHash(prefixHash []byte, witnessSetIDs map[string]bool, quorum int) bool {
	valid := c.corroboratingWitnessesFromPrefixHash(prefixHash)
	counted := make(map[string]struct{}, len(valid))
	for _, w := range valid {
		k := hex.EncodeToString(w.NodeID)
		if witnessSetIDs == nil || witnessSetIDs[k] {
			counted[k] = struct{}{}
		}
	}
	return len(counted) >= quorum
}

// FreshAttestations filters the given attestations to the ones that are
// VALID for the claim identity (v2 signature over prefixHash, node key
// binding, distinct) AND dated within freshWindow of now — the §8.3
// re-attestation evidence class (v2 renewal amendment): unlike the mint
// attestations' corroboration band (around the claim's asserted ts), these
// are dated by witnesses against THEIR CURRENT clock, which the §6.3 ts gate
// guarantees they would only put under a claim they have been holding. The
// attestations arrive from storing nodes' pools (each re-attesting witness
// keeps what it signed); the verifier re-checks every signature — pool state
// is untrusted input, exactly like pooled envelopes.
func FreshAttestations(atts []*WitnessAttestation, prefixHash []byte, now int64, freshWindow int64) []*WitnessAttestation {
	if len(atts) == 0 {
		return nil
	}
	lo := now - freshWindow
	hi := now + int64(constants.SkewTolerance)
	seen := make(map[string]struct{}, len(atts))
	out := make([]*WitnessAttestation, 0, len(atts))
	for _, w := range atts {
		k := hex.EncodeToString(w.NodeID)
		if _, dup := seen[k]; dup {
			continue
		}
		if !w.Verify(prefixHash) {
			continue
		}
		if ts := int64(w.TS); ts >= lo && ts <= hi {
			seen[k] = struct{}{}
			out = append(out, w)
		}
	}
	return out
}

// HasFreshQuorum reports whether atts carry at least quorum DISTINCT fresh
// attestations for the claim identity (see FreshAttestations), optionally
// restricted to witnessSetIDs — the same §7.3 WITNESS_SET restriction as
// HasQuorum, and for the same reason: fresh attestations are dated NOW, so
// membership in the converged set IS checkable, and the restriction is what
// makes the evidence cost a real sybil presence instead of five self-made
// keypairs. Non-nil witnessSetIDs with a nil set from a sparse view must
// pass nil (unenforced), matching HasQuorum semantics.
func HasFreshQuorum(atts []*WitnessAttestation, prefixHash []byte, now int64, freshWindow int64, witnessSetIDs map[string]bool, quorum int) bool {
	counted := make(map[string]struct{}, len(atts))
	for _, w := range FreshAttestations(atts, prefixHash, now, freshWindow) {
		k := hex.EncodeToString(w.NodeID)
		if witnessSetIDs == nil || witnessSetIDs[k] {
			counted[k] = struct{}{}
		}
	}
	return len(counted) >= quorum
}

// CanonicalBytes returns the canonical CBOR encoding of the whole claim
// (RFC 8949 §4.2). This is the byte string embedded verbatim in
// wire.Record.Claim (field 11).
func (c *AliasClaim) CanonicalBytes() ([]byte, error) {
	return canonicalEM.Marshal(c)
}

// validate enforces the §7.3 structural constraints (field lengths, alias
// validity, witness integrity). Used by DecodeAliasClaim.
func (c *AliasClaim) validate() error {
	if _, err := naming.ValidateAlias(c.Alias); err != nil {
		return fmt.Errorf("%w: %v", ErrClaim, err)
	}
	if len(c.TldID) != constants.SHA256Len {
		return fmt.Errorf("%w: tld_id must be %d bytes, got %d", ErrClaim, constants.SHA256Len, len(c.TldID))
	}
	if len(c.ClaimantPK) != constants.Ed25519PublicKeyLen {
		return fmt.Errorf("%w: claimant_pk must be %d bytes, got %d", ErrClaim, constants.Ed25519PublicKeyLen, len(c.ClaimantPK))
	}
	if len(c.PowHash) != constants.SHA256Len {
		return fmt.Errorf("%w: pow_hash must be %d bytes, got %d", ErrClaim, constants.SHA256Len, len(c.PowHash))
	}
	if len(c.Nonce) > maxNonceLen {
		return fmt.Errorf("%w: nonce must be <=%d bytes, got %d", ErrClaim, maxNonceLen, len(c.Nonce))
	}
	for i, w := range c.Witnesses {
		if err := w.validate(); err != nil {
			return fmt.Errorf("%w: witness %d: %v", ErrClaim, i, err)
		}
	}
	return nil
}

// DecodeAliasClaim decodes canonical CBOR into an AliasClaim, normalizes the
// alias, and validates all structural constraints (field lengths, witness
// integrity).
func DecodeAliasClaim(data []byte) (*AliasClaim, error) {
	var c AliasClaim
	if err := cbor.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("%w: decode AliasClaim: %v", ErrClaim, err)
	}
	aliasN, err := naming.ValidateAlias(c.Alias)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrClaim, err)
	}
	c.Alias = aliasN
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// ---------------------------------------------------------------------------
// §7.3 — Mining factory
// ---------------------------------------------------------------------------

// MineAliasClaim normalizes the alias, derives the claimant key, builds the PoW
// prefix, and searches a nonce until SHA-256(prefix || nonce) has at least
// difficultyBits leading zero bits (Appendix C.1). The returned claim satisfies
// VerifyClaimantConsistency and VerifyPoW (with Nonce[0] == difficultyBits) by
// construction. Witnesses is left empty — attach them via the witness RPC and
// re-encode, or set the field directly before CanonicalBytes.
//
// maxIters bounds the search; nonceSize is the nonce byte length (the first
// byte is fixed to min(difficultyBits, 255) per Appendix A.4; only the
// remaining nonceSize-1 bytes are randomized each attempt). Returns ErrCrypto
// (wrapped) if maxIters is exhausted.
func MineAliasClaim(alias string, claimantKP *crypto.Keypair, timestamp uint64, difficultyBits, maxIters, nonceSize int) (*AliasClaim, error) {
	if claimantKP == nil {
		return nil, fmt.Errorf("%w: nil keypair", ErrClaim)
	}
	aliasN, err := naming.ValidateAlias(alias)
	if err != nil {
		return nil, err
	}
	claimantPK := claimantKP.Public()
	tldID, err := crypto.TldID(claimantPK)
	if err != nil {
		return nil, err
	}
	prefix, err := buildPrefix(aliasN, tldID, timestamp, claimantPK)
	if err != nil {
		return nil, err
	}
	nonce, powHash, err := crypto.MinePoW(prefix, difficultyBits, maxIters, nonceSize)
	if err != nil {
		return nil, err
	}
	return &AliasClaim{
		Alias:      aliasN,
		TldID:      tldID,
		Timestamp:  timestamp,
		Nonce:      nonce,
		ClaimantPK: claimantPK,
		PowHash:    powHash,
		Witnesses:  []*WitnessAttestation{}, // non-nil so field 7 encodes as [] (not null)
	}, nil
}

// ---------------------------------------------------------------------------
// §7.4 — deterministic ordering / full-validity helpers
// ---------------------------------------------------------------------------

// LessOrderKey implements the §7.4 step-3 ascending total order
// (timestamp, pow_hash, tld_id): earlier timestamp wins; ties broken by lower
// PoW hash, then lower TLD ID. Used by SelectWinner (linear min) and
// OrderClaims (sort.SliceStable) for deterministic, observation-independent
// convergence.
func LessOrderKey(a, b *AliasClaim) bool {
	if a.Timestamp != b.Timestamp {
		return a.Timestamp < b.Timestamp
	}
	if cmp := bytes.Compare(a.PowHash, b.PowHash); cmp != 0 {
		return cmp < 0
	}
	return bytes.Compare(a.TldID, b.TldID) < 0
}

// structurallyAndPoWValid is the §7.4 step-2 core filter (EXCLUDING the witness
// quorum check): the claimant key binds to TldID AND the stored PoW recomputes
// against the inferred/default difficulty. SelectWinner and OrderClaims
// deliberately do NOT require a witness quorum (a caller may want the best
// candidate even before quorum is assembled); use VerifyFull for the full
// filter.
func structurallyAndPoWValid(c *AliasClaim) bool {
	return c.VerifyClaimantConsistency() && c.VerifyPoW(InferDifficulty)
}

// SelectWinner returns the deterministic winner of a set of competing claims
// (§7.4 step 3): it filters to claims whose claimant key is consistent
// (TldID binds to ClaimantPK) and whose PoW recomputes (difficulty inferred
// from Nonce[0] when sane, else PoWDifficultyInit), then returns the one with
// the SMALLEST OrderKey. It returns nil if no claim survives. Witness quorum is
// intentionally NOT required here; use VerifyFull for the full §7.4 step-2
// filter.
func SelectWinner(claims []*AliasClaim) *AliasClaim {
	var best *AliasClaim
	for _, c := range claims {
		if !structurallyAndPoWValid(c) {
			continue
		}
		if best == nil || LessOrderKey(c, best) {
			best = c
		}
	}
	return best
}

// OrderClaims returns the surviving claims sorted ascending by OrderKey
// (§7.4 step 3). Only structurally-and-PoW-valid claims are included; the rest
// are dropped. The sort is stable so equal-key claims (impossible for distinct
// claimants) retain input order.
func OrderClaims(claims []*AliasClaim) []*AliasClaim {
	survivors := make([]*AliasClaim, 0, len(claims))
	for _, c := range claims {
		if structurallyAndPoWValid(c) {
			survivors = append(survivors, c)
		}
	}
	sort.SliceStable(survivors, func(i, j int) bool {
		return LessOrderKey(survivors[i], survivors[j])
	})
	return survivors
}

// VerifyFull is the full §7.4 step-2 validity filter. It returns true iff ALL
// hold:
//
//   - the claimant key is consistent (TldID == SHA-256(ClaimantPK));
//   - the PoW is valid at difficultyBits (<0 / InferDifficulty → inferred from
//     Nonce[0] when sane, else PoWDifficultyInit) — recomputed, never trusting
//     the stored hash;
//   - the witness quorum is met among DISTINCT CORROBORATING witnesses: v2
//     attestations bound to this claim's prefix hash, dated inside the
//     corroboration band around the claim's asserted timestamp (see
//     corroboratingWitnesses), optionally restricted to witnessSetIDs (the
//     WITNESS_SET closest to K_claim when the verifier's view can name it).
//
// The canonical PoW prefix (and its hash) is built ONCE and shared by the
// PoW and witness stages — Prefix() allocates and re-encodes canonical CBOR
// on every call, and this filter runs on the hot path of every claim put
// and every resolver claim verification.
func VerifyFull(c *AliasClaim, difficultyBits int, witnessSetIDs map[string]bool, quorum int) bool {
	if !c.VerifyClaimantConsistency() {
		return false
	}
	d := difficultyBits
	if d < 0 {
		if len(c.Nonce) >= 1 && int(c.Nonce[0]) >= int(PoWDifficultyInit.Load()) {
			d = int(c.Nonce[0])
		} else {
			d = int(PoWDifficultyInit.Load())
		}
	}
	prefix, err := c.Prefix()
	if err != nil {
		return false
	}
	if !c.verifyPoWFromPrefix(prefix, d) {
		return false
	}
	ph := sha256.Sum256(prefix)
	return c.hasQuorumFromPrefixHash(ph[:], witnessSetIDs, quorum)
}
