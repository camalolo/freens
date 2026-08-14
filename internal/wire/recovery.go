// Package wire — recovery.go implements the §8.4 recovery-declaration
// EVIDENCE: the off-record proof object that threshold-many recovery keys
// (§5.4, Record field 10) signed a hand-off of a name to a fresh primary key.
//
// specifications.md §8.4 (lines 689-707):
//
//  1. Any `threshold`-of-`keys` sign a recovery declaration: `(name,
//     new_primary_pk, execute_not_before = now + timelock)`, published like
//     any record (sequence +1, `recovery` fields updated).
//  2. During the `timelock` (default 72 h), the *current* primary key MAY
//     cancel by publishing a higher-sequence normal record ...
//  3. After the timelock elapses with no cancellation, the recovery record
//     takes effect and the new primary key owns the name.
//
// The §4.1 Record schema carries the recovery POLICY (field 10:
// RecoveryPolicyWire — threshold + keys + timelock) but has NO field for
// recovery PROOFS, so the declaration lives outside the record as this
// package's RecoveryEvidence: the new primary key, the threshold signatures,
// and the declaration's execute_not_before instant (§8.4 line 694). The
// signatures cover a domain-separated message that binds all three to the
// record being recovered via its H_record (§4.2) — the same prev_hash anchor
// §8.3 uses for transfers, which both identifies the name and prevents
// replaying one declaration onto an unrelated hand-off.
//
// Verification is a pure function ([VerifyRecovery]); wiring it into the
// resolver/daemon acceptance path (where the §8.4 cancellation race is
// decided by sequence numbers) is future work.
package wire

import (
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/laurent/freens/internal/constants"
	"github.com/laurent/freens/internal/crypto"
)

// RecoverySigningTag is the canonical domain-separation tag for §8.4 recovery
// declarations (mirrors crypto.WitnessSigningTag for §7.3 attestations).
var RecoverySigningTag = []byte("freens-recovery-v1")

// RecoveryEvidence is the §8.4 recovery declaration: proof that
// threshold-many of a record's §5.4 recovery keys signed the hand-off of the
// record to NewOwnerPK, executable not before NotBefore.
//
// On the wire it is the canonical CBOR map
//
//	RecoveryEvidence = {
//	  1 : new_owner_pk   ; bstr(32), the fresh primary key (§8.4 new_primary_pk)
//	  2 : signatures     ; array of bstr(64), Ed25519 sigs over
//	                      // RecoverySigningMessage; order-insensitive
//	  3 : not_before     ; uint, §8.4's execute_not_before = now + timelock
//	}
//
// encoded with the package's RFC 8949 §4.2 core-deterministic mode (nil
// Signatures encodes as the empty array), so encoding is byte-stable:
// DecodeRecoveryEvidence(ev.Bytes()).Bytes() == ev.Bytes().
type RecoveryEvidence struct {
	NewOwnerPK []byte   `cbor:"1,keyasint"`
	Signatures [][]byte `cbor:"2,keyasint"`
	NotBefore  uint64   `cbor:"3,keyasint"`
}

// Bytes returns the canonical CBOR of the evidence (the bytes written by
// freens-cli recover and hashed/verified by acceptance paths).
func (e *RecoveryEvidence) Bytes() ([]byte, error) {
	sigs := e.Signatures
	if sigs == nil {
		sigs = [][]byte{}
	}
	return canonicalEM.Marshal(map[uint64]any{
		1: e.NewOwnerPK,
		2: sigs,
		3: e.NotBefore,
	})
}

// DecodeRecoveryEvidence decodes canonical CBOR evidence bytes. Keys 1-3 must
// all be present (Bytes always emits them); NewOwnerPK must be 32 bytes and
// every signature 64 bytes (mirroring DecodeEnvelope's length checks).
func DecodeRecoveryEvidence(data []byte) (*RecoveryEvidence, error) {
	var m map[uint64]cbor.RawMessage
	if err := cbor.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("wire: recovery evidence must be a CBOR map: %w", err)
	}
	for _, k := range []uint64{1, 2, 3} {
		if _, ok := m[k]; !ok {
			return nil, fmt.Errorf("wire: recovery evidence missing required key %d", k)
		}
	}
	var e RecoveryEvidence
	if err := cbor.Unmarshal(m[1], &e.NewOwnerPK); err != nil {
		return nil, fmt.Errorf("wire: recovery evidence.new_owner_pk: %w", err)
	}
	if len(e.NewOwnerPK) != constants.Ed25519PublicKeyLen {
		return nil, fmt.Errorf("wire: recovery evidence new_owner_pk (key 1) must be %d bytes, got %d", constants.Ed25519PublicKeyLen, len(e.NewOwnerPK))
	}
	if err := cbor.Unmarshal(m[2], &e.Signatures); err != nil {
		return nil, fmt.Errorf("wire: recovery evidence.signatures: %w", err)
	}
	for i, s := range e.Signatures {
		if len(s) != constants.Ed25519SignatureLen {
			return nil, fmt.Errorf("wire: recovery evidence signature %d must be %d bytes, got %d", i, constants.Ed25519SignatureLen, len(s))
		}
	}
	if err := cbor.Unmarshal(m[3], &e.NotBefore); err != nil {
		return nil, fmt.Errorf("wire: recovery evidence.not_before: %w", err)
	}
	return &e, nil
}

// RecoverySigningMessage returns the canonical bytes a recovery key signs for
// a §8.4 declaration. Mirroring crypto.WitnessSigningMessage's style (fixed
// 32-byte fields carried raw, the timestamp as big-endian uint64, a
// versioned domain-separation tag), the message is:
//
//	"freens-recovery-v1" || prev_record_hash(32) || new_owner_pk(32)
//	|| uint64_be(execute_not_before)
//
// prevRecordHash is H_record = SHA-256(canonical_cbor(SignedEnvelope)) (§4.2)
// of the record being recovered — the §8.3/§8.4 chain anchor that names the
// hand-off unambiguously. execute_not_before is §8.4 line 694's
// `execute_not_before = now + timelock`, so the timelock is enforced by the
// verifiable inequality now >= execute_not_before rather than by trust in any
// particular verifier's clock.
func RecoverySigningMessage(prevRecordHash, newOwnerPK []byte, executeNotBefore uint64) ([]byte, error) {
	if len(prevRecordHash) != constants.SHA256Len {
		return nil, fmt.Errorf("wire: prev_record_hash must be %d bytes, got %d", constants.SHA256Len, len(prevRecordHash))
	}
	if len(newOwnerPK) != constants.Ed25519PublicKeyLen {
		return nil, fmt.Errorf("wire: new_owner_pk must be %d bytes, got %d", constants.Ed25519PublicKeyLen, len(newOwnerPK))
	}
	var ts [8]byte
	for i := 0; i < 8; i++ {
		ts[7-i] = byte(executeNotBefore >> (8 * i))
	}
	out := make([]byte, 0, len(RecoverySigningTag)+constants.SHA256Len+constants.Ed25519PublicKeyLen+8)
	out = append(out, RecoverySigningTag...)
	out = append(out, prevRecordHash...)
	out = append(out, newOwnerPK...)
	out = append(out, ts[:]...)
	return out, nil
}

// VerifyRecovery reports whether evidence satisfies policy for the record
// whose H_record is prevRecordHash at instant now (§8.4 lines 689-707).
//
// Two conditions must hold:
//
//   - Quorum: at least policy.Threshold DISTINCT policy keys have each
//     produced a valid Ed25519 signature over
//     RecoverySigningMessage(prevRecordHash, evidence.NewOwnerPK,
//     evidence.NotBefore). Signatures are order-insensitive; a signature
//     from a key not in the policy, a duplicated signature, or a tampered
//     signature simply fails to contribute (duplicate policy keys are
//     likewise counted once).
//
//   - Timelock (§8.4 line 694): the declaration carries
//     execute_not_before = evidence.NotBefore (signed by the quorum, so it
//     cannot be moved after the fact); the recovery takes effect only once
//     the timelock has elapsed, i.e. now >= evidence.NotBefore. During the
//     window the current primary key cancels by publishing a
//     higher-sequence record (§8.4 step 2) — a DHT/resolver concern outside
//     this pure function.
//
// Non-raising: any nil argument, wrong length, or failed check yields false.
func VerifyRecovery(policy *RecoveryPolicyWire, evidence *RecoveryEvidence, prevRecordHash []byte, now uint64) bool {
	if policy == nil || evidence == nil {
		return false
	}
	if policy.Threshold < 1 {
		return false
	}
	if len(prevRecordHash) != constants.SHA256Len {
		return false
	}
	if len(evidence.NewOwnerPK) != constants.Ed25519PublicKeyLen {
		return false
	}
	msg, err := RecoverySigningMessage(prevRecordHash, evidence.NewOwnerPK, evidence.NotBefore)
	if err != nil {
		return false
	}
	// Count DISTINCT policy keys (by content) that produced any valid
	// signature. Duplicated keys in the policy and duplicated signatures in
	// the evidence each count once; signatures from foreign keys contribute
	// nothing.
	verified := 0
	seen := make(map[string]bool, len(policy.Keys))
	for _, k := range policy.Keys {
		if len(k) != constants.Ed25519PublicKeyLen || seen[string(k)] {
			continue
		}
		for _, sig := range evidence.Signatures {
			if crypto.Verify(k, sig, msg) {
				seen[string(k)] = true
				verified++
				break
			}
		}
	}
	if uint64(verified) < policy.Threshold {
		return false
	}
	// §8.4 step 3: effective only after the timelock elapses.
	return now >= evidence.NotBefore
}

// ErrNoRecoveryPolicy is returned by callers assembling evidence when the
// record carries no §5.4 policy; defined here so CLI and library callers
// share one sentinel.
var ErrNoRecoveryPolicy = errors.New("wire: record has no recovery policy (field 10)")
