package wire

import (
	"bytes"
	"testing"

	"github.com/laurent/freens/internal/constants"
	"github.com/laurent/freens/internal/crypto"
)

// recoveryTestKit builds a 2-of-3 policy with deterministic keys plus the
// pieces of a §8.4 declaration.
func recoveryTestKit(t *testing.T, threshold uint64) (policy *RecoveryPolicyWire, keys []*crypto.Keypair, prevHash []byte, newOwnerPK []byte) {
	t.Helper()
	for _, seed := range []byte{0x51, 0x52, 0x53} {
		kp, err := crypto.FromSeed(bytes.Repeat([]byte{seed}, constants.Ed25519PrivateKeyLen))
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, kp)
	}
	pks := make([][]byte, len(keys))
	for i, kp := range keys {
		pks[i] = kp.Public()
	}
	policy, err := NewRecoveryPolicyWire(threshold, pks, 3600)
	if err != nil {
		t.Fatal(err)
	}
	prevHash = bytes.Repeat([]byte{0xab}, constants.SHA256Len)
	newOwnerPK = bytes.Repeat([]byte{0x99}, constants.Ed25519PublicKeyLen)
	return policy, keys, prevHash, newOwnerPK
}

// signRecovery signs the §8.4 declaration message with the given keypairs.
func signRecovery(t *testing.T, kps []*crypto.Keypair, prevHash, newOwnerPK []byte, notBefore uint64) [][]byte {
	t.Helper()
	msg, err := RecoverySigningMessage(prevHash, newOwnerPK, notBefore)
	if err != nil {
		t.Fatal(err)
	}
	sigs := make([][]byte, 0, len(kps))
	for _, kp := range kps {
		sigs = append(sigs, kp.Sign(msg))
	}
	return sigs
}

func TestRecoverySigningMessage(t *testing.T) {
	prevHash := bytes.Repeat([]byte{0x01}, constants.SHA256Len)
	newPK := bytes.Repeat([]byte{0x02}, constants.Ed25519PublicKeyLen)
	msg, err := RecoverySigningMessage(prevHash, newPK, 0x1122334455667788)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte(nil), RecoverySigningTag...)
	want = append(want, prevHash...)
	want = append(want, newPK...)
	want = append(want, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88)
	if !bytes.Equal(msg, want) {
		t.Errorf("RecoverySigningMessage = %x, want %x", msg, want)
	}
	if _, err := RecoverySigningMessage([]byte{1, 2, 3}, newPK, 0); err == nil {
		t.Error("short prevRecordHash should be rejected")
	}
	if _, err := RecoverySigningMessage(prevHash, []byte{1}, 0); err == nil {
		t.Error("short newOwnerPK should be rejected")
	}
}

func TestRecoveryEvidenceRoundTrip(t *testing.T) {
	_, keys, prevHash, newPK := recoveryTestKit(t, 2)
	sigs := signRecovery(t, keys[:2], prevHash, newPK, 42)
	ev := &RecoveryEvidence{NewOwnerPK: newPK, Signatures: sigs, NotBefore: 42}
	b, err := ev.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecodeRecoveryEvidence(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec.NewOwnerPK, ev.NewOwnerPK) || dec.NotBefore != ev.NotBefore || len(dec.Signatures) != len(ev.Signatures) {
		t.Fatalf("decoded evidence mismatch: %+v", dec)
	}
	for i := range sigs {
		if !bytes.Equal(dec.Signatures[i], sigs[i]) {
			t.Errorf("signature %d mismatch", i)
		}
	}
	// Byte-stability (RFC 8949 §4.2 core-deterministic mode).
	b2, err := dec.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, b2) {
		t.Error("re-encoding is not byte-stable")
	}
	// A nil Signatures slice encodes as the empty array and survives decode.
	empty := &RecoveryEvidence{NewOwnerPK: newPK}
	eb, err := empty.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	edec, err := DecodeRecoveryEvidence(eb)
	if err != nil {
		t.Fatal(err)
	}
	if len(edec.Signatures) != 0 || edec.NotBefore != 0 {
		t.Errorf("empty evidence round-trip = %+v", edec)
	}
}

func TestDecodeRecoveryEvidenceErrors(t *testing.T) {
	if _, err := DecodeRecoveryEvidence([]byte{0xff, 0xff}); err == nil {
		t.Error("garbage should fail to decode")
	}
	// Missing key 3 (not_before): hand-build the map without it.
	partial, err := canonicalEM.Marshal(map[uint64]any{
		1: bytes.Repeat([]byte{7}, constants.Ed25519PublicKeyLen),
		2: [][]byte{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeRecoveryEvidence(partial); err == nil {
		t.Error("missing not_before (key 3) should be rejected")
	}
	// Wrong new_owner_pk length.
	badPK, err := canonicalEM.Marshal(map[uint64]any{
		1: []byte{1, 2, 3},
		2: [][]byte{},
		3: uint64(0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeRecoveryEvidence(badPK); err == nil {
		t.Error("short new_owner_pk should be rejected")
	}
}

func TestVerifyRecoveryThreshold(t *testing.T) {
	policy, keys, prevHash, newPK := recoveryTestKit(t, 2)
	notBefore := uint64(1_000_000)

	// Valid 2-of-3 quorum, after the timelock.
	ev := &RecoveryEvidence{NewOwnerPK: newPK, Signatures: signRecovery(t, keys[:2], prevHash, newPK, notBefore), NotBefore: notBefore}
	if !VerifyRecovery(policy, ev, prevHash, notBefore) {
		t.Error("threshold quorum after timelock should verify")
	}

	// Order-insensitive.
	ev.Signatures = signRecovery(t, []*crypto.Keypair{keys[2], keys[0]}, prevHash, newPK, notBefore)
	if !VerifyRecovery(policy, ev, prevHash, notBefore) {
		t.Error("shuffled quorum should verify")
	}

	// Below threshold (1 of 2 needed).
	ev.Signatures = signRecovery(t, keys[:1], prevHash, newPK, notBefore)
	if VerifyRecovery(policy, ev, prevHash, notBefore) {
		t.Error("below-threshold quorum should fail")
	}

	// The same key's signature duplicated does not double-count.
	one := signRecovery(t, keys[:1], prevHash, newPK, notBefore)
	ev.Signatures = [][]byte{one[0], append([]byte(nil), one[0]...)}
	if VerifyRecovery(policy, ev, prevHash, notBefore) {
		t.Error("duplicated signature must count once")
	}

	// A signature from a key that is not in the policy contributes nothing.
	foreign, err := crypto.FromSeed(bytes.Repeat([]byte{0xee}, constants.Ed25519PrivateKeyLen))
	if err != nil {
		t.Fatal(err)
	}
	ev.Signatures = append(signRecovery(t, keys[:1], prevHash, newPK, notBefore), foreign.Sign(mustMsg(t, prevHash, newPK, notBefore)))
	if VerifyRecovery(policy, ev, prevHash, notBefore) {
		t.Error("foreign-key signature should not count toward the threshold")
	}

	// Tampered signature.
	ev.Signatures = signRecovery(t, keys[:2], prevHash, newPK, notBefore)
	ev.Signatures[0][0] ^= 0xff
	if VerifyRecovery(policy, ev, prevHash, notBefore) {
		t.Error("tampered signature should fail")
	}
}

func mustMsg(t *testing.T, prevHash, newPK []byte, notBefore uint64) []byte {
	t.Helper()
	msg, err := RecoverySigningMessage(prevHash, newPK, notBefore)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func TestVerifyRecoveryBindingAndTimelock(t *testing.T) {
	policy, keys, prevHash, newPK := recoveryTestKit(t, 2)
	notBefore := uint64(1_000_000)
	sigs := signRecovery(t, keys[:2], prevHash, newPK, notBefore)

	// Replay onto a different NewOwnerPK: the signatures no longer match the
	// signed message, so the declaration fails.
	otherPK := bytes.Repeat([]byte{0x77}, constants.Ed25519PublicKeyLen)
	if VerifyRecovery(policy, &RecoveryEvidence{NewOwnerPK: otherPK, Signatures: sigs, NotBefore: notBefore}, prevHash, notBefore) {
		t.Error("evidence replayed onto a different new owner should fail")
	}

	// Replay onto a different prev record (name): prev_hash is bound into the
	// signed message.
	otherHash := bytes.Repeat([]byte{0xcd}, constants.SHA256Len)
	if VerifyRecovery(policy, &RecoveryEvidence{NewOwnerPK: newPK, Signatures: sigs, NotBefore: notBefore}, otherHash, notBefore) {
		t.Error("evidence replayed onto a different prev_hash should fail")
	}

	// Timelock not yet elapsed (§8.4: effective only after the timelock).
	ev := &RecoveryEvidence{NewOwnerPK: newPK, Signatures: sigs, NotBefore: notBefore}
	if VerifyRecovery(policy, ev, prevHash, notBefore-1) {
		t.Error("recovery before execute_not_before should fail")
	}
	if !VerifyRecovery(policy, ev, prevHash, notBefore) {
		t.Error("recovery exactly at execute_not_before should verify (timelock elapsed)")
	}
}

func TestVerifyRecoveryMalformed(t *testing.T) {
	policy, keys, prevHash, newPK := recoveryTestKit(t, 2)
	notBefore := uint64(1_000_000)
	sigs := signRecovery(t, keys[:2], prevHash, newPK, notBefore)
	ev := &RecoveryEvidence{NewOwnerPK: newPK, Signatures: sigs, NotBefore: notBefore}

	if VerifyRecovery(nil, ev, prevHash, notBefore) {
		t.Error("nil policy should fail")
	}
	if VerifyRecovery(policy, nil, prevHash, notBefore) {
		t.Error("nil evidence should fail")
	}
	if VerifyRecovery(policy, ev, []byte{1, 2}, notBefore) {
		t.Error("short prevRecordHash should fail")
	}
	// Zero-threshold policy is unsignable by construction and unverifiable.
	bad := &RecoveryPolicyWire{Threshold: 0, Keys: policy.Keys}
	if VerifyRecovery(bad, ev, prevHash, notBefore) {
		t.Error("threshold < 1 should fail")
	}
	// Duplicate policy keys count once: a [K1, K1] policy with threshold 2
	// must never verify on a single key's signature.
	dup, err := NewRecoveryPolicyWire(2, [][]byte{keys[0].Public(), keys[0].Public()}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if VerifyRecovery(dup, ev, prevHash, notBefore) {
		t.Error("duplicate policy keys must not satisfy a 2-threshold")
	}
}
