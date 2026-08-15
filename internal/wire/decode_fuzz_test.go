package wire

// decode_fuzz_test.go — Go native fuzz targets (go.dev/security/fuzz) for the
// wire package's hostile-input decode paths: the DHT store payload
// (DecodeEnvelope, §4.1) and the §8.4 recovery evidence
// (DecodeRecoveryEvidence).
//
// Properties asserted on every input:
//
//   - decoding never panics — malformed input must yield an error, never a
//     raised fault (these bytes arrive from untrusted DHT peers);
//   - when decode SUCCEEDS, the canonical RFC 8949 §4.2 core-deterministic
//     encoder is byte-stable:
//
//	Decode(Bytes(b)).Bytes() == Bytes(b)
//
//     which simultaneously fuzzes the canonical encoder (the bytes that get
//     signed and hashed downstream).
//
// Seeds: one real, fully-populated valid object per target (built via the
// package's own constructors) plus the malformed inputs lifted from
// TestDecodeEnvelopeRejectsBad / TestDecodeRecoveryEvidenceErrors.
//
// Without -fuzz these run only the seed corpus as fast unit tests (<50 ms).

import (
	"bytes"
	"testing"

	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/naming"
	"github.com/fxamacker/cbor/v2"
)

// fuzzSignedEnvelopeBytes builds one fully-populated, signed envelope (every
// optional Record field set) and returns its canonical bytes.
func fuzzSignedEnvelopeBytes(f *testing.F) []byte {
	kp, err := crypto.Generate()
	if err != nil {
		f.Fatal(err)
	}
	tldID, err := crypto.TldID(kp.Public())
	if err != nil {
		f.Fatal(err)
	}
	name, err := naming.EncodeWireName([]string{"www", "alice"}, "foo", tldID)
	if err != nil {
		f.Fatal(err)
	}
	rec, err := NewRecord(name, kp.Public(), 7, 1000, 2000)
	if err != nil {
		f.Fatal(err)
	}
	a, _ := A([]byte{203, 0, 113, 42}, 300)
	aaaa, _ := AAAA(bytes.Repeat([]byte{1}, 16), 600)
	txt, _ := TXT("hello", 100)
	rec.RRset = []*RR{a, aaaa, txt}
	rec.Delegation = bytes.Repeat([]byte{0xDE}, 32)
	rec.PrevHash = bytes.Repeat([]byte{0xAD}, 32)
	rec.Recovery, _ = NewRecoveryPolicyWire(1, [][]byte{kp.Public()}, 3600)
	rec.Claim = cbor.RawMessage{0xa1, 0x01, 0x02} // any embedded canonical CBOR map
	rv := true
	rec.Revoke = &rv
	env, err := SignRecord(rec, kp)
	if err != nil {
		f.Fatal(err)
	}
	b, err := env.Bytes()
	if err != nil {
		f.Fatal(err)
	}
	return b
}

// FuzzDecodeEnvelope: no panic on arbitrary bytes; on success the canonical
// round trip Decode(Bytes()).Bytes() is byte-stable.
func FuzzDecodeEnvelope(f *testing.F) {
	valid := fuzzSignedEnvelopeBytes(f)
	f.Add(valid)
	f.Add([]byte("not cbor")) // garbage (TestDecodeEnvelopeRejectsBad)
	f.Add([]byte{})
	f.Add(valid[:len(valid)/2])  // truncated mid-record
	f.Add(valid[:headerFuzzLen]) // truncated mid-envelope

	// Record missing owner (field 3) — the second case of
	// TestDecodeEnvelopeRejectsBad.
	fuzzWithMissingOwner(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		env, err := DecodeEnvelope(data)
		if err != nil {
			return // clean rejection is fine; panics are not
		}
		b1, err := env.Bytes()
		if err != nil {
			t.Fatalf("decoded envelope fails Bytes(): %v", err)
		}
		env2, err := DecodeEnvelope(b1)
		if err != nil {
			t.Fatalf("DecodeEnvelope of canonical Bytes() failed: %v", err)
		}
		b2, err := env2.Bytes()
		if err != nil {
			t.Fatalf("re-decoded envelope fails Bytes(): %v", err)
		}
		if !bytes.Equal(b1, b2) {
			t.Fatalf("round trip not byte-stable:\n  b1 %x\n  b2 %x", b1, b2)
		}
	})
}

// headerFuzzLen is a truncation point just past the envelope's CBOR map
// header (used as a malformed seed above).
const headerFuzzLen = 12

func fuzzWithMissingOwner(f *testing.F) {
	name, err := naming.EncodeWireName(nil, "foo", bytes.Repeat([]byte{0xAB}, 32))
	if err != nil {
		f.Fatal(err)
	}
	badRecord := map[uint64]any{
		1: uint64(1), 2: name, 4: uint64(1), 5: uint64(0), 6: uint64(1), 7: []any{}, // no key 3
	}
	badEnv := map[uint64]any{1: badRecord, 2: bytes.Repeat([]byte{0}, 64), 3: bytes.Repeat([]byte{0}, 32)}
	bad, err := canonicalEM.Marshal(badEnv)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(bad)
}

// FuzzDecodeRecoveryEvidence: same shape — no panic; on success
// Decode(Bytes()).Bytes() is byte-stable.
func FuzzDecodeRecoveryEvidence(f *testing.F) {
	newPK := bytes.Repeat([]byte{0x07}, 32)
	valid, err := (&RecoveryEvidence{
		NewOwnerPK: newPK,
		Signatures: [][]byte{bytes.Repeat([]byte{0x11}, 64), bytes.Repeat([]byte{0x22}, 64)},
		NotBefore:  42,
	}).Bytes()
	if err != nil {
		f.Fatal(err)
	}
	empty, err := (&RecoveryEvidence{NewOwnerPK: newPK}).Bytes() // nil Signatures -> []
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add(empty)
	f.Add([]byte{0xff, 0xff}) // garbage (TestDecodeRecoveryEvidenceErrors)

	// Missing key 3 (not_before) and short new_owner_pk — the two crafted
	// malformed cases of TestDecodeRecoveryEvidenceErrors.
	partial, err := canonicalEM.Marshal(map[uint64]any{1: newPK, 2: [][]byte{}})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(partial)
	badPK, err := canonicalEM.Marshal(map[uint64]any{1: []byte{1, 2, 3}, 2: [][]byte{}, 3: uint64(0)})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(badPK)

	f.Fuzz(func(t *testing.T, data []byte) {
		ev, err := DecodeRecoveryEvidence(data)
		if err != nil {
			return
		}
		b1, err := ev.Bytes()
		if err != nil {
			t.Fatalf("decoded evidence fails Bytes(): %v", err)
		}
		ev2, err := DecodeRecoveryEvidence(b1)
		if err != nil {
			t.Fatalf("DecodeRecoveryEvidence of canonical Bytes() failed: %v", err)
		}
		b2, err := ev2.Bytes()
		if err != nil {
			t.Fatalf("re-decoded evidence fails Bytes(): %v", err)
		}
		if !bytes.Equal(b1, b2) {
			t.Fatalf("round trip not byte-stable:\n  b1 %x\n  b2 %x", b1, b2)
		}
	})
}
