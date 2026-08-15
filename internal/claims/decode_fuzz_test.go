package claims

// decode_fuzz_test.go — Go native fuzz targets for the §7.3 claim decoders
// fed by hostile DHT traffic (alias claims and witness attestations arrive as
// opaque CBOR from untrusted peers).
//
// Properties asserted on every input:
//
//   - DecodeAliasClaim / DecodeWitnessAttestation never panic;
//   - on success the verification paths (VerifyPoW, VerifyClaimantConsistency,
//     ValidWitnesses/HasQuorum, WitnessAttestation.Verify) are callable
//     without panic — any boolean result is acceptable, the contract is only
//     "no raised fault";
//   - CanonicalBytes output re-decodes and is byte-stable across a second
//     canonical encode (the claim bytes get embedded verbatim in wire records,
//     so encode stability matters as much as decode robustness).
//
// Witnesses are capped at 32 per ValidWitnesses call to keep each fuzz exec
// bounded (each witness verification is an Ed25519 verify); decoding a claim
// with an unbounded witness array is still exercised by the decode itself.
//
// Without -fuzz these run only the seed corpus as fast unit tests (<100 ms —
// one difficulty-8 mining pass dominates).

import (
	"bytes"
	"testing"

	"github.com/camalolo/freens/internal/crypto"
	"github.com/fxamacker/cbor/v2"
)

// fuzzMinedClaim mines one difficulty-8 claim (fast; Appendix C.1 shape) and
// returns its canonical bytes, optionally with n valid witness attestations.
func fuzzMinedClaim(f *testing.F, witnesses int) []byte {
	kp, err := crypto.Generate()
	if err != nil {
		f.Fatal(err)
	}
	c, err := MineAliasClaim("foo", kp, 1_700_000_000, 8, 2_000_000, 16)
	if err != nil {
		f.Fatal(err)
	}
	for i := 0; i < witnesses; i++ {
		wkp, err := crypto.Generate()
		if err != nil {
			f.Fatal(err)
		}
		w, err := NewWitnessAttestation(wkp, uint64(1_700_000_001+i), c.Alias, c.TldID, c.ClaimantPK)
		if err != nil {
			f.Fatal(err)
		}
		c.Witnesses = append(c.Witnesses, w)
	}
	b, err := c.CanonicalBytes()
	if err != nil {
		f.Fatal(err)
	}
	return b
}

// FuzzDecodeAliasClaim: no panic; VerifyPoW/consistency/quorum callable; on
// success CanonicalBytes re-decodes byte-stably.
func FuzzDecodeAliasClaim(f *testing.F) {
	f.Add(fuzzMinedClaim(f, 0))
	f.Add(fuzzMinedClaim(f, 2))
	f.Add([]byte("not cbor"))
	f.Add([]byte{})

	// Short tld_id (field 2 shrunk by one byte) and an invalid alias — the
	// two crafted malformed cases of TestDecodeValidation.
	good := fuzzMinedClaim(f, 0)
	var m map[int]cbor.RawMessage
	if err := cbor.Unmarshal(good, &m); err != nil {
		f.Fatal(err)
	}
	em, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		f.Fatal(err)
	}
	var tld []byte
	if err := cbor.Unmarshal(m[2], &tld); err != nil {
		f.Fatal(err)
	}
	short, err := em.Marshal(tld[:len(tld)-1])
	if err != nil {
		f.Fatal(err)
	}
	m[2] = short
	bad, err := em.Marshal(m)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(bad)

	var badAlias map[int]any
	if err := cbor.Unmarshal(good, &badAlias); err != nil {
		f.Fatal(err)
	}
	badAlias[1] = "UPPER_NOT_ALLOWED" // fails LDH
	badAliasBytes, err := em.Marshal(badAlias)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(badAliasBytes)

	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := DecodeAliasClaim(data)
		if err != nil {
			return // clean rejection is fine; panics are not
		}
		_ = c.VerifyClaimantConsistency()
		_ = c.VerifyPoW(InferDifficulty)
		if len(c.Witnesses) <= 32 {
			_ = c.ValidWitnesses()
			_ = c.HasQuorum(nil, 1)
		}
		b1, err := c.CanonicalBytes()
		if err != nil {
			t.Fatalf("decoded claim fails CanonicalBytes(): %v", err)
		}
		c2, err := DecodeAliasClaim(b1)
		if err != nil {
			t.Fatalf("DecodeAliasClaim of canonical bytes failed: %v", err)
		}
		b2, err := c2.CanonicalBytes()
		if err != nil {
			t.Fatalf("re-decoded claim fails CanonicalBytes(): %v", err)
		}
		if !bytes.Equal(b1, b2) {
			t.Fatalf("canonical encoding not byte-stable:\n  b1 %x\n  b2 %x", b1, b2)
		}
	})
}

// FuzzDecodeWitnessAttestation: no panic; on success Verify is callable under
// a fixed claim context and CanonicalBytes round-trips byte-stably.
func FuzzDecodeWitnessAttestation(f *testing.F) {
	kp, err := crypto.Generate()
	if err != nil {
		f.Fatal(err)
	}
	claimantPK := kp.Public()
	tldID, err := crypto.TldID(claimantPK)
	if err != nil {
		f.Fatal(err)
	}
	w, err := NewWitnessAttestation(kp, 1_700_000_000, "foo", tldID, claimantPK)
	if err != nil {
		f.Fatal(err)
	}
	valid, err := w.CanonicalBytes()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte("not cbor"))
	f.Add([]byte{})
	f.Add(valid[:len(valid)/2]) // truncated
	tampered := append([]byte{}, valid...)
	tampered[len(tampered)-1] ^= 0xff // flip a signature byte
	f.Add(tampered)

	f.Fuzz(func(t *testing.T, data []byte) {
		w, err := DecodeWitnessAttestation(data)
		if err != nil {
			return
		}
		_ = w.Verify("foo", bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32))
		b1, err := w.CanonicalBytes()
		if err != nil {
			t.Fatalf("decoded attestation fails CanonicalBytes(): %v", err)
		}
		w2, err := DecodeWitnessAttestation(b1)
		if err != nil {
			t.Fatalf("DecodeWitnessAttestation of canonical bytes failed: %v", err)
		}
		b2, err := w2.CanonicalBytes()
		if err != nil {
			t.Fatalf("re-decoded attestation fails CanonicalBytes(): %v", err)
		}
		if !bytes.Equal(b1, b2) {
			t.Fatalf("canonical encoding not byte-stable:\n  b1 %x\n  b2 %x", b1, b2)
		}
	})
}
