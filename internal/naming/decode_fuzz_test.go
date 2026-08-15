package naming

// decode_fuzz_test.go — Go native fuzz target for the §3.3 wire-name decoder
// (DecodeWireName). Wire names are the name bytes carried inside every DHT
// record (Record field 2) and signed envelope, so a hostile peer controls
// them completely.
//
// Properties asserted on every input:
//
//   - DecodeWireName never panics (malformed wire names must yield
//     ErrNaming, never a raised fault);
//   - on success, re-encoding the decoded parts via EncodeWireName either
//     errors cleanly (decoded labels may legitimately fail §3.2/§3.3
//     re-validation — e.g. non-LDH bytes or a non-normalized alias-adjacent
//     label) or round-trips:
//       * if every decoded label is already in normalized form,
//         EncodeWireName(labels, alias, tldID) must reproduce the input
//         bytes exactly;
//       * otherwise the re-encoded form must itself decode to each label's
//         ValidateLabel normalization (ASCII lowercasing + whitespace trim)
//         and the same tld_id.
//
// Without -fuzz these run only the seed corpus as fast unit tests (<1 ms).

import (
	"bytes"
	"testing"
)

// FuzzDecodeWireName: no panic; clean-error-or-round-trip on re-encode.
func FuzzDecodeWireName(f *testing.F) {
	tid := bytes.Repeat([]byte{0x01}, 32)
	bare, err := EncodeWireName(nil, "foo", tid)
	if err != nil {
		f.Fatal(err)
	}
	deep, err := EncodeWireName([]string{"www", "alice"}, "foo", tid)
	if err != nil {
		f.Fatal(err)
	}

	f.Add(bare)
	f.Add(deep)
	// Malformed cases from TestDecodeWireNameMalformed.
	f.Add([]byte{0x00})                             // truncated (no tld_id)
	f.Add(append([]byte{0x02}, tid...))             // bad marker
	f.Add([]byte{0x01, 5, 'a', 'l', 'i', 'c', 'e'}) // missing terminator
	f.Add(append([]byte{0x00}, tid[:31]...))        // wrong tld_id length
	f.Add([]byte{})                                 // empty
	f.Add([]byte{0x01, 0x00, 0x00})                 // zero-length label
	// Non-normalized labels: decodable, but not byte-reproducible.
	upper := []byte{0x01, 3, 'W', 'W', 'W', 0x00}
	upper = append(upper, tid...)
	f.Add(upper)

	f.Fuzz(func(t *testing.T, wire []byte) {
		labels, tldID, err := DecodeWireName(wire)
		if err != nil {
			return // clean rejection is fine; panics are not
		}
		if len(tldID) != 32 {
			t.Fatalf("decoded tld_id is %d bytes, want 32", len(tldID))
		}
		re, err := EncodeWireName(labels, "foo", tldID)
		if err != nil {
			return // decoded labels may fail re-validation — clean error is fine
		}
		// The expected re-encoded labels are ValidateLabel's normalization of
		// the decoded ones (ASCII lowercasing + surrounding-whitespace trim);
		// ValidateLabel cannot fail here because EncodeWireName just
		// succeeded on the same labels.
		normalized := true
		want := make([]string, len(labels))
		for i, l := range labels {
			n, verr := ValidateLabel(l)
			if verr != nil {
				t.Fatalf("ValidateLabel failed although EncodeWireName succeeded: %v", verr)
			}
			want[i] = n
			if n != l {
				normalized = false
			}
		}
		if normalized {
			if !bytes.Equal(re, wire) {
				t.Fatalf("byte round trip failed for normalized labels:\n  in  %x\n  out %x", wire, re)
			}
			return
		}
		l2, t2, err := DecodeWireName(re)
		if err != nil {
			t.Fatalf("re-decode of EncodeWireName output failed: %v", err)
		}
		if !bytes.Equal(t2, tldID) || len(l2) != len(labels) {
			t.Fatalf("semantic round trip mismatch: labels %q/%q tld %x/%x", labels, l2, tldID, t2)
		}
		for i := range labels {
			if l2[i] != want[i] {
				t.Fatalf("label %d re-encoded as %q, want its normalized form %q (decoded %q)", i, l2[i], want[i], labels[i])
			}
		}
	})
}
