package resolver

// dnsname_fuzz_test.go — Go native fuzz target for the RFC 4343 §3.1
// presentation-format unescaper (unescapeName), the first transform applied
// to an inbound DNS question name — i.e. fully attacker-controlled bytes.
//
// Properties asserted on every input:
//
//   - no panic for any string (the function's contract is "never fails");
//   - a backslash-free input passes through unchanged (the documented fast
//     path);
//   - the output is never longer than the input (every escape consumes at
//     least as many input bytes as it produces: \DDD consumes 4 -> 1 byte,
//     \C consumes 2 -> 1, a plain byte 1 -> 1, a trailing lone backslash
//     1 -> 1).
//
// Output is NOT required to be printable or valid UTF-8 — raw octets are the
// point of the unescaping (they then flow into §3.2 IDNA normalization).
//
// Without -fuzz these run only the seed corpus as fast unit tests (<1 ms).

import "testing"

// FuzzUnescapeName: never panic; fast-path passthrough and length monotonicity.
func FuzzUnescapeName(f *testing.F) {
	// Table inputs from TestUnescapeName, plus neighboring edges.
	f.Add("www.example.com.")
	f.Add(`www.b\195\188cher.`) // UTF-8 ü as \195\188
	f.Add(`www.xn--bcher-kva.`) // punycode untouched
	f.Add(`a\046b.`)            // \046 = escaped dot in a label
	f.Add(`weird\9.`)           // \C literal escape of '9'
	f.Add(`trailing\`)          // lone trailing backslash
	f.Add(`\255\000x.`)         // raw byte values
	f.Add(`\999.`)              // \DDD over 255: literal fallback
	f.Add(`\256.`)              // boundary just above 255
	f.Add(`\099.`)              // valid \DDD with leading zero
	f.Add(`\12`)                // incomplete \DDD at end of string
	f.Add(`\\`)                 // escaped backslash
	f.Add(`\.`)                 // escaped dot
	f.Add("")
	f.Add(`\`)
	f.Add(`.......`)
	f.Add(`\000\000\000\000\000\000`) // NUL flood

	f.Fuzz(func(t *testing.T, s string) {
		out := unescapeName(s)
		if len(out) > len(s) {
			t.Fatalf("output longer than input: %q (%d) -> %q (%d)", s, len(s), out, len(out))
		}
		if !containsBackslash(s) && out != s {
			t.Fatalf("backslash-free input must pass through unchanged: %q -> %q", s, out)
		}
	})
}
