package resolver

// dnsname_test.go pins the RFC 4343 presentation-format unescaping that lets
// raw-UTF-8 U-label aliases (opaque wire octets) reach the §3.2 IDNA
// normalization — including the escaped form dns.Server actually produces
// (miekg/dns unpacks non-ASCII label bytes as "\DDD" decimal escapes).

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestUnescapeName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"www.example.com.", "www.example.com."},     // fast path
		{`www.b\195\188cher.`, "www.bücher."},        // UTF-8 ü as \195\188
		{`www.xn--bcher-kva.`, "www.xn--bcher-kva."}, // punycode untouched
		{`a\046b.`, "a.b."},                          // \046 = escaped dot in a label
		{`weird\9.`, "weird9."},                      // \C literal escape of '9' (RFC 4343)
		{`trailing\`, `trailing\`},                   // lone backslash
		{`\255\000x.`, "\xff\x00x."},                 // byte values
	}
	for _, c := range cases {
		if got := unescapeName(c.in); got != c.want {
			t.Errorf("unescapeName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestResolveQuestionEscapedULabelWithIDNA: a question whose Name carries the
// presentation-escaped U-label — exactly what msg.Unpack yields for a raw
// UTF-8 wire label — resolves through the IDNA path (§3.2) to the A-label
// world's record.
func TestResolveQuestionEscapedULabelWithIDNA(t *testing.T) {
	withIDNA(t, func() {
		w := newIDNATestWorld(t)
		q := dns.Question{Name: `b\195\188cher.`, Qtype: dns.TypeA, Qclass: dns.ClassINET}
		rrs, rcode, aa, err := w.res.ResolveQuestion(nil, q)
		if err != nil {
			t.Fatalf("ResolveQuestion: %v", err)
		}
		if rcode != dns.RcodeSuccess || !aa || len(rrs) != 1 {
			t.Fatalf("rcode=%d aa=%v n=%d — escaped U-label must resolve via IDNA", rcode, aa, len(rrs))
		}
		if got := rrs[0].(*dns.A).A; !got.Equal(net.IPv4(192, 0, 2, 10).To4()) {
			t.Errorf("answer = %v, want 192.0.2.10", got)
		}
	})
}

// TestResolveQuestionEscapedULabelIDNAOff: without IDNA the unescaped alias is
// non-LDH and must NXDOMAIN non-authoritatively (identical outcome to the
// pre-unescape behavior, where the escaped form also failed LDH).
func TestResolveQuestionEscapedULabelIDNAOff(t *testing.T) {
	w := newIDNATestWorld(t)
	q := dns.Question{Name: `b\195\188cher.`, Qtype: dns.TypeA, Qclass: dns.ClassINET}
	rrs, rcode, aa, err := w.res.ResolveQuestion(nil, q)
	if err != nil {
		t.Fatalf("ResolveQuestion: %v", err)
	}
	if rcode != dns.RcodeNameError || aa || len(rrs) != 0 {
		t.Fatalf("rcode=%d aa=%v n=%d — non-LDH alias must NXDOMAIN without IDNA", rcode, aa, len(rrs))
	}
}
