package resolver

// dnsname.go — RFC 4343 presentation-format unescaping for inbound DNS
// question names.
//
// miekg/dns unpacks wire labels containing bytes outside printable ASCII into
// their ESCAPED presentation form: the UTF-8 sequence b\xc3\xbc ("ü") comes
// back from msg.Unpack as the literal 4-character sequence "\195\188", not as
// the two raw bytes. A stub resolver that sends a raw UTF-8 U-label alias
// (legal on the wire — labels are opaque octets) therefore reaches
// ResolveQuestion as an ASCII string containing backslash escapes, which:
//
//   - never triggers the non-ASCII IDNA normalization path (§3.2), and
//   - fails LDH validation outright (backslashes are not LDH) → NXDOMAIN.
//
// unescapeName reverses the presentation escaping (\DDD decimal and \C
// character escapes, per RFC 4343 §3.1) so DecomposeName sees the original
// octets. It is applied ONLY to the name fed into freens name parsing; the
// response's answer RRs echo the question's presentation form verbatim, so
// clients see exactly what they asked. Names without backslashes — i.e. every
// conventional ASCII name — pass through unchanged (the fast path).

// unescapeName converts an RFC 4343 presentation-format domain name to its
// raw-octet form. Dots are preserved as label separators. Escapes:
//
//	\DDD   — exactly three decimal digits, value 0..255
//	\X     — any other single character, literally (covers \. \\ etc.)
//
// A malformed \DDD (non-digits) degrades to the literal backslash + character.
// The function never fails: best-effort round-tripping is strictly better than
// rejecting a name the client's own resolver considers well-formed.
func unescapeName(s string) string {
	if !containsBackslash(s) {
		return s // fast path: conventional ASCII name
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' {
			out = append(out, c)
			continue
		}
		if i+3 < len(s)+1 && i+4 <= len(s) && isDigit(s[i+1]) && isDigit(s[i+2]) && isDigit(s[i+3]) {
			v := int(s[i+1]-'0')*100 + int(s[i+2]-'0')*10 + int(s[i+3]-'0')
			if v <= 255 {
				out = append(out, byte(v))
				i += 3
				continue
			}
		}
		// \C literal escape (or malformed \DDD): keep the next char.
		if i+1 < len(s) {
			out = append(out, s[i+1])
			i++
		} else {
			out = append(out, '\\') // trailing lone backslash
		}
	}
	return string(out)
}

func containsBackslash(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			return true
		}
	}
	return false
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }
