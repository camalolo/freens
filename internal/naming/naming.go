// Package naming implements the freens naming model: alias validation
// (specifications.md §3.2), name decomposition and the wire-name binary
// encoding (§3.3), and DHT storage-key derivation (K_tld / K_name / K_claim).
//
// Wire-name encoding (§3.3, spec line 181):
//
//	wire_name = concat( for each label from TLD-adjacent to most-specific:
//	                      0x01 || uint8(len) || label_bytes )
//	            || 0x00
//	            || tld_id            // 32 raw bytes
//
// Labels are stored TLD-adjacent first (reverse of display order), mirroring
// DNS canonical ordering. Worked example (spec line 192):
//
//	wire_name("www.alice.foo") = 0x01 05 "alice" 0x01 03 "www" 0x00 <tld_id>
//
// DHT storage keys (§3.3, spec lines 195-201):
//
//	K_tld   = tld_id
//	K_name  = SHA-256(0x02 || wire_name)
//	K_claim = SHA-256(0x03 || "claim:" || alias_bytes)
package naming

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"github.com/camalolo/freens/internal/constants"
	"golang.org/x/net/idna"
)

// ErrNaming is returned for any alias/label/name validation failure.
var ErrNaming = errors.New("naming: invalid alias, label, or name")

// IDNANormalizer, when non-nil, is applied to non-ASCII alias input before the
// LDH checks (spec §3.2 MAY: IDNA2008 U-labels). It defaults to nil, meaning
// strict ASCII LDH. Call EnableIDNA() to wire in the golang.org/x/net/idna
// UTS#46 (transitional=false, useSTD3Rules=true) profile the spec recommends.
var IDNANormalizer func(string) (string, error)

// EnableIDNA installs the x/net/idna Lookup profile (UTS #46
// transitional=false, useSTD3Rules=true) as the IDNANormalizer, so
// internationalized aliases are accepted via punycode A-labels.
func EnableIDNA() {
	IDNANormalizer = func(s string) (string, error) {
		return idna.Lookup.ToASCII(s)
	}
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func checkLDH(s, what string, allowNumeric bool) error {
	if len(s) < 1 || len(s) > constants.MaxLabelLen {
		return errf("%s length must be 1-%d bytes, got %d", what, constants.MaxLabelLen, len(s))
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'
		if !ok {
			return errf("%s contains characters outside [a-z0-9-]: %q", what, s)
		}
	}
	if strings.HasPrefix(s, "-") || strings.HasSuffix(s, "-") {
		return errf("%s must not begin or end with '-': %q", what, s)
	}
	if !allowNumeric && isAllDigits(s) {
		return errf("%s must not be all-numeric: %q", what, s)
	}
	return nil
}

func errf(format string, args ...any) error {
	return fmt.Errorf("naming: %s: %w", fmt.Sprintf(format, args...), ErrNaming)
}

// errWrap wraps a literal error message with the "naming: " prefix and the
// ErrNaming sentinel so errors.Is(err, ErrNaming) holds for every error
// returned by this package.
func errWrap(msg string) error {
	return fmt.Errorf("naming: %s: %w", msg, ErrNaming)
}

// ValidateAlias normalizes and validates an alias per §3.2. Returns the
// normalized (lowercase ASCII) alias. Non-ASCII input is passed through
// IDNANormalizer when configured.
func ValidateAlias(alias string) (string, error) {
	s := strings.TrimSpace(alias)
	if !isASCII(s) && IDNANormalizer != nil {
		var err error
		s, err = IDNANormalizer(s)
		if err != nil {
			return "", err
		}
	}
	s = strings.ToLower(s)
	if err := checkLDH(s, "alias", false); err != nil {
		return "", err
	}
	return s, nil
}

// IsValidAlias reports whether ValidateAlias succeeds.
func IsValidAlias(alias string) bool {
	_, err := ValidateAlias(alias)
	return err == nil
}

// ValidateLabel normalizes and validates a single DNS-style label. Unlike an
// alias, all-numeric labels are allowed (subdomains may be numeric).
func ValidateLabel(label string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(label))
	if err := checkLDH(s, "label", true); err != nil {
		return "", err
	}
	return s, nil
}

// DecomposeName splits a displayed dotted name into display-order labels and
// the alias (the TLD-adjacent component). "foo" -> ([], "foo");
// "www.alice.foo" -> (["www","alice"], "foo"). A single trailing root dot is
// stripped. Each label and the alias are normalized.
func DecomposeName(name string) ([]string, string, error) {
	s := strings.TrimSpace(name)
	s = strings.TrimSuffix(s, ".")
	parts := strings.Split(s, ".")
	for _, p := range parts {
		if p == "" {
			return nil, "", errf("empty label or alias in name %q", name)
		}
	}
	if len(parts)-1 > constants.MaxLabels {
		return nil, "", errf("too many labels in name %q: max %d", name, constants.MaxLabels)
	}
	labels := make([]string, 0, len(parts)-1)
	for _, p := range parts[:len(parts)-1] {
		l, err := ValidateLabel(p)
		if err != nil {
			return nil, "", err
		}
		labels = append(labels, l)
	}
	alias, err := ValidateAlias(parts[len(parts)-1])
	if err != nil {
		return nil, "", err
	}
	return labels, alias, nil
}

// EncodeWireName builds the §3.3 wire_name. displayLabels is in display order
// (most-specific first); it is reversed so labels are emitted TLD-adjacent
// first. For each label: 0x01 || uint8(len) || bytes; then 0x00; then tld_id.
func EncodeWireName(displayLabels []string, alias string, tldID []byte) ([]byte, error) {
	if len(tldID) != constants.SHA256Len {
		return nil, errf("tld_id must be %d bytes, got %d", constants.SHA256Len, len(tldID))
	}
	if _, err := ValidateAlias(alias); err != nil {
		return nil, err
	}
	labels := make([]string, len(displayLabels))
	for i, lb := range displayLabels {
		nl, err := ValidateLabel(lb)
		if err != nil {
			return nil, err
		}
		labels[i] = nl
	}
	if len(labels) > constants.MaxLabels {
		return nil, errf("too many labels: max %d, got %d", constants.MaxLabels, len(labels))
	}
	out := make([]byte, 0, len(labels)*2+1+constants.SHA256Len)
	// TLD-adjacent first == reverse of display order.
	for i := len(labels) - 1; i >= 0; i-- {
		raw := []byte(labels[i]) // validated ASCII, 1..63 bytes
		out = append(out, constants.WireNameLabelMarker, byte(len(raw)))
		out = append(out, raw...)
	}
	out = append(out, constants.WireNameTerminator)
	out = append(out, tldID...)
	return out, nil
}

// DecodeWireName is the inverse of EncodeWireName. Returns display-order
// labels and the 32-byte tld_id.
func DecodeWireName(wire []byte) ([]string, []byte, error) {
	pos := 0
	var tldAdjacentFirst []string
	for {
		if pos >= len(wire) {
			return nil, nil, errWrap("missing 0x00 terminator in wire name")
		}
		marker := wire[pos]
		pos++
		if marker == constants.WireNameTerminator {
			break
		}
		if marker != constants.WireNameLabelMarker {
			return nil, nil, errf("bad marker byte 0x%02x (expected 0x01 or 0x00)", marker)
		}
		if pos >= len(wire) {
			return nil, nil, errWrap("truncated wire name (missing label length)")
		}
		length := int(wire[pos])
		pos++
		if length == 0 {
			return nil, nil, errWrap("zero-length label in wire name")
		}
		if pos+length > len(wire) {
			return nil, nil, errWrap("label length overruns end of wire name")
		}
		tldAdjacentFirst = append(tldAdjacentFirst, string(wire[pos:pos+length]))
		pos += length
	}
	if len(tldAdjacentFirst) > constants.MaxLabels {
		return nil, nil, errf("too many labels in wire name: max %d, got %d", constants.MaxLabels, len(tldAdjacentFirst))
	}
	tldID := make([]byte, len(wire[pos:]))
	copy(tldID, wire[pos:])
	if len(tldID) != constants.SHA256Len {
		return nil, nil, errf("tld_id must be exactly %d bytes after terminator, got %d", constants.SHA256Len, len(tldID))
	}
	// Reverse TLD-adjacent-first into display order.
	display := make([]string, len(tldAdjacentFirst))
	for i, lb := range tldAdjacentFirst {
		display[len(tldAdjacentFirst)-1-i] = lb
	}
	return display, tldID, nil
}

// DHTKeyTld returns K_tld = tld_id (must be 32 bytes).
func DHTKeyTld(tldID []byte) ([]byte, error) {
	if len(tldID) != constants.SHA256Len {
		return nil, errf("tld_id must be %d bytes, got %d", constants.SHA256Len, len(tldID))
	}
	out := make([]byte, len(tldID))
	copy(out, tldID)
	return out, nil
}

// DHTKeyName returns K_name = SHA-256(0x02 || wire_name).
func DHTKeyName(wireName []byte) []byte {
	h := sha256.New()
	h.Write([]byte{constants.DHTKeyPrefixName})
	h.Write(wireName)
	return h.Sum(nil)
}

// DHTKeyClaim returns K_claim = SHA-256(0x03 || "claim:" || alias). The alias
// is validated first so K_claim("FOO") == K_claim("foo").
func DHTKeyClaim(alias string) ([]byte, error) {
	a, err := ValidateAlias(alias)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write([]byte{constants.DHTKeyPrefixClaim})
	h.Write([]byte("claim:"))
	h.Write([]byte(a))
	return h.Sum(nil), nil
}
