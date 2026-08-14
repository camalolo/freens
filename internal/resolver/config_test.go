package resolver

import (
	"bytes"
	"encoding/base32"
	"fmt"
	"reflect"
	"testing"
)

// specExampleConfig is the §9.3 example config (spec lines 760-779), reused
// across several tests.
const specExampleConfig = `; freens resolver config — spec §9.3 example
[listen]
udp = 127.0.0.1:53
tcp = 127.0.0.1:53

[upstream]              ; conventional DNS forwarders
servers = 9.9.9.9, 149.112.112.112
doh = https://dns.quad9.net/dns-query

[tld-routes]
; route = freens | dns | freens-first | dns-first | deny
; default is dns-first: safe, non-surprising
*     = dns-first
foo   = freens
laurent = freens
example = deny

[alias-pins]            ; pin aliases to TLD IDs, bypassing claims
; foo = <base32 tld_id>
`

func TestParseConfigSpecExample(t *testing.T) {
	cfg, err := ParseConfig(specExampleConfig)
	if err != nil {
		t.Fatalf("ParseConfig: unexpected error: %v", err)
	}
	if cfg.ListenUDP != "127.0.0.1:53" {
		t.Errorf("ListenUDP = %q, want 127.0.0.1:53", cfg.ListenUDP)
	}
	if cfg.ListenTCP != "127.0.0.1:53" {
		t.Errorf("ListenTCP = %q, want 127.0.0.1:53", cfg.ListenTCP)
	}
	wantServers := []string{"9.9.9.9", "149.112.112.112"}
	if !reflect.DeepEqual(cfg.UpstreamServers, wantServers) {
		t.Errorf("UpstreamServers = %v, want %v", cfg.UpstreamServers, wantServers)
	}
	if cfg.UpstreamDoH != "https://dns.quad9.net/dns-query" {
		t.Errorf("UpstreamDoH = %q", cfg.UpstreamDoH)
	}

	wantRoutes := map[string]Route{
		"*":       RouteDNSFirst,
		"foo":     RouteFREENS,
		"laurent": RouteFREENS,
		"example": RouteDENY,
	}
	if !reflect.DeepEqual(cfg.TLDRoutes, wantRoutes) {
		t.Errorf("TLDRoutes = %v, want %v", cfg.TLDRoutes, wantRoutes)
	}
	if len(cfg.AliasPins) != 0 {
		t.Errorf("AliasPins = %v, want empty", cfg.AliasPins)
	}
}

func TestRouteFor(t *testing.T) {
	cfg, err := ParseConfig(specExampleConfig)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		alias string
		want  Route
	}{
		{"foo", RouteFREENS},
		{"FOO", RouteFREENS}, // normalized to lowercase
		{"Foo", RouteFREENS}, // normalized
		{"laurent", RouteFREENS},
		{"example", RouteDENY},
		{"com", RouteDNSFirst},   // falls through to "*"
		{"net", RouteDNSFirst},   // falls through to "*"
		{"*", RouteDNSFirst},     // the wildcard itself
		{"UPPER", RouteDNSFirst}, // invalid alias → default
	}
	for _, c := range cases {
		got := RouteFor(cfg, c.alias)
		if got != c.want {
			t.Errorf("RouteFor(%q) = %q, want %q", c.alias, got, c.want)
		}
	}
	// RouteFor on a nil config never panics and yields the default.
	if got := RouteFor(nil, "foo"); got != DefaultRoute {
		t.Errorf("RouteFor(nil, foo) = %q, want %q", got, DefaultRoute)
	}
}

func TestParseConfigDefaultsAndEmpty(t *testing.T) {
	// Wholly empty input → defaults, with TLDRoutes == {"*": DefaultRoute}.
	cfg, err := ParseConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenUDP != "127.0.0.1:53" {
		t.Errorf("ListenUDP = %q", cfg.ListenUDP)
	}
	if cfg.ListenTCP != "127.0.0.1:53" {
		t.Errorf("ListenTCP = %q", cfg.ListenTCP)
	}
	want := map[string]Route{"*": DefaultRoute}
	if !reflect.DeepEqual(cfg.TLDRoutes, want) {
		t.Errorf("TLDRoutes = %v, want %v", cfg.TLDRoutes, want)
	}
	if cfg.AliasPins == nil || len(cfg.AliasPins) != 0 {
		t.Errorf("AliasPins = %v, want non-nil empty map", cfg.AliasPins)
	}
	if len(cfg.UpstreamServers) != 0 {
		t.Errorf("UpstreamServers = %v, want empty", cfg.UpstreamServers)
	}

	// Whitespace-only input also yields defaults.
	cfg2, err := ParseConfig("   \n\t\n  ")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg2.TLDRoutes, want) {
		t.Errorf("whitespace TLDRoutes = %v", cfg2.TLDRoutes)
	}
}

func TestParseConfigWhitespaceServers(t *testing.T) {
	// Servers may be space- or comma-separated (or mixed); empties dropped.
	cfg, err := ParseConfig(`[upstream]
servers = 9.9.9.9 1.1.1.1, , 8.8.8.8
`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"9.9.9.9", "1.1.1.1", "8.8.8.8"}
	if !reflect.DeepEqual(cfg.UpstreamServers, want) {
		t.Errorf("UpstreamServers = %v, want %v", cfg.UpstreamServers, want)
	}
}

func TestParseConfigTLDRouteDefaultStarInjected(t *testing.T) {
	// [tld-routes] present but no "*" entry → DefaultRoute injected.
	cfg, err := ParseConfig(`[tld-routes]
foo = freens
`)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Route{"foo": RouteFREENS, "*": DefaultRoute}
	if !reflect.DeepEqual(cfg.TLDRoutes, want) {
		t.Errorf("TLDRoutes = %v, want %v", cfg.TLDRoutes, want)
	}
}

func TestParseConfigUnknownSectionIgnored(t *testing.T) {
	// Unknown sections are silently ignored (forward-compat); no error.
	cfg, err := ParseConfig(`[some-future-section]
weird-key = weird-value
key2 = v

[tld-routes]
foo = dns
`)
	if err != nil {
		t.Fatalf("unknown section should not error: %v", err)
	}
	if got := cfg.TLDRoutes["foo"]; got != RouteDNS {
		t.Errorf("foo route = %q, want dns", got)
	}
	if _, ok := cfg.TLDRoutes["*"]; !ok {
		t.Error("default '*' route missing")
	}
}

func TestParseConfigErrors(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{"bad route token", "[tld-routes]\nfoo = banana\n"},
		{"bad route token uppercase", "[tld-routes]\nfoo = FREENS-X\n"},
		{"bad base32 pin", "[alias-pins]\nfoo = not!!!base32!!!\n"},
		{"wrong pin length", "[alias-pins]\nfoo = AAAAAA\n"}, // decodes to <32 bytes
		{"invalid alias in tld-routes", "[tld-routes]\nfoo_bar = freens\n"},
		{"invalid alias in alias-pins", "[alias-pins]\n-foo = AAAAAAAA\n"},
		{"unterminated section", "[oops\nfoo = dns\n"},
		{"malformed line", "this has no equals or colon\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ParseConfig(c.text); err == nil {
				t.Errorf("ParseConfig(%q) expected error, got nil", c.name)
			}
		})
	}
}

// --- alias pins + base32 -------------------------------------------------

// makeTLDIDBytes returns the 32-byte slice [0,1,2,...,31] used for pin
// round-trip tests.
func makeTLDIDBytes() []byte {
	b := make([]byte, 32)
	for i := 0; i < 32; i++ {
		b[i] = byte(i)
	}
	return b
}

func TestAliasPinRoundTrip(t *testing.T) {
	raw := makeTLDIDBytes()
	enc := base32.StdEncoding.EncodeToString(raw) // includes padding
	cfg, err := ParseConfig(fmt.Sprintf("[alias-pins]\nfoo = %s\n", enc))
	if err != nil {
		t.Fatalf("ParseConfig pin: %v", err)
	}
	got := ResolvePin(cfg, "foo")
	if !bytes.Equal(got, raw) {
		t.Errorf("ResolvePin(foo) = %x, want %x", got, raw)
	}
	// Case-insensitive alias lookup.
	got = ResolvePin(cfg, "FOO")
	if !bytes.Equal(got, raw) {
		t.Errorf("ResolvePin(FOO) = %x, want %x (normalized)", got, raw)
	}
	// Unpinned alias → nil.
	if got := ResolvePin(cfg, "bar"); got != nil {
		t.Errorf("ResolvePin(bar) = %x, want nil", got)
	}
	// Invalid alias → nil (no panic).
	if got := ResolvePin(cfg, "UPPER"); got != nil {
		t.Errorf("ResolvePin(UPPER) = %x, want nil", got)
	}
	// nil config never panics.
	if got := ResolvePin(nil, "foo"); got != nil {
		t.Errorf("ResolvePin(nil, foo) = %x, want nil", got)
	}
}

func TestDecodeBase32TLDIDTolerant(t *testing.T) {
	raw := makeTLDIDBytes()
	std := base32.StdEncoding.EncodeToString(raw)
	// Strip padding → still decodes.
	noPad := std
	for len(noPad) > 0 && noPad[len(noPad)-1] == '=' {
		noPad = noPad[:len(noPad)-1]
	}
	// Lowercase → still decodes.
	lower := []byte(noPad)
	for i := range lower {
		if lower[i] >= 'A' && lower[i] <= 'Z' {
			lower[i] += 'a' - 'A'
		}
	}
	cases := []struct {
		name string
		in   string
	}{
		{"standard padded", std},
		{"no padding", noPad},
		{"lowercase", string(lower)},
		{"lowercase with surrounding whitespace", "  " + string(lower) + "\t"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := decodeBase32TLDID(c.in)
			if err != nil {
				t.Fatalf("decodeBase32TLDID(%q): %v", c.in, err)
			}
			if !bytes.Equal(got, raw) {
				t.Errorf("decodeBase32TLDID(%q) = %x, want %x", c.in, got, raw)
			}
		})
	}

	// Error cases.
	for _, bad := range []string{"", "!!!", "AAAAAA", "===="} {
		if _, err := decodeBase32TLDID(bad); err == nil {
			t.Errorf("decodeBase32TLDID(%q) expected error", bad)
		}
	}
}
