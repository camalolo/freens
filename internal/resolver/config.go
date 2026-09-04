// Package resolver implements the freens local DNS resolver
// (specifications.md §9): an INI-driven routing table (§9.3), the §9.2
// resolution algorithm that consults the freens namespace with a conventional
// DNS fallback, and a UDP+TCP DNS server (§9.1) built on github.com/miekg/dns.
//
// This file covers §9.3: the on-disk INI config that drives the resolver's
// listening sockets, upstream conventional-DNS forwarders, the per-alias
// routing policy ([tld-routes]), and optional vendor/user alias pins
// ([alias-pins]). It is the Go port of archive/python-v0.1/freens/resolver_config.py
// and stays stdlib-only (bufio, encoding/base32, strings).
package resolver

import (
	"bufio"
	"encoding/base32"
	"fmt"
	"strings"

	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/naming"
)

// Route is a per-alias routing policy (spec §9.3 lines 770-786). Each constant's
// string value is the lowercase token used in [tld-routes].
type Route string

const (
	// RouteDNS forwards the query verbatim to conventional upstreams only.
	RouteDNS Route = "dns"
	// RouteFREENS resolves only against the freens namespace.
	RouteFREENS Route = "freens"
	// RouteFREENSFirst tries freens first, falling through to DNS on a miss.
	RouteFREENSFirst Route = "freens-first"
	// RouteDNSFirst asks DNS first, falling through to freens on NXDOMAIN.
	RouteDNSFirst Route = "dns-first"
	// RouteDENY refuses the query (DNS REFUSED).
	RouteDENY Route = "deny"
)

// DefaultRoute is the route used for any alias lacking an explicit entry or a
// "*" match. Per spec line 772 the default for "*" is dns-first: safe and
// non-surprising, so freens never silently shadows ICANN names.
const DefaultRoute = RouteDNSFirst

// Config is the parsed §9.3 resolver configuration.
type Config struct {
	ListenUDP       string            // default "127.0.0.1:53"
	ListenTCP       string            // default "127.0.0.1:53"
	UpstreamServers []string          // comma/space list from [upstream]
	UpstreamDoH     string            // optional DoH URL from [upstream]
	TLDRoutes       map[string]Route  // alias -> Route; "*" always present
	AliasPins       map[string][]byte // alias -> 32-byte tld_id
	// EnableIDNA mirrors [options] "idna = true" (spec §3.2 MAY:
	// IDNA2008 U-labels). It is pure data: ParseConfig itself never touches
	// the naming package-global normalizer — the daemon decides when to call
	// naming.EnableIDNA (cmd/freens applies the flag, then this field,
	// before any query is parsed). Note the ordering consequence: alias keys
	// inside [tld-routes] / [alias-pins] are validated during parsing, so a
	// U-label key in the config file itself only normalizes when IDNA was
	// already enabled by the -idna flag; config authors should write A-labels
	// (xn--) there, as DNS wire traffic does.
	EnableIDNA bool

	// SuffixRescue mirrors [options] "suffix-rescue = true" (off by
	// default): for a name that resolves to an upstream NXDOMAIN under an
	// unknown-alias OR freens-first last label, fall back to a freens
	// lookup of the name with that last label stripped. This makes
	// Windows-style suffix-appended queries work ("desktop.freens"
	// resolves as "desktop") without touching ordinary DNS: real domains
	// answer upstream before the rescue can run, and explicit routes
	// other than freens-first never rescue. Setup enables it on Windows,
	// where the OS resolver otherwise never resolves single-label freens
	// names at all, and pairs it with a "freens" connection suffix.
	SuffixRescue bool

	// AllowReserved overrides the §7.6 reserved-alias policy
	// (naming/reserved.go): default OFF, meaning freensResolve treats an
	// alias that equals a delegated ICANN TLD or an IANA special-use name
	// ("com", "localhost", …) as claim-less — NXDOMAIN, no network walk —
	// EVEN IF a (rogue-witnessed) claim for it exists in the network. This
	// is the resolution-side gate that keeps a first-time user from being
	// routed to a spoofed site under a real-TLD-shaped freens name.
	// [options] "allow-reserved = true" or the daemon's -allow-reserved
	// flag opts in. [alias-pins] are checked BEFORE this gate: an explicit
	// local pin is the operator's own policy and still resolves.
	AllowReserved bool
}

// ParseConfig parses a §9.3 INI config string into a *Config.
//
// Sections handled: [listen], [upstream], [tld-routes], [alias-pins], and the
// optional [options] section (currently just the §3.2 "idna" boolean). Unknown
// sections are silently ignored (forward-compat). Missing sections yield the
// corresponding field defaults. Comment prefixes are ';' and '#' as FULL-LINE
// comments only (matching Python configparser defaults); inline comments are
// not stripped.
//
// Returns an error on: an unterminated section header, a malformed key/value
// line, an unknown route token, a bad base32 pin, a pin whose decoded length is
// not 32 bytes, an alias that fails naming.ValidateAlias (for [tld-routes]
// and [alias-pins] entries other than the "*" wildcard), or a non-boolean
// [options] value.
//
// Empty / whitespace-only text returns a *Config with defaults
// (TLDRoutes == {"*": DefaultRoute}).
func ParseConfig(text string) (*Config, error) {
	cfg := &Config{
		ListenUDP: "127.0.0.1:53",
		ListenTCP: "127.0.0.1:53",
		TLDRoutes: map[string]Route{"*": DefaultRoute},
		AliasPins: map[string][]byte{},
	}
	if strings.TrimSpace(text) == "" {
		return cfg, nil
	}

	// routes is lazily allocated the first time [tld-routes] is seen, so a
	// config without that section keeps the default {"*": DefaultRoute} map.
	var routes map[string]Route
	pins := map[string][]byte{}

	section := ""
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 0, 4096), 1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		// Full-line comments only (configparser default); inline not stripped.
		if trimmed[0] == ';' || trimmed[0] == '#' {
			continue
		}
		if trimmed[0] == '[' {
			end := strings.IndexByte(trimmed, ']')
			if end < 0 {
				return nil, fmt.Errorf("resolver: unterminated section header: %q", line)
			}
			section = strings.ToLower(strings.TrimSpace(trimmed[1:end]))
			if section == "tld-routes" && routes == nil {
				routes = map[string]Route{}
			}
			continue
		}
		key, value, ok := splitKV(trimmed)
		if !ok {
			return nil, fmt.Errorf("resolver: malformed config line (expected key = value): %q", line)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)

		switch section {
		case "listen":
			switch key {
			case "udp":
				cfg.ListenUDP = value
			case "tcp":
				cfg.ListenTCP = value
			}
		case "upstream":
			switch key {
			case "servers":
				// Comma- and/or whitespace-separated; drop empties (matches the
				// Python `value.replace(',', ' ').split()`).
				cfg.UpstreamServers = strings.Fields(strings.ReplaceAll(value, ",", " "))
			case "doh":
				cfg.UpstreamDoH = value
			}
		case "tld-routes":
			alias, err := routeAliasKey(key)
			if err != nil {
				return nil, err
			}
			rt, err := parseRouteToken(value)
			if err != nil {
				return nil, err
			}
			routes[alias] = rt
		case "options":
			switch key {
			case "idna":
				b, err := parseConfigBool(value)
				if err != nil {
					return nil, err
				}
				cfg.EnableIDNA = b
			case "suffix-rescue":
				b, err := parseConfigBool(value)
				if err != nil {
					return nil, err
				}
				cfg.SuffixRescue = b
			case "allow-reserved":
				b, err := parseConfigBool(value)
				if err != nil {
					return nil, err
				}
				cfg.AllowReserved = b
			}
		case "alias-pins":
			// No "*" wildcard for pins; every alias must validate.
			alias, err := naming.ValidateAlias(key)
			if err != nil {
				return nil, err
			}
			id, err := decodeBase32TLDID(value)
			if err != nil {
				return nil, err
			}
			pins[alias] = id
		default:
			// Unknown section: silently ignore (forward-compat).
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("resolver: config scan error: %w", err)
	}

	if routes != nil {
		// [tld-routes] was present (possibly empty): normalize so "*" exists.
		if _, ok := routes["*"]; !ok {
			routes["*"] = DefaultRoute
		}
		cfg.TLDRoutes = routes
	}
	cfg.AliasPins = pins
	return cfg, nil
}

// RouteFor returns the Route for alias under cfg. The alias is normalized via
// naming.ValidateAlias; an invalid alias yields DefaultRoute (never panics).
// Lookup is exact-match first, then the "*" wildcard, then DefaultRoute.
func RouteFor(cfg *Config, alias string) Route {
	if cfg == nil {
		return DefaultRoute
	}
	a, err := naming.ValidateAlias(alias)
	if err != nil {
		return cfg.TLDRoutes["*"]
	}
	if rt, ok := cfg.TLDRoutes[a]; ok {
		return rt
	}
	if rt, ok := cfg.TLDRoutes["*"]; ok {
		return rt
	}
	return DefaultRoute
}

// ResolvePin returns the pinned 32-byte tld_id for alias if any, else nil. The
// alias is normalized via naming.ValidateAlias; an invalid alias yields nil.
func ResolvePin(cfg *Config, alias string) []byte {
	if cfg == nil {
		return nil
	}
	a, err := naming.ValidateAlias(alias)
	if err != nil {
		return nil
	}
	return cfg.AliasPins[a]
}

// decodeBase32TLDID decodes an RFC 4648 base32 string to exactly 32 bytes.
// Whitespace is stripped, the input is upper-cased (so lowercase base32 is
// accepted), and "=" padding is appended to a multiple of 8 before decoding.
// Returns an error on a non-base32 alphabet or a decoded length != 32.
func decodeBase32TLDID(s string) ([]byte, error) {
	s2 := strings.ToUpper(strings.TrimSpace(s))
	if s2 == "" {
		return nil, fmt.Errorf("resolver: empty base32 tld_id pin")
	}
	pad := (-len(s2)) % 8
	if pad < 0 {
		pad += 8
	}
	s2 += strings.Repeat("=", pad)
	decoded, err := base32.StdEncoding.DecodeString(s2)
	if err != nil {
		return nil, fmt.Errorf("resolver: invalid base32 tld_id pin %q: %w", s, err)
	}
	if len(decoded) != constants.SHA256Len {
		return nil, fmt.Errorf("resolver: decoded tld_id pin is %d bytes, expected %d: %q", len(decoded), constants.SHA256Len, s)
	}
	return decoded, nil
}

// routeAliasKey validates a [tld-routes] key. "*" is accepted verbatim as the
// wildcard; any other key is normalized via naming.ValidateAlias.
func routeAliasKey(key string) (string, error) {
	if key == "*" {
		return "*", nil
	}
	return naming.ValidateAlias(key)
}

// parseRouteToken matches a [tld-routes] value (case-insensitive) to a Route.
func parseRouteToken(value string) (Route, error) {
	tok := strings.ToLower(strings.TrimSpace(value))
	switch Route(tok) {
	case RouteDNS, RouteFREENS, RouteFREENSFirst, RouteDNSFirst, RouteDENY:
		return Route(tok), nil
	default:
		return "", fmt.Errorf("resolver: unknown route %q (expected one of: dns, freens, freens-first, dns-first, deny)", value)
	}
}

// parseConfigBool parses a boolean config value. Accepted spellings follow
// Python's configparser.getboolean: 1/yes/true/on and 0/no/false/off in any
// letter case.
func parseConfigBool(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "yes", "true", "on":
		return true, nil
	case "0", "no", "false", "off":
		return false, nil
	default:
		return false, fmt.Errorf("resolver: invalid boolean %q (expected one of: 1/yes/true/on, 0/no/false/off)", value)
	}
}

// splitKV splits a "key = value" (or "key : value") line at the first separator.
// configparser accepts both '=' and ':' as delimiters; whichever appears first
// wins so that values containing ':' (e.g. DoH URLs) survive when the key uses
// '='.
func splitKV(s string) (string, string, bool) {
	eq := strings.IndexByte(s, '=')
	co := strings.IndexByte(s, ':')
	idx := -1
	switch {
	case eq < 0 && co < 0:
		return "", "", false
	case eq < 0:
		idx = co
	case co < 0:
		idx = eq
	case eq < co:
		idx = eq
	default:
		idx = co
	}
	return s[:idx], s[idx+1:], true
}
