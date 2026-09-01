package resolver

import (
	"net"
	"net/url"
	"strings"
)

// DefaultUpstreamServers is the §9.1 default plaintext fallback list, used
// wherever a conf spells no [upstream] servers (the daemon's initial wiring,
// its /reload re-read, and the doctor's DoH check): an EMPTY fallback list
// would silently strip the safety net under the DoH upstream.
var DefaultUpstreamServers = []string{"9.9.9.9", "1.1.1.1"}

// DoHPresets maps friendly preset names to well-known public DoH endpoints
// the CLI (`freens doh upstream <preset>`) and the webui Settings page
// offer. The default two are IP-FORM URLs on purpose: with the fleet's
// standard wiring (resolv.conf → 127.0.0.1, i.e. the OS resolver IS this
// daemon) a hostname endpoint needs bootstrap resolution — which DoHUpstream
// handles via the plaintext fallback servers — but an IP endpoint needs no
// resolution at all, so the default path has nothing to bootstrap, ever.
// Both providers serve valid certificates covering their bare IPs. Google is
// offered as the hostname form (its plain resolvers are not the fallback
// defaults); bootstrapping covers it.
var DoHPresets = map[string]string{
	"quad9":      "https://9.9.9.9/dns-query",
	"cloudflare": "https://1.1.1.1/dns-query",
	"google":     "https://dns.google/dns-query",
}

// DoHPresetURL resolves a config/UI value to a DoH endpoint URL: preset
// names map through DoHPresets, a full https:// URL passes through
// verbatim, anything else is rejected (ok == false).
func DoHPresetURL(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	if u, ok := DoHPresets[strings.ToLower(s)]; ok {
		return u, true
	}
	if strings.HasPrefix(s, "https://") {
		return s, true
	}
	// Plain http is accepted ONLY for loopback endpoints — a legal shape
	// for local integration testing (a DoH server on 127.0.0.1), never for
	// a real upstream (RFC 8484 §1: https only on the public internet).
	if u, err := url.Parse(s); err == nil && u.Scheme == "http" && u.Host != "" {
		host := u.Hostname()
		if strings.EqualFold(host, "localhost") || func() bool {
			ip := net.ParseIP(host)
			return ip != nil && ip.IsLoopback()
		}() {
			return s, true
		}
	}
	return "", false
}

// ValidateServeBool parses the [doh] "serve" value shape (same spellings as
// the resolver's config booleans). Exported so the CLI and webui can
// validate before writing the key.
func ValidateServeBool(v string) error {
	_, err := parseConfigBool(v)
	return err
}
