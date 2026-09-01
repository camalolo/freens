// Package webui — freens-web: the LAN management web UI.
//
// A small server-rendered Go application (html/template + htmx, no build
// step, everything embedded) that manages the local freens installation:
// view the daemon, names, keys and DHT store; register names (async PoW +
// witness + publish); add/update/revoke sub-names; renew leases; download
// key backups.
//
// TRUST MODEL (read twice before changing auth code):
//
//   - The listener binds 0.0.0.0 by default but serves ONLY the machine's
//     own private/LAN subnets (auto-detected; the [webui] allow config can
//     narrow or widen this, "any" disables the gate with a loud warning).
//     A daemon box often holds a WAN address too (ppp0) — the gate keeps
//     the public side out.
//   - Above the gate sits password auth: a bcrypt hash in
//     <home>/webui/auth (0600), bootstrapped by the FIRST visitor ("set
//     your password") and then required for everything else. Sessions are
//     in-memory (24 h) with HttpOnly+SameSite=Lax cookies; logins are
//     rate-limited per source subnet (IPv4 /24, IPv6 /64).
//   - Mutations additionally require the X-Requested-With header (htmx
//     always sends it; plain cross-site form posts cannot set it) — CSRF
//     defense in depth on top of SameSite.
//   - The process runs as the daemon user and reads the keychain exactly
//     like the CLI does (via internal/keychain). Passphrases for encrypted
//     owner keys are supplied per operation in the form and never stored.
package webui

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/camalolo/freens/internal/home"
)

// Config is the [webui] section of freens.conf (or the built-in defaults).
// Zero values mean "not configured".
type Config struct {
	Listen   string // e.g. "0.0.0.0:8090"
	Allow    string // comma list of CIDRs; "" = auto (private subnets); "any" = no gate (warn)
	HomeDir  string // freens home ("" = the standard ~/.freens resolution)
	AuthPath string // where the bcrypt hash lives ("" = <home>/webui/auth)
	Name     string // alias whose TLS leaf to serve (§9.5; "" = first keychain alias)
	TLSOff   bool   // [webui] tls = false serves plain HTTP even when a leaf is issuable

	// SelfVersion is THIS webui binary's own build stamp, reported by
	// /healthz. The footer version comes from the daemon's admin socket,
	// so it can never expose a stale UI process (found live 2026-09-01:
	// the desktop's freens-web served pre-upgrade templates through two
	// "successful" upgrades while every version surface showed the
	// daemon's fresh stamp).
	SelfVersion string
}

// DefaultListen is the out-of-the-box bind address.
const DefaultListen = "0.0.0.0:8090"

// ParseConfig extracts the [webui] section of an INI-style config (same
// conventions as the daemon's other sections: full-line ;/# comments,
// key = value). Returns defaults for absent keys.
func ParseConfig(text string) (*Config, error) {
	cfg := &Config{}
	section := ""
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 0, 4096), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(strings.TrimRight(sc.Text(), "\r"))
		if line == "" || line[0] == ';' || line[0] == '#' {
			continue
		}
		if line[0] == '[' {
			end := strings.IndexByte(line, ']')
			if end < 0 {
				return nil, fmt.Errorf("[webui] config: unterminated section header %q", line)
			}
			section = strings.TrimSpace(line[1:end])
			continue
		}
		if section != "webui" {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			return nil, fmt.Errorf("[webui] config: want key = value, got %q", line)
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		switch key {
		case "listen":
			cfg.Listen = val
		case "allow":
			cfg.Allow = val
		case "home":
			cfg.HomeDir = val
		case "auth":
			cfg.AuthPath = val
		case "name":
			cfg.Name = val
		case "tls":
			if val != "true" && val != "false" {
				return nil, fmt.Errorf("[webui] config: tls = %q (want true|false)", val)
			}
			cfg.TLSOff = val == "false"
		default:
			return nil, fmt.Errorf("[webui] config: unknown key %q", key)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if cfg.Listen == "" {
		cfg.Listen = DefaultListen
	}
	return cfg, nil
}

// privateCIDRs are the prefixes the auto-allowlist admits: RFC 1918, the
// IPv6 ULA range (fd00::/8), and IPv6 link-local (fe80::/10 — a browser on
// the same segment reaches the UI by link-local too). Loopback is always
// allowed separately.
var privateCIDRs = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"169.254.0.0/16",
	"fd00::/8",
	"fe80::/10",
}

// AutoAllowlists derives the allowlist from the machine's own unicast
// addresses: every private-range address expands to its /24 (v4) or /64
// (v6) so DHCP siblings stay admitted, deduplicated. Loopback is added
// unconditionally. This is the default gate when [webui] allow is unset.
func AutoAllowlists() ([]*net.IPNet, error) {
	ifaces, ierr := net.Interfaces()
	if ierr != nil {
		return nil, ierr
	}
	seen := map[string]bool{}
	var out []*net.IPNet
	add := func(cidr string) {
		if seen[cidr] {
			return
		}
		seen[cidr] = true
		if _, n, err := net.ParseCIDR(cidr); err == nil {
			out = append(out, n)
		}
	}
	add("127.0.0.0/8")
	add("::1/128")
	priv := parseNets(privateCIDRs)
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipnet.IP
			if !containsAny(priv, ip) {
				continue // skip WAN/global addresses (ppp0 & friends)
			}
			if v4 := ip.To4(); v4 != nil {
				add(fmt.Sprintf("%s/24", ip.Mask(ipnet.IP.DefaultMask()).String()))
			} else if ones, _ := ipnet.Mask.Size(); ones >= 64 {
				// Keep the interface's own /64 (or narrower) when known.
				add(ipnet.String())
			}
		}
	}
	return out, nil
}

// ParseAllow parses the [webui] allow value: "" (auto), "any" (no gate), or
// a comma list of CIDRs / single IPs (a bare IP becomes /32 or /128).
func ParseAllow(v string) ([]*net.IPNet, bool, error) {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "" {
		nets, aerr := AutoAllowlists()
		return nets, true, aerr
	}
	if v == "any" {
		return nil, false, nil
	}
	var out []*net.IPNet
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "/") {
			if ip := net.ParseIP(part); ip != nil {
				if ip.To4() != nil {
					part += "/32"
				} else {
					part += "/128"
				}
			}
		}
		_, n, err := net.ParseCIDR(part)
		if err != nil {
			return nil, false, fmt.Errorf("[webui] allow: bad CIDR %q", part)
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil, false, fmt.Errorf("[webui] allow: no valid CIDRs in %q", v)
	}
	return out, true, nil
}

func parseNets(cidrs []string) []*net.IPNet {
	var out []*net.IPNet
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func containsAny(nets []*net.IPNet, ip net.IP) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// homeDir resolves the freens home: explicit config > FREENS_HOME > ~/.freens.
// homeDir resolves the freens home the UI reads (keychain, admin socket,
// freens.conf): the [webui] home key, then $FREENS_HOME, then the PLATFORM
// default (internal/home.Dir: %ProgramData%\freens on Windows, ~/.freens
// elsewhere). The old default here was os.UserHomeDir()+"/.freens" — which
// on Windows under LocalSystem (the freens-web SCM service) is
// systemprofile\.freens while the DAEMON runs in %ProgramData%\freens, so
// the UI silently read a different keychain and a nonexistent admin socket
// (found live in the v0.14.0 fleet test: the desktop's /dns-query stayed
// 404 because the UI was reading the WRONG freens.conf's [doh] serve).
func homeDir(configured string) string {
	if configured != "" {
		return configured
	}
	if v := os.Getenv("FREENS_HOME"); v != "" {
		return v
	}
	return home.Dir()
}
