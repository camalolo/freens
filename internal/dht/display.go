package dht

// display.go — presentation ordering for a multi-homed contact's addresses,
// shared by the web UI's peers table and the CLI's `freens peers`. Purely
// cosmetic: the daemon's preferred (probe) address and Alts bookkeeping are
// untouched.

import (
	"net"
	"sort"
)

// DisplayAddrs merges a contact's preferred address with its alternates into
// (headline, alternates) display form: non-literal addresses dropped, public
// addresses first, LAN/private/loopback after, stored order preserved within
// each class. Addresses that are not IP literals are dropped — pre-2026-09-02
// fleets exchanged hostname-shaped seed contacts as empty {nodes} ip bytes,
// which receivers learned as the literal "<nil>:port" (see encodeNodes).
func DisplayAddrs(primary string, alts []AddrState) (string, []string) {
	var addrs []string
	if isIPLiteralAddr(primary) {
		addrs = append(addrs, primary)
	}
	for _, a := range alts {
		if a.Addr != primary && isIPLiteralAddr(a.Addr) {
			addrs = append(addrs, a.Addr)
		}
	}
	sort.SliceStable(addrs, func(i, j int) bool {
		return addrDisplayRank(addrs[i]) < addrDisplayRank(addrs[j])
	})
	if len(addrs) == 0 {
		return primary, nil // nothing parseable: show the raw value as-is
	}
	return addrs[0], addrs[1:]
}

// isIPLiteralAddr reports whether addr is "ip:port" with a parseable IP.
func isIPLiteralAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	return net.ParseIP(host) != nil
}

// addrDisplayRank orders addresses for display: 0 = public/global,
// 1 = LAN (private, loopback, link-local) or unparseable (sorts last).
func addrDisplayRank(addr string) int {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return 1
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return 1
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return 1
	}
	return 0
}
