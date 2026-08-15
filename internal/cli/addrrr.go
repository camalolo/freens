// addrrr.go — the shared "-ip accepts v4 OR v6" rule of the easy buttons
// (register / name): a dotted quad builds an A record, an IPv6 literal
// builds an AAAA record. Both commands default to the machine's outbound
// IPv4 for A; explicit v6 opt-in keeps the zero-config path unchanged.
package cli

import (
	"fmt"
	"net"
	"strings"

	"github.com/camalolo/freens/internal/wire"
)

// addrRR builds the single address RR for ipStr (A or AAAA by form).
func addrRR(ipStr string, ttl uint64) (*wire.RR, error) {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	switch {
	case ip == nil:
		return nil, fmt.Errorf("invalid IP address %q", ipStr)
	case ip.To4() != nil:
		return wire.A(ip.To4(), ttl)
	case strings.Contains(ipStr, ":"):
		return wire.AAAA(ip.To16(), ttl)
	default:
		return nil, fmt.Errorf("invalid IP address %q", ipStr)
	}
}
